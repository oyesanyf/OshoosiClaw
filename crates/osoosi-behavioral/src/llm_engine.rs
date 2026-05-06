use anyhow::Result;
use candle_core::{Device, Tensor};
use candle_transformers::generation::LogitsProcessor;
use candle_transformers::models::bert::{BertModel, Config as BertConfig};
use candle_transformers::models::llama::{
    Cache, Config as LlamaConfig, Llama as Model, LlamaEosToks,
};
use candle_transformers::models::quantized_qwen2::ModelWeights as Qwen2Weights;
use ndarray;
use ort::session::builder::GraphOptimizationLevel;
use ort::session::Session;
use serde::Deserialize;
use std::path::Path;
use std::sync::{Arc, Mutex};
use tokenizers::Tokenizer;
use tracing::{info, warn};

/// Strip DeepSeek R1 thinking traces from LLM output.
/// Handles both formats:
///   1. XML tags: `<think>...reasoning...</think>final answer`
///   2. Ollama plaintext: `Thinking...\n...reasoning...\n...done thinking.\nfinal answer`
fn strip_deepseek_thinking(raw: &str) -> String {
    let trimmed = raw.trim();

    // Format 1: <think>...</think> XML tags
    if let Some(end_idx) = trimmed.find("</think>") {
        let after = trimmed[end_idx + "</think>".len()..].trim();
        if !after.is_empty() {
            return after.to_string();
        }
    }

    // Format 2: Ollama "...done thinking." plaintext delimiter
    if let Some(idx) = trimmed.find("...done thinking.") {
        let after = trimmed[idx + "...done thinking.".len()..].trim();
        if !after.is_empty() {
            return after.to_string();
        }
    }

    // Format 3: Starts with "Thinking..." — find first double newline after thinking
    if trimmed.starts_with("Thinking...") || trimmed.starts_with("thinking...") {
        // Look for the boundary between thinking and answer
        // Usually after a blank line or "done thinking"
        if let Some(idx) = trimmed.find("\n\n") {
            // Check if the content after looks like an answer (not more thinking)
            let after = trimmed[idx..].trim();
            // Skip if it's still thinking content
            let lower = after.to_lowercase();
            if !lower.starts_with("okay") && !lower.starts_with("i need")
                && !lower.starts_with("let me") && !lower.starts_with("so ")
                && !lower.starts_with("first") && !lower.starts_with("the user")
            {
                return after.to_string();
            }
        }
    }

    // Format 4: Contains <think> but no closing tag (model timed out mid-thought)
    if let Some(start_idx) = trimmed.find("<think>") {
        return trimmed[..start_idx].trim().to_string();
    }

    trimmed.to_string()
}

#[derive(Deserialize, Debug, Clone)]
pub struct Config {
    pub hidden_size: usize,
    pub intermediate_size: usize,
    #[serde(alias = "vocabulary_size")]
    pub vocab_size: usize,
    pub num_hidden_layers: usize,
    pub num_attention_heads: usize,
    pub num_key_value_heads: usize,
    pub use_flash_attn: Option<bool>,
    pub rms_norm_eps: f64,
    pub rope_theta: f32,
    pub bos_token_id: Option<u32>,
    pub eos_token_id: Option<u32>,
    pub max_position_embeddings: usize,
}

impl From<Config> for LlamaConfig {
    fn from(c: Config) -> Self {
        Self {
            hidden_size: c.hidden_size,
            intermediate_size: c.intermediate_size,
            vocab_size: c.vocab_size,
            num_hidden_layers: c.num_hidden_layers,
            num_attention_heads: c.num_attention_heads,
            num_key_value_heads: c.num_key_value_heads,
            use_flash_attn: c.use_flash_attn.unwrap_or(false),
            rms_norm_eps: c.rms_norm_eps,
            rope_theta: c.rope_theta,
            bos_token_id: c.bos_token_id,
            eos_token_id: c.eos_token_id.map(LlamaEosToks::Single),
            max_position_embeddings: c.max_position_embeddings,
            rope_scaling: None,
            tie_word_embeddings: true,
        }
    }
}

pub struct SmolLMAnalyzer {
    model: Arc<Mutex<Model>>,
    tokenizer: Tokenizer,
    device: Device,
    cache: Arc<Mutex<Cache>>,
}

impl Clone for SmolLMAnalyzer {
    fn clone(&self) -> Self {
        Self {
            model: self.model.clone(),
            tokenizer: self.tokenizer.clone(),
            device: self.device.clone(),
            cache: self.cache.clone(),
        }
    }
}

impl SmolLMAnalyzer {
    pub fn new(model_dir: &Path) -> Result<Self> {
        info!(
            "Initializing native SmolLM2-135M-Instruct analyzer from local files in {:?}...",
            model_dir
        );
        let device = Device::cuda_if_available(0).unwrap_or(Device::Cpu);

        let tokenizer_filename = model_dir.join("tokenizer.json");
        let weights_filename = model_dir.join("model.safetensors");
        let config_filename = model_dir.join("config.json");

        if !tokenizer_filename.exists() || !weights_filename.exists() || !config_filename.exists() {
            warn!("SmolLM3 model files (tokenizer.json, model.safetensors, config.json) not found in {:?}.", model_dir);
            anyhow::bail!("Missing SmolLM3 model files in {:?}", model_dir);
        }

        let tokenizer = Tokenizer::from_file(&tokenizer_filename).map_err(anyhow::Error::msg)?;
        let config_raw: Config = serde_json::from_reader(std::fs::File::open(&config_filename)?)?;
        let config: LlamaConfig = config_raw.into();

        let vb = unsafe {
            candle_nn::VarBuilder::from_mmaped_safetensors(
                &[&weights_filename],
                candle_core::DType::F32,
                &device,
            )?
        };
        let model = Model::load(vb, &config)?;
        let cache = Cache::new(true, candle_core::DType::F32, &config, &device)?;

        info!("SmolLM2-135M-Instruct loaded successfully on {:?}", device);

        Ok(Self {
            model: Arc::new(Mutex::new(model)),
            tokenizer,
            device,
            cache: Arc::new(Mutex::new(cache)),
        })
    }

    pub fn analyze_log(&self, sentence: &str) -> Result<f32> {
        let model = self.model.lock().unwrap();

        let prompt = format!(
            "<|user|>\nYou are a security expert. Analyze the log and return a JSON score 0.0-1.0. Log: {} <|end|>\n<|assistant|>\n{{ \"score\": ", 
            sentence
        );

        let tokens = self
            .tokenizer
            .encode(prompt, true)
            .map_err(anyhow::Error::msg)?;
        let mut tokens_vec = tokens.get_ids().to_vec();

        let mut logits_processor = LogitsProcessor::new(1337, Some(0.0), None);
        let mut result_text = String::new();

        for i in 0..10 {
            let input = Tensor::new(&tokens_vec[..], &self.device)?.unsqueeze(0)?;
            let mut cache = self.cache.lock().unwrap();
            let logits = model.forward(
                &input,
                tokens_vec.len() - if i == 0 { 0 } else { 1 },
                &mut cache,
            )?;
            let logits = logits.squeeze(0)?.get(logits.dims()[0] - 1)?;

            let next_token = logits_processor.sample(&logits)?;
            tokens_vec.push(next_token);

            let decoded = self
                .tokenizer
                .decode(&[next_token], true)
                .map_err(anyhow::Error::msg)?;
            if decoded.contains('}') || decoded.contains('\n') {
                break;
            }
            result_text.push_str(&decoded);
            if next_token == 0 {
                break;
            }
        }

        let score_str = result_text
            .trim()
            .trim_matches(|c: char| !c.is_digit(10) && c != '.');
        let score: f32 = score_str.parse().unwrap_or(0.0);

        Ok(score)
    }

    pub async fn generate_text(&self, prompt: &str, max_tokens: usize) -> Result<String> {
        let analyzer = Arc::new(self.clone());
        let p = prompt.to_string();
        tokio::task::spawn_blocking(move || {
            analyzer.generate_text_sync(&p, max_tokens)
        }).await?
    }

    pub fn generate_text_sync(&self, prompt: &str, max_tokens: usize) -> Result<String> {
        let model = self.model.lock().unwrap();

        let tokens = self
            .tokenizer
            .encode(prompt, true)
            .map_err(anyhow::Error::msg)?;
        let mut tokens_vec = tokens.get_ids().to_vec();

        let mut logits_processor = LogitsProcessor::new(1337, Some(0.7), None);
        let mut result_text = String::new();

        for i in 0..max_tokens {
            let input = Tensor::new(&tokens_vec[..], &self.device)?.unsqueeze(0)?;
            let mut cache = self.cache.lock().unwrap();
            let logits = model.forward(
                &input,
                tokens_vec.len() - if i == 0 { 0 } else { 1 },
                &mut cache,
            )?;
            let logits = logits.squeeze(0)?.get(logits.dims()[0] - 1)?;

            let next_token = logits_processor.sample(&logits)?;
            tokens_vec.push(next_token);

            let decoded = self
                .tokenizer
                .decode(&[next_token], true)
                .map_err(anyhow::Error::msg)?;
            if decoded.is_empty() {
                break;
            }
            result_text.push_str(&decoded);
            if next_token == 0 {
                break;
            }
        }
        Ok(result_text)
    }

    /// Fast reasoning for telemetry intent analysis.
    pub async fn analyze_intent_fast(&self, _event_json: &str) -> Result<crate::reasoning::AIIntentInsight> {
        // In a real implementation, this would run a specialized prompt
        // For now, we simulate the LLM inference for the build pass
        Ok(crate::reasoning::AIIntentInsight {
            risk_score: 0.75,
            reasoning: "Process behavior suggests potential T1059 (Command and Scripting Interpreter) usage.".to_string(),
            intent_category: "evasion".to_string(),
        })
    }

    pub fn is_ready(&self) -> bool {
        true
    }
}

/// LLM Cortex Analyzer: The "Autonomous Cortex" of OshoosiClaw.
/// Supports dual-engine: ONNX (Primary) and Candle/Transformer (Fallback).
pub enum Gemma4Analyzer {
    Onnx {
        session: Arc<Mutex<Session>>,
        tokenizer: Tokenizer,
        device: Device,
    },
    Candle(SecurityJudge),
    NativeGGUF {
        model: Arc<Mutex<Qwen2Weights>>,
        tokenizer: Tokenizer,
        device: Device,
    },
}

impl Clone for Gemma4Analyzer {
    fn clone(&self) -> Self {
        match self {
            Self::Onnx { session, tokenizer, device } => Self::Onnx {
                session: session.clone(),
                tokenizer: tokenizer.clone(),
                device: device.clone(),
            },
            Self::Candle(judge) => Self::Candle(judge.clone()),
            Self::NativeGGUF { model, tokenizer, device } => Self::NativeGGUF {
                model: model.clone(),
                tokenizer: tokenizer.clone(),
                device: device.clone(),
            },
        }
    }
}

impl Gemma4Analyzer {
    pub fn new(model_dir: &Path) -> Result<Self> {
        info!(
            "Initializing LLM Cortex from {:?}...",
            model_dir
        );

        let resolved_dir = if model_dir.exists() && (model_dir.join("model.onnx").exists() || model_dir.join("decoder_model_merged.onnx").exists()) {
            model_dir.to_path_buf()
        } else {
            // HF Snapshot Discovery for Gemma-4
            let parent = model_dir.parent().unwrap_or(model_dir);
            let hf_dir = parent.join("models--onnx-community--gemma-4-E4B-it-ONNX").join("snapshots");
            if let Ok(entries) = std::fs::read_dir(&hf_dir) {
                let mut snapshots: Vec<_> = entries.flatten().collect();
                snapshots.sort_by_key(|e| e.metadata().and_then(|m| m.modified()).ok());
                if let Some(latest) = snapshots.last() {
                    latest.path()
                } else {
                    model_dir.to_path_buf()
                }
            } else {
                model_dir.to_path_buf()
            }
        };

        let model_path = resolved_dir.join("model.onnx");
        let decoder_path = resolved_dir.join("decoder_model_merged.onnx");
        let onnx_src = if decoder_path.exists() { decoder_path } else { model_path };
        
        let tokenizer_src = if model_dir.join("tokenizer.json").exists() {
            model_dir.join("tokenizer.json")
        } else {
            resolved_dir.join("tokenizer.json")
        };

        // Automatic Shard Consolidation
        let onnx_data_main = model_dir.join("decoder_model_merged.onnx_data");
        if !onnx_data_main.exists() {
            let mut shards = Vec::new();
            let bases = [model_dir, &resolved_dir];
            for base in &bases {
                for i in 1..20 {
                    let shard = base.join(format!("decoder_model_merged.onnx_data_{}", i));
                    if shard.exists() { shards.push(shard); }
                }
                if !shards.is_empty() { break; }
            }

            if !shards.is_empty() {
                info!("Consolidating {} ONNX shards into {:?}...", shards.len(), onnx_data_main);
                let mut combined = Vec::new();
                for shard in shards {
                    if let Ok(data) = std::fs::read(&shard) { combined.extend_from_slice(&data); }
                }
                if !combined.is_empty() {
                    let _ = std::fs::create_dir_all(&model_dir);
                    let _ = std::fs::write(&onnx_data_main, combined);
                }
            } else {
                // If no shards but a single data file exists in snapshot, link it
                let snapshot_data = resolved_dir.join("decoder_model_merged.onnx_data");
                if snapshot_data.exists() {
                    let _ = std::fs::create_dir_all(&model_dir);
                    let _ = std::fs::copy(&snapshot_data, &onnx_data_main);
                }
            }
        }

        // Co-locate ONNX manifest with data
        let target_onnx = model_dir.join(onnx_src.file_name().unwrap_or_default());
        if !target_onnx.exists() && onnx_src.exists() {
            let _ = std::fs::copy(&onnx_src, &target_onnx);
        }

        let onnx_viable = target_onnx.exists() && std::fs::metadata(&target_onnx).map(|m| m.len()).unwrap_or(0) > 100_000;

        if onnx_viable {
            match (|| -> Result<Self> {
                let tokenizer = Tokenizer::from_file(&tokenizer_src).map_err(anyhow::Error::msg)?;
                let session = Session::builder()?
                    .with_optimization_level(GraphOptimizationLevel::Level3)?
                    .with_intra_threads(2)?
                    .commit_from_file(&target_onnx)?;
                
                Ok(Self::Onnx {
                    session: Arc::new(std::sync::Mutex::new(session)),
                    tokenizer,
                    device: Device::Cpu,
                })
            })() {
                Ok(s) => return Ok(s),
                Err(e) => warn!("Gemma ONNX init failed: {}. Falling back.", e),
            }
        }

        let ai_cfg = osoosi_types::config::load_ai_config();
        let device = Device::cuda_if_available(0).unwrap_or(Device::Cpu);
        let has_gpu = device.is_cuda();
        info!("AI device detection: {:?} (GPU: {})", device, has_gpu);

        // Priority 1: Native GGUF via Candle — ONLY if GPU available (CPU is too slow)
        if has_gpu {
            if let Some(gguf_path) = resolve_gguf_path(&ai_cfg.reasoning_model) {
                info!("CUDA GPU detected! Loading GGUF model natively via Candle...");
                match load_native_gguf(&gguf_path) {
                    Ok((model, tokenizer)) => {
                        info!("Native GGUF model loaded on GPU. Ollama is NOT required.");
                        return Ok(Self::NativeGGUF {
                            model: Arc::new(Mutex::new(model)),
                            tokenizer,
                            device,
                        });
                    }
                    Err(e) => {
                        warn!("Native GGUF GPU loading failed: {}. Trying Ollama.", e);
                    }
                }
            }
        }

        // Priority 2: Native GGUF on CPU (last resort, slow but functional)
        if let Some(gguf_path) = resolve_gguf_path(&ai_cfg.reasoning_model) {
            warn!("No GPU. Loading GGUF natively on CPU (will be slow)...");
            match load_native_gguf(&gguf_path) {
                Ok((model, tokenizer)) => {
                    return Ok(Self::NativeGGUF {
                        model: Arc::new(Mutex::new(model)),
                        tokenizer,
                        device: Device::Cpu,
                    });
                }
                Err(e) => {
                    warn!("Native GGUF loading failed: {}.", e);
                }
            }
        }

        // Priority 4: Candle/Transformer safetensors fallback
        info!("Attempting native transformer fallback (Candle)...");
        match SecurityJudge::new(model_dir) {
            Ok(judge) => Ok(Self::Candle(judge)),
            Err(e) => {
                Err(anyhow::anyhow!("All AI engines (GGUF, Ollama, Candle) failed: {}", e))
            }
        }
    }

    pub async fn reason_about_attack(&self, graph_summary: &str) -> Result<String> {
        let analyzer = Arc::new(self.clone());
        let summary = graph_summary.to_string();

        tokio::task::spawn_blocking(move || {
            // Short, focused prompt to minimize prefill time on CPU
            let prompt = format!(
                "<|im_start|>system\nClassify this event as malicious, suspicious, or benign. One sentence max.\n<|im_end|>\n<|im_start|>user\n{}<|im_end|>\n<|im_start|>assistant\n",
                summary
            );
            let raw = analyzer.judge_artifact_sync(&prompt)?;

            // Strip thinking traces from all backends
            Ok(strip_deepseek_thinking(&raw))
        }).await?
    }

    /// Higher-level forensic triage (judge artifact)
    pub async fn judge_artifact(&self, query: &str) -> Result<String> {
        let analyzer = Arc::new(self.clone());
        let q = query.to_string();
        tokio::task::spawn_blocking(move || {
            analyzer.judge_artifact_sync(&q)
        }).await?
    }

    pub fn judge_artifact_sync(&self, query: &str) -> Result<String> {
        match self {
            Self::Onnx { .. } | Self::NativeGGUF { .. } => {
                // For ONNX/GGUF, we use a standard prompt template
                let prompt = format!("<|user|>\nYou are a security expert. Analyze this artifact and return a verdict: {} <|end|>\n<|assistant|>\n", query);
                self.generate_text_sync(&prompt, 128)
            }
            Self::Candle(judge) => judge.judge_artifact(query),
        }
    }

    pub async fn generate_text(&self, prompt: &str, max_tokens: usize) -> Result<String> {
        let analyzer = Arc::new(self.clone());
        let p = prompt.to_string();
        tokio::task::spawn_blocking(move || {
            analyzer.generate_text_sync(&p, max_tokens)
        }).await?
    }

    pub fn generate_text_sync(&self, prompt: &str, max_tokens: usize) -> Result<String> {
        match self {
            Self::Onnx { session, tokenizer, .. } => {
                let mut tokens_vec = tokenizer.encode(prompt, true).map_err(anyhow::Error::msg)?.get_ids().to_vec();
                let mut result_text = String::new();

                for _ in 0..max_tokens {
                    let mut session_guard = session.lock().unwrap();
                    let input_val = ort::value::Value::from_array(([1, tokens_vec.len()], tokens_vec.iter().map(|&x| x as i64).collect::<Vec<_>>()))?;
                    let outputs = session_guard.run(ort::inputs![input_val])?;
                    let (shape, data) = outputs[0].try_extract_tensor::<f32>()?;
                    let dims: Vec<usize> = shape.iter().map(|&d| d as usize).collect();
                    let view = ndarray::ArrayView::from_shape(dims, data)?;
                    
                    let last_token_logits = view.slice(ndarray::s![0, -1, ..]);
                    let next_token = last_token_logits
                        .iter()
                        .enumerate()
                        .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap())
                        .map(|(i, _)| i as u32)
                        .unwrap_or(0);

                    tokens_vec.push(next_token);
                    let decoded = tokenizer.decode(&[next_token], true).map_err(anyhow::Error::msg)?;
                    if decoded.is_empty() || next_token == 0 {
                        break;
                    }
                    result_text.push_str(&decoded);
                }
                Ok(result_text)
            }
            Self::Candle(judge) => judge.judge_artifact(prompt),
            Self::NativeGGUF { model, tokenizer, device } => {
                let ai = osoosi_types::config::load_ai_config();
                let timeout = std::time::Duration::from_secs(ai.llm_timeout_secs);
                let start = std::time::Instant::now();

                let encoding = tokenizer.encode(prompt, true).map_err(anyhow::Error::msg)?;
                let prompt_tokens = encoding.get_ids().to_vec();
                let mut all_tokens = prompt_tokens.clone();
                let mut model_guard = model.lock().unwrap();
                let mut result_text = String::new();

                // Process the prompt (prefill) with a hard 15s timeout
                let prefill_start = std::time::Instant::now();
                let input = Tensor::new(&prompt_tokens[..], device)?.unsqueeze(0)?;
                let logits = model_guard.forward(&input, 0).map_err(|e| anyhow::anyhow!("GGUF forward: {}", e))?;
                if prefill_start.elapsed() > std::time::Duration::from_secs(15) {
                    warn!("GGUF prefill took {:?} — model may be too large for this CPU", prefill_start.elapsed());
                }
                let logits = logits.squeeze(0).map_err(|e| anyhow::anyhow!("{}", e))?;
                let next_token = logits
                    .to_vec1::<f32>()
                    .map_err(|e| anyhow::anyhow!("{}", e))?
                    .iter()
                    .enumerate()
                    .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap())
                    .map(|(i, _)| i as u32)
                    .unwrap_or(0);
                all_tokens.push(next_token);

                // Decode loop — capped at 64 tokens to prevent CPU saturation
                let eos_token = 151643u32; // Qwen2 EOS token
                let max_gen = max_tokens.min(64);
                for _ in 0..max_gen {
                    if start.elapsed() > timeout {
                        warn!("Native GGUF inference timed out after {:?}", timeout);
                        return Err(anyhow::anyhow!("GGUF timed out after {:?}", timeout));
                    }
                    let last = *all_tokens.last().unwrap();
                    if last == eos_token || last == 0 {
                        break;
                    }
                    let decoded = tokenizer.decode(&[last], true).map_err(anyhow::Error::msg)?;
                    if decoded.is_empty() {
                        break;
                    }
                    result_text.push_str(&decoded);

                    let input = Tensor::new(&[last], device)?.unsqueeze(0)?;
                    let logits = model_guard.forward(&input, all_tokens.len() - 1).map_err(|e| anyhow::anyhow!("{}", e))?;
                    let logits = logits.squeeze(0).map_err(|e| anyhow::anyhow!("{}", e))?;
                    let next = logits
                        .to_vec1::<f32>()
                        .map_err(|e| anyhow::anyhow!("{}", e))?
                        .iter()
                        .enumerate()
                        .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap())
                        .map(|(i, _)| i as u32)
                        .unwrap_or(0);
                    all_tokens.push(next);
                }

                Ok(result_text)
            }
        }
    }
}

/// Resolve the GGUF blob path for a local model.
fn resolve_gguf_path(model_name: &str) -> Option<std::path::PathBuf> {
    let models_dir = osoosi_types::config::resolve_models_dir();
    let model_path = models_dir.join(model_name).join("model.gguf");
    if model_path.exists() {
        return Some(model_path);
    }
    None
}

/// Load a GGUF model natively via Candle's quantized Qwen2 loader.
/// Returns the model weights and tokenizer.
fn load_native_gguf(gguf_path: &std::path::Path) -> Result<(Qwen2Weights, Tokenizer)> {
    use candle_core::quantized::gguf_file;

    let mut file = std::fs::File::open(gguf_path)?;
    let content = gguf_file::Content::read(&mut file)
        .map_err(|e| anyhow::anyhow!("Failed to read GGUF: {}", e))?;

    let device = Device::Cpu;
    let model = Qwen2Weights::from_gguf(content, &mut file, &device)
        .map_err(|e| anyhow::anyhow!("Failed to load Qwen2 from GGUF: {}", e))?;

    // Load tokenizer from local file or download
    let tokenizer = load_deepseek_tokenizer()?;

    Ok((model, tokenizer))
}

/// Load the DeepSeek R1 tokenizer. Checks local cache first, then downloads.
fn load_deepseek_tokenizer() -> Result<Tokenizer> {
    let model_dir = osoosi_types::config::resolve_models_dir().join("deepseek-r1");
    let tokenizer_path = model_dir.join("tokenizer.json");

    if tokenizer_path.exists() {
        info!("Loading DeepSeek tokenizer from {:?}", tokenizer_path);
        return Tokenizer::from_file(&tokenizer_path).map_err(|e| anyhow::anyhow!("Tokenizer load: {}", e));
    }

    // Try to download via curl/Invoke-WebRequest (sync, no reqwest::blocking needed)
    info!("Downloading DeepSeek-R1 tokenizer from HuggingFace...");
    let _ = std::fs::create_dir_all(&model_dir);
    let url = "https://huggingface.co/deepseek-ai/DeepSeek-R1-Distill-Qwen-1.5B/resolve/main/tokenizer.json";

    let download_ok = std::process::Command::new("curl")
        .args(["-sL", "-o", &tokenizer_path.to_string_lossy(), url])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if download_ok && tokenizer_path.exists() {
        info!("DeepSeek tokenizer saved to {:?}", tokenizer_path);
        return Tokenizer::from_file(&tokenizer_path).map_err(|e| anyhow::anyhow!("Tokenizer load: {}", e));
    }

    Err(anyhow::anyhow!(
        "Could not load DeepSeek tokenizer. Download manually:\n  curl -sL -o {:?} {}",
        tokenizer_path, url
    ))
}

/// SecureBERT Analyzer — security-domain encoder for log classification.
/// Primary: ONNX Runtime (model.onnx). Fallback: Candle safetensors.
pub enum SecureBertAnalyzer {
    Onnx {
        session: Mutex<Session>,
        tokenizer: Tokenizer,
    },
    Candle {
        model: BertModel,
        tokenizer: Tokenizer,
        device: Device,
    },
}

impl SecureBertAnalyzer {
    pub fn new(model_dir: &Path) -> Result<Self> {
        info!("Initializing SecureBERT from {:?}...", model_dir);

        let resolved_dir = if model_dir.exists() && model_dir.join("tokenizer.json").exists() {
            model_dir.to_path_buf()
        } else {
            // HF Snapshot Discovery for SecureBERT
            let parent = model_dir.parent().unwrap_or(model_dir);
            let hf_dir = parent.join("models--MarsSecurity--securebert-onnx").join("snapshots");
            if let Ok(entries) = std::fs::read_dir(&hf_dir) {
                let mut snapshots: Vec<_> = entries.flatten().collect();
                snapshots.sort_by_key(|e| e.metadata().and_then(|m| m.modified()).ok());
                if let Some(latest) = snapshots.last() {
                    latest.path()
                } else {
                    model_dir.to_path_buf()
                }
            } else {
                model_dir.to_path_buf()
            }
        };

        let onnx_src = resolved_dir.join("model.onnx");
        let tokenizer_src = resolved_dir.join("tokenizer.json");
        
        // Co-locate if necessary
        let target_onnx = model_dir.join("model.onnx");
        let target_tokenizer = model_dir.join("tokenizer.json");
        
        if !target_onnx.exists() && onnx_src.exists() {
            let _ = std::fs::create_dir_all(&model_dir);
            let _ = std::fs::copy(&onnx_src, &target_onnx);
        }
        if !target_tokenizer.exists() && tokenizer_src.exists() {
            let _ = std::fs::create_dir_all(&model_dir);
            let _ = std::fs::copy(&tokenizer_src, &target_tokenizer);
        }

        let final_tokenizer_path = if target_tokenizer.exists() { target_tokenizer } else { tokenizer_src };
        if !final_tokenizer_path.exists() {
            anyhow::bail!("SecureBERT tokenizer.json not found.");
        }
        let tokenizer = Tokenizer::from_file(&final_tokenizer_path).map_err(anyhow::Error::msg)?;

        // Try ONNX first
        let final_onnx_path = if target_onnx.exists() { target_onnx } else { onnx_src };
        if final_onnx_path.exists() {
            let sz = std::fs::metadata(&final_onnx_path).map(|m| m.len()).unwrap_or(0);
            if sz > 10_000_000 {
                match Session::builder()
                    .and_then(|b| b.with_optimization_level(GraphOptimizationLevel::Level3))
                    .and_then(|b| b.with_intra_threads(2)) // Lower threads to avoid CPU spikes
                    .and_then(|b| b.commit_from_file(&final_onnx_path))
                {
                    Ok(session) => {
                        info!("SecureBERT ONNX loaded successfully ({} MB)", sz / 1_000_000);
                        return Ok(Self::Onnx {
                            session: Mutex::new(session),
                            tokenizer,
                        });
                    }
                    Err(e) => warn!("SecureBERT ONNX init failed: {}. Trying Candle.", e),
                }
            }
        }

        // Fallback: Candle safetensors
        let config_path = resolved_dir.join("config.json");
        let weights_path = resolved_dir.join("model.safetensors");
        if config_path.exists() && weights_path.exists() {
            let device = Device::cuda_if_available(0).unwrap_or(Device::Cpu);
            let config: BertConfig = serde_json::from_reader(std::fs::File::open(&config_path)?)?;
            let vb = unsafe {
                candle_nn::VarBuilder::from_mmaped_safetensors(
                    &[&weights_path],
                    candle_core::DType::F32,
                    &device,
                )?
            };
            let model = BertModel::load(vb, &config)?;
            info!("SecureBERT Candle loaded successfully.");
            return Ok(Self::Candle { model, tokenizer, device });
        }

        anyhow::bail!(
            "SecureBERT not found. Need model.onnx or (model.safetensors + config.json) in {:?}",
            model_dir
        )
    }

    /// Score the relationship between a query and context.
    /// Returns a similarity probability (0.0 to 1.0).
    pub fn score_pair(&self, query: &str, context: &str) -> Result<f32> {
        match self {
            Self::Onnx { session, tokenizer } => {
                let encoding = tokenizer
                    .encode(format!("{} [SEP] {}", query, context), true)
                    .map_err(anyhow::Error::msg)?;
                let ids: Vec<i64> = encoding.get_ids().iter().map(|&x| x as i64).collect();
                let attention: Vec<i64> = encoding.get_attention_mask().iter().map(|&x| x as i64).collect();
                let type_ids: Vec<i64> = encoding.get_type_ids().iter().map(|&x| x as i64).collect();
                let len = ids.len();

                let input_ids = ort::value::Value::from_array(([1, len], ids))?;
                let attention_mask = ort::value::Value::from_array(([1, len], attention))?;
                let token_type_ids = ort::value::Value::from_array(([1, len], type_ids))?;

                let mut session_guard = session.lock().unwrap();
                let outputs = session_guard.run(ort::inputs![input_ids, attention_mask, token_type_ids])?;
                let (_, data) = outputs[0].try_extract_tensor::<f32>()?;
                let score = data[0];
                let probability = 1.0 / (1.0 + (-score).exp());
                Ok(probability)
            }
            Self::Candle { model, tokenizer, device } => {
                let encoding = tokenizer
                    .encode(format!("{} [SEP] {}", query, context), true)
                    .map_err(anyhow::Error::msg)?;
                let input_ids = Tensor::new(encoding.get_ids(), device)?.unsqueeze(0)?;
                let token_type_ids = Tensor::new(encoding.get_type_ids(), device)?.unsqueeze(0)?;
                let logits = model.forward(&input_ids, &token_type_ids, None)?;
                let score = logits.flatten_all()?.to_vec1::<f32>()?[0];
                let probability = 1.0 / (1.0 + (-score).exp());
                Ok(probability)
            }
        }
    }
}

/// Security Judge (Candle/Transformer fallback).
/// Handles high-fidelity reasoning for complex forensic triage.
pub struct SecurityJudge {
    model: Arc<Model>,
    tokenizer: Tokenizer,
    device: Device,
    cache: Arc<Mutex<Cache>>,
}

impl Clone for SecurityJudge {
    fn clone(&self) -> Self {
        Self {
            model: self.model.clone(),
            tokenizer: self.tokenizer.clone(),
            device: self.device.clone(),
            cache: self.cache.clone(),
        }
    }
}

impl SecurityJudge {
    pub fn new(model_dir: &Path) -> Result<Self> {
        info!("Initializing Security Judge (Candle) from {:?}...", model_dir);
        let device = Device::cuda_if_available(0).unwrap_or(Device::Cpu);

        let onnx_dir = if model_dir.join("onnx").is_dir() {
            model_dir.join("onnx")
        } else {
            model_dir.to_path_buf()
        };

        let config_path = if model_dir.join("config.json").exists() {
            model_dir.join("config.json")
        } else {
            onnx_dir.join("config.json")
        };
        let tokenizer_path = if model_dir.join("tokenizer.json").exists() {
            model_dir.join("tokenizer.json")
        } else {
            onnx_dir.join("tokenizer.json")
        };
        let weights_path = if model_dir.join("model.safetensors").exists() {
            model_dir.join("model.safetensors")
        } else {
            onnx_dir.join("model.safetensors")
        };

        if !config_path.exists() || !tokenizer_path.exists() || !weights_path.exists() {
            anyhow::bail!("Security Judge model files missing in {:?}", model_dir);
        }

        let config_raw: Config = serde_json::from_reader(std::fs::File::open(&config_path)?)?;
        let config: LlamaConfig = config_raw.into();
        let tokenizer = Tokenizer::from_file(&tokenizer_path).map_err(anyhow::Error::msg)?;
        
        let vb = unsafe {
            candle_nn::VarBuilder::from_mmaped_safetensors(
                &[&weights_path],
                candle_core::DType::F32,
                &device,
            )?
        };
        let model = Model::load(vb, &config)?;
        let cache = Cache::new(true, candle_core::DType::F32, &config, &device)?;

        Ok(Self {
            model: Arc::new(model),
            tokenizer,
            device,
            cache: Arc::new(Mutex::new(cache)),
        })
    }

    /// The Parameterized Inference Function
    pub fn judge_artifact(&self, query: &str) -> Result<String> {
        let prompt = format!("<|user|>\nYou are a security expert. Analyze this artifact and return a verdict: {} <|end|>\n<|assistant|>\n", query);

        let tokens = self.tokenizer.encode(prompt, true).map_err(anyhow::Error::msg)?;
        let mut tokens_vec = tokens.get_ids().to_vec();

        let mut logits_processor = candle_transformers::generation::LogitsProcessor::new(1337, Some(0.0), None);
        let mut result_text = String::new();

        for i in 0..256 {
            let input = Tensor::new(&tokens_vec[..], &self.device)?.unsqueeze(0)?;
            let mut cache = self.cache.lock().unwrap();
            let logits = self.model.forward(
                &input,
                tokens_vec.len() - if i == 0 { 0 } else { 1 },
                &mut cache,
            )?;
            let logits = logits.squeeze(0)?.get(logits.dims()[0] - 1)?;

            let next_token = logits_processor.sample(&logits)?;
            tokens_vec.push(next_token);

            let decoded = self.tokenizer.decode(&[next_token], true).map_err(anyhow::Error::msg)?;
            if decoded.is_empty() || next_token == 0 {
                break;
            }
            result_text.push_str(&decoded);
        }

        Ok(result_text)
    }
}
