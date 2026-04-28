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
use std::sync::Mutex;
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
    model: Mutex<Model>,
    tokenizer: Tokenizer,
    device: Device,
    cache: Mutex<Cache>,
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
            model: Mutex::new(model),
            tokenizer,
            device,
            cache: Mutex::new(cache),
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

    pub fn generate_text(&self, prompt: &str, max_tokens: usize) -> Result<String> {
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
}

/// LLM Cortex Analyzer: The "Autonomous Cortex" of OshoosiClaw.
/// Supports dual-engine: ONNX (Primary) and Candle/Transformer (Fallback).
pub enum Gemma4Analyzer {
    Onnx {
        session: std::sync::Mutex<Session>,
        tokenizer: Tokenizer,
        device: Device,
    },
    Candle(SecurityJudge),
    NativeGGUF {
        model: Mutex<Qwen2Weights>,
        tokenizer: Tokenizer,
        device: Device,
    },
    OllamaFallback,
}

impl Gemma4Analyzer {
    pub fn new(model_dir: &Path) -> Result<Self> {
        info!(
            "Initializing LLM Cortex from {:?}...",
            model_dir
        );

        let model_path = model_dir.join("model.onnx");
        let decoder_path = model_dir.join("decoder_model_merged.onnx");
        let tokenizer_filename = model_dir.join("tokenizer.json");

        // The ONNX model requires multi-GB data shards alongside the manifest.
        // If the .onnx file is smaller than 10 MB it's just a manifest stub and
        // ONNX Runtime will fail with "file_size: The system cannot find the file".
        // Skip straight to Ollama/Candle in that case.
        let onnx_file = if decoder_path.exists() { &decoder_path } else { &model_path };
        let onnx_viable = onnx_file.exists() && {
            let sz = std::fs::metadata(onnx_file).map(|m| m.len()).unwrap_or(0);
            sz > 10_000_000 // > 10 MB means it's likely a real model, not a manifest
        };

        // Try ONNX only if the model file is large enough to be real
        if onnx_viable {
            match (|| -> Result<Self> {
                let tokenizer = Tokenizer::from_file(&tokenizer_filename).map_err(anyhow::Error::msg)?;
                let session = Session::builder()?
                    .with_optimization_level(GraphOptimizationLevel::Level3)?
                    .with_intra_threads(4)?
                    .commit_from_file(onnx_file)?;
                
                Ok(Self::Onnx {
                    session: std::sync::Mutex::new(session),
                    tokenizer,
                    device: Device::Cpu, // ONNX default
                })
            })() {
                Ok(s) => return Ok(s),
                Err(e) => warn!("LLM ONNX initialization failed: {}. Falling back.", e),
            }
        } else if onnx_file.exists() {
            info!("LLM ONNX manifest is a stub ({} bytes). Skipping ONNX, using Ollama/Candle fallback.",
                std::fs::metadata(onnx_file).map(|m| m.len()).unwrap_or(0));
        }

        // Priority 1: Native GGUF via Candle (in-process, no external deps, GPU if available)
        let ai_cfg = osoosi_types::config::load_ai_config();
        if let Some(gguf_path) = resolve_gguf_path(&ai_cfg.reasoning_model) {
            info!("Loading GGUF model natively via Candle (in-process, no Ollama needed)...");
            let device = Device::cuda_if_available(0).unwrap_or(Device::Cpu);
            info!("Candle device: {:?}", device);
            match load_native_gguf(&gguf_path) {
                Ok((model, tokenizer)) => {
                    info!("Native GGUF model loaded on {:?}. Ollama is NOT required.", device);
                    return Ok(Self::NativeGGUF {
                        model: Mutex::new(model),
                        tokenizer,
                        device,
                    });
                }
                Err(e) => {
                    warn!("Native GGUF loading failed: {}. Trying Ollama fallback.", e);
                }
            }
        }

        // Priority 2: Ollama HTTP API (optional, for machines with Ollama installed)
        if std::process::Command::new("ollama").arg("--version").output().is_ok() {
            info!("Ollama detected. Using Ollama HTTP API for AI reasoning (optional fallback).");
            return Ok(Self::OllamaFallback);
        }

        // Priority 3: Candle/Transformer safetensors fallback
        info!("Attempting native transformer fallback (Candle)...");
        match SecurityJudge::new(model_dir) {
            Ok(judge) => Ok(Self::Candle(judge)),
            Err(e) => {
                Err(anyhow::anyhow!("All AI engines (GGUF, Ollama, Candle) failed: {}", e))
            }
        }
    }

    pub fn reason_about_attack(&self, graph_summary: &str) -> Result<String> {
        // Short, focused prompt to minimize prefill time on CPU
        let prompt = format!(
            "<|im_start|>system\nClassify this event as malicious, suspicious, or benign. One sentence max.\n<|im_end|>\n<|im_start|>user\n{}<|im_end|>\n<|im_start|>assistant\n",
            graph_summary
        );
        let raw = match self {
            Self::Onnx { .. } => self.generate_text(&prompt, 48),
            Self::Candle(judge) => judge.judge_artifact(&prompt),
            Self::NativeGGUF { .. } => self.generate_text(&prompt, 48),
            Self::OllamaFallback => {
                let ai = osoosi_types::config::load_ai_config();
                let model = ai.reasoning_model;
                let timeout_secs = ai.llm_timeout_secs;

                // Use Ollama HTTP API via raw TCP (no extra deps, reuses loaded model)
                let body = serde_json::json!({
                    "model": model,
                    "messages": [
                        {"role": "system", "content": "You are the OshoosiClaw Autonomous Cortex. Analyze security events concisely. State if the process is malicious, suspicious, or benign. Be brief."},
                        {"role": "user", "content": graph_summary}
                    ],
                    "stream": false
                });
                let body_str = serde_json::to_string(&body)?;

                // Parse host:port from reasoning_url
                let url = &ai.reasoning_url;
                let host_port = url
                    .strip_prefix("http://").unwrap_or(url)
                    .split('/').next().unwrap_or("127.0.0.1:11434");
                let path = url
                    .strip_prefix("http://").unwrap_or(url)
                    .find('/').map(|i| &url.strip_prefix("http://").unwrap_or(url)[i..])
                    .unwrap_or("/v1/chat/completions");

                let timeout = std::time::Duration::from_secs(timeout_secs);
                let stream = std::net::TcpStream::connect_timeout(
                    &host_port.parse().unwrap_or_else(|_| "127.0.0.1:11434".parse().unwrap()),
                    std::time::Duration::from_secs(5),
                ).map_err(|e| anyhow::anyhow!("Ollama not reachable at {}: {}", host_port, e))?;
                stream.set_read_timeout(Some(timeout)).ok();
                stream.set_write_timeout(Some(std::time::Duration::from_secs(5))).ok();

                use std::io::{Write, Read};
                let request = format!(
                    "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    path, host_port, body_str.len(), body_str
                );
                let mut stream = stream;
                stream.write_all(request.as_bytes())?;

                let mut response = String::new();
                stream.read_to_string(&mut response).ok();

                // Extract JSON body (after \r\n\r\n headers)
                let json_body = response.split("\r\n\r\n").nth(1).unwrap_or(&response);
                let json: serde_json::Value = serde_json::from_str(json_body)
                    .map_err(|e| anyhow::anyhow!("Ollama JSON parse: {}", e))?;

                let content = json["choices"][0]["message"]["content"]
                    .as_str()
                    .unwrap_or("No response");

                Ok(strip_deepseek_thinking(content))
            }
        }?;

        // Strip thinking traces from all backends
        Ok(strip_deepseek_thinking(&raw))
    }

    pub fn generate_text(&self, prompt: &str, max_tokens: usize) -> Result<String> {
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
            Self::OllamaFallback => {
                let ai = osoosi_types::config::load_ai_config();
                let model = ai.reasoning_model;
                let timeout_secs = ai.llm_timeout_secs;

                let mut child = std::process::Command::new("ollama")
                    .args(["run", &model, prompt])
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()?;

                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
                loop {
                    match child.try_wait() {
                        Ok(Some(status)) => {
                            let out = child.wait_with_output()?;
                            if status.success() {
                                return Ok(String::from_utf8_lossy(&out.stdout).trim().to_string());
                            } else {
                                return Err(anyhow::anyhow!("Ollama failed: {}", String::from_utf8_lossy(&out.stderr)));
                            }
                        }
                        Ok(None) => {
                            if std::time::Instant::now() >= deadline {
                                let _ = child.kill();
                                return Err(anyhow::anyhow!("Ollama inference timed out after {}s", timeout_secs));
                            }
                            std::thread::sleep(std::time::Duration::from_millis(250));
                        }
                        Err(e) => return Err(e.into()),
                    }
                }
            }
        }
    }
}

/// Resolve the GGUF blob path for an Ollama model (e.g. "deepseek-r1:1.5b").
fn resolve_gguf_path(model_name: &str) -> Option<std::path::PathBuf> {
    // Try `ollama show <model> --modelfile` to get the FROM path
    let output = std::process::Command::new("ollama")
        .args(["show", model_name, "--modelfile"])
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let line = line.trim();
        if line.starts_with("FROM ") {
            let path_str = line.strip_prefix("FROM ")?.trim();
            let path = std::path::PathBuf::from(path_str);
            if path.exists() {
                return Some(path);
            }
        }
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

        let tokenizer_path = model_dir.join("tokenizer.json");
        if !tokenizer_path.exists() {
            anyhow::bail!("SecureBERT tokenizer.json not found in {:?}", model_dir);
        }
        let tokenizer = Tokenizer::from_file(&tokenizer_path).map_err(anyhow::Error::msg)?;

        // Try ONNX first (model.onnx — already downloaded, architecture-agnostic)
        let onnx_path = model_dir.join("model.onnx");
        if onnx_path.exists() {
            let sz = std::fs::metadata(&onnx_path).map(|m| m.len()).unwrap_or(0);
            if sz > 10_000_000 {
                match Session::builder()
                    .and_then(|b| b.with_optimization_level(GraphOptimizationLevel::Level3))
                    .and_then(|b| b.with_intra_threads(4))
                    .and_then(|b| b.commit_from_file(&onnx_path))
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
        let config_path = model_dir.join("config.json");
        let weights_path = model_dir.join("model.safetensors");
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
    model: Model,
    tokenizer: Tokenizer,
    device: Device,
    cache: Mutex<Cache>,
}

impl SecurityJudge {
    pub fn new(model_dir: &Path) -> Result<Self> {
        info!("Initializing Security Judge (Candle) from {:?}...", model_dir);
        let device = Device::cuda_if_available(0).unwrap_or(Device::Cpu);

        let config_path = model_dir.join("config.json");
        let tokenizer_path = model_dir.join("tokenizer.json");
        let weights_path = model_dir.join("model.safetensors");

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
            model,
            tokenizer,
            device,
            cache: Mutex::new(cache),
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
