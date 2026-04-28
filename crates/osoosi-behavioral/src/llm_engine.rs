use anyhow::Result;
use candle_core::{Device, Tensor};
use candle_transformers::generation::LogitsProcessor;
use candle_transformers::models::bert::{BertModel, Config as BertConfig};
use candle_transformers::models::llama::{
    Cache, Config as LlamaConfig, Llama as Model, LlamaEosToks,
};
use ndarray;
use ort::session::builder::GraphOptimizationLevel;
use ort::session::Session;
use serde::Deserialize;
use std::path::Path;
use std::sync::Mutex;
use tokenizers::Tokenizer;
use tracing::{info, warn};

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

/// Gemma 4 E2B Analyzer: The "Autonomous Cortex" of OshoosiClaw.
/// Supports dual-engine: ONNX (Primary) and Candle/Transformer (Fallback).
pub enum Gemma4Analyzer {
    Onnx {
        session: std::sync::Mutex<Session>,
        tokenizer: Tokenizer,
        device: Device,
    },
    Candle(SecurityJudge),
    OllamaFallback,
}

impl Gemma4Analyzer {
    pub fn new(model_dir: &Path) -> Result<Self> {
        info!(
            "Initializing Gemma 4 Autonomous Cortex from {:?}...",
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
                Err(e) => warn!("Gemma 4 ONNX initialization failed: {}. Falling back.", e),
            }
        } else if onnx_file.exists() {
            info!("Gemma 4 ONNX manifest is a stub ({} bytes). Skipping ONNX, using Ollama/Candle fallback.",
                std::fs::metadata(onnx_file).map(|m| m.len()).unwrap_or(0));
        }

        // Fallback to Ollama first if available (faster and better reasoning)
        if std::process::Command::new("ollama").arg("--version").output().is_ok() {
            info!("Ollama detected. Prioritizing Ollama for AI reasoning fallback.");
            return Ok(Self::OllamaFallback);
        }

        // Final Fallback to Candle/Transformer
        info!("Gemma 4: attempting native transformer fallback (Candle)...");
        match SecurityJudge::new(model_dir) {
            Ok(judge) => Ok(Self::Candle(judge)),
            Err(e) => {
                Err(anyhow::anyhow!("All local AI fallback engines (ONNX, Ollama, Candle) failed: {}", e))
            }
        }
    }

    pub fn reason_about_attack(&self, graph_summary: &str) -> Result<String> {
        let prompt = format!(
            "<|im_start|>system\nYou are the OshoosiClaw Autonomous Cortex. Reason about this attack graph.<|im_end|>\n<|im_start|>user\n{}<|im_end|>\n<|im_start|>assistant\n",
            graph_summary
        );
        match self {
            Self::Onnx { .. } => self.generate_text(&prompt, 256),
            Self::Candle(judge) => judge.judge_artifact(&prompt),
            Self::OllamaFallback => {
                let ai = osoosi_types::config::load_ai_config();
                let model = ai.reasoning_model;
                let timeout_secs = ai.llm_timeout_secs;

                let mut child = std::process::Command::new("ollama")
                    .args(["run", &model, &prompt])
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

/// SecureBERT 2.0 Analyzer (Candle/Transformer fallback).
/// Uses a Cross-Encoder architecture to calculate the relationship between
/// a security Query (e.g. "potential ransomware") and Context (the log sentence).
pub struct SecureBertAnalyzer {
    model: BertModel,
    tokenizer: Tokenizer,
    device: Device,
}

impl SecureBertAnalyzer {
    pub fn new(model_dir: &Path) -> Result<Self> {
        info!("Initializing native SecureBERT Cross-Encoder from {:?}...", model_dir);
        let device = Device::cuda_if_available(0).unwrap_or(Device::Cpu);

        let config_path = model_dir.join("config.json");
        let tokenizer_path = model_dir.join("tokenizer.json");
        let weights_path = model_dir.join("model.safetensors");

        if !config_path.exists() || !tokenizer_path.exists() || !weights_path.exists() {
            anyhow::bail!("SecureBERT files missing in {:?}", model_dir);
        }

        let config: BertConfig = serde_json::from_reader(std::fs::File::open(&config_path)?)?;
        let tokenizer = Tokenizer::from_file(&tokenizer_path).map_err(anyhow::Error::msg)?;
        
        let vb = unsafe {
            candle_nn::VarBuilder::from_mmaped_safetensors(
                &[&weights_path],
                candle_core::DType::F32,
                &device,
            )?
        };
        let model = BertModel::load(vb, &config)?;

        Ok(Self {
            model,
            tokenizer,
            device,
        })
    }

    /// Score the relationship between a query and context using the Cross-Encoder.
    /// Returns a similarity probability (0.0 to 1.0).
    pub fn score_pair(&self, query: &str, context: &str) -> Result<f32> {
        // Tokenize the Pair [Query] + [SEP] + [Context]
        let encoding = self.tokenizer.encode(format!("{} [SEP] {}", query, context), true)
            .map_err(anyhow::Error::msg)?;
        
        let input_ids = Tensor::new(encoding.get_ids(), &self.device)?.unsqueeze(0)?;
        let token_type_ids = Tensor::new(encoding.get_type_ids(), &self.device)?.unsqueeze(0)?;

        // Forward pass
        let logits = self.model.forward(&input_ids, &token_type_ids, None)?;
        
        // SecureBERT Cross-Encoder usually outputs a single logit or a 2-class vector.
        // We assume index 0 is the similarity score (or the 'benign' class depending on training).
        // If it's 2 classes (Benign, Malicious), we'd take the softmax.
        // The user example uses a single logit with sigmoid.
        let score = logits.flatten_all()?.to_vec1::<f32>()?[0];
        let probability = 1.0 / (1.0 + (-score).exp()); // Sigmoid

        Ok(probability)
    }
}

/// Gemma 4 E4B-it "Security Judge" (Candle/Transformer fallback).
/// Handles high-fidelity reasoning for complex forensic triage.
pub struct SecurityJudge {
    model: Model,
    tokenizer: Tokenizer,
    device: Device,
    cache: Mutex<Cache>,
}

impl SecurityJudge {
    pub fn new(model_dir: &Path) -> Result<Self> {
        info!("Initializing native Gemma 4 Security Judge (Candle) from {:?}...", model_dir);
        let device = Device::cuda_if_available(0).unwrap_or(Device::Cpu);

        let config_path = model_dir.join("config.json");
        let tokenizer_path = model_dir.join("tokenizer.json");
        let weights_path = model_dir.join("model.safetensors");

        if !config_path.exists() || !tokenizer_path.exists() || !weights_path.exists() {
            anyhow::bail!("Gemma 4 files missing in {:?}", model_dir);
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
