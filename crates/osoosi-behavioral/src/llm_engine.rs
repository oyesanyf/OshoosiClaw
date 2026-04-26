use anyhow::Result;
use candle_core::{Device, Tensor};
use candle_transformers::generation::LogitsProcessor;
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
pub struct Gemma4Analyzer {
    session: std::sync::Mutex<Session>,
    tokenizer: Tokenizer,
}

impl Gemma4Analyzer {
    pub fn new(model_dir: &Path) -> Result<Self> {
        info!(
            "Initializing Gemma 4 E2B ONNX Cortex from {:?}...",
            model_dir
        );

        let model_path = model_dir.join("model.onnx");
        let tokenizer_filename = model_dir.join("tokenizer.json");

        if !model_path.exists() {
            anyhow::bail!("Missing Gemma 4 ONNX model at {:?}", model_path);
        }

        let tokenizer = Tokenizer::from_file(&tokenizer_filename).map_err(anyhow::Error::msg)?;

        let session = Session::builder()?
            .with_optimization_level(GraphOptimizationLevel::Level3)?
            .with_intra_threads(4)?
            .commit_from_file(&model_path)?;

        Ok(Self {
            session: std::sync::Mutex::new(session),
            tokenizer,
        })
    }

    pub fn reason_about_attack(&self, graph_summary: &str) -> Result<String> {
        let prompt = format!(
            "<|im_start|>system\nYou are the OshoosiClaw Autonomous Cortex. Reason about this attack graph.<|im_end|>\n<|im_start|>user\n{}<|im_end|>\n<|im_start|>assistant\n",
            graph_summary
        );
        self.generate_text(&prompt, 256)
    }

    pub fn generate_text(&self, prompt: &str, max_tokens: usize) -> Result<String> {
        let tokens = self
            .tokenizer
            .encode(prompt, true)
            .map_err(anyhow::Error::msg)?;
        let mut tokens_vec = tokens.get_ids().to_vec();
        let mut result_text = String::new();

        for _ in 0..max_tokens {
            let input_tensor = ndarray::Array2::from_shape_vec(
                (1, tokens_vec.len()),
                tokens_vec.iter().map(|&x| x as i64).collect(),
            )?;

            let mut session = self
                .session
                .lock()
                .map_err(|_| anyhow::anyhow!("Session lock poisoned"))?;
            let outputs = session.run(ort::inputs![ort::value::TensorRef::from_array_view(
                &input_tensor
            )?])?;
            let (shape, data) = outputs[0].try_extract_tensor::<f32>()?;

            let shape_vec = shape.clone();
            let vocab_size = *shape_vec.last().unwrap() as usize;
            let last_token_logits = &data[data.len() - vocab_size..];

            let next_token = last_token_logits
                .iter()
                .enumerate()
                .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap())
                .map(|(index, _)| index)
                .unwrap_or(0) as u32;

            if next_token == 0 || next_token == 1 {
                break;
            }

            tokens_vec.push(next_token);
            let decoded = self
                .tokenizer
                .decode(&[next_token], true)
                .map_err(anyhow::Error::msg)?;
            if decoded.is_empty() {
                break;
            }
            result_text.push_str(&decoded);
        }

        Ok(result_text)
    }
}
