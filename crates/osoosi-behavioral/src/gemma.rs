use anyhow::Result;
use candle_core::{Device, Tensor};
use candle_transformers::models::gemma::{Config, Model};
use candle_transformers::generation::LogitsProcessor;
use tokenizers::Tokenizer;
use std::sync::Mutex;
use std::path::Path;
use tracing::{info, warn};

pub struct GemmaAnalyzer {
    model: Mutex<Model>,
    tokenizer: Tokenizer,
    device: Device,
}

impl GemmaAnalyzer {
    pub fn new(model_dir: &Path) -> Result<Self> {
        info!("Initializing native Gemma analyzer from local files in {:?}...", model_dir);
        let device = Device::cuda_if_available(0).unwrap_or(Device::Cpu);

        let tokenizer_filename = model_dir.join("tokenizer.json");
        let config_filename = model_dir.join("config.json");
        let weights_filename = model_dir.join("model.safetensors");

        if !tokenizer_filename.exists() || !config_filename.exists() || !weights_filename.exists() {
            warn!("Gemma model files (tokenizer.json, config.json, model.safetensors) not found in {:?}. Run bootstrap command or place files manually.", model_dir);
            anyhow::bail!("Missing Gemma model files in {:?}", model_dir);
        }

        // 2. Load Tokenizer & Config
        let tokenizer = Tokenizer::from_file(&tokenizer_filename).map_err(anyhow::Error::msg)?;
        let config: Config = serde_json::from_reader(std::fs::File::open(&config_filename)?)?;

        // 3. Initialize Model
        let vb = unsafe { 
            candle_nn::VarBuilder::from_mmaped_safetensors(&[&weights_filename], candle_core::DType::F32, &device)? 
        };
        let model = Model::new(false, &config, vb)?;

        info!("Gemma 3 4B loaded successfully on {:?}", device);

        Ok(Self {
            model: Mutex::new(model),
            tokenizer,
            device,
        })
    }

    pub fn analyze_log(&self, sentence: &str) -> Result<f32> {
        let mut model = self.model.lock().unwrap();
        
        let prompt = format!(
            "Analyze this security log and return a JSON score between 0.0 (Benign) and 1.0 (Malicious). \
             Only respond with the JSON. \
             Log: {}\nJSON: {{ \"score\": ", 
            sentence
        );

        let tokens = self.tokenizer.encode(prompt, true).map_err(anyhow::Error::msg)?;
        let mut tokens_vec = tokens.get_ids().to_vec();
        
        let mut logits_processor = LogitsProcessor::new(1337, Some(0.0), None); // Deterministic
        let mut result_text = String::new();

        // Generate up to 10 tokens for the score
        for _i in 0..10 {
            let input = Tensor::new(&tokens_vec[..], &self.device)?.unsqueeze(0)?;
            let logits = model.forward(&input, tokens_vec.len())?;
            let logits = logits.squeeze(0)?.get(logits.dims()[0] - 1)?;
            
            let next_token = logits_processor.sample(&logits)?;
            tokens_vec.push(next_token);
            
            let decoded = self.tokenizer.decode(&[next_token], true).map_err(anyhow::Error::msg)?;
            if decoded.contains('}') || decoded.contains('\n') {
                break;
            }
            result_text.push_str(&decoded);
        }

        // Parse result e.g. "0.85"
        let score_str = result_text.trim().trim_matches(|c: char| !c.is_digit(10) && c != '.');
        let score: f32 = score_str.parse().unwrap_or(0.0);
        
        Ok(score)
    }

    pub fn generate_text(&self, prompt: &str, max_tokens: usize) -> Result<String> {
        let mut model = self.model.lock().unwrap();
        
        let tokens = self.tokenizer.encode(prompt, true).map_err(anyhow::Error::msg)?;
        let mut tokens_vec = tokens.get_ids().to_vec();
        
        let mut logits_processor = LogitsProcessor::new(1337, Some(0.7), None);
        let mut result_text = String::new();

        for _i in 0..max_tokens {
            let input = Tensor::new(&tokens_vec[..], &self.device)?.unsqueeze(0)?;
            let logits = model.forward(&input, tokens_vec.len())?;
            let logits = logits.squeeze(0)?.get(logits.dims()[0] - 1)?;
            
            let next_token = logits_processor.sample(&logits)?;
            tokens_vec.push(next_token);
            
            let decoded = self.tokenizer.decode(&[next_token], true).map_err(anyhow::Error::msg)?;
            if decoded.is_empty() { break; }
            result_text.push_str(&decoded);
        }

        Ok(result_text)
    }
}
