use crate::statistical_filter::{StatisticalFilter, StatisticalFilterConfig};
use serde::{Deserialize, Serialize};
use anyhow::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OutputFormat {
    Text,
    Json,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressorConfig {
    pub output_format: OutputFormat,
    pub filter_config: StatisticalFilterConfig,
}

impl Default for CompressorConfig {
    fn default() -> Self {
        Self {
            output_format: OutputFormat::Text,
            filter_config: StatisticalFilterConfig::default(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CompressionResult {
    pub original_tokens: usize,
    pub compressed_tokens: usize,
    pub compression_ratio: f32,
    pub compressed_text: String,
}

pub struct Compressor {
    #[allow(dead_code)]
    config: CompressorConfig,
    filter: StatisticalFilter,
}

impl Compressor {
    pub fn new(config: CompressorConfig) -> Self {
        let filter = StatisticalFilter::new(config.filter_config.clone());
        Self { config, filter }
    }

    pub fn compress(&self, input: &str, tokenizer: &tokenizers::Tokenizer) -> Result<CompressionResult> {
        let encoding = tokenizer.encode(input, false).map_err(|e| anyhow::anyhow!("{}", e))?;
        let tokens = encoding.get_tokens().to_vec();
        let original_tokens = tokens.len();

        let filtered_tokens = self.filter.filter(tokens);
        let compressed_tokens = filtered_tokens.len();
        
        let compressed_text = filtered_tokens.join("").replace(" ", " ").trim().to_string();
        
        let compression_ratio = if original_tokens > 0 {
            compressed_tokens as f32 / original_tokens as f32
        } else {
            1.0
        };

        Ok(CompressionResult {
            original_tokens,
            compressed_tokens,
            compression_ratio,
            compressed_text,
        })
    }
}
