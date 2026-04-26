//! MalConv (Malware Convolutional Neural Network) Implementation.
//!
//! Processes raw binary bytes directly for end-to-end classification
//! without manual feature engineering.

use anyhow::{Context, Result as AnyhowResult};
use candle_core::{DType, Device, Result, Tensor};
use candle_nn::{ops, Conv1d, Conv1dConfig, Embedding, Linear, Module, VarBuilder};
use std::fs::File;
use std::io::Read;
use std::path::Path;

pub struct MalConv {
    embedding: Embedding,
    conv_feat: Conv1d,
    conv_gate: Conv1d,
    fc: Linear,
}

impl MalConv {
    pub fn new(vb: VarBuilder) -> Result<Self> {
        // MalConv typically uses a 257-entry embedding (256 bytes + padding/EOS)
        let embedding = candle_nn::embedding(257, 8, vb.pp("embedding"))?;

        // 1D Convolutions with a large window (e.g., 512) and stride (e.g., 512)
        let cfg = Conv1dConfig {
            stride: 512,
            padding: 0,
            dilation: 1,
            groups: 1,
            cudnn_fwd_algo: None,
        };

        let conv_feat = candle_nn::conv1d(8, 128, 512, cfg, vb.pp("conv_feat"))?;
        let conv_gate = candle_nn::conv1d(8, 128, 512, cfg, vb.pp("conv_gate"))?;

        let fc = candle_nn::linear(128, 2, vb.pp("fc"))?;

        Ok(Self {
            embedding,
            conv_feat,
            conv_gate,
            fc,
        })
    }

    /// Load MalConv weights from a Safetensors file.
    pub fn load<P: AsRef<Path>>(path: P, device: &Device) -> AnyhowResult<Self> {
        let vb = unsafe { VarBuilder::from_mmaped_safetensors(&[path], DType::F32, device)? };
        Ok(Self::new(vb)?)
    }
}

impl Module for MalConv {
    fn forward(&self, xs: &Tensor) -> Result<Tensor> {
        // 1. Embedding: [batch, seq_len] -> [batch, seq_len, 8]
        let x = self.embedding.forward(xs)?;

        // Transpose for Conv1d: [batch, 8, seq_len]
        let x = x.transpose(1, 2)?;

        // 2. Gated Convolution (GLU)
        let feat = self.conv_feat.forward(&x)?;
        let gate = self.conv_gate.forward(&x)?;
        let gated = (feat * ops::sigmoid(&gate)?)?;

        // 3. Global Max Pooling: [batch, 128, 1]
        let (_, _, _) = gated.dims3()?;
        let pooled = gated.max(2)?;

        // 4. Final Classification
        self.fc.forward(&pooled)
    }
}

/// Binary Preprocessing Implementation
/// Reads a file, truncates or pads it to a fixed length (e.g., 2MB),
/// and converts the bytes into a Tensor of integer indices.
pub fn preprocess_binary<P: AsRef<Path>>(
    path: P,
    max_len: usize,
    device: &Device,
) -> AnyhowResult<Tensor> {
    let mut file = File::open(&path)
        .with_context(|| format!("Failed to open binary for MalConv: {:?}", path.as_ref()))?;

    let mut buffer = vec![0u8; max_len];
    let bytes_read = file.read(&mut buffer)?;

    // Use index 256 as a padding/EOS token
    let mut input_data = vec![256u32; max_len];
    for i in 0..bytes_read {
        input_data[i] = buffer[i] as u32;
    }

    let tensor = Tensor::from_vec(input_data, (1, max_len), device)?;

    Ok(tensor)
}

/// Helper to convert raw bytes to tensor if the file is already read.
pub fn preprocess_bytes(bytes: &[u8], max_len: usize, device: &Device) -> AnyhowResult<Tensor> {
    let mut input_data = vec![256u32; max_len];
    let len = bytes.len().min(max_len);
    for i in 0..len {
        input_data[i] = bytes[i] as u32;
    }
    let tensor = Tensor::from_vec(input_data, (1, max_len), device)?;
    Ok(tensor)
}
