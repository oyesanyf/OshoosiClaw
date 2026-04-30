//! MalConv (Malware Convolutional Neural Network) Implementation.
//!
//! Processes raw binary bytes directly for end-to-end classification
//! without manual feature engineering.
//!
//! This implementation matches the architecture described in the
//! "Machine Learning for Cybersecurity Cookbook" (Chapter 3).

use anyhow::{Context, Result as AnyhowResult};
use candle_core::{DType, Device, Result, Tensor};
use candle_nn::{ops, Conv1d, Conv1dConfig, Linear, Module, VarBuilder};
use std::fs::File;
use std::io::Read;
use std::path::Path;

pub struct MalConv {
    conv_feat: Conv1d,
    conv_gate: Conv1d,
    fc1: Linear,
    fc2: Linear,
}

impl MalConv {
    pub fn new(vb: VarBuilder) -> Result<Self> {
        // 1D Convolutions with kernel size 128 and stride 128
        let cfg = Conv1dConfig {
            stride: 128,
            padding: 64, // 'same' padding for kernel 128
            dilation: 1,
            groups: 1,
            cudnn_fwd_algo: None,
        };

        // Notebook uses 8 input channels (one for each bit of a byte)
        // and 32 filters (output channels).
        let conv_feat = candle_nn::conv1d(8, 32, 128, cfg, vb.pp("conv_feat"))?;
        let conv_gate = candle_nn::conv1d(8, 32, 128, cfg, vb.pp("conv_gate"))?;

        // Dense layers: 16 units then 1 unit
        let fc1 = candle_nn::linear(32, 16, vb.pp("fc1"))?;
        let fc2 = candle_nn::linear(16, 1, vb.pp("fc2"))?;

        Ok(Self {
            conv_feat,
            conv_gate,
            fc1,
            fc2,
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
        // 1. Gated Convolution (GLU variant)
        // Input xs shape: [batch, 8, seq_len]
        let feat = self.conv_feat.forward(xs)?;
        let gate = self.conv_gate.forward(xs)?;
        let gated = (feat * ops::sigmoid(&gate)?)?;
        
        // 2. ReLU Activation (as per notebook)
        let b = gated.relu()?;

        // 3. Global Max Pooling: [batch, 32, 1]
        let pooled = b.max(2)?;

        // 4. Final Classification
        let d = self.fc1.forward(&pooled)?;
        let d = d.relu()?;
        let logits = self.fc2.forward(&d)?;
        ops::sigmoid(&logits)
    }
}

/// Bit-wise embedding: converts a byte into an 8-dimensional vector.
/// Each bit (from MSB to LSB) is mapped to 1/16 if 1, and -1/16 if 0.
fn embed_byte(byte: u8) -> [f32; 8] {
    let mut vec = [0.0; 8];
    for i in 0..8 {
        // Check bits from MSB (leftmost) to LSB (rightmost)
        if (byte >> (7 - i)) & 1 == 1 {
            vec[i] = 1.0 / 16.0;
        } else {
            vec[i] = -1.0 / 16.0;
        }
    }
    vec
}

/// Binary Preprocessing Implementation
/// Reads a file, truncates or pads it to a fixed length,
/// and performs bit-wise embedding.
pub fn preprocess_binary<P: AsRef<Path>>(
    path: P,
    max_len: usize,
    device: &Device,
) -> AnyhowResult<Tensor> {
    let mut file = File::open(&path)
        .with_context(|| format!("Failed to open binary for MalConv: {:?}", path.as_ref()))?;

    let mut buffer = vec![0u8; max_len];
    let _ = file.read(&mut buffer)?;

    let mut embedded_data = vec![0.0f32; 8 * max_len];
    
    // We want shape (8, max_len) for Candle's Conv1d (channels_first)
    for (i, &byte) in buffer.iter().enumerate() {
        let embedding = embed_byte(byte);
        for bit_idx in 0..8 {
            embedded_data[bit_idx * max_len + i] = embedding[bit_idx];
        }
    }

    let tensor = Tensor::from_vec(embedded_data, (1, 8, max_len), device)?;
    Ok(tensor)
}

/// Helper to convert raw bytes to tensor if the file is already read.
pub fn preprocess_bytes(bytes: &[u8], max_len: usize, device: &Device) -> AnyhowResult<Tensor> {
    let mut embedded_data = vec![0.0f32; 8 * max_len];
    let len = bytes.len().min(max_len);
    
    for i in 0..len {
        let embedding = embed_byte(bytes[i]);
        for bit_idx in 0..8 {
            embedded_data[bit_idx * max_len + i] = embedding[bit_idx];
        }
    }
    
    // Fill remaining with 0 or use the embedding of 0?
    // The notebook uses np.zeros for the whole X, then fills what it reads.
    // If it's a 0 byte, embed_byte(0) would give [-1/16, ..., -1/16].
    // BUT the notebook loop stops at len(sample_byte_sequence).
    // So the rest remains 0.0.
    // We already initialized embedded_data with 0.0, so we're good.

    let tensor = Tensor::from_vec(embedded_data, (1, 8, max_len), device)?;
    Ok(tensor)
}

