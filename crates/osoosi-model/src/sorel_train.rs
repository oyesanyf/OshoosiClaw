use crate::sorel_ffnn::SorelFFNN;
use crate::malware::extract_pe_ensemble_features;
use anyhow::Result;
use candle_core::{DType, Device, Module, Tensor};
use candle_nn::{Optimizer, SGD, VarBuilder, VarMap};
use std::path::{Path, PathBuf};
use tracing::{info, warn};

pub struct SorelTrainer {
    varmap: VarMap,
    model: SorelFFNN,
    device: Device,
}

fn binary_crossentropy(logits: &Tensor, target: &Tensor) -> Result<Tensor> {
    let eps = 1e-7;
    // Sigmoid is usually applied outside or inside the model. 
    // SorelFFNN doesn't have sigmoid at the end.
    let probs = (logits.neg()?.exp()? + 1.0)?.recip()?;
    let probs = probs.clamp(eps, 1.0 - eps)?;
    
    let pos_loss = (target * probs.log()?)?;
    let ones = target.ones_like()?;
    let neg_target = (ones.clone() - target)?;
    let neg_probs = (ones - probs)?;
    let neg_loss = (neg_target * neg_probs.log()?)?;
    
    let loss = (pos_loss + neg_loss)?.neg()?.mean_all()?;
    Ok(loss)
}

impl SorelTrainer {
    pub fn new(device: &Device) -> Result<Self> {
        let varmap = VarMap::new();
        let vb = VarBuilder::from_varmap(&varmap, DType::F32, device);
        let model = SorelFFNN::new(vb)?;
        Ok(Self {
            varmap,
            model,
            device: device.clone(),
        })
    }

    pub async fn train(
        &mut self,
        samples: &[(PathBuf, f32)],
        epochs: usize,
        batch_size: usize,
        learning_rate: f64,
    ) -> Result<()> {
        let mut sgd = SGD::new(self.varmap.all_vars(), learning_rate)?;

        for epoch in 0..epochs {
            let mut total_loss = 0.0f32;
            let mut batch_count = 0;

            for chunk in samples.chunks(batch_size) {
                let mut batch_features = Vec::new();
                let mut batch_labels = Vec::new();

                use rayon::prelude::*;
                let results: Vec<_> = chunk.par_iter().map(|(path, label)| {
                    if let Ok(bytes) = std::fs::read(path) {
                        if let Some(features) = extract_pe_ensemble_features(&bytes) {
                            return Some((features, *label));
                        }
                    }
                    None
                }).collect();

                for res in results.into_iter().flatten() {
                    let (features, label) = res;
                    batch_features.push(Tensor::from_vec(features, (1, 2381), &self.device)?);
                    batch_labels.push(label);
                }

                if batch_features.is_empty() {
                    continue;
                }

                let x = Tensor::cat(&batch_features, 0)?;
                let y = Tensor::from_vec(batch_labels, (batch_features.len(), 1), &self.device)?;

                let logits = self.model.forward(&x)?;
                let loss = binary_crossentropy(&logits, &y)?;
                
                sgd.backward_step(&loss)?;
                
                total_loss += loss.to_vec0::<f32>()?;
                batch_count += 1;
            }

            if batch_count > 0 {
                info!(
                    "Epoch {}/{}: Avg Loss = {:.4}",
                    epoch + 1,
                    epochs,
                    total_loss / batch_count as f32
                );
            }
        }

        Ok(())
    }

    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        self.model.save(path)?;
        Ok(())
    }
}
