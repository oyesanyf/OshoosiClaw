use crate::malconv::{preprocess_bytes, MalConv};
use anyhow::Result;
use candle_core::{DType, Device, Module, Tensor};
use candle_nn::{Optimizer, SGD, VarBuilder, VarMap};
use std::path::{Path, PathBuf};
use tracing::{info, warn};

pub struct MalConvTrainer {
    varmap: VarMap,
    model: MalConv,
    device: Device,
}

fn binary_crossentropy(logits: &Tensor, target: &Tensor) -> Result<Tensor> {
    let eps = 1e-7;
    let logits = logits.clamp(eps, 1.0 - eps)?;
    let pos_loss = (target * logits.log()?)?;
    
    let ones = target.ones_like()?;
    let neg_target = (ones.clone() - target)?;
    let neg_logits = (ones - logits)?;
    let neg_loss = (neg_target * neg_logits.log()?)?;
    
    let loss = (pos_loss + neg_loss)?.neg()?.mean_all()?;
    Ok(loss)
}

impl MalConvTrainer {
    pub fn new(device: &Device) -> Result<Self> {
        let varmap = VarMap::new();
        let vb = VarBuilder::from_varmap(&varmap, DType::F32, device);
        let model = MalConv::new(vb)?;
        Ok(Self {
            varmap,
            model,
            device: device.clone(),
        })
    }

    pub async fn train(
        &mut self,
        list_of_samples: &[(PathBuf, f32)],
        epochs: usize,
        batch_size: usize,
        learning_rate: f64,
    ) -> Result<()> {
        let mut sgd = SGD::new(self.varmap.all_vars(), learning_rate)?;

        for epoch in 0..epochs {
            let mut total_loss = 0.0f32;
            let mut batch_count = 0;

            for chunk in list_of_samples.chunks(batch_size) {
                let mut batch_images = Vec::new();
                let mut batch_labels = Vec::new();

                for (path, label) in chunk {
                    if let Ok(bytes) = std::fs::read(path) {
                        if let Ok(input) = preprocess_bytes(&bytes, 15000, &self.device) {
                            batch_images.push(input);
                            batch_labels.push(*label);
                        }
                    }
                }

                if batch_images.is_empty() {
                    continue;
                }

                let x = Tensor::cat(&batch_images, 0)?;
                let y = Tensor::from_vec(batch_labels, (batch_images.len(), 1), &self.device)?;

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

    /// Fine-tunes the model on a single sample (e.g. from ClamAV signals)
    pub fn fine_tune(&mut self, bytes: &[u8], label: f32, learning_rate: f64) -> Result<()> {
        let mut sgd = SGD::new(self.varmap.all_vars(), learning_rate)?;
        let input = preprocess_bytes(bytes, 15000, &self.device)?;
        let target = Tensor::from_vec(vec![label], (1, 1), &self.device)?;

        let logits = self.model.forward(&input)?;
        let loss = binary_crossentropy(&logits, &target)?;
        
        sgd.backward_step(&loss)?;
        info!("MalConv fine-tuned on new signal (label={}): loss={:.4}", label, loss.to_vec0::<f32>()?);
        Ok(())
    }

    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        self.varmap.save(path)?;
        Ok(())
    }
}

pub async fn download_and_extract_dataset(base_dir: &Path) -> Result<Vec<(PathBuf, f32)>> {
    let urls = [
        ("Benign_PE_samples", "https://github.com/PacktPublishing/Machine-Learning-for-Cybersecurity-Cookbook/raw/master/PE%20Samples%20Dataset/Benign%20PE%20Samples%201.7z"),
        ("Benign_PE_samples", "https://github.com/PacktPublishing/Machine-Learning-for-Cybersecurity-Cookbook/raw/master/PE%20Samples%20Dataset/Benign%20PE%20Samples%202.7z"),
        ("Benign_PE_samples", "https://github.com/PacktPublishing/Machine-Learning-for-Cybersecurity-Cookbook/raw/master/PE%20Samples%20Dataset/Benign%20PE%20Samples%203.7z"),
        ("Benign_PE_samples", "https://github.com/PacktPublishing/Machine-Learning-for-Cybersecurity-Cookbook/raw/master/PE%20Samples%20Dataset/Benign%20PE%20Samples%204.7z"),
        ("Benign_PE_samples", "https://github.com/PacktPublishing/Machine-Learning-for-Cybersecurity-Cookbook/raw/master/PE%20Samples%20Dataset/Benign%20PE%20Samples%205.7z"),
        ("Benign_PE_samples", "https://github.com/PacktPublishing/Machine-Learning-for-Cybersecurity-Cookbook/raw/master/PE%20Samples%20Dataset/Benign%20PE%20Samples%206.7z"),
        ("Malicious_PE_samples", "https://github.com/PacktPublishing/Machine-Learning-for-Cybersecurity-Cookbook/raw/master/PE%20Samples%20Dataset/Malicious%20PE%20Samples%201.7z"),
        ("Malicious_PE_samples", "https://github.com/PacktPublishing/Machine-Learning-for-Cybersecurity-Cookbook/raw/master/PE%20Samples%20Dataset/Malicious%20PE%20Samples%202.7z"),
    ];

    let client = reqwest::Client::new();
    let mut samples = Vec::new();

    for (label_dir, url) in urls {
        let dest_dir = base_dir.join(label_dir);
        std::fs::create_dir_all(&dest_dir)?;

        let filename = url.split('/').last().unwrap_or("sample.7z");
        let archive_path = base_dir.join(filename);

        if !archive_path.exists() {
            info!("Downloading {}...", url);
            let response = client.get(url).send().await?;
            let bytes = response.bytes().await?;
            std::fs::write(&archive_path, &bytes)?;
        }

        info!("Extracting {}...", filename);
        let label = if label_dir.contains("Benign") { 0.0f32 } else { 1.0f32 };
        
        // Extract using sevenz-rust
        let password = if label == 1.0 { "infected" } else { "" };
        
        // Correct API: Password is passed directly or via Password::from
        if let Err(e) = sevenz_rust::decompress_file_with_password(&archive_path, &dest_dir, password.into()) {
             warn!("Extraction failed for {}: {}", filename, e);
        }

        // Add extracted files to the list
        if dest_dir.exists() {
            for entry in std::fs::read_dir(&dest_dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_file() {
                    samples.push((path, label));
                }
            }
        }
    }

    Ok(samples)
}



