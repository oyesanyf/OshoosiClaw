use osoosi_model::malconv_train::{MalConvTrainer, download_and_extract_dataset};
use candle_core::Device;
use std::path::Path;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let device = Device::Cpu;
    let mut trainer = MalConvTrainer::new(&device)?;
    
    // Dataset in the root folder as requested
    let root_dataset_dir = Path::new("..").join("..").join("dataset");
    std::fs::create_dir_all(&root_dataset_dir)?;
    
    println!("📥 Discovering samples in {}...", root_dataset_dir.display());
    let mut samples = Vec::new();
    for entry in walkdir::WalkDir::new(&root_dataset_dir) {
        if let Ok(entry) = entry {
            let path = entry.path();
            if path.is_file() && (path.extension().map_or(false, |e| e == "exe") || path.metadata().map_or(false, |m| m.len() > 1024)) {
                let p_str = path.to_string_lossy().to_lowercase();
                let label = if p_str.contains("malicious") || p_str.contains("infected") {
                    1.0f32
                } else {
                    0.0f32
                };
                samples.push((path.to_path_buf(), label));
            }
        }
    }
    
    if samples.is_empty() {
        println!("❌ No samples found. Training aborted.");
        return Ok(());
    }
    
    println!("🚀 Training MalConv on {} samples...", samples.len());
    trainer.train(&samples, 1, 4, 0.001).await?;
    
    let models_dir = Path::new("..").join("..").join("models").join("malware");
    std::fs::create_dir_all(&models_dir)?;
    let weight_path = models_dir.join("malconv.safetensors");
    
    println!("💾 Saving trained weights to {}...", weight_path.display());
    trainer.save(&weight_path)?;
    
    println!("✨ MalConv model created successfully!");
    Ok(())
}
