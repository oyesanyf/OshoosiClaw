use osoosi_model::malconv_train::{MalConvTrainer, download_and_extract_dataset};
use candle_core::Device;
use std::path::Path;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    
    let device = Device::Cpu;
    let mut trainer = MalConvTrainer::new(&device)?;
    
    let base_dir = Path::new("malware_training");
    std::fs::create_dir_all(base_dir)?;
    
    println!("📥 Downloading and extracting dataset (this may take a while)...");
    let samples = download_and_extract_dataset(base_dir).await?;
    println!("✅ Found {} samples.", samples.len());
    
    if samples.is_empty() {
        println!("❌ No samples found. Cannot train.");
        return Ok(());
    }
    
    println!("🚀 Starting training (tiny run for bootstrap)...");
    // Just 1 epoch, small batch for quick bootstrap
    trainer.train(&samples, 1, 4, 0.001).await?;
    
    let models_dir = Path::new("models").join("malware");
    std::fs::create_dir_all(&models_dir)?;
    let weight_path = models_dir.join("malconv.safetensors");
    
    println!("💾 Saving weights to {}...", weight_path.display());
    trainer.save(&weight_path)?;
    
    println!("✨ MalConv bootstrap complete!");
    Ok(())
}
