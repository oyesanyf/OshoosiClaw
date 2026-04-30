use osoosi_model::malconv_train::MalConvTrainer;
use candle_core::Device;
use std::path::Path;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let device = Device::Cpu;
    let trainer = MalConvTrainer::new(&device)?;
    
    // Use project root for models dir
    let models_dir = Path::new("models").join("malware");
    std::fs::create_dir_all(&models_dir)?;
    let weight_path = models_dir.join("malconv.safetensors");
    
    println!("💾 Saving dummy weights to {}...", weight_path.display());
    trainer.save(&weight_path)?;
    
    println!("✨ Dummy weights generated successfully at {}!", weight_path.display());
    Ok(())
}
