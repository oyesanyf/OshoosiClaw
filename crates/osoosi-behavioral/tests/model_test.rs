use std::path::Path;
use osoosi_behavioral::llm_engine::{SecureBertAnalyzer, Gemma4Analyzer};

#[tokio::test]
async fn test_load_models() {
    // Set the ORT_DYLIB_PATH environment variable so that ONNX Runtime can find onnxruntime.dll in target directory
    let workspace_dir = Path::new("d:/harfile/OshoosiClaw");
    let target_debug_dll = workspace_dir.join("target/x86_64-pc-windows-msvc/debug/onnxruntime.dll");
    if target_debug_dll.exists() {
        std::env::set_var("ORT_DYLIB_PATH", target_debug_dll.to_str().unwrap());
        println!("Set ORT_DYLIB_PATH to {:?}", target_debug_dll);
    }

    // Initialize ORT
    let _ = ort::init().commit().unwrap();

    let models_dir = workspace_dir.join("models");

    // Test SecureBERT loading
    let bert_dir = models_dir.join("securebert");
    println!("Testing SecureBERT loading from {:?}", bert_dir);
    match SecureBertAnalyzer::new(&bert_dir) {
        Ok(_) => println!("✅ SecureBERT loaded successfully!"),
        Err(e) => {
            println!("❌ SecureBERT failed to load: {:?}", e);
            panic!("SecureBERT failed to load: {:?}", e);
        }
    }

    // Test Gemma 4 loading
    let gemma_dir = models_dir.join("gemma4-e4b");
    println!("Testing Gemma-4 loading from {:?}", gemma_dir);
    match Gemma4Analyzer::new(&gemma_dir) {
        Ok(_) => println!("✅ Gemma-4 loaded successfully!"),
        Err(e) => {
            println!("❌ Gemma-4 failed to load: {:?}", e);
            panic!("Gemma-4 failed to load: {:?}", e);
        }
    }
}
