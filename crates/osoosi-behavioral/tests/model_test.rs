use osoosi_behavioral::llm_engine::{Gemma4Analyzer, SecureBertAnalyzer};
use std::path::PathBuf;

#[tokio::test]
async fn test_load_models() {
    if std::env::var("OSOOSI_NO_ORT").is_ok() || std::env::var("OSOOSI_NO_AI").is_ok() {
        println!("Skipping ONNX model load test (OSOOSI_NO_ORT / OSOOSI_NO_AI is set).");
        return;
    }

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_dir = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));

    let candidates = [
        workspace_dir.join("target/debug/onnxruntime.dll"),
        workspace_dir.join("target/release/onnxruntime.dll"),
        workspace_dir.join("onnxruntime.dll"),
        workspace_dir.join("bin/onnxruntime.dll"),
        workspace_dir.join("target/x86_64-pc-windows-msvc/debug/onnxruntime.dll"),
    ];
    let mut found_ort = std::env::var("ORT_DYLIB_PATH").is_ok();
    if !found_ort {
        for candidate in &candidates {
            if candidate.exists() {
                if let Some(s) = candidate.to_str() {
                    std::env::set_var("ORT_DYLIB_PATH", s);
                    println!("Set ORT_DYLIB_PATH to {:?}", candidate);
                    found_ort = true;
                    break;
                }
            }
        }
    }

    let models_dir = workspace_dir.join("models");
    let bert_dir = models_dir.join("securebert");
    let gemma_dir = models_dir.join("gemma4-e4b");

    if !found_ort || !bert_dir.exists() || !gemma_dir.exists() {
        println!(
            "Skipping local ONNX weight test (found_ort={}, bert={}, gemma={}).",
            found_ort,
            bert_dir.exists(),
            gemma_dir.exists()
        );
        return;
    }

    if let Err(e) = ort::init().commit() {
        println!(
            "Skipping ONNX runtime init in headless test environment: {:?}",
            e
        );
        return;
    }

    println!("Testing SecureBERT loading from {:?}", bert_dir);
    match SecureBertAnalyzer::new(&bert_dir) {
        Ok(_) => println!("SecureBERT loaded successfully!"),
        Err(e) => panic!("SecureBERT failed to load: {:?}", e),
    }

    println!("Testing Gemma-4 loading from {:?}", gemma_dir);
    match Gemma4Analyzer::new(&gemma_dir) {
        Ok(_) => println!("Gemma-4 loaded successfully!"),
        Err(e) => panic!("Gemma-4 failed to load: {:?}", e),
    }
}
