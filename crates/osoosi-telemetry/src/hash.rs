//! High-speed file hashing using BLAKE3.

use std::path::Path;
use tokio::fs::File;
use tokio::io::AsyncReadExt;

/// Calculate BLAKE3 hash of a file at the given path.
pub async fn calculate_blake3_hash<P: AsRef<Path>>(path: P) -> anyhow::Result<String> {
    let mut file = File::open(path).await?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0u8; 65536]; // 64KB buffer
    
    loop {
        let n = file.read(&mut buffer).await?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    
    Ok(hasher.finalize().to_hex().to_string())
}

/// Calculate BLAKE3 hash of file content in memory.
pub fn calculate_blake3_hash_mem(data: &[u8]) -> String {
    blake3::hash(data).to_hex().to_string()
}
