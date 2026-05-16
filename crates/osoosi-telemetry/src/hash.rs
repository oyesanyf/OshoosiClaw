//! High-speed file hashing using BLAKE3.

use std::path::Path;

/// Calculate BLAKE3 hash of a file at the given path.
pub async fn calculate_blake3_hash<P: AsRef<Path>>(path: P) -> anyhow::Result<String> {
    let path = path.as_ref().to_path_buf();
    tokio::task::spawn_blocking(move || {
        let file = std::fs::File::open(path)?;
        let mut reader = std::io::BufReader::with_capacity(128 * 1024, file);
        let mut hasher = blake3::Hasher::new();
        let mut buffer = [0u8; 128 * 1024]; // 128KB buffer
        use std::io::Read;
        loop {
            let n = reader.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
        }
        Ok(hasher.finalize().to_hex().to_string())
    }).await?
}

/// Calculate BLAKE3 hash of file content in memory.
pub fn calculate_blake3_hash_mem(data: &[u8]) -> String {
    blake3::hash(data).to_hex().to_string()
}
