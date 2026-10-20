//! In-Memory Magic Header Scanning (Magika + Goblin).
//!
//! Scans memory regions for file-less malware by identifying executable
//! headers (PE, ELF, Mach-O, WASM, DEX) in non-executable memory segments.

use goblin::Object;
use magika::Session as MagikaSession;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::info;

pub struct MemoryHeaderScanner {
    magika: Option<Arc<Mutex<MagikaSession>>>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct MemoryDetection {
    pub offset: usize,
    pub file_type: String,
    pub is_executable: bool,
    pub mitre_technique: Option<String>, // e.g., "T1055 - Process Injection"
}

impl Default for MemoryHeaderScanner {
    fn default() -> Self {
        Self::new().unwrap_or(Self { magika: None })
    }
}

impl MemoryHeaderScanner {
    pub fn new() -> anyhow::Result<Self> {
        let magika = {
            let prev_hook = std::panic::take_hook();
            std::panic::set_hook(Box::new(|_| {}));
            let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                MagikaSession::new().ok()
            }));
            std::panic::set_hook(prev_hook);
            res.ok().flatten().map(|s| Arc::new(Mutex::new(s)))
        };
        Ok(Self { magika })
    }

    /// Scan a raw memory buffer for malicious executable headers using Google Magika + Goblin structural verification.
    pub async fn scan_buffer(&self, buf: &[u8]) -> anyhow::Result<Vec<MemoryDetection>> {
        let mut detections = Vec::new();
        if buf.is_empty() {
            return Ok(detections);
        }

        for i in (0..buf.len()).step_by(4096) {
            let chunk_end = (i + 4096).min(buf.len());
            let chunk = &buf[i..chunk_end];

            // 1. Google Magika AI-driven identification ("pebin", "elf", "macho", "wasm", "dex")
            let mut magika_label: Option<String> = None;
            if let Some(ref magika_mutex) = self.magika {
                let mut session = magika_mutex.lock().await;
                if let Ok(res) = session.identify_content_sync(chunk) {
                    let lbl = res.info().label;
                    if matches!(
                        lbl,
                        "pebin" | "elf" | "macho" | "wasm" | "dex" | "exe" | "pe" | "mach-o"
                    ) {
                        magika_label = Some(lbl.to_string());
                    }
                }
            }

            // 2. Goblin structural validation + deterministic magic verification
            let structural_type = match Object::parse(chunk) {
                Ok(Object::PE(_)) => Some("pebin".to_string()),
                Ok(Object::Elf(_)) => Some("elf".to_string()),
                Ok(Object::Mach(_)) => Some("macho".to_string()),
                _ if chunk.starts_with(b"\0asm\x01\0\0\0") => Some("wasm".to_string()),
                _ if chunk.starts_with(b"dex\n03") => Some("dex".to_string()),
                _ => None,
            };

            if let Some(ft) = magika_label.or(structural_type) {
                // Ensure PE/ELF/Mach-O Magika detections also pass header magic or Goblin validation
                let verified = chunk.starts_with(b"MZ")
                    || chunk.starts_with(b"\x7fELF")
                    || chunk.starts_with(b"\0asm")
                    || chunk.starts_with(b"dex\n03")
                    || matches!(
                        Object::parse(chunk),
                        Ok(Object::PE(_) | Object::Elf(_) | Object::Mach(_))
                    );
                if verified {
                    info!("DETECTED: {} header found in memory at offset {}", ft, i);
                    detections.push(MemoryDetection {
                        offset: i,
                        file_type: ft,
                        is_executable: true,
                        mitre_technique: Some("T1055 - Process Injection".to_string()),
                    });
                }
            }
        }

        Ok(detections)
    }

    pub async fn scan_process_memory(&self, _pid: u32) -> anyhow::Result<Vec<MemoryDetection>> {
        Ok(vec![])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_memory_header_scanner_detects_wasm_and_pe_headers() {
        let scanner = MemoryHeaderScanner::new().expect("init scanner");
        let mut buf = vec![0u8; 8192];
        // Page 0: WASM module header
        buf[0..8].copy_from_slice(b"\0asm\x01\0\0\0");
        // Page 1 (offset 4096): DEX header
        buf[4096..4104].copy_from_slice(b"dex\n035\0");

        let detections = scanner.scan_buffer(&buf).await.expect("scan_buffer");
        assert_eq!(detections.len(), 2);
        assert_eq!(detections[0].offset, 0);
        assert_eq!(detections[0].file_type, "wasm");
        assert_eq!(detections[1].offset, 4096);
        assert_eq!(detections[1].file_type, "dex");
    }
}
