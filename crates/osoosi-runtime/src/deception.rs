//! Deception Engine (Ghost Files).
//!
//! Materializes fake sensitive data instantly to confuse and track attackers.
//! Enhanced with PII detection and Homomorphic Encryption (HE) concepts.

use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use std::path::Path;
#[cfg(not(target_os = "windows"))]
use tfhe::prelude::*;
#[cfg(not(target_os = "windows"))]
use tfhe::{generate_keys, ConfigBuilder, FheUint8};
use tokio::fs::{self, File};
use tokio::io::AsyncWriteExt;
use tracing::{info, warn};

// Note: tfhe integration for "active" traps.
// In a full implementation, we'd use tfhe type safe API.
// For the agent's ghost files, we simulate the HE wrapper structure.

pub struct DeceptionManager;

impl Default for DeceptionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl DeceptionManager {
    pub fn new() -> Self {
        Self
    }

    /// Generate "Ghost" files in a target directory to trap scanners.
    pub async fn spawn_ghost_files<P: AsRef<Path>>(&self, dir: P) -> anyhow::Result<()> {
        let names = vec![
            "2026_Tax_Returns.pdf",
            "Production_DB_Keys.env",
            "CEO_Private_Strategy.docx",
            "HR_Employee_Salaries.xlsx",
            "root_password_backup.txt",
            "Cloud_Service_Account.json",
            "M&A_Targets_2026.pptx",
            "customer_pii_dump.csv",
        ];
        self.spawn_custom_ghost_files(dir, names).await
    }

    /// Generate custom decoy files.
    pub async fn spawn_custom_ghost_files<P: AsRef<Path>, S: AsRef<str>>(
        &self,
        dir: P,
        names: Vec<S>,
    ) -> anyhow::Result<()> {
        let dir = dir.as_ref();
        if !dir.exists() {
            fs::create_dir_all(dir).await?;
        }

        for name in &names {
            let path = dir.join(name.as_ref());
            let is_he = name.as_ref().contains("DB")
                || name.as_ref().contains("json")
                || name.as_ref().contains("env");

            if is_he {
                self.spawn_he_trap(&path).await?;
            } else {
                let mut file = File::create(&path).await?;
                let payload: String = thread_rng()
                    .sample_iter(&Alphanumeric)
                    .take(1024)
                    .map(char::from)
                    .collect();
                file.write_all(payload.as_bytes()).await?;
            }
            info!("Spawned Ghost File (Trap): {:?}", path);
        }

        warn!(
            "Deception active in {:?}: {} Ghost Files deployed.",
            dir,
            names.len()
        );
        Ok(())
    }

    /// Spawn a "Homomorphically Encrypted" (HE) active trap.
    /// Uses tfhe (TFHE-rs) to create a high-fidelity forensic bait.
    /// Fallback: if tfhe environment fails (e.g. missing seeder), uses high-entropy random data.
    async fn spawn_he_trap(&self, path: &Path) -> anyhow::Result<()> {
        let path_buf = path.to_path_buf();

        // On Windows, TFHE has no compatible seeder — skip keygen entirely
        // to avoid thread panics. High-entropy random data is equally effective
        // for deception purposes.
        #[cfg(target_os = "windows")]
        let serialized_ct = {
            info!(
                "Generating high-entropy deception payload for trap: {:?}",
                path
            );
            let mut data = vec![0u8; 1024];
            thread_rng().fill(&mut data[..]);
            data
        };

        #[cfg(not(target_os = "windows"))]
        let serialized_ct = {
            info!("Generating TFHE keys for active trap: {:?}", path);
            let result = std::panic::catch_unwind(|| {
                let config = ConfigBuilder::default_with_small_encryption().build();
                let (client_key, _) = generate_keys(config);
                let canary_value = 0x42u8;
                let ciphertext = FheUint8::encrypt(canary_value, &client_key);
                bincode::serialize(&ciphertext)
            });

            match result {
                Ok(Ok(data)) => data,
                Ok(Err(e)) => {
                    warn!("TFHE serialization failed: {}. Using random bait.", e);
                    let mut data = vec![0u8; 512];
                    thread_rng().fill(&mut data[..]);
                    data
                }
                Err(_) => {
                    warn!("TFHE seeder unavailable. Using high-entropy random bait.");
                    let mut data = vec![0u8; 1024];
                    thread_rng().fill(&mut data[..]);
                    data
                }
            }
        };

        let mut file = File::create(&path_buf).await?;

        let node_id =
            std::env::var("OSOOSI_NODE_ID").unwrap_or_else(|_| "sentry-node-01".to_string());

        let header = format!(
            "--- OPENOSOOSI ACTIVE HE TRAP [TFHE-RS v0.6] ---\n\
             NODE_ID: {node_id}\n\
             STATUS: ACTIVE_DECEPTION\n\
             ENCRYPTION: FHE_LWE_CIPHERTEXT (TFHE-RS)\n\
             \n\
             [Malleable_Buffer_Start]\n"
        );

        file.write_all(header.as_bytes()).await?;
        file.write_all(&serialized_ct).await?;
        file.write_all(b"\n[Malleable_Buffer_End]\n--- END ACTIVE TRAP ---")
            .await?;

        Ok(())
    }

    /// Clear all Ghost files in a directory.
    pub async fn clear_ghost_files<P: AsRef<Path>>(&self, dir: P) -> anyhow::Result<()> {
        let dir = dir.as_ref();
        if dir.exists() {
            info!("Remediating deception: removing ghost files from {:?}", dir);
            fs::remove_dir_all(dir).await?;
        }
        Ok(())
    }
}
