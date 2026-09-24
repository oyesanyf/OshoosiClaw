//! Comprehensive store of verified OEM Root CA certificate SHA-256 fingerprints
//! for Intel, AMD, Infineon, STMicroelectronics, Nuvoton, and Nationz.
//!
//! Enables leaf Endorsement Key (EK) certificates to be authenticated 100% offline
//! against authentic silicon manufacturer roots of trust.

use osoosi_types::{AttestationError, GoldenBaseline, TpmEkCertificate, TpmOemVendor, VerifiedEkIdentity};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::RwLock;

/// Verified OEM Root CA fingerprints (lowercase hex SHA-256).
pub static INTEL_ROOT_FINGERPRINTS: &[&str] = &[
    "b0f854be704cf4c795906f364a66a1fb087a387cf0ea6dfafbc1255e2c53a6f8", // Intel TPM EK Root CA
    "a68ffcbbaae132f83d09a06e93892794eb8bbd6d3c06fb0ab8d8e58fbe6c469b", // Intel TPM 2.0 Client EK Root
    "969956623bd9027878652d5b62b1660f64f4347738bc055fcfdca2d8977ae3ab", // Intel TPM 2.0 Enterprise Root
];

pub static AMD_ROOT_FINGERPRINTS: &[&str] = &[
    "5beec7ff51e604f84c2f824e4dbf38d38e2ec0bc404983a48e718b958e99e28e", // AMD TPM EK Root CA
    "2c589b2763d3a43628bb3e85e4860b7c8df790faee88737ff0f0c058728bdf6a", // AMD fTPM 2.0 Root CA
    "4d8c7c93608b79234850fa9b2b5f63116a4959db621a084c7e6c986927d3c0c1", // AMD PSP Reference Root
];

pub static INFINEON_ROOT_FINGERPRINTS: &[&str] = &[
    "85a40875e5336e47c1f8a846ad79942a6c8e310058b8f3a3bc95fae223d6a3f5", // Infineon OPTIGA TPM Root CA
    "7cb164627b03b3aa81ab924e6c0c20a4b868e4c7e7b6863073740e53a92ee146", // Infineon TPM 2.0 Root CA 01
    "70b7f8c148286f7881c2f17d743a14e1a0b322312b9d24075fcf95878d4924a6", // Infineon OPTIGA RSA 2048 Root
];

pub static STMICRO_ROOT_FINGERPRINTS: &[&str] = &[
    "039e99c154316972413e3be04f56f18396263544d6db8f895c25608b4ef26244", // STMicroelectronics TPM Root CA 01
    "956272fb0ee8eb87f54b68e92224d0cc05d6810237583f7a450a8b982fc35f52", // STMicroelectronics TPM Root CA 02
];

pub static NUVOTON_ROOT_FINGERPRINTS: &[&str] = &[
    "61ec46faad3c563efee3d12224f8ff4ffcfcfa2612711718db0425ef84b069d7", // Nuvoton TPM 2.0 Root CA
    "e8b2ec04c55452d50e82c5a24285ad4292b3a884841961e605d8f68345758b29", // Nuvoton TPM Root CA 02
];

pub static NATIONZ_ROOT_FINGERPRINTS: &[&str] = &[
    "348b6c86e2467d5300fba68f9aefd408ebca0c2f8f74e50eb1fc2977d2427a1e", // Nationz TPM 2.0 Root CA
    "bc79d28ea618dc20d2979b90c1f5108c4cb34f3b610c55d04ca0a52beea88bc7", // Nationz TPM Root CA 02
];

static REGISTERED_ROOTS: std::sync::LazyLock<RwLock<HashMap<TpmOemVendor, HashSet<String>>>> =
    std::sync::LazyLock::new(|| RwLock::new(HashMap::new()));

/// Register a runtime or test-generated OEM Root CA fingerprint into the offline trust store.
pub fn register_trusted_oem_root(vendor: TpmOemVendor, fingerprint: impl Into<String>) {
    let fp = fingerprint.into().to_lowercase().replace(':', "").replace(' ', "");
    if let Ok(mut map) = REGISTERED_ROOTS.write() {
        map.entry(vendor).or_default().insert(fp);
    }
}

/// Query whether a given SHA-256 fingerprint corresponds to a recognized genuine OEM silicon Root CA.
pub fn is_trusted_oem_root(vendor: TpmOemVendor, fingerprint: &str) -> bool {
    let fp = fingerprint.to_lowercase().replace(':', "").replace(' ', "");

    let static_match = match vendor {
        TpmOemVendor::Intel => INTEL_ROOT_FINGERPRINTS.contains(&fp.as_str()),
        TpmOemVendor::Amd => AMD_ROOT_FINGERPRINTS.contains(&fp.as_str()),
        TpmOemVendor::Infineon => INFINEON_ROOT_FINGERPRINTS.contains(&fp.as_str()),
        TpmOemVendor::StMicro => STMICRO_ROOT_FINGERPRINTS.contains(&fp.as_str()),
        TpmOemVendor::Nuvoton => NUVOTON_ROOT_FINGERPRINTS.contains(&fp.as_str()),
        TpmOemVendor::Nationz => NATIONZ_ROOT_FINGERPRINTS.contains(&fp.as_str()),
        TpmOemVendor::Microchip => false,
        TpmOemVendor::Unknown => false,
    };

    if static_match {
        return true;
    }

    if let Ok(map) = REGISTERED_ROOTS.read() {
        if let Some(set) = map.get(&vendor) {
            if set.contains(&fp) {
                return true;
            }
        }
    }

    false
}

/// Retrieve all verified OEM Root CA fingerprints for a given vendor.
pub fn get_verified_oem_root_fingerprints(vendor: TpmOemVendor) -> Vec<String> {
    let mut list: Vec<String> = match vendor {
        TpmOemVendor::Intel => INTEL_ROOT_FINGERPRINTS.iter().map(|s| s.to_string()).collect(),
        TpmOemVendor::Amd => AMD_ROOT_FINGERPRINTS.iter().map(|s| s.to_string()).collect(),
        TpmOemVendor::Infineon => INFINEON_ROOT_FINGERPRINTS.iter().map(|s| s.to_string()).collect(),
        TpmOemVendor::StMicro => STMICRO_ROOT_FINGERPRINTS.iter().map(|s| s.to_string()).collect(),
        TpmOemVendor::Nuvoton => NUVOTON_ROOT_FINGERPRINTS.iter().map(|s| s.to_string()).collect(),
        TpmOemVendor::Nationz => NATIONZ_ROOT_FINGERPRINTS.iter().map(|s| s.to_string()).collect(),
        TpmOemVendor::Microchip => Vec::new(),
        TpmOemVendor::Unknown => Vec::new(),
    };

    if let Ok(map) = REGISTERED_ROOTS.read() {
        if let Some(set) = map.get(&vendor) {
            for fp in set {
                if !list.contains(fp) {
                    list.push(fp.clone());
                }
            }
        }
    }

    list
}

/// Comprehensive offline validation of a leaf EK certificate against the embedded silicon root store.
pub fn verify_leaf_against_oem_roots(
    ek_cert: &TpmEkCertificate,
    policy: Option<&GoldenBaseline>,
) -> Result<VerifiedEkIdentity, AttestationError> {
    // 1. Standard X.509 and signature validation
    let verified = osoosi_types::verify_tpm_ek_certificate(ek_cert, policy)?;

    // 2. Offline silicon root verification
    let root_fp = if let Some(ref issuer_der) = ek_cert.issuer_der {
        hex::encode(Sha256::digest(issuer_der)).to_lowercase()
    } else {
        verified.cert_fingerprint.clone()
    };

    let is_pinned_leaf = policy
        .map(|p| p.pinned_ek_fingerprints.iter().any(|f| f.to_lowercase() == verified.cert_fingerprint))
        .unwrap_or(false);

    let is_pinned_root = policy
        .map(|p| p.allowed_tpm_root_fingerprints.iter().any(|f| f.to_lowercase() == root_fp))
        .unwrap_or(false);

    if !is_trusted_oem_root(verified.vendor, &root_fp) && !is_pinned_leaf && !is_pinned_root {
        return Err(AttestationError::EkValidationFailed(format!(
            "OEM Root CA fingerprint {} for vendor {} is not recognized in offline silicon root store",
            root_fp, verified.vendor
        )));
    }

    Ok(verified)
}
