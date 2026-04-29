use std::path::Path;

/// Ported logic from OpenEDR's normalizeRegKeyName.
/// Handles WOW64 redirection, HKLM/HKU mapping, and CurrentControlSet normalization.
pub fn normalize_registry_path(path: &str) -> String {
    let mut normalized = path.to_lowercase();
    normalized = normalized.replace('/', "\\");

    // 1. Handle WOW6432Node redirection (strip it for consistency)
    normalized = normalized.replace("\\wow6432node\\", "\\");
    normalized = normalized.replace("\\wowaa32node\\", "\\");

    // 2. Handle Root Mapping (consistent prefixes)
    if normalized.starts_with("\\registry\\machine\\") {
        normalized = normalized.replace("\\registry\\machine\\", "hklm\\");
    } else if normalized.starts_with("\\registry\\user\\") {
        normalized = normalized.replace("\\registry\\user\\", "hku\\");
    }

    // 3. Handle CurrentControlSet (resolve to consistent path)
    // In Windows kernel, CurrentControlSet is usually \Registry\Machine\System\ControlSet001
    if normalized.contains("\\system\\controlset") {
        // Find if it matches \system\controlset[0-9]{3}
        // We normalize all ControlSetXXX to currentcontrolset
        let parts: Vec<&str> = normalized.split('\\').collect();
        let mut new_parts = Vec::new();
        for part in parts {
            if part.starts_with("controlset") && part.len() == 13 {
                new_parts.push("currentcontrolset");
            } else {
                new_parts.push(part);
            }
        }
        normalized = new_parts.join("\\");
    }

    // 4. Handle HKCU (HKEY_CURRENT_USER is usually \Registry\User\SID)
    // If it's Hku but has _Classes, it's HKCU Classes
    if normalized.starts_with("hku\\") && normalized.contains("_classes") {
        normalized = "hkcu\\software\\classes".to_string() + &normalized.split("_classes").last().unwrap_or("");
    }

    normalized
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalization() {
        assert_eq!(
            normalize_registry_path("\\Registry\\Machine\\Software\\Wow6432Node\\Microsoft"),
            "hklm\\software\\microsoft"
        );
        assert_eq!(
            normalize_registry_path("\\Registry\\Machine\\System\\ControlSet001\\Services"),
            "hklm\\system\\currentcontrolset\\services"
        );
    }
}
