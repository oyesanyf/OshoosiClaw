//! Cross-OS hex patching with script logic (Lua-style API via Rhai).
//!
//! Usage: `hex-patch --script patch_logic.lua target_binary.exe`
//!
//! The script (`.lua` or `.rhai`) receives a `buffer` API and defines patch logic.
//! Define either `patches()` returning array of `#{offset, hex}` or `apply()` to patch in-place.

use anyhow::{Context, Result};
use rhai::{Engine, EvalAltResult, Scope, Dynamic, Array, Map};
use std::path::Path;
use tracing::info;

/// Hex-patch a binary file using a script. Works on all OS.
///
/// # Script API (Rhai - Lua/JS-like syntax)
///
/// Global `buffer` object:
/// - `buffer.len()` -> INT
/// - `buffer.get(offset)` -> INT (0-255)
/// - `buffer.set(offset, byte)` -> void
/// - `buffer.set_bytes(offset, hex_string)` -> void  // "90 90" or "9090"
/// - `buffer.find(hex_pattern)` -> INT or ()  // first offset
/// - `buffer.find_all(hex_pattern)` -> array of INT
/// - `buffer.patch(offset, hex_string)` -> void
///
/// Define either:
/// - `patches()` returning `[#{offset: N, hex: "..."}, ...]`
/// - `apply()` to patch in-place (calls buffer methods)
pub fn hex_patch(script_path: &Path, target_path: &Path) -> Result<()> {
    let script = std::fs::read_to_string(script_path)
        .with_context(|| format!("Failed to read script: {}", script_path.display()))?;
    let mut data = std::fs::read(target_path)
        .with_context(|| format!("Failed to read target: {}", target_path.display()))?;

    let mut engine = Engine::new();
    let mut scope = Scope::new();

    // Register buffer API (method-style: buffer.len(), buffer.set_bytes(), etc.)
    let buffer = PatchBuffer::new(&mut data);
    engine.register_type_with_name::<PatchBuffer>("Buffer");
    engine.register_fn("len", buffer_len);
    engine.register_fn("get", buffer_get);
    engine.register_fn("set", buffer_set);
    engine.register_fn("set_bytes", buffer_set_bytes);
    engine.register_fn("find", buffer_find);
    engine.register_fn("find_all", buffer_find_all);
    engine.register_fn("patch", buffer_patch);

    scope.push("buffer", buffer);

    // Run script
    engine.run_with_scope(&mut scope, &script).map_err(|e| {
        anyhow::anyhow!("Script error: {}", e)
    })?;

    // Try patches() first
    let has_patches = engine.eval_with_scope::<Array>(&mut scope, "patches()");
    if let Ok(patches) = has_patches {
        let buffer = scope.get_value::<PatchBuffer>("buffer").unwrap();
        for (i, entry) in patches.iter().enumerate() {
            let map = entry.clone().try_cast::<Map>().ok_or_else(|| {
                anyhow::anyhow!("patches()[{}] must be map {{offset, hex}}", i)
            })?;
            let offset: i64 = map.get("offset")
                .and_then(|v| v.as_int().ok())
                .ok_or_else(|| anyhow::anyhow!("patches()[{}] missing 'offset'", i))?;
            let hex: String = map.get("hex")
                .and_then(|v| v.clone().into_string().ok())
                .ok_or_else(|| anyhow::anyhow!("patches()[{}] missing 'hex'", i))?;
            buffer.patch(offset as usize, &hex)?;
            info!("Patched offset 0x{:X} with {}", offset, hex);
        }
    } else if engine.eval_with_scope::<()>(&mut scope, "apply()").is_ok() {
        // apply() ran
    } else {
        anyhow::bail!(
            "Script must define patches() or apply(). See osoosi-hexpatch docs."
        );
    }

    let buffer = scope.get_value::<PatchBuffer>("buffer").unwrap();
    let data = buffer.into_data();
    std::fs::write(target_path, &data)
        .with_context(|| format!("Failed to write target: {}", target_path.display()))?;
    info!("Patched {} successfully", target_path.display());
    Ok(())
}

/// Dynamically patch a binary with find-and-replace. No script file needed.
/// Creates the patch logic in-memory: find `find_hex`, replace with `replace_hex` at all matches.
pub fn hex_patch_find_replace(target_path: &Path, find_hex: &str, replace_hex: &str) -> Result<()> {
    let find_bytes = parse_hex(find_hex)?;
    let replace_bytes = parse_hex(replace_hex)?;
    if find_bytes.len() != replace_bytes.len() {
        anyhow::bail!(
            "find_hex len ({}) must equal replace_hex len ({})",
            find_bytes.len(),
            replace_bytes.len()
        );
    }
    let mut data = std::fs::read(target_path)
        .with_context(|| format!("Failed to read target: {}", target_path.display()))?;
    let offsets: Vec<usize> = data
        .windows(find_bytes.len())
        .enumerate()
        .filter(|(_, w)| *w == find_bytes.as_slice())
        .map(|(i, _)| i)
        .collect();
    for &i in &offsets {
        data[i..i + replace_bytes.len()].copy_from_slice(&replace_bytes);
    }
    let count = offsets.len();
    if count == 0 {
        anyhow::bail!("Pattern {:?} not found in {}", find_hex, target_path.display());
    }
    std::fs::write(target_path, &data)
        .with_context(|| format!("Failed to write target: {}", target_path.display()))?;
    info!("Patched {} ({} occurrence(s) of {} -> {})", target_path.display(), count, find_hex, replace_hex);
    Ok(())
}

/// Generate a Rhai script for find-and-replace. Used when patch logic is created dynamically.
pub fn generate_find_replace_script(find_hex: &str, replace_hex: &str) -> String {
    format!(
        r#"// Auto-generated find-replace patch
fn apply() {{
  let offsets = buffer.find_all("{}");
  for off in offsets {{
    buffer.set_bytes(off, "{}");
  }}
}}
"#,
        find_hex.replace('"', "\\\""),
        replace_hex.replace('"', "\\\"")
    )
}

/// Patch using dynamically generated script (find-replace). No external script file.
pub fn hex_patch_dynamic(target_path: &Path, find_hex: &str, replace_hex: &str) -> Result<()> {
    let script = generate_find_replace_script(find_hex, replace_hex);
    let mut data = std::fs::read(target_path)
        .with_context(|| format!("Failed to read target: {}", target_path.display()))?;

    let mut engine = rhai::Engine::new();
    let mut scope = rhai::Scope::new();
    let buffer = PatchBuffer::new(&mut data);
    engine.register_type_with_name::<PatchBuffer>("Buffer");
    engine.register_fn("len", buffer_len);
    engine.register_fn("get", buffer_get);
    engine.register_fn("set", buffer_set);
    engine.register_fn("set_bytes", buffer_set_bytes);
    engine.register_fn("find", buffer_find);
    engine.register_fn("find_all", buffer_find_all);
    engine.register_fn("patch", buffer_patch);
    scope.push("buffer", buffer);

    engine.run_with_scope(&mut scope, &script)
        .map_err(|e| anyhow::anyhow!("Generated script error: {}", e))?;
    engine.eval_with_scope::<()>(&mut scope, "apply()")
        .map_err(|e| anyhow::anyhow!("apply() failed: {}", e))?;

    let data = scope.get_value::<PatchBuffer>("buffer").unwrap().into_data();
    std::fs::write(target_path, &data)
        .with_context(|| format!("Failed to write target: {}", target_path.display()))?;
    info!("Patched {} (dynamic find {} -> {})", target_path.display(), find_hex, replace_hex);
    Ok(())
}

#[derive(Clone)]
pub struct PatchBuffer {
    data: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
}

impl PatchBuffer {
    pub fn new(data: &mut Vec<u8>) -> Self {
        let data = std::mem::take(data);
        Self {
            data: std::sync::Arc::new(std::sync::Mutex::new(data)),
        }
    }

    pub fn into_data(self) -> Vec<u8> {
        match std::sync::Arc::try_unwrap(self.data) {
            Ok(m) => m.into_inner().unwrap_or_default(),
            Err(arc) => arc.lock().map(|g| g.clone()).unwrap_or_default(),
        }
    }

    pub fn patch(&self, offset: usize, hex: &str) -> Result<()> {
        let bytes = parse_hex(hex)?;
        let mut data = self.data.lock().map_err(|_| anyhow::anyhow!("lock failed"))?;
        if offset + bytes.len() > data.len() {
            anyhow::bail!(
                "patch at offset 0x{:X} would exceed buffer (len={})",
                offset,
                data.len()
            );
        }
        data[offset..offset + bytes.len()].copy_from_slice(&bytes);
        Ok(())
    }
}

fn buffer_len(buffer: &mut PatchBuffer) -> Result<i64, Box<EvalAltResult>> {
    let data = buffer.data.lock().map_err(|_| Box::<EvalAltResult>::from("lock failed"))?;
    Ok(data.len() as i64)
}

fn buffer_get(buffer: &mut PatchBuffer, offset: i64) -> Result<i64, Box<EvalAltResult>> {
    let data = buffer.data.lock().map_err(|_| Box::<EvalAltResult>::from("lock failed"))?;
    if offset >= 0 && (offset as usize) < data.len() {
        Ok(data[offset as usize] as i64)
    } else {
        Err(Box::<EvalAltResult>::from(format!("offset {} out of range", offset)))
    }
}

fn buffer_set(buffer: &mut PatchBuffer, offset: i64, byte: i64) -> Result<(), Box<EvalAltResult>> {
    let mut data = buffer.data.lock().map_err(|_| Box::<EvalAltResult>::from("lock failed"))?;
    if offset >= 0 && (offset as usize) < data.len() && byte >= 0 && byte <= 255 {
        data[offset as usize] = byte as u8;
        Ok(())
    } else {
        Err(Box::<EvalAltResult>::from(format!("offset {} or byte {} out of range", offset, byte)))
    }
}

fn buffer_set_bytes(buffer: &mut PatchBuffer, offset: i64, hex_str: &str) -> Result<(), Box<EvalAltResult>> {
    let bytes = parse_hex(hex_str).map_err(|e| Box::<EvalAltResult>::from(e.to_string()))?;
    let mut data = buffer.data.lock().map_err(|_| Box::<EvalAltResult>::from("lock failed"))?;
    let start = offset as usize;
    if start + bytes.len() > data.len() {
        return Err(Box::<EvalAltResult>::from(format!("patch at offset {} would exceed buffer", offset)));
    }
    data[start..start + bytes.len()].copy_from_slice(&bytes);
    Ok(())
}

fn buffer_find(buffer: &mut PatchBuffer, hex_pattern: &str) -> Result<Dynamic, Box<EvalAltResult>> {
    let pattern = parse_hex(hex_pattern).map_err(|e| Box::<EvalAltResult>::from(e.to_string()))?;
    let data = buffer.data.lock().map_err(|_| Box::<EvalAltResult>::from("lock failed"))?;
    let pos = data.windows(pattern.len()).position(|w| w == pattern.as_slice());
    Ok(match pos {
        Some(p) => Dynamic::from(p as i64),
        None => Dynamic::UNIT,
    })
}

fn buffer_find_all(buffer: &mut PatchBuffer, hex_pattern: &str) -> Result<Array, Box<EvalAltResult>> {
    let pattern = parse_hex(hex_pattern).map_err(|e| Box::<EvalAltResult>::from(e.to_string()))?;
    let data = buffer.data.lock().map_err(|_| Box::<EvalAltResult>::from("lock failed"))?;
    let mut offsets = Array::new();
    for (i, w) in data.windows(pattern.len()).enumerate() {
        if w == pattern.as_slice() {
            offsets.push(Dynamic::from(i as i64));
        }
    }
    Ok(offsets)
}

fn buffer_patch(buffer: &mut PatchBuffer, offset: i64, hex_str: &str) -> Result<(), Box<EvalAltResult>> {
    buffer.patch(offset as usize, hex_str).map_err(|e| Box::<EvalAltResult>::from(e.to_string()))
}

fn parse_hex(s: &str) -> Result<Vec<u8>> {
    let s = s.replace(' ', "").replace('\n', "").replace('\r', "");
    if s.len() % 2 != 0 {
        anyhow::bail!("hex string must have even length");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|_| anyhow::anyhow!("invalid hex at position {}", i))
        })
        .collect()
}
