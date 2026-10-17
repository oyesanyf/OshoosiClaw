//! Discover external tools from **PATH** and well-known *env-based* locations (no hard-coded drive letters),
//! and persist resolved paths so `osoosi start` can reuse them without rescans every time.
//!
//! Cache file: `{config_dir}/osoosi/tool_paths.json` (see [`cache_path`]).

use std::env;
use std::fs;
use std::path::PathBuf;
use tracing::info;

use serde::{Deserialize, Serialize};

/// Last-resort filename if `dirs::config_dir()` is unavailable.
const TOOL_PATHS_FILE: &str = "tool_paths.json";

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ToolPathsCache {
    /// Full path to `openshell` / `openshell.exe`
    #[serde(default)]
    pub openshell_cli: Option<String>,
    /// Full path to `git` / `git.exe`
    #[serde(default)]
    pub git: Option<String>,
}

/// Config / state file for tool path cache.
pub fn cache_path() -> PathBuf {
    if let Some(d) = dirs::config_dir() {
        d.join("osoosi").join(TOOL_PATHS_FILE)
    } else {
        env::temp_dir().join("osoosi").join(TOOL_PATHS_FILE)
    }
}

pub fn load_cache() -> Option<ToolPathsCache> {
    let p = cache_path();
    let data = fs::read_to_string(&p).ok()?;
    serde_json::from_str(&data).ok()
}

fn save_cache_inner(c: &ToolPathsCache) -> std::io::Result<()> {
    let p = cache_path();
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent)?;
    }
    let data = serde_json::to_string_pretty(c)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    fs::write(&p, data)
}

/// Run on `osoosi start`: search for `git` and `openshell`, merge with cache, write if anything new.
pub fn discover_and_persist() {
    let prev = load_cache().unwrap_or_default();
    let mut next = prev.clone();

    if let Some(p) = discover_git_unconstrained() {
        let s = p.to_string_lossy().to_string();
        if next.git.as_ref() != Some(&s) {
            info!(path = %s, "Resolved Git; persisting to tool_paths cache");
            next.git = Some(s);
        }
    }
    if let Some(p) = discover_openshell_unconstrained() {
        let s = p.to_string_lossy().to_string();
        if next.openshell_cli.as_ref() != Some(&s) {
            info!(path = %s, "Resolved OpenShell CLI; persisting to tool_paths cache");
            next.openshell_cli = Some(s);
        }
    }

    if next != prev {
        if let Err(e) = save_cache_inner(&next) {
            tracing::warn!(
                "Could not save tool_paths cache at {:?}: {}",
                cache_path(),
                e
            );
        }
    }
}

/// Git: override env → cache (if file still exists) → `where`/`which` + PATH walk → `%ProgramFiles%\\Git\\cmd\\git.exe` (env only).
#[cfg(windows)]
pub fn resolve_git_executable() -> Option<PathBuf> {
    if let Ok(p) = env::var("OSOOSI_GIT_PATH") {
        let pb = PathBuf::from(p.trim());
        if pb.is_file() {
            return Some(pb);
        }
    }
    if let Some(c) = load_cache() {
        if let Some(ref s) = c.git {
            let pb = PathBuf::from(s);
            if pb.is_file() {
                return Some(pb);
            }
        }
    }
    discover_git_unconstrained()
}

#[cfg(not(windows))]
pub fn resolve_git_executable() -> Option<PathBuf> {
    if let Ok(p) = env::var("OSOOSI_GIT_PATH") {
        let pb = PathBuf::from(p.trim());
        if pb.is_file() {
            return Some(pb);
        }
    }
    if let Some(c) = load_cache() {
        if let Some(ref s) = c.git {
            let pb = PathBuf::from(s);
            if pb.is_file() {
                return Some(pb);
            }
        }
    }
    resolve_executable("git")
}

fn discover_git_unconstrained() -> Option<PathBuf> {
    if let Ok(p) = env::var("OSOOSI_GIT_PATH") {
        let pb = PathBuf::from(p.trim());
        if pb.is_file() {
            return Some(pb);
        }
    }
    if let Some(p) = resolve_executable("git") {
        return Some(p);
    }
    #[cfg(windows)]
    {
        program_files_git_cmd()
    }
    #[cfg(not(windows))]
    {
        None
    }
}

#[cfg(windows)]
fn program_files_git_cmd() -> Option<PathBuf> {
    for key in ["ProgramFiles", "ProgramFiles(x86)"] {
        if let Ok(pf) = env::var(key) {
            let g = PathBuf::from(pf).join("Git").join("cmd").join("git.exe");
            if g.is_file() {
                return Some(g);
            }
        }
    }
    None
}

/// OpenShell CLI: `OPENSHELL_CLI_PATH` → cache → `where openshell` / PATH → Python `Scripts` → `~/.local/bin` (Unix) / `%USERPROFILE%\\.local\\bin` (Windows).
pub fn resolve_openshell_cli_path() -> PathBuf {
    if let Ok(p) = env::var("OPENSHELL_CLI_PATH") {
        let path = PathBuf::from(p);
        if path.exists() {
            return path;
        }
    }
    if let Some(c) = load_cache() {
        if let Some(ref s) = c.openshell_cli {
            let pb = PathBuf::from(s);
            if pb.is_file() {
                return pb;
            }
        }
    }
    if let Some(p) = discover_openshell_unconstrained() {
        return p;
    }
    PathBuf::from("openshell")
}

fn discover_openshell_unconstrained() -> Option<PathBuf> {
    if let Some(p) = local_tools_openshell() {
        return Some(p);
    }
    if let Some(p) = resolve_executable("openshell") {
        return Some(p);
    }
    #[cfg(windows)]
    if let Some(p) = find_openshell_in_local_python_scripts() {
        return Some(p);
    }
    #[cfg(unix)]
    {
        if let Ok(home) = env::var("HOME") {
            let local_bin = PathBuf::from(&home).join(".local/bin/openshell");
            if local_bin.exists() {
                return Some(local_bin);
            }
        }
        let usr_local = PathBuf::from("/usr/local/bin/openshell");
        if usr_local.exists() {
            return Some(usr_local);
        }
    }
    #[cfg(windows)]
    {
        if let Ok(userprofile) = env::var("USERPROFILE") {
            let local_bin = PathBuf::from(&userprofile).join(".local\\bin\\openshell.exe");
            if local_bin.exists() {
                return Some(local_bin);
            }
        }
    }
    None
}

fn local_tools_openshell() -> Option<PathBuf> {
    let tools_dir = osoosi_types::resolve_tools_dir();
    let candidates = if cfg!(windows) {
        vec![
            tools_dir.join("openshell").join("openshell.exe"),
            tools_dir
                .join("openshell")
                .join("bin")
                .join("openshell.exe"),
            tools_dir.join("openshell.exe"),
        ]
    } else {
        vec![
            tools_dir.join("openshell").join("openshell"),
            tools_dir.join("openshell").join("bin").join("openshell"),
            tools_dir.join("openshell"),
        ]
    };
    candidates.into_iter().find(|p| p.is_file())
}

/// `%LOCALAPPDATA%\\Python\\*\\Scripts\\openshell.exe`
#[cfg(windows)]
fn find_openshell_in_local_python_scripts() -> Option<PathBuf> {
    let local = env::var("LOCALAPPDATA").ok()?;
    let base = PathBuf::from(&local).join("Python");
    let rd = fs::read_dir(&base).ok()?;
    for e in rd.flatten() {
        let candidate = e.path().join("Scripts").join("openshell.exe");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Resolve `stem` / `stem.exe` purely in Rust by walking `PATH` and standard system directories (zero `where.exe` subprocesses).
pub fn resolve_executable(stem: &str) -> Option<PathBuf> {
    find_in_path_directories(stem)
}

fn find_in_path_directories(stem: &str) -> Option<PathBuf> {
    if let Some(path_var) = env::var_os("PATH") {
        for dir in env::split_paths(&path_var) {
            #[cfg(windows)]
            {
                for name in [
                    format!("{stem}.exe"),
                    format!("{stem}.EXE"),
                    stem.to_string(),
                ] {
                    let p = dir.join(&name);
                    if p.is_file() {
                        return Some(p);
                    }
                }
            }
            #[cfg(not(windows))]
            {
                let p = dir.join(stem);
                if p.is_file() {
                    return Some(p);
                }
            }
        }
    }

    let resolved = osoosi_types::resolve_system_binary(stem);
    if resolved.is_file() {
        return Some(resolved);
    }

    #[cfg(windows)]
    {
        let sys_root = env::var("SystemRoot")
            .or_else(|_| env::var("windir"))
            .unwrap_or_else(|_| r"C:\Windows".to_string());
        let sys32_candidate = PathBuf::from(&sys_root)
            .join("System32")
            .join(format!("{stem}.exe"));
        if sys32_candidate.is_file() {
            return Some(sys32_candidate);
        }

        if stem.eq_ignore_ascii_case("ollama") {
            if let Ok(local) = env::var("LOCALAPPDATA") {
                let p = PathBuf::from(local)
                    .join("Programs")
                    .join("Ollama")
                    .join("ollama.exe");
                if p.is_file() {
                    return Some(p);
                }
            }
            for pf_var in ["ProgramFiles", "ProgramFiles(x86)"] {
                if let Ok(pf) = env::var(pf_var) {
                    let p = PathBuf::from(pf).join("Ollama").join("ollama.exe");
                    if p.is_file() {
                        return Some(p);
                    }
                }
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_executable_standard_binaries() {
        #[cfg(windows)]
        {
            let cmd_path = resolve_executable("cmd");
            assert!(cmd_path.is_some(), "Should resolve cmd.exe on Windows");
            assert!(cmd_path.unwrap().is_file());

            let netsh_path = resolve_executable("netsh");
            assert!(netsh_path.is_some(), "Should resolve netsh.exe on Windows");
            assert!(netsh_path.unwrap().is_file());
        }
    }

    #[test]
    fn test_resolve_executable_nonexistent() {
        let nonexistent = resolve_executable("non_existent_binary_xyz_12345");
        assert!(nonexistent.is_none());
    }
}
