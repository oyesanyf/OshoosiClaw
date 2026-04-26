//! Discover external tools from **PATH** and well-known *env-based* locations (no hard-coded drive letters),
//! and persist resolved paths so `osoosi start` can reuse them without rescans every time.
//!
//! Cache file: `{config_dir}/osoosi/tool_paths.json` (see [`cache_path`]).

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
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
        return program_files_git_cmd();
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

/// Resolve `stem` / `stem.exe` using `where` (Windows) or `which` (Unix), then every entry in `PATH`.
pub fn resolve_executable(stem: &str) -> Option<PathBuf> {
    #[cfg(windows)]
    {
        for arg in [stem, &format!("{stem}.exe")] {
            if let Ok(o) = Command::new("where").arg(arg).output() {
                if o.status.success() {
                    if let Some(line) = String::from_utf8_lossy(&o.stdout).lines().next() {
                        let p = PathBuf::from(line.trim());
                        if p.is_file() {
                            return Some(p);
                        }
                    }
                }
            }
        }
    }
    #[cfg(unix)]
    {
        if let Ok(o) = Command::new("which").arg(stem).output() {
            if o.status.success() {
                if let Ok(s) = String::from_utf8(o.stdout) {
                    let p = PathBuf::from(s.trim());
                    if p.is_file() {
                        return Some(p);
                    }
                }
            }
        }
    }
    find_in_path_directories(stem)
}

fn find_in_path_directories(stem: &str) -> Option<PathBuf> {
    let path_var = env::var_os("PATH")?;
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
    None
}
