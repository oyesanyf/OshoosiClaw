//! OpenỌ̀ṣọ́ọ̀sì Agentic EDR - Native Process Hooking Engine (Injected Payload)
//!
//! Provides in-process API hooking for Windows (Detours), Linux (LD_PRELOAD), 
//! and macOS (DYLD_INSERT_LIBRARIES).

#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod unix;
