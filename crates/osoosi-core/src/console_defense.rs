//! Interactive Elevated Console Window & Conhost Defense (EDR-VEC-23).
//!
//! Mitigates and prevents:
//! 1. QuickEdit Mode DoS / Sensor Blinding: Entering `Select` mode blocks stdout/stderr writes
//!    and freezes security daemons logging to the console.
//! 2. Console Input Injection & Screen-Buffer Scraping: Malicious processes attaching via
//!    `AttachConsole`, injecting keystrokes via `WriteConsoleInputW`, or reading tokens.
//! 3. Elevated cmd.exe Parent Shell Drop: Ctrl+C / Ctrl+Break terminating daemons and dropping
//!    desktop users into an interactive Administrator prompt.
//! 4. Windows child process window flashing: Enforces `CREATE_NO_WINDOW (0x08000000)`.

pub use osoosi_behavioral::detectors::{
    ConsoleProcessContext, ConsoleSecurityAlert, ElevatedConsoleHijackDetector,
};

// Console Mode & Process Creation Constants
pub const CREATE_NO_WINDOW: u32 = 0x0800_0000;
pub const ENABLE_PROCESSED_INPUT: u32 = 0x0001;
pub const ENABLE_LINE_INPUT: u32 = 0x0002;
pub const ENABLE_ECHO_INPUT: u32 = 0x0004;
pub const ENABLE_WINDOW_INPUT: u32 = 0x0008;
pub const ENABLE_MOUSE_INPUT: u32 = 0x0010;
pub const ENABLE_INSERT_MODE: u32 = 0x0020;
pub const ENABLE_QUICK_EDIT_MODE: u32 = 0x0040;
pub const ENABLE_EXTENDED_FLAGS: u32 = 0x0080;
pub const ENABLE_AUTO_POSITION: u32 = 0x0100;
pub const ENABLE_VIRTUAL_TERMINAL_INPUT: u32 = 0x0200;

pub const STD_INPUT_HANDLE: u32 = 0xFFFFFFF6;
pub const STD_OUTPUT_HANDLE: u32 = 0xFFFFFFF5;
pub const STD_ERROR_HANDLE: u32 = 0xFFFFFFF4;
pub const INVALID_HANDLE_VALUE: isize = -1;

/// Computes the hardened console input mode mask:
/// Clears `ENABLE_QUICK_EDIT_MODE (0x0040)`, `ENABLE_INSERT_MODE (0x0020)`,
/// and `ENABLE_MOUSE_INPUT (0x0010)`, while setting `ENABLE_EXTENDED_FLAGS (0x0080)`.
pub fn compute_hardened_console_mode(current_mode: u32) -> u32 {
    (current_mode & !(ENABLE_QUICK_EDIT_MODE | ENABLE_INSERT_MODE | ENABLE_MOUSE_INPUT))
        | ENABLE_EXTENDED_FLAGS
}

/// Checks whether a console mode mask has QuickEdit, Insert, and Mouse input stripped,
/// and has `ENABLE_EXTENDED_FLAGS` set.
pub fn is_console_mode_hardened(mode: u32) -> bool {
    ((mode & (ENABLE_QUICK_EDIT_MODE | ENABLE_INSERT_MODE | ENABLE_MOUSE_INPUT)) == 0)
        && ((mode & ENABLE_EXTENDED_FLAGS) != 0)
}

#[cfg(target_os = "windows")]
mod win32 {
    use super::*;

    #[link(name = "kernel32")]
    extern "system" {
        pub fn GetStdHandle(nStdHandle: u32) -> isize;
        pub fn GetConsoleMode(hConsoleHandle: isize, lpMode: *mut u32) -> i32;
        pub fn SetConsoleMode(hConsoleHandle: isize, dwMode: u32) -> i32;
        pub fn FlushConsoleInputBuffer(hConsoleInput: isize) -> i32;
        pub fn FreeConsole() -> i32;
        pub fn AllocConsole() -> i32;
        pub fn AttachConsole(dwProcessId: u32) -> i32;
        pub fn GetConsoleWindow() -> isize;
    }
}

/// Hardens the current Windows console input mode to prevent interactive QuickEdit / Select freezes,
/// enforces `ENABLE_EXTENDED_FLAGS`, and flushes any pending input events from the console input buffer.
#[cfg(target_os = "windows")]
pub fn harden_windows_console() -> bool {
    unsafe {
        let handle = win32::GetStdHandle(STD_INPUT_HANDLE);
        if handle == 0 || handle == INVALID_HANDLE_VALUE {
            return false;
        }
        let mut mode: u32 = 0;
        if win32::GetConsoleMode(handle, &mut mode) == 0 {
            return false;
        }
        let hardened = compute_hardened_console_mode(mode);
        let set_ok = win32::SetConsoleMode(handle, hardened) != 0;
        let _ = win32::FlushConsoleInputBuffer(handle);
        set_ok
    }
}

#[cfg(not(target_os = "windows"))]
pub fn harden_windows_console() -> bool {
    false
}

/// Flushes pending input records from the standard input console buffer.
#[cfg(target_os = "windows")]
pub fn flush_console_input() -> bool {
    unsafe {
        let handle = win32::GetStdHandle(STD_INPUT_HANDLE);
        if handle != 0 && handle != INVALID_HANDLE_VALUE {
            win32::FlushConsoleInputBuffer(handle) != 0
        } else {
            false
        }
    }
}

#[cfg(not(target_os = "windows"))]
pub fn flush_console_input() -> bool {
    false
}

/// Detaches the process from any attached console window (`FreeConsole`).
#[cfg(target_os = "windows")]
pub fn detach_console() -> bool {
    unsafe { win32::FreeConsole() != 0 }
}

#[cfg(not(target_os = "windows"))]
pub fn detach_console() -> bool {
    false
}

/// Checks whether the process is attached to an interactive console window.
#[cfg(target_os = "windows")]
pub fn has_interactive_console() -> bool {
    unsafe { win32::GetConsoleWindow() != 0 }
}

#[cfg(not(target_os = "windows"))]
pub fn has_interactive_console() -> bool {
    false
}

/// Extension trait for configuring child process command creation flags
/// to ensure `CREATE_NO_WINDOW (0x08000000)` is enforced.
pub trait CommandConsoleExt {
    fn enforce_no_window(&mut self) -> &mut Self;
}

#[cfg(target_os = "windows")]
impl CommandConsoleExt for std::process::Command {
    fn enforce_no_window(&mut self) -> &mut Self {
        use std::os::windows::process::CommandExt;
        self.creation_flags(CREATE_NO_WINDOW)
    }
}

#[cfg(not(target_os = "windows"))]
impl CommandConsoleExt for std::process::Command {
    fn enforce_no_window(&mut self) -> &mut Self {
        self
    }
}

#[cfg(target_os = "windows")]
impl CommandConsoleExt for tokio::process::Command {
    fn enforce_no_window(&mut self) -> &mut Self {
        self.creation_flags(CREATE_NO_WINDOW)
    }
}

#[cfg(not(target_os = "windows"))]
impl CommandConsoleExt for tokio::process::Command {
    fn enforce_no_window(&mut self) -> &mut Self {
        self
    }
}
