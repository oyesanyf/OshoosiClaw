//! Unix-like (Linux/macOS) Process Hooking Payload
//!
//! Uses LD_PRELOAD (Linux) or DYLD_INSERT_LIBRARIES (macOS) mechanics 
//! to intercept standard libc functions. This gives Oshoosi inner-process
//! telemetry and prevention capabilities on POSIX systems.

#![allow(non_camel_case_types)]

use libc::{c_char, c_int, c_void, size_t, ssize_t};
use std::ffi::CStr;
use std::sync::Once;
use lazy_static::lazy_static;

// Definitions for dlsym
extern "C" {
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
}
const RTLD_NEXT: *mut c_void = -1isize as *mut c_void;

// Original function pointers
lazy_static! {
    static ref REAL_EXECVE: std::sync::Mutex<Option<extern "C" fn(*const c_char, *const *const c_char, *const *const c_char) -> c_int>> = std::sync::Mutex::new(None);
    static ref REAL_PTRACE: std::sync::Mutex<Option<extern "C" fn(c_int, c_int, *mut c_void, *mut c_void) -> c_int>> = std::sync::Mutex::new(None);
    static ref REAL_SEND: std::sync::Mutex<Option<extern "C" fn(c_int, *const c_void, size_t, c_int) -> ssize_t>> = std::sync::Mutex::new(None);
}

static INIT: Once = Once::new();

unsafe fn init_hooks() {
    INIT.call_once(|| {
        let execve_sym = b"execve\0".as_ptr() as *const c_char;
        let ptrace_sym = b"ptrace\0".as_ptr() as *const c_char;
        let send_sym = b"send\0".as_ptr() as *const c_char;

        let orig_execve = dlsym(RTLD_NEXT, execve_sym);
        if !orig_execve.is_null() {
            *REAL_EXECVE.lock().unwrap() = Some(std::mem::transmute(orig_execve));
        }

        let orig_ptrace = dlsym(RTLD_NEXT, ptrace_sym);
        if !orig_ptrace.is_null() {
            *REAL_PTRACE.lock().unwrap() = Some(std::mem::transmute(orig_ptrace));
        }

        let orig_send = dlsym(RTLD_NEXT, send_sym);
        if !orig_send.is_null() {
            *REAL_SEND.lock().unwrap() = Some(std::mem::transmute(orig_send));
        }
    });
}

// --- 1. Execution Protection (Ported CreateProcessW equivalent) ---

#[no_mangle]
pub unsafe extern "C" fn execve(
    path: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_int {
    init_hooks();

    if !path.is_null() {
        let path_str = CStr::from_ptr(path).to_string_lossy();
        // Here Oshoosi can block malicious executions (e.g., reverse shells or cryptominers)
        // if path_str.contains("nc") || path_str.contains("bash") { ... return -1; }
    }

    let lock = REAL_EXECVE.lock().unwrap();
    if let Some(orig) = *lock {
        orig(path, argv, envp)
    } else {
        -1
    }
}

// --- 2. Memory/Anti-Debug Protection (Ported ReadProcessMemory/OpenProcess equivalent) ---

#[no_mangle]
pub unsafe extern "C" fn ptrace(
    request: c_int,
    pid: c_int,
    addr: *mut c_void,
    data: *mut c_void,
) -> c_int {
    init_hooks();

    // PTRACE_ATTACH (16) or PTRACE_TRACEME (0) can be intercepted to prevent
    // unauthorized debuggers or memory dumpers from attaching to protected processes.
    // if request == 16 /* PTRACE_ATTACH */ { return -1; }

    let lock = REAL_PTRACE.lock().unwrap();
    if let Some(orig) = *lock {
        orig(request, pid, addr, data)
    } else {
        -1
    }
}

// --- 3. Network Deep Packet Inspection (Ported libnetmon/WSASend equivalent) ---

#[no_mangle]
pub unsafe extern "C" fn send(
    sockfd: c_int,
    buf: *const c_void,
    len: size_t,
    flags: c_int,
) -> ssize_t {
    init_hooks();

    // Deep packet inspection logic here. We can parse HTTP headers or DNS payloads
    // out of `buf` up to `len` bytes.

    let lock = REAL_SEND.lock().unwrap();
    if let Some(orig) = *lock {
        orig(sockfd, buf, len, flags)
    } else {
        -1
    }
}
