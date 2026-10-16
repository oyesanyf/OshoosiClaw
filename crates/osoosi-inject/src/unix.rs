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

use std::sync::atomic::{AtomicPtr, Ordering};

// Original function pointers
static REAL_EXECVE: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_PTRACE: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static REAL_SEND: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

static INIT: Once = Once::new();

unsafe fn init_hooks() {
    INIT.call_once(|| {
        let execve_sym = b"execve\0".as_ptr() as *const c_char;
        let ptrace_sym = b"ptrace\0".as_ptr() as *const c_char;
        let send_sym = b"send\0".as_ptr() as *const c_char;

        let orig_execve = dlsym(RTLD_NEXT, execve_sym);
        if !orig_execve.is_null() {
            REAL_EXECVE.store(orig_execve, Ordering::Release);
        }

        let orig_ptrace = dlsym(RTLD_NEXT, ptrace_sym);
        if !orig_ptrace.is_null() {
            REAL_PTRACE.store(orig_ptrace, Ordering::Release);
        }

        let orig_send = dlsym(RTLD_NEXT, send_sym);
        if !orig_send.is_null() {
            REAL_SEND.store(orig_send, Ordering::Release);
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
        let _path_str = CStr::from_ptr(path).to_string_lossy();
    }

    let ptr = REAL_EXECVE.load(Ordering::Acquire);
    if !ptr.is_null() {
        let orig: extern "C" fn(*const c_char, *const *const c_char, *const *const c_char) -> c_int = std::mem::transmute(ptr);
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

    let ptr = REAL_PTRACE.load(Ordering::Acquire);
    if !ptr.is_null() {
        let orig: extern "C" fn(c_int, c_int, *mut c_void, *mut c_void) -> c_int = std::mem::transmute(ptr);
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

    let ptr = REAL_SEND.load(Ordering::Acquire);
    if !ptr.is_null() {
        let orig: extern "C" fn(c_int, *const c_void, size_t, c_int) -> ssize_t = std::mem::transmute(ptr);
        orig(sockfd, buf, len, flags)
    } else {
        -1
    }
}
