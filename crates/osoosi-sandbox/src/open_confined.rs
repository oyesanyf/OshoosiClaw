//! Handle-based confined file opener (`crates/osoosi-sandbox/src/open_confined.rs`).
//!
//! Eliminates the TOCTOU / symlink / junction / hardlink gap in lexical path checks by:
//! 1. Running [`crate::validate_sandbox_relative_path`] as a fast lexical pre-filter.
//! 2. Opening `sandbox_root` and reading its kernel-resolved path via `GetFinalPathNameByHandleW`.
//! 3. Walking each component from `sandbox_root` downward, opening every intermediate directory and
//!    the target with `FILE_FLAG_OPEN_REPARSE_POINT` and inspecting `BY_HANDLE_FILE_INFORMATION`:
//!    - Rejects any component with `FILE_ATTRIBUTE_REPARSE_POINT` (NTFS junctions, mount points,
//!      symbolic links) *before* the kernel traverses it.
//!    - Rejects regular files with `nNumberOfLinks > 1` (hardlinks to files outside the sandbox).
//! 4. Querying `GetFinalPathNameByHandleW` on the opened file handle and verifying that its
//!    canonical path is strictly inside the canonical `sandbox_root` (with a path-separator
//!    boundary check).
//! 5. Returning the already-opened [`std::fs::File`] so the caller never re-opens by path.

use osoosi_types::OctopusSecurityError;
use std::path::Path;

/// Opens a relative path strictly inside `sandbox_root` with handle-level reparse-point,
/// Opens a relative path strictly inside `sandbox_root` with handle-level reparse-point,
/// hardlink (`nNumberOfLinks == 1`), and `GetFinalPathNameByHandleW` verification.
pub fn open_confined(
    sandbox_root: &Path,
    relative_input: &str,
    write: bool,
) -> Result<std::fs::File, OctopusSecurityError> {
    let _joined = crate::validate_sandbox_relative_path(sandbox_root, relative_input)
        .map_err(OctopusSecurityError::IsolationViolation)?;

    #[cfg(windows)]
    {
        win_confined::open_confined_windows(sandbox_root, relative_input, write)
    }

    #[cfg(not(windows))]
    {
        unix_confined::open_confined_unix(sandbox_root, relative_input, write)
    }
}

/// Reads the entire contents of a file strictly inside `sandbox_root` using handle-based confinement.
/// Guarantees that neither intermediate directories nor the leaf file are reparse points or symlinks.
pub fn read_confined(
    sandbox_root: &Path,
    relative_input: &str,
) -> Result<Vec<u8>, OctopusSecurityError> {
    use std::io::Read;
    let mut file = open_confined(sandbox_root, relative_input, false)?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).map_err(|e| {
        OctopusSecurityError::IsolationViolation(format!(
            "CONFINED_READ_FAILED: Failed to read from '{}': {}",
            relative_input, e
        ))
    })?;
    Ok(buf)
}

/// Writes data to a file strictly inside `sandbox_root` using handle-based confinement.
/// Post-verification, truncates existing contents on the verified handle before writing.
pub fn write_confined(
    sandbox_root: &Path,
    relative_input: &str,
    data: &[u8],
) -> Result<(), OctopusSecurityError> {
    use std::io::Write;
    let mut file = open_confined(sandbox_root, relative_input, true)?;
    file.write_all(data).map_err(|e| {
        OctopusSecurityError::IsolationViolation(format!(
            "CONFINED_WRITE_FAILED: Failed to write to '{}': {}",
            relative_input, e
        ))
    })?;
    file.flush().map_err(|e| {
        OctopusSecurityError::IsolationViolation(format!(
            "CONFINED_FLUSH_FAILED: Failed to flush '{}': {}",
            relative_input, e
        ))
    })?;
    Ok(())
}

/// Creates a directory hierarchy strictly within `sandbox_root` with handle-based reparse-point and canonical root confinement checks at every level.
pub fn create_confined_dir_all(
    sandbox_root: &Path,
    relative_input: &str,
) -> Result<(), OctopusSecurityError> {
    let _ = crate::validate_sandbox_relative_path(sandbox_root, relative_input)
        .map_err(OctopusSecurityError::IsolationViolation)?;

    #[cfg(windows)]
    {
        win_confined::create_confined_dir_all_windows(sandbox_root, relative_input)
    }

    #[cfg(not(windows))]
    {
        unix_confined::create_confined_dir_all_unix(sandbox_root, relative_input)
    }
}

#[cfg(windows)]
mod win_confined {
    use osoosi_types::OctopusSecurityError;
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, RawHandle};
    use std::path::{Component, Path, PathBuf};

    type HANDLE = *mut c_void;
    type BOOL = i32;
    type DWORD = u32;

    const INVALID_HANDLE_VALUE: HANDLE = -1isize as HANDLE;
    const GENERIC_READ: DWORD = 0x8000_0000;
    const GENERIC_WRITE: DWORD = 0x4000_0000;
    const FILE_SHARE_READ: DWORD = 0x0000_0001;
    const OPEN_EXISTING: DWORD = 3;
    const OPEN_ALWAYS: DWORD = 4;
    const FILE_FLAG_BACKUP_SEMANTICS: DWORD = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: DWORD = 0x0020_0000;
    const FILE_ATTRIBUTE_NORMAL: DWORD = 0x0000_0080;
    const FILE_ATTRIBUTE_DIRECTORY: DWORD = 0x0000_0010;
    const FILE_ATTRIBUTE_REPARSE_POINT: DWORD = 0x0000_0400;

    #[repr(C)]
    #[allow(non_snake_case)]
    #[derive(Clone, Copy)]
    struct FILETIME {
        dwLowDateTime: DWORD,
        dwHighDateTime: DWORD,
    }

    #[repr(C)]
    #[allow(non_snake_case)]
    struct BY_HANDLE_FILE_INFORMATION {
        dwFileAttributes: DWORD,
        ftCreationTime: FILETIME,
        ftLastAccessTime: FILETIME,
        ftLastWriteTime: FILETIME,
        dwVolumeSerialNumber: DWORD,
        nFileSizeHigh: DWORD,
        nFileSizeLow: DWORD,
        nNumberOfLinks: DWORD,
        nFileIndexHigh: DWORD,
        nFileIndexLow: DWORD,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn CreateFileW(
            lpFileName: *const u16,
            dwDesiredAccess: DWORD,
            dwShareMode: DWORD,
            lpSecurityAttributes: *const c_void,
            dwCreationDisposition: DWORD,
            dwFlagsAndAttributes: DWORD,
            hTemplateFile: HANDLE,
        ) -> HANDLE;
        fn GetFileInformationByHandle(
            hFile: HANDLE,
            lpFileInformation: *mut BY_HANDLE_FILE_INFORMATION,
        ) -> BOOL;
        fn GetFinalPathNameByHandleW(
            hFile: HANDLE,
            lpszFilePath: *mut u16,
            cchFilePath: DWORD,
            dwFlags: DWORD,
        ) -> DWORD;
        fn GetLastError() -> DWORD;
    }

    fn to_wide(p: &Path) -> Vec<u16> {
        p.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    fn final_path_of_handle(h: HANDLE) -> Result<String, OctopusSecurityError> {
        let mut buf = vec![0u16; 1024];
        let len = unsafe { GetFinalPathNameByHandleW(h, buf.as_mut_ptr(), buf.len() as DWORD, 0) };
        if len == 0 {
            let err = unsafe { GetLastError() };
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "CONFINED_OPEN_FINAL_PATH_FAILED: GetFinalPathNameByHandleW failed (OS Error {})",
                err
            )));
        }
        if (len as usize) >= buf.len() {
            buf.resize((len as usize) + 2, 0);
            let len2 =
                unsafe { GetFinalPathNameByHandleW(h, buf.as_mut_ptr(), buf.len() as DWORD, 0) };
            if len2 == 0 || (len2 as usize) >= buf.len() {
                return Err(OctopusSecurityError::IsolationViolation(
                    "CONFINED_OPEN_FINAL_PATH_OVERFLOW: Path exceeds buffer".to_string(),
                ));
            }
            return Ok(String::from_utf16_lossy(&buf[..len2 as usize]));
        }
        Ok(String::from_utf16_lossy(&buf[..len as usize]))
    }

    fn handle_info(h: HANDLE) -> Result<BY_HANDLE_FILE_INFORMATION, OctopusSecurityError> {
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        let ok = unsafe { GetFileInformationByHandle(h, &mut info) };
        if ok == 0 {
            let err = unsafe { GetLastError() };
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "CONFINED_OPEN_INFO_FAILED: GetFileInformationByHandle failed (OS Error {})",
                err
            )));
        }
        Ok(info)
    }

    fn open_raw(
        path: &Path,
        access: DWORD,
        disposition: DWORD,
        flags: DWORD,
    ) -> Result<std::fs::File, OctopusSecurityError> {
        let wide = to_wide(path);
        let h = unsafe {
            CreateFileW(
                wide.as_ptr(),
                access,
                FILE_SHARE_READ,
                std::ptr::null(),
                disposition,
                flags,
                std::ptr::null_mut(),
            )
        };
        if h.is_null() || h == INVALID_HANDLE_VALUE {
            let err = unsafe { GetLastError() };
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "CONFINED_OPEN_CREATEFILE_FAILED: '{}' failed (OS Error {})",
                path.display(),
                err
            )));
        }
        Ok(unsafe { std::fs::File::from_raw_handle(h as RawHandle) })
    }

    fn normalize_final(s: &str) -> String {
        s.trim_end_matches(&['\\', '/'][..])
            .replace('/', "\\")
            .to_ascii_lowercase()
    }

    fn is_strictly_inside_or_equal(candidate: &str, root: &str) -> bool {
        let c = normalize_final(candidate);
        let r = normalize_final(root);
        if c == r {
            return true;
        }
        c.strip_prefix(&r)
            .map(|rest| rest.starts_with('\\'))
            .unwrap_or(false)
    }

    pub fn open_confined_windows(
        sandbox_root: &Path,
        relative_input: &str,
        write: bool,
    ) -> Result<std::fs::File, OctopusSecurityError> {
        let root_file = open_raw(
            sandbox_root,
            GENERIC_READ,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        )?;
        let root_h = root_file.as_raw_handle() as HANDLE;
        let root_info = handle_info(root_h)?;
        if root_info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "CONFINED_OPEN_REPARSE_ROOT_BLOCKED: Sandbox root '{}' is itself a reparse point / junction / symlink",
                sandbox_root.display()
            )));
        }
        if root_info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "CONFINED_OPEN_ROOT_NOT_DIR: Sandbox root '{}' is not a directory",
                sandbox_root.display()
            )));
        }
        let canonical_root = final_path_of_handle(root_h)?;

        let comps: Vec<String> = Path::new(relative_input.trim())
            .components()
            .filter_map(|c| match c {
                Component::Normal(o) => Some(o.to_string_lossy().into_owned()),
                _ => None,
            })
            .collect();
        if comps.is_empty() {
            return Err(OctopusSecurityError::IsolationViolation(
                "CONFINED_OPEN_EMPTY_COMPONENTS: Relative path has no target component".to_string(),
            ));
        }

        let mut cursor = PathBuf::from(&canonical_root);
        let mut _held_dirs: Vec<std::fs::File> = vec![root_file];
        for dir_comp in &comps[..comps.len() - 1] {
            cursor.push(dir_comp);
            let dir_file = open_raw(
                &cursor,
                GENERIC_READ,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            )?;
            let dh = dir_file.as_raw_handle() as HANDLE;
            let dinfo = handle_info(dh)?;
            if dinfo.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(OctopusSecurityError::IsolationViolation(format!(
                    "CONFINED_OPEN_REPARSE_DIR_BLOCKED: Directory component '{}' is a junction or symlink",
                    dir_comp
                )));
            }
            if dinfo.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
                return Err(OctopusSecurityError::IsolationViolation(format!(
                    "CONFINED_OPEN_INTERMEDIATE_NOT_DIR: '{}' is not a directory",
                    dir_comp
                )));
            }
            let dir_final = final_path_of_handle(dh)?;
            if !is_strictly_inside_or_equal(&dir_final, &canonical_root) {
                return Err(OctopusSecurityError::IsolationViolation(format!(
                    "CONFINED_OPEN_DIR_ESCAPED_ROOT: '{}' resolved to '{}' outside '{}'",
                    dir_comp, dir_final, canonical_root
                )));
            }
            cursor = PathBuf::from(dir_final);
            _held_dirs.push(dir_file);
        }

        let leaf_comp = comps.last().ok_or_else(|| {
            OctopusSecurityError::IsolationViolation(
                "CONFINED_OPEN_EMPTY_COMPONENTS: Missing leaf path component".to_string(),
            )
        })?;
        cursor.push(leaf_comp);
        let access = if write {
            GENERIC_READ | GENERIC_WRITE
        } else {
            GENERIC_READ
        };
        let disposition = if write { OPEN_ALWAYS } else { OPEN_EXISTING };
        let leaf_file = open_raw(
            &cursor,
            access,
            disposition,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
        )?;
        let lh = leaf_file.as_raw_handle() as HANDLE;
        let linfo = handle_info(lh)?;
        if linfo.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "CONFINED_OPEN_REPARSE_FILE_BLOCKED: Target '{}' is a symlink or reparse point",
                relative_input
            )));
        }
        if linfo.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "CONFINED_OPEN_TARGET_IS_DIR: Target '{}' is a directory, expected regular file",
                relative_input
            )));
        }
        if linfo.nNumberOfLinks > 1 {
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "CONFINED_OPEN_HARDLINK_BLOCKED: Target '{}' has nNumberOfLinks={} (> 1); hardlinks are prohibited inside the sandbox",
                relative_input, linfo.nNumberOfLinks
            )));
        }

        let leaf_final = final_path_of_handle(lh)?;
        if !is_strictly_inside_or_equal(&leaf_final, &canonical_root)
            || normalize_final(&leaf_final) == normalize_final(&canonical_root)
        {
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "CONFINED_OPEN_ESCAPE_DETECTED: Handle final path '{}' is outside canonical sandbox root '{}'",
                leaf_final, canonical_root
            )));
        }

        if write {
            leaf_file.set_len(0).map_err(|e| {
                OctopusSecurityError::IsolationViolation(format!(
                    "CONFINED_OPEN_TRUNCATE_FAILED: Failed to truncate leaf file '{}' (OS Error {})",
                    relative_input, e
                ))
            })?;
        }

        Ok(leaf_file)
    }

    pub fn create_confined_dir_all_windows(
        sandbox_root: &Path,
        relative_input: &str,
    ) -> Result<(), OctopusSecurityError> {
        let root_file = open_raw(
            sandbox_root,
            GENERIC_READ,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        )?;
        let root_h = root_file.as_raw_handle() as HANDLE;
        let root_info = handle_info(root_h)?;
        if root_info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "CONFINED_DIR_REPARSE_ROOT_BLOCKED: Sandbox root '{}' is a reparse point",
                sandbox_root.display()
            )));
        }
        if root_info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "CONFINED_DIR_ROOT_NOT_DIR: Sandbox root '{}' is not a directory",
                sandbox_root.display()
            )));
        }
        let canonical_root = final_path_of_handle(root_h)?;

        let comps: Vec<String> = Path::new(relative_input.trim())
            .components()
            .filter_map(|c| match c {
                Component::Normal(o) => Some(o.to_string_lossy().into_owned()),
                _ => None,
            })
            .collect();
        if comps.is_empty() {
            return Ok(());
        }

        let mut cursor = PathBuf::from(&canonical_root);
        let mut _held_dirs: Vec<std::fs::File> = vec![root_file];

        for comp in &comps {
            cursor.push(comp);
            if !cursor.exists() {
                std::fs::create_dir(&cursor).map_err(|e| {
                    OctopusSecurityError::IsolationViolation(format!(
                        "CONFINED_CREATE_DIR_FAILED: Failed to create '{}' (OS Error {})",
                        cursor.display(),
                        e
                    ))
                })?;
            }

            let dir_file = open_raw(
                &cursor,
                GENERIC_READ,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            )?;
            let dh = dir_file.as_raw_handle() as HANDLE;
            let dinfo = handle_info(dh)?;
            if dinfo.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(OctopusSecurityError::IsolationViolation(format!(
                    "CONFINED_DIR_REPARSE_BLOCKED: Component '{}' is a junction or symlink",
                    comp
                )));
            }
            if dinfo.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
                return Err(OctopusSecurityError::IsolationViolation(format!(
                    "CONFINED_DIR_NOT_DIR: Component '{}' exists but is not a directory",
                    comp
                )));
            }
            let dir_final = final_path_of_handle(dh)?;
            if !is_strictly_inside_or_equal(&dir_final, &canonical_root) {
                return Err(OctopusSecurityError::IsolationViolation(format!(
                    "CONFINED_DIR_ESCAPED_ROOT: Component '{}' resolved to '{}' outside canonical root '{}'",
                    comp, dir_final, canonical_root
                )));
            }
            cursor = PathBuf::from(dir_final);
            _held_dirs.push(dir_file);
        }

        Ok(())
    }
}

#[cfg(not(windows))]
mod unix_confined {
    use osoosi_types::OctopusSecurityError;
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::io::{FromRawFd, RawFd};
    use std::path::{Component, Path, PathBuf};

    #[cfg(target_os = "linux")]
    #[repr(C)]
    struct open_how {
        flags: u64,
        mode: u64,
        resolve: u64,
    }

    #[cfg(target_os = "linux")]
    const SYS_openat2: libc::c_long = 437;
    #[cfg(target_os = "linux")]
    const RESOLVE_BENEATH: u64 = 0x08;
    #[cfg(target_os = "linux")]
    const RESOLVE_NO_SYMLINKS: u64 = 0x04;

    pub fn open_confined_unix(
        sandbox_root: &Path,
        relative_input: &str,
        write: bool,
    ) -> Result<std::fs::File, OctopusSecurityError> {
        let root_meta = std::fs::symlink_metadata(sandbox_root).map_err(|e| {
            OctopusSecurityError::IsolationViolation(format!("CONFINED_OPEN_ROOT_FAILED: {}", e))
        })?;
        if root_meta.file_type().is_symlink() || !root_meta.is_dir() {
            return Err(OctopusSecurityError::IsolationViolation(
                "CONFINED_OPEN_ROOT_INVALID: Sandbox root must be a real directory".to_string(),
            ));
        }
        let canonical_root = std::fs::canonicalize(sandbox_root).map_err(|e| {
            OctopusSecurityError::IsolationViolation(format!("CONFINED_OPEN_CANON_FAILED: {}", e))
        })?;

        let root_c = CString::new(canonical_root.as_os_str().as_bytes()).map_err(|e| {
            OctopusSecurityError::IsolationViolation(format!("CONFINED_OPEN_CSTRING_FAILED: {}", e))
        })?;

        let root_fd = unsafe {
            libc::open(
                root_c.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if root_fd < 0 {
            let err = std::io::Error::last_os_error();
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "CONFINED_OPEN_ROOT_FD_FAILED: {}",
                err
            )));
        }

        struct FdGuard(RawFd);
        impl Drop for FdGuard {
            fn drop(&mut self) {
                if self.0 >= 0 {
                    unsafe { libc::close(self.0) };
                }
            }
        }
        let _root_guard = FdGuard(root_fd);

        let clean_rel = relative_input.trim();
        let comps: Vec<_> = Path::new(clean_rel)
            .components()
            .filter_map(|c| match c {
                Component::Normal(o) => Some(o.to_os_string()),
                _ => None,
            })
            .collect();
        if comps.is_empty() {
            return Err(OctopusSecurityError::IsolationViolation(
                "CONFINED_OPEN_EMPTY_COMPONENTS".to_string(),
            ));
        }

        #[cfg(target_os = "linux")]
        {
            let flags = if write {
                (libc::O_RDWR | libc::O_CREAT | libc::O_CLOEXEC) as u64
            } else {
                (libc::O_RDONLY | libc::O_CLOEXEC) as u64
            };
            let how = open_how {
                flags,
                mode: 0o644,
                resolve: RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS,
            };

            let rel_path_buf: PathBuf = comps.iter().collect();
            if let Ok(rel_c) = CString::new(rel_path_buf.as_os_str().as_bytes()) {
                let res = unsafe {
                    libc::syscall(
                        SYS_openat2,
                        root_fd,
                        rel_c.as_ptr(),
                        &how as *const open_how,
                        std::mem::size_of::<open_how>(),
                    )
                };
                if res >= 0 {
                    let raw_fd = res as RawFd;
                    let file = unsafe { std::fs::File::from_raw_fd(raw_fd) };
                    let fmeta = file.metadata().map_err(|e| {
                        OctopusSecurityError::IsolationViolation(format!(
                            "CONFINED_OPEN_META_FAILED: {}",
                            e
                        ))
                    })?;
                    if fmeta.nlink() > 1 {
                        return Err(OctopusSecurityError::IsolationViolation(
                            "CONFINED_OPEN_HARDLINK_BLOCKED".to_string(),
                        ));
                    }
                    if write {
                        let _ = file.set_len(0);
                    }
                    return Ok(file);
                } else {
                    let err = std::io::Error::last_os_error();
                    let raw_os_err = err.raw_os_error().unwrap_or(0);
                    if raw_os_err == libc::EXDEV || raw_os_err == libc::ELOOP {
                        return Err(OctopusSecurityError::IsolationViolation(format!(
                            "CONFINED_OPEN_KERNEL_ESCAPE_BLOCKED: openat2 detected sandbox escape or symlink (OS Error {})",
                            raw_os_err
                        )));
                    }
                    // If ENOSYS or other failure, fall through to strict handle walking below
                }
            }
        }

        // Strict handle-level iterative directory component walking with O_NOFOLLOW
        let mut cur_fd = root_fd;
        let mut held_guards: Vec<FdGuard> = Vec::new();

        for dir_comp in &comps[..comps.len() - 1] {
            let comp_c = CString::new(dir_comp.as_bytes()).map_err(|e| {
                OctopusSecurityError::IsolationViolation(format!(
                    "CONFINED_OPEN_COMP_CSTRING: {}",
                    e
                ))
            })?;

            let next_fd = unsafe {
                libc::openat(
                    cur_fd,
                    comp_c.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if next_fd < 0 {
                let err = std::io::Error::last_os_error();
                return Err(OctopusSecurityError::IsolationViolation(format!(
                    "CONFINED_OPEN_DIR_FAILED: component {:?} failed openat (OS Error {})",
                    dir_comp, err
                )));
            }
            held_guards.push(FdGuard(next_fd));
            cur_fd = next_fd;
        }

        let leaf_comp = comps.last().unwrap();
        let leaf_c = CString::new(leaf_comp.as_bytes()).map_err(|e| {
            OctopusSecurityError::IsolationViolation(format!("CONFINED_OPEN_LEAF_CSTRING: {}", e))
        })?;

        let leaf_flags = if write {
            libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC
        } else {
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC
        };

        let leaf_fd = unsafe { libc::openat(cur_fd, leaf_c.as_ptr(), leaf_flags, 0o644) };
        if leaf_fd < 0 {
            let err = std::io::Error::last_os_error();
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "CONFINED_OPEN_LEAF_FAILED: {:?} failed openat (OS Error {})",
                leaf_comp, err
            )));
        }

        let leaf_file = unsafe { std::fs::File::from_raw_fd(leaf_fd) };
        let fmeta = leaf_file.metadata().map_err(|e| {
            OctopusSecurityError::IsolationViolation(format!("CONFINED_OPEN_META_FAILED: {}", e))
        })?;
        if fmeta.file_type().is_symlink() {
            return Err(OctopusSecurityError::IsolationViolation(
                "CONFINED_OPEN_SYMLINK_FILE_BLOCKED".to_string(),
            ));
        }
        if fmeta.nlink() > 1 {
            return Err(OctopusSecurityError::IsolationViolation(
                "CONFINED_OPEN_HARDLINK_BLOCKED".to_string(),
            ));
        }

        let mut verify_path = canonical_root.clone();
        for comp in &comps {
            verify_path.push(comp);
        }
        if let Ok(canon_leaf) = std::fs::canonicalize(&verify_path) {
            if !canon_leaf.starts_with(&canonical_root) || canon_leaf == canonical_root {
                return Err(OctopusSecurityError::IsolationViolation(
                    "CONFINED_OPEN_ESCAPE_DETECTED".to_string(),
                ));
            }
        }

        if write {
            let _ = leaf_file.set_len(0);
        }

        Ok(leaf_file)
    }

    pub fn create_confined_dir_all_unix(
        sandbox_root: &Path,
        relative_input: &str,
    ) -> Result<(), OctopusSecurityError> {
        let root_meta = std::fs::symlink_metadata(sandbox_root).map_err(|e| {
            OctopusSecurityError::IsolationViolation(format!("CONFINED_DIR_ROOT_FAILED: {}", e))
        })?;
        if root_meta.file_type().is_symlink() || !root_meta.is_dir() {
            return Err(OctopusSecurityError::IsolationViolation(
                "CONFINED_DIR_ROOT_INVALID: Sandbox root must be a directory".to_string(),
            ));
        }
        let canonical_root = std::fs::canonicalize(sandbox_root).map_err(|e| {
            OctopusSecurityError::IsolationViolation(format!("CONFINED_DIR_CANON_FAILED: {}", e))
        })?;

        let mut cursor = canonical_root.clone();
        for comp in Path::new(relative_input.trim()).components() {
            if let Component::Normal(seg) = comp {
                cursor.push(seg);
                if !cursor.exists() {
                    std::fs::create_dir(&cursor).map_err(|e| {
                        OctopusSecurityError::IsolationViolation(format!(
                            "CONFINED_DIR_CREATE_FAILED: {}",
                            e
                        ))
                    })?;
                }
                let meta = std::fs::symlink_metadata(&cursor).map_err(|e| {
                    OctopusSecurityError::IsolationViolation(format!(
                        "CONFINED_DIR_META_FAILED: {}",
                        e
                    ))
                })?;
                if meta.file_type().is_symlink() {
                    return Err(OctopusSecurityError::IsolationViolation(
                        "CONFINED_DIR_SYMLINK_BLOCKED".to_string(),
                    ));
                }
                let canon = std::fs::canonicalize(&cursor).map_err(|e| {
                    OctopusSecurityError::IsolationViolation(format!(
                        "CONFINED_DIR_CANON_FAILED: {}",
                        e
                    ))
                })?;
                if !canon.starts_with(&canonical_root) {
                    return Err(OctopusSecurityError::IsolationViolation(
                        "CONFINED_DIR_ESCAPE_DETECTED".to_string(),
                    ));
                }
            }
        }
        Ok(())
    }
}
