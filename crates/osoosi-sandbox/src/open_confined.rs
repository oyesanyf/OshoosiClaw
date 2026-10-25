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
}

#[cfg(not(windows))]
mod unix_confined {
    use osoosi_types::OctopusSecurityError;
    use std::os::unix::fs::MetadataExt;
    use std::path::{Component, Path};

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

        let mut cursor = canonical_root.clone();
        let comps: Vec<_> = Path::new(relative_input.trim())
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

        for dir_comp in &comps[..comps.len() - 1] {
            cursor.push(dir_comp);
            let m = std::fs::symlink_metadata(&cursor).map_err(|e| {
                OctopusSecurityError::IsolationViolation(format!("CONFINED_OPEN_DIR_FAILED: {}", e))
            })?;
            if m.file_type().is_symlink() || !m.is_dir() {
                return Err(OctopusSecurityError::IsolationViolation(
                    "CONFINED_OPEN_SYMLINK_DIR_BLOCKED".to_string(),
                ));
            }
        }

        let leaf_comp = comps.last().ok_or_else(|| {
            OctopusSecurityError::IsolationViolation(
                "CONFINED_OPEN_EMPTY_COMPONENTS: Missing leaf path component".to_string(),
            )
        })?;
        cursor.push(leaf_comp);
        if let Ok(m) = std::fs::symlink_metadata(&cursor) {
            if m.file_type().is_symlink() {
                return Err(OctopusSecurityError::IsolationViolation(
                    "CONFINED_OPEN_SYMLINK_FILE_BLOCKED".to_string(),
                ));
            }
        }
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(write)
            .create(write)
            .open(&cursor)
            .map_err(|e| {
                OctopusSecurityError::IsolationViolation(format!("CONFINED_OPEN_FAILED: {}", e))
            })?;
        let fmeta = file.metadata().map_err(|e| {
            OctopusSecurityError::IsolationViolation(format!("CONFINED_OPEN_META_FAILED: {}", e))
        })?;
        if fmeta.nlink() > 1 {
            return Err(OctopusSecurityError::IsolationViolation(
                "CONFINED_OPEN_HARDLINK_BLOCKED".to_string(),
            ));
        }
        let canonical_leaf = std::fs::canonicalize(&cursor).map_err(|e| {
            OctopusSecurityError::IsolationViolation(format!("CONFINED_OPEN_CANON_LEAF: {}", e))
        })?;
        if !canonical_leaf.starts_with(&canonical_root) || canonical_leaf == canonical_root {
            return Err(OctopusSecurityError::IsolationViolation(
                "CONFINED_OPEN_ESCAPE_DETECTED".to_string(),
            ));
        }
        if write {
            file.set_len(0).map_err(|e| {
                OctopusSecurityError::IsolationViolation(format!(
                    "CONFINED_OPEN_TRUNCATE_FAILED: Failed to truncate leaf file: {}",
                    e
                ))
            })?;
        }
        Ok(file)
    }
}
