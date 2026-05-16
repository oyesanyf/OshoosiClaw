use windows::Win32::Foundation::{HANDLE, CloseHandle};
use windows::Win32::Security::{
    GetTokenInformation, TokenIntegrityLevel, TokenPrivileges, TokenIsAppContainer,
    TOKEN_QUERY, TOKEN_ELEVATION, TokenElevation,
    TOKEN_MANDATORY_LABEL, TOKEN_PRIVILEGES, SE_PRIVILEGE_ENABLED,
};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, OpenProcessToken};


pub struct SandboxSurfaceInfo {
    pub integrity_level: String,
    pub is_app_container: bool,
    pub is_elevated: bool,
    pub privileges: Vec<String>,
}

pub fn analyze_process_sandbox(pid: u32) -> anyhow::Result<SandboxSurfaceInfo> {
    unsafe {
        let process_handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)?;
        if process_handle.is_invalid() {
            return Err(anyhow::anyhow!("Failed to open process {}", pid));
        }

        let mut token_handle = HANDLE::default();
        if OpenProcessToken(process_handle, TOKEN_QUERY, &mut token_handle).is_err() {
            let _ = CloseHandle(process_handle);
            return Err(anyhow::anyhow!("Failed to open token for process {}", pid));
        }

        // 1. AppContainer Check
        let mut is_app_container: u32 = 0;
        let mut return_len: u32 = 0;
        let _ = GetTokenInformation(
            token_handle,
            TokenIsAppContainer,
            Some(&mut is_app_container as *mut _ as *mut _),
            std::mem::size_of::<u32>() as u32,
            &mut return_len,
        );

        // 2. Elevation Check
        let mut elevation: TOKEN_ELEVATION = std::mem::zeroed();
        let _ = GetTokenInformation(
            token_handle,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut return_len,
        );

        // 3. Integrity Level
        let mut integrity_info_buf = [0u8; 128];
        let mut integrity_level = "Medium".to_string();
        if GetTokenInformation(
            token_handle,
            TokenIntegrityLevel,
            Some(integrity_info_buf.as_mut_ptr() as *mut _),
            128,
            &mut return_len,
        ).is_ok() {
            let label = &*(integrity_info_buf.as_ptr() as *const TOKEN_MANDATORY_LABEL);
            let sid = label.Label.Sid;
            // Get the RID (last subauthority)
            let count = *windows::Win32::Security::GetSidSubAuthorityCount(sid);
            if count > 0 {
                let rid = *windows::Win32::Security::GetSidSubAuthority(sid, (count - 1) as u32);
                integrity_level = match rid {
                    0x0000..0x2000 => "Low".to_string(),
                    0x2000..0x3000 => "Medium".to_string(),
                    0x3000..0x4000 => "High".to_string(),
                    0x4000.. => "System".to_string(),
                };
            }
        }

        // 4. Privileges
        let mut privileges = Vec::new();
        let mut priv_buf = [0u8; 2048];
        if GetTokenInformation(
            token_handle,
            TokenPrivileges,
            Some(priv_buf.as_mut_ptr() as *mut _),
            2048,
            &mut return_len,
        ).is_ok() {
            let token_privs = &*(priv_buf.as_ptr() as *const TOKEN_PRIVILEGES);
            for i in 0..token_privs.PrivilegeCount {
                let luid_and_attrs = token_privs.Privileges[i as usize];
                if (luid_and_attrs.Attributes.0 & SE_PRIVILEGE_ENABLED.0) != 0 {
                    // In a real port, we'd use LookupPrivilegeNameW
                    // For detection, we'll flag high-risk LUIDs
                    let risk = match luid_and_attrs.Luid.LowPart {
                        20 => "SeDebugPrivilege",
                        29 => "SeImpersonatePrivilege",
                        7 => "SeTcbPrivilege",
                        30 => "SeCreateGlobalPrivilege",
                        _ => "Other",
                    };
                    if risk != "Other" {
                        privileges.push(risk.to_string());
                    }
                }
            }
        }

        let _ = CloseHandle(token_handle);
        let _ = CloseHandle(process_handle);

        Ok(SandboxSurfaceInfo {
            integrity_level,
            is_app_container: is_app_container != 0,
            is_elevated: elevation.TokenIsElevated != 0,
            privileges,
        })
    }
}
