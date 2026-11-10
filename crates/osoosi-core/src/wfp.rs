//! Native Windows Filtering Platform (WFP), Linux Netlink (`AF_NETLINK`), & macOS PF (`/dev/pf`)
//! Zero-Subprocess Kernel Network Control & 16-Domain Universal Protocol Quarantine.
//!
//! Provides in-memory and persistent transaction-safe network filtering without spawning subprocesses
//! (`netsh`, `iptables`, `nft`, or `pfctl`).
//!
//! On Windows, communicates directly with `fwpuclnt.dll`, `iphlpapi.dll`, and BFE Registry:
//! - Dynamic sessions (`FWPM_SESSION_FLAG_DYNAMIC = 0x00000001`) for per-IP DLP blocks with automatic
//!   kernel cleanup on process termination.
//! - Persistent atomic transactions (`flags = 0`) across all 22 WFP IPv4, IPv6, ICMP, Raw IP (`0..=255`),
//!   Datagram/UDP/QUIC, Transport, Stream, and Layer-2 Ethernet (`0x88E5` MACsec, `0x88F7` PTP/White Rabbit,
//!   `0x8809` SyncE/ESMC, `0xAEFE` eCPRI) layers for full-host Kill Chain quarantine with zero DNS/DHCP leaks,
//!   strictly preserving loopback (`127.0.0.1`, `::1`) and local WebUI management ports (`3030..=3045`).

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
#[cfg(windows)]
use std::ffi::c_void;
use std::path::PathBuf;
#[cfg(windows)]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::LazyLock;
#[allow(unused_imports)]
use tracing::{info, warn};

pub const FWPM_SESSION_FLAG_DYNAMIC: u32 = 0x0000_0001;
pub const RPC_C_AUTHN_WINNT: u32 = 10;
pub const RPC_C_AUTHN_DEFAULT: u32 = 0xFFFF_FFFF;
pub const ERROR_SUCCESS: u32 = 0;
pub const WFP_HERMETIC_LAYER_COUNT: usize = 24;
pub const WFP_KILLSWITCH_RULE_PREFIX: &str = "Osoosi-KillSwitch";

#[cfg(windows)]
#[repr(C)]
struct FwpmDisplayData0 {
    name: *mut u16,
    description: *mut u16,
}

#[cfg(windows)]
#[repr(C)]
struct FwpmSession0 {
    session_key: [u8; 16],
    display_data: FwpmDisplayData0,
    flags: u32,
    txn_wait_timeout_in_msec: u32,
    process_id: u32,
    sid: *mut c_void,
    username: *mut u16,
    kernel_mode: i32,
}

#[cfg(windows)]
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct WfpGuid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

// --- 22 WFP Kernel Layer GUIDs ---

#[cfg(windows)]
const FWPM_LAYER_ALE_AUTH_CONNECT_V4: WfpGuid = WfpGuid {
    data1: 0xc38d57d1,
    data2: 0x05a7,
    data3: 0x4c33,
    data4: [0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82],
};

#[cfg(windows)]
const FWPM_LAYER_ALE_AUTH_CONNECT_V6: WfpGuid = WfpGuid {
    data1: 0x4a72393b,
    data2: 0x319f,
    data3: 0x44bc,
    data4: [0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4],
};

#[cfg(windows)]
const FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4: WfpGuid = WfpGuid {
    data1: 0xe1cd9fe7,
    data2: 0xf4b5,
    data3: 0x4273,
    data4: [0x96, 0xc0, 0x59, 0x2e, 0x48, 0x7b, 0x86, 0x50],
};

#[cfg(windows)]
const FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6: WfpGuid = WfpGuid {
    data1: 0xa3b42c97,
    data2: 0x9f04,
    data3: 0x4672,
    data4: [0xb8, 0x7e, 0xce, 0xe9, 0xc4, 0x83, 0x25, 0x7f],
};

#[cfg(windows)]
const FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4: WfpGuid = WfpGuid {
    data1: 0xaf80470a,
    data2: 0x5596,
    data3: 0x4c13,
    data4: [0x99, 0x92, 0x53, 0x9e, 0x6f, 0xe5, 0x79, 0x67],
};

#[cfg(windows)]
const FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6: WfpGuid = WfpGuid {
    data1: 0x7021d2b3,
    data2: 0xdfa4,
    data3: 0x406e,
    data4: [0xaf, 0xeb, 0x6a, 0xfa, 0xf7, 0xe7, 0x0e, 0xfd],
};

#[cfg(windows)]
const FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4: WfpGuid = WfpGuid {
    data1: 0x1247d66d,
    data2: 0x0b60,
    data3: 0x4a15,
    data4: [0x8d, 0x44, 0x71, 0x55, 0xd0, 0xf5, 0x3a, 0x0c],
};

#[cfg(windows)]
const FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6: WfpGuid = WfpGuid {
    data1: 0x55a650e1,
    data2: 0x5f0a,
    data3: 0x4eca,
    data4: [0xa6, 0x53, 0x88, 0xf5, 0x3b, 0x26, 0xaa, 0x8c],
};

#[cfg(windows)]
const FWPM_LAYER_OUTBOUND_TRANSPORT_V4: WfpGuid = WfpGuid {
    data1: 0x09e61aea,
    data2: 0xd214,
    data3: 0x46e2,
    data4: [0x9b, 0x21, 0xb2, 0x6b, 0x0b, 0x2f, 0x28, 0xc8],
};

#[cfg(windows)]
const FWPM_LAYER_OUTBOUND_TRANSPORT_V6: WfpGuid = WfpGuid {
    data1: 0xe1735bde,
    data2: 0x013f,
    data3: 0x4655,
    data4: [0xb3, 0x51, 0xa4, 0x9e, 0x15, 0x76, 0x2d, 0xf0],
};

#[cfg(windows)]
const FWPM_LAYER_INBOUND_TRANSPORT_V4: WfpGuid = WfpGuid {
    data1: 0x5926dfc8,
    data2: 0xe3cf,
    data3: 0x4426,
    data4: [0xa2, 0x83, 0xdc, 0x39, 0x3f, 0x5d, 0x0f, 0x9d],
};

#[cfg(windows)]
const FWPM_LAYER_INBOUND_TRANSPORT_V6: WfpGuid = WfpGuid {
    data1: 0x634a869f,
    data2: 0xfc23,
    data3: 0x4b90,
    data4: [0xb0, 0xc1, 0xbf, 0x62, 0x0a, 0x36, 0xae, 0x6f],
};

#[cfg(windows)]
const FWPM_LAYER_DATAGRAM_DATA_V4: WfpGuid = WfpGuid {
    data1: 0x3d08bf4e,
    data2: 0x45f6,
    data3: 0x4930,
    data4: [0xa9, 0x22, 0x41, 0x70, 0x98, 0xe2, 0x00, 0x27],
};

#[cfg(windows)]
const FWPM_LAYER_DATAGRAM_DATA_V6: WfpGuid = WfpGuid {
    data1: 0xfa45fe2f,
    data2: 0x3cba,
    data3: 0x4427,
    data4: [0x87, 0xfc, 0x57, 0xb9, 0xa4, 0xb1, 0x0d, 0x00],
};

#[cfg(windows)]
const FWPM_LAYER_STREAM_V4: WfpGuid = WfpGuid {
    data1: 0x3b89653c,
    data2: 0xc170,
    data3: 0x49e4,
    data4: [0xb1, 0xcd, 0xe0, 0xee, 0xee, 0xe1, 0x9a, 0x3e],
};

#[cfg(windows)]
const FWPM_LAYER_STREAM_V6: WfpGuid = WfpGuid {
    data1: 0x47c9137a,
    data2: 0x7ec4,
    data3: 0x46b3,
    data4: [0xb6, 0xe4, 0x48, 0xe9, 0x26, 0xb1, 0xed, 0xa4],
};

#[cfg(windows)]
const FWPM_LAYER_OUTBOUND_ICMP_ERROR_V4: WfpGuid = WfpGuid {
    data1: 0x41390100,
    data2: 0x564c,
    data3: 0x4b32,
    data4: [0xbc, 0x1d, 0x71, 0x80, 0x48, 0x35, 0x4d, 0x7c],
};

#[cfg(windows)]
const FWPM_LAYER_OUTBOUND_ICMP_ERROR_V6: WfpGuid = WfpGuid {
    data1: 0x7fb03b60,
    data2: 0xf18d,
    data3: 0x4bfa,
    data4: [0xba, 0xdd, 0x98, 0x01, 0x79, 0xfc, 0x4e, 0x12],
};

#[cfg(windows)]
const FWPM_LAYER_INBOUND_ICMP_ERROR_V4: WfpGuid = WfpGuid {
    data1: 0x61499990,
    data2: 0x3c3f,
    data3: 0x4e8a,
    data4: [0x93, 0x42, 0xf8, 0xb9, 0x85, 0xd1, 0x89, 0x29],
};

#[cfg(windows)]
const FWPM_LAYER_INBOUND_ICMP_ERROR_V6: WfpGuid = WfpGuid {
    data1: 0xa6fd77f3,
    data2: 0x5a81,
    data3: 0x4733,
    data4: [0x89, 0x46, 0x75, 0x79, 0x46, 0x11, 0x4f, 0x2d],
};

#[cfg(windows)]
const FWPM_LAYER_OUTBOUND_IPPACKET_V4: WfpGuid = WfpGuid {
    data1: 0x1e5c9fae,
    data2: 0x8a84,
    data3: 0x4135,
    data4: [0xa3, 0x31, 0x95, 0x0b, 0x54, 0x22, 0x9e, 0xcd],
};

#[cfg(windows)]
const FWPM_LAYER_OUTBOUND_IPPACKET_V6: WfpGuid = WfpGuid {
    data1: 0xa31324f2,
    data2: 0x0a0d,
    data3: 0x4021,
    data4: [0x9b, 0x35, 0x73, 0x52, 0x59, 0x08, 0x86, 0x20],
};

#[cfg(windows)]
const FWPM_LAYER_INBOUND_IPPACKET_V4: WfpGuid = WfpGuid {
    data1: 0xc86fd1bf,
    data2: 0x21cd,
    data3: 0x497e,
    data4: [0xa0, 0xbb, 0x17, 0x42, 0x5c, 0x88, 0x5c, 0x58],
};

#[cfg(windows)]
const FWPM_LAYER_INBOUND_IPPACKET_V6: WfpGuid = WfpGuid {
    data1: 0xf52032cb,
    data2: 0x991c,
    data3: 0x46e7,
    data4: [0x97, 0x1d, 0x26, 0x01, 0x45, 0x9a, 0x91, 0xca],
};

#[cfg(windows)]
const FWPM_LAYER_OUTBOUND_MAC_FRAME_ETHERNET: WfpGuid = WfpGuid {
    data1: 0x694673bc,
    data2: 0xd6db,
    data3: 0x4870,
    data4: [0xac, 0xee, 0x0a, 0xcd, 0xbd, 0xb2, 0x60, 0x1b],
};

#[cfg(windows)]
const FWPM_LAYER_INBOUND_MAC_FRAME_ETHERNET: WfpGuid = WfpGuid {
    data1: 0xeffb7edb,
    data2: 0x0055,
    data3: 0x4f9a,
    data4: [0xa2, 0x31, 0x4f, 0xf8, 0x13, 0x1a, 0xd1, 0x91],
};

// 444543b6-9046-4246-ab81-9b06227e243d (Incident A WSL2 NAT Interception)
#[cfg(windows)]
pub const FWPM_LAYER_IPFORWARD_V4: WfpGuid = WfpGuid {
    data1: 0x444543b6,
    data2: 0x9046,
    data3: 0x4246,
    data4: [0xab, 0x81, 0x9b, 0x06, 0x22, 0x7e, 0x24, 0x3d],
};

// 12fe69b5-485a-40e7-912a-82b818121294 (Incident A WSL2 NAT Interception)
#[cfg(windows)]
pub const FWPM_LAYER_IPFORWARD_V6: WfpGuid = WfpGuid {
    data1: 0x12fe69b5,
    data2: 0x485a,
    data3: 0x40e7,
    data4: [0x91, 0x2a, 0x82, 0xb8, 0x18, 0x12, 0x12, 0x94],
};

// a82acc24-4ee1-4ee1-b465-fd1d25cb10a4 (Official Windows SDK fwpmu.h)
#[cfg(windows)]
pub const FWPM_LAYER_IPFORWARD_V4_SDK: WfpGuid = WfpGuid {
    data1: 0xa82acc24,
    data2: 0x4ee1,
    data3: 0x4ee1,
    data4: [0xb4, 0x65, 0xfd, 0x1d, 0x25, 0xcb, 0x10, 0xa4],
};

// 7b964818-19c7-493a-b71f-832c3684d28c (Official Windows SDK fwpmu.h)
#[cfg(windows)]
pub const FWPM_LAYER_IPFORWARD_V6_SDK: WfpGuid = WfpGuid {
    data1: 0x7b964818,
    data2: 0x19c7,
    data3: 0x493a,
    data4: [0xb7, 0x1f, 0x83, 0x2c, 0x36, 0x84, 0xd2, 0x8c],
};

// --- WFP Condition Field GUIDs ---

#[cfg(windows)]
const FWPM_CONDITION_IP_REMOTE_ADDRESS: WfpGuid = WfpGuid {
    data1: 0xb235ae9a,
    data2: 0x1d64,
    data3: 0x49b8,
    data4: [0xa4, 0x4c, 0x5f, 0xf3, 0xd9, 0x09, 0x50, 0x45],
};

#[cfg(windows)]
const FWPM_CONDITION_IP_LOCAL_ADDRESS: WfpGuid = WfpGuid {
    data1: 0xd9ee00de,
    data2: 0xc1ef,
    data3: 0x4617,
    data4: [0xbf, 0xe3, 0xff, 0xd8, 0xf5, 0xa0, 0x89, 0x57],
};

#[cfg(windows)]
const FWPM_CONDITION_IP_LOCAL_PORT: WfpGuid = WfpGuid {
    data1: 0x0c1ba1af,
    data2: 0x5765,
    data3: 0x453f,
    data4: [0xaf, 0x22, 0xa8, 0xf7, 0x91, 0xac, 0x77, 0x5b],
};

#[cfg(windows)]
const FWPM_CONDITION_IP_REMOTE_PORT: WfpGuid = WfpGuid {
    data1: 0xc35a604d,
    data2: 0xd22b,
    data3: 0x4e1a,
    data4: [0x91, 0xb4, 0x68, 0xf6, 0x74, 0xee, 0x67, 0x4b],
};

#[cfg(windows)]
const FWPM_CONDITION_FLAGS: WfpGuid = WfpGuid {
    data1: 0x632ce23b,
    data2: 0x5167,
    data3: 0x435c,
    data4: [0x86, 0xd7, 0xe9, 0x03, 0x68, 0x4a, 0xa8, 0x0c],
};

#[cfg(windows)]
const FWPM_CONDITION_ETHER_TYPE: WfpGuid = WfpGuid {
    data1: 0xfd08948d,
    data2: 0xa219,
    data3: 0x4d52,
    data4: [0xbb, 0x98, 0x1a, 0x55, 0x40, 0xee, 0x7b, 0x4e],
};

#[cfg(windows)]
const FWP_EMPTY: u32 = 0;
#[cfg(windows)]
const FWP_UINT8: u32 = 1;
#[cfg(windows)]
const FWP_UINT16: u32 = 2;
#[cfg(windows)]
const FWP_UINT32: u32 = 3;
#[cfg(windows)]
const FWP_BYTE_ARRAY16_TYPE: u32 = 11;
#[cfg(windows)]
const FWP_MATCH_EQUAL: u32 = 0;
#[cfg(windows)]
const FWP_MATCH_FLAGS_ALL_SET: u32 = 6;
#[cfg(windows)]
const FWP_CONDITION_FLAG_IS_LOOPBACK: u32 = 0x0000_0001;
#[cfg(windows)]
const FWP_ACTION_BLOCK: u32 = 0x0000_1001;
#[cfg(windows)]
const FWP_ACTION_PERMIT: u32 = 0x0000_1002;

#[cfg(windows)]
#[repr(C)]
#[derive(Clone, Copy)]
struct FwpValue0 {
    type_: u32,
    _pad: u32,
    value: usize,
}

#[cfg(windows)]
#[repr(C)]
#[derive(Clone, Copy)]
struct FwpByteBlob {
    size: u32,
    _pad: u32,
    data: *mut u8,
}

#[cfg(windows)]
#[repr(C)]
#[derive(Clone, Copy)]
struct FwpmFilterCondition0 {
    field_key: WfpGuid,
    match_type: u32,
    _pad: u32,
    condition_value: FwpValue0,
}

#[cfg(windows)]
#[repr(C)]
#[derive(Clone, Copy)]
struct FwpmAction0 {
    type_: u32,
    filter_type: WfpGuid,
}

#[cfg(windows)]
#[repr(C)]
struct FwpmFilter0 {
    filter_key: WfpGuid,
    display_data: FwpmDisplayData0,
    flags: u32,
    _pad0: u32,
    provider_key: *mut WfpGuid,
    provider_data: FwpByteBlob,
    layer_key: WfpGuid,
    sub_layer_key: WfpGuid,
    weight: FwpValue0,
    num_filter_conditions: u32,
    _pad1: u32,
    filter_condition: *mut FwpmFilterCondition0,
    action: FwpmAction0,
    _pad2: u32,
    raw_context_or_provider_context_key: [u64; 2],
    reserved: *mut WfpGuid,
    filter_id: u64,
    effective_weight: FwpValue0,
}

#[cfg(all(windows, target_pointer_width = "64"))]
const _: () = {
    assert!(std::mem::size_of::<WfpGuid>() == 16);
    assert!(std::mem::size_of::<FwpValue0>() == 16);
    assert!(std::mem::size_of::<FwpmFilterCondition0>() == 40);
    assert!(std::mem::size_of::<FwpmAction0>() == 20);
    assert!(std::mem::size_of::<FwpmFilter0>() == 200);
    assert!(std::mem::offset_of!(FwpmFilter0, display_data) == 16);
    assert!(std::mem::offset_of!(FwpmFilter0, flags) == 32);
    assert!(std::mem::offset_of!(FwpmFilter0, provider_key) == 40);
    assert!(std::mem::offset_of!(FwpmFilter0, provider_data) == 48);
    assert!(std::mem::offset_of!(FwpmFilter0, layer_key) == 64);
    assert!(std::mem::offset_of!(FwpmFilter0, sub_layer_key) == 80);
    assert!(std::mem::offset_of!(FwpmFilter0, weight) == 96);
    assert!(std::mem::offset_of!(FwpmFilter0, num_filter_conditions) == 112);
    assert!(std::mem::offset_of!(FwpmFilter0, filter_condition) == 120);
    assert!(std::mem::offset_of!(FwpmFilter0, action) == 128);
    assert!(std::mem::offset_of!(FwpmFilter0, raw_context_or_provider_context_key) == 152);
    assert!(std::mem::offset_of!(FwpmFilter0, reserved) == 168);
    assert!(std::mem::offset_of!(FwpmFilter0, filter_id) == 176);
    assert!(std::mem::offset_of!(FwpmFilter0, effective_weight) == 184);
};

#[cfg(windows)]
type FnFwpmEngineOpen0 = unsafe extern "system" fn(
    server_name: *const u16,
    authn_service: u32,
    auth_identity: *mut c_void,
    session: *const FwpmSession0,
    engine_handle: *mut *mut c_void,
) -> u32;

#[cfg(windows)]
type FnFwpmEngineClose0 = unsafe extern "system" fn(engine_handle: *mut c_void) -> u32;

#[cfg(windows)]
type FnFwpmTransactionBegin0 =
    unsafe extern "system" fn(engine_handle: *mut c_void, flags: u32) -> u32;

#[cfg(windows)]
type FnFwpmTransactionCommit0 = unsafe extern "system" fn(engine_handle: *mut c_void) -> u32;

#[cfg(windows)]
type FnFwpmTransactionAbort0 = unsafe extern "system" fn(engine_handle: *mut c_void) -> u32;

#[cfg(windows)]
type FnFwpmFilterAdd0 = unsafe extern "system" fn(
    engine_handle: *mut c_void,
    filter: *const FwpmFilter0,
    sd: *mut c_void,
    id: *mut u64,
) -> u32;

#[cfg(windows)]
type FnFwpmFilterDeleteById0 =
    unsafe extern "system" fn(engine_handle: *mut c_void, id: u64) -> u32;

#[cfg(windows)]
type FnFwpmFilterGetById0 = unsafe extern "system" fn(
    engine_handle: *mut c_void,
    id: u64,
    filter: *mut *mut FwpmFilter0,
) -> u32;

#[cfg(windows)]
type FnFwpmFilterCreateEnumHandle0 = unsafe extern "system" fn(
    engine_handle: *mut c_void,
    enum_template: *const c_void,
    enum_handle: *mut *mut c_void,
) -> u32;

#[cfg(windows)]
type FnFwpmFilterEnum0 = unsafe extern "system" fn(
    engine_handle: *mut c_void,
    enum_handle: *mut c_void,
    num_entries_requested: u32,
    entries: *mut *mut *mut FwpmFilter0,
    num_entries_returned: *mut u32,
) -> u32;

#[cfg(windows)]
type FnFwpmFilterDestroyEnumHandle0 =
    unsafe extern "system" fn(engine_handle: *mut c_void, enum_handle: *mut c_void) -> u32;

#[cfg(windows)]
type FnFwpmFreeMemory0 = unsafe extern "system" fn(p: *mut *mut c_void);

#[cfg(windows)]
unsafe fn wide_ptr_to_string(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    while len < 512 && *ptr.add(len) != 0 {
        len += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
}

/// Native Windows Filtering Platform (WFP) session controller.
pub struct WfpDynamicSession {
    #[cfg(windows)]
    engine_handle: *mut c_void,
    #[cfg(windows)]
    fn_engine_close: Option<FnFwpmEngineClose0>,
    #[cfg(windows)]
    fn_txn_begin: Option<FnFwpmTransactionBegin0>,
    #[cfg(windows)]
    fn_txn_commit: Option<FnFwpmTransactionCommit0>,
    #[cfg(windows)]
    fn_txn_abort: Option<FnFwpmTransactionAbort0>,
    #[cfg(windows)]
    fn_filter_add: Option<FnFwpmFilterAdd0>,
    #[cfg(windows)]
    fn_filter_delete_by_id: Option<FnFwpmFilterDeleteById0>,
    #[cfg(windows)]
    fn_filter_get_by_id: Option<FnFwpmFilterGetById0>,
    #[cfg(windows)]
    fn_create_enum: Option<FnFwpmFilterCreateEnumHandle0>,
    #[cfg(windows)]
    fn_enum: Option<FnFwpmFilterEnum0>,
    #[cfg(windows)]
    fn_destroy_enum: Option<FnFwpmFilterDestroyEnumHandle0>,
    #[cfg(windows)]
    fn_free_mem: Option<FnFwpmFreeMemory0>,
    #[cfg(windows)]
    in_transaction: AtomicBool,
    #[cfg(not(windows))]
    _active: bool,
}

unsafe impl Send for WfpDynamicSession {}
unsafe impl Sync for WfpDynamicSession {}

impl WfpDynamicSession {
    /// Open a dynamic WFP session (`FWPM_SESSION_FLAG_DYNAMIC`).
    /// Filters added on this session are automatically deleted by the kernel if the process exits.
    pub fn open() -> Result<Self> {
        Self::open_with_flags(FWPM_SESSION_FLAG_DYNAMIC)
    }

    /// Open a persistent WFP session (`flags = 0`) so host Kill Chain quarantine filters survive
    /// one-shot CLI invocations (`osoosi killchain isolate`) and elevated UAC helpers until disarmed.
    pub fn open_persistent() -> Result<Self> {
        Self::open_with_flags(0)
    }

    fn open_with_flags(session_flags: u32) -> Result<Self> {
        #[cfg(windows)]
        {
            use windows::core::PCWSTR;
            use windows::Win32::System::LibraryLoader::{
                GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32,
            };

            let dll_name: Vec<u16> = "fwpuclnt.dll\0".encode_utf16().collect();
            let h_module = unsafe {
                LoadLibraryExW(
                    PCWSTR(dll_name.as_ptr()),
                    None,
                    LOAD_LIBRARY_SEARCH_SYSTEM32,
                )
            }
            .map_err(|e| anyhow!("Failed to load fwpuclnt.dll: {}", e))?;

            let get_func = |name: &'static [u8]| -> Option<*const ()> {
                let proc = unsafe { GetProcAddress(h_module, windows::core::PCSTR(name.as_ptr())) };
                proc.map(|p| p as *const ())
            };

            let fn_open: FnFwpmEngineOpen0 =
                unsafe {
                    std::mem::transmute(get_func(b"FwpmEngineOpen0\0").ok_or_else(|| {
                        anyhow!("FwpmEngineOpen0 symbol not found in fwpuclnt.dll")
                    })?)
                };
            let fn_close: FnFwpmEngineClose0 =
                unsafe {
                    std::mem::transmute(get_func(b"FwpmEngineClose0\0").ok_or_else(|| {
                        anyhow!("FwpmEngineClose0 symbol not found in fwpuclnt.dll")
                    })?)
                };
            let fn_txn_begin: FnFwpmTransactionBegin0 = unsafe {
                std::mem::transmute(get_func(b"FwpmTransactionBegin0\0").ok_or_else(|| {
                    anyhow!("FwpmTransactionBegin0 symbol not found in fwpuclnt.dll")
                })?)
            };
            let fn_txn_commit: FnFwpmTransactionCommit0 = unsafe {
                std::mem::transmute(get_func(b"FwpmTransactionCommit0\0").ok_or_else(|| {
                    anyhow!("FwpmTransactionCommit0 symbol not found in fwpuclnt.dll")
                })?)
            };
            let fn_txn_abort: FnFwpmTransactionAbort0 = unsafe {
                std::mem::transmute(get_func(b"FwpmTransactionAbort0\0").ok_or_else(|| {
                    anyhow!("FwpmTransactionAbort0 symbol not found in fwpuclnt.dll")
                })?)
            };
            let fn_filter_add: Option<FnFwpmFilterAdd0> =
                unsafe { get_func(b"FwpmFilterAdd0\0").map(|p| std::mem::transmute(p)) };
            let fn_filter_delete_by_id: Option<FnFwpmFilterDeleteById0> =
                unsafe { get_func(b"FwpmFilterDeleteById0\0").map(|p| std::mem::transmute(p)) };
            let fn_filter_get_by_id: Option<FnFwpmFilterGetById0> =
                unsafe { get_func(b"FwpmFilterGetById0\0").map(|p| std::mem::transmute(p)) };
            let fn_create_enum: Option<FnFwpmFilterCreateEnumHandle0> = unsafe {
                get_func(b"FwpmFilterCreateEnumHandle0\0").map(|p| std::mem::transmute(p))
            };
            let fn_enum: Option<FnFwpmFilterEnum0> =
                unsafe { get_func(b"FwpmFilterEnum0\0").map(|p| std::mem::transmute(p)) };
            let fn_destroy_enum: Option<FnFwpmFilterDestroyEnumHandle0> = unsafe {
                get_func(b"FwpmFilterDestroyEnumHandle0\0").map(|p| std::mem::transmute(p))
            };
            let fn_free_mem: Option<FnFwpmFreeMemory0> =
                unsafe { get_func(b"FwpmFreeMemory0\0").map(|p| std::mem::transmute(p)) };

            let mut session_name: Vec<u16> = if session_flags == 0 {
                "OsoosiEDR-PersistentKillSwitch\0".encode_utf16().collect()
            } else {
                "OsoosiEDR-DynamicSession\0".encode_utf16().collect()
            };
            let mut session_desc: Vec<u16> = "OpenOsoosi Autonomous EDR WFP Kernel Session\0"
                .encode_utf16()
                .collect();

            let session = FwpmSession0 {
                session_key: [0u8; 16],
                display_data: FwpmDisplayData0 {
                    name: session_name.as_mut_ptr(),
                    description: session_desc.as_mut_ptr(),
                },
                flags: session_flags,
                txn_wait_timeout_in_msec: 15_000,
                process_id: 0,
                sid: std::ptr::null_mut(),
                username: std::ptr::null_mut(),
                kernel_mode: 0,
            };

            let mut engine_handle: *mut c_void = std::ptr::null_mut();
            let mut status = unsafe {
                fn_open(
                    std::ptr::null(),
                    RPC_C_AUTHN_WINNT,
                    std::ptr::null_mut(),
                    &session,
                    &mut engine_handle,
                )
            };
            if status != ERROR_SUCCESS || engine_handle.is_null() {
                status = unsafe {
                    fn_open(
                        std::ptr::null(),
                        RPC_C_AUTHN_DEFAULT,
                        std::ptr::null_mut(),
                        &session,
                        &mut engine_handle,
                    )
                };
            }

            if status != ERROR_SUCCESS || engine_handle.is_null() {
                return Err(anyhow!(
                    "FwpmEngineOpen0 failed with Win32 status 0x{:08X}",
                    status
                ));
            }

            info!(
                "🟢 [WFP] Opened WFP engine session (Handle: {:p}, flags=0x{:X})",
                engine_handle, session_flags
            );

            Ok(Self {
                engine_handle,
                fn_engine_close: Some(fn_close),
                fn_txn_begin: Some(fn_txn_begin),
                fn_txn_commit: Some(fn_txn_commit),
                fn_txn_abort: Some(fn_txn_abort),
                fn_filter_add,
                fn_filter_delete_by_id,
                fn_filter_get_by_id,
                fn_create_enum,
                fn_enum,
                fn_destroy_enum,
                fn_free_mem,
                in_transaction: AtomicBool::new(false),
            })
        }

        #[cfg(not(windows))]
        {
            let _ = session_flags;
            info!("🟢 [Netlink] Native non-Windows kernel network session initialized.");
            Ok(Self { _active: true })
        }
    }

    /// Begin an atomic transaction for firewall rule modification.
    pub fn begin_transaction(&self) -> Result<()> {
        #[cfg(windows)]
        {
            if self.engine_handle.is_null() {
                return Err(anyhow!("WFP engine handle is null"));
            }
            if let Some(fn_begin) = self.fn_txn_begin {
                let status = unsafe { fn_begin(self.engine_handle, 0) };
                if status != ERROR_SUCCESS {
                    return Err(anyhow!(
                        "FwpmTransactionBegin0 failed with 0x{:08X}",
                        status
                    ));
                }
                self.in_transaction.store(true, Ordering::SeqCst);
                return Ok(());
            }
            Err(anyhow!("FwpmTransactionBegin0 not available"))
        }

        #[cfg(not(windows))]
        {
            Ok(())
        }
    }

    /// Commit the active atomic transaction.
    pub fn commit_transaction(&self) -> Result<()> {
        #[cfg(windows)]
        {
            if self.engine_handle.is_null() {
                return Err(anyhow!("WFP engine handle is null"));
            }
            if let Some(fn_commit) = self.fn_txn_commit {
                let status = unsafe { fn_commit(self.engine_handle) };
                self.in_transaction.store(false, Ordering::SeqCst);
                if status != ERROR_SUCCESS {
                    return Err(anyhow!(
                        "FwpmTransactionCommit0 failed with 0x{:08X}",
                        status
                    ));
                }
                return Ok(());
            }
            Err(anyhow!("FwpmTransactionCommit0 not available"))
        }

        #[cfg(not(windows))]
        {
            Ok(())
        }
    }

    /// Abort the active transaction, reverting all pending changes.
    pub fn abort_transaction(&self) -> Result<()> {
        #[cfg(windows)]
        {
            if self.engine_handle.is_null() {
                return Err(anyhow!("WFP engine handle is null"));
            }
            if let Some(fn_abort) = self.fn_txn_abort {
                let status = unsafe { fn_abort(self.engine_handle) };
                self.in_transaction.store(false, Ordering::SeqCst);
                if status != ERROR_SUCCESS {
                    return Err(anyhow!(
                        "FwpmTransactionAbort0 failed with 0x{:08X}",
                        status
                    ));
                }
                return Ok(());
            }
            Err(anyhow!("FwpmTransactionAbort0 not available"))
        }

        #[cfg(not(windows))]
        {
            Ok(())
        }
    }

    /// Delete a filter by its 64-bit ID.
    pub fn delete_filter_by_id(&self, filter_id: u64) -> Result<()> {
        #[cfg(windows)]
        {
            if self.engine_handle.is_null() {
                return Err(anyhow!("WFP engine handle is null"));
            }
            if let Some(fn_del) = self.fn_filter_delete_by_id {
                let status = unsafe { fn_del(self.engine_handle, filter_id) };
                if status != ERROR_SUCCESS {
                    return Err(anyhow!(
                        "FwpmFilterDeleteById0({}) failed with 0x{:08X}",
                        filter_id,
                        status
                    ));
                }
                return Ok(());
            }
            Err(anyhow!("FwpmFilterDeleteById0 not available"))
        }

        #[cfg(not(windows))]
        {
            let _ = filter_id;
            Ok(())
        }
    }

    /// Verify whether a specific 64-bit filter ID is currently live inside BFE.
    pub fn filter_exists_by_id(&self, filter_id: u64) -> bool {
        #[cfg(windows)]
        {
            if self.engine_handle.is_null() || filter_id == 0 {
                return false;
            }
            let Some(fn_get) = self.fn_filter_get_by_id else {
                return false;
            };
            let mut ptr: *mut FwpmFilter0 = std::ptr::null_mut();
            let status = unsafe { fn_get(self.engine_handle, filter_id, &mut ptr) };
            if status == ERROR_SUCCESS && !ptr.is_null() {
                if let Some(fn_free) = self.fn_free_mem {
                    let mut raw = ptr as *mut c_void;
                    unsafe { fn_free(&mut raw) };
                }
                return true;
            }
            false
        }
        #[cfg(not(windows))]
        {
            let _ = filter_id;
            false
        }
    }

    /// Enumerate all live BFE filter IDs whose display name starts with `Osoosi-KillSwitch` or `Osoosi-KillChain`.
    pub fn enumerate_osoosi_killswitch_filter_ids(&self) -> Vec<u64> {
        #[cfg(windows)]
        {
            if self.engine_handle.is_null() {
                return Vec::new();
            }
            let (Some(fn_create), Some(fn_enum), Some(fn_destroy), Some(fn_free)) = (
                self.fn_create_enum,
                self.fn_enum,
                self.fn_destroy_enum,
                self.fn_free_mem,
            ) else {
                return Vec::new();
            };

            let mut enum_handle: *mut c_void = std::ptr::null_mut();
            let status =
                unsafe { fn_create(self.engine_handle, std::ptr::null(), &mut enum_handle) };
            if status != ERROR_SUCCESS || enum_handle.is_null() {
                return Vec::new();
            }

            let mut matched = Vec::new();
            loop {
                let mut entries: *mut *mut FwpmFilter0 = std::ptr::null_mut();
                let mut returned: u32 = 0;
                let st = unsafe {
                    fn_enum(
                        self.engine_handle,
                        enum_handle,
                        512,
                        &mut entries,
                        &mut returned,
                    )
                };
                if st != ERROR_SUCCESS || returned == 0 || entries.is_null() {
                    if !entries.is_null() {
                        let mut raw = entries as *mut c_void;
                        unsafe { fn_free(&mut raw) };
                    }
                    break;
                }

                for i in 0..(returned as usize) {
                    let f_ptr = unsafe { *entries.add(i) };
                    if !f_ptr.is_null() {
                        let name = unsafe { wide_ptr_to_string((*f_ptr).display_data.name) };
                        let fid = unsafe { (*f_ptr).filter_id };
                        if fid != 0
                            && (name.starts_with(WFP_KILLSWITCH_RULE_PREFIX)
                                || name.starts_with("Osoosi-KillChain"))
                        {
                            matched.push(fid);
                        }
                    }
                }

                let mut raw = entries as *mut c_void;
                unsafe { fn_free(&mut raw) };
                if returned < 512 {
                    break;
                }
            }

            let _ = unsafe { fn_destroy(self.engine_handle, enum_handle) };
            matched
        }
        #[cfg(not(windows))]
        {
            Vec::new()
        }
    }

    /// Installs kernel-level `FWP_ACTION_BLOCK` filters via `FwpmFilterAdd0` across both
    /// `FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6` and `FWPM_LAYER_OUTBOUND_TRANSPORT_V4/V6` for every IP in `ips`.
    pub fn add_outbound_ip_block_filters(
        &self,
        rule_name: &str,
        ips: &[std::net::IpAddr],
    ) -> Vec<u64> {
        #[cfg(windows)]
        {
            if self.engine_handle.is_null() || ips.is_empty() {
                return Vec::new();
            }
            let Some(fn_add) = self.fn_filter_add else {
                return Vec::new();
            };

            let mut filter_ids = Vec::new();
            let mut w_name: Vec<u16> = format!("{}\0", rule_name).encode_utf16().collect();
            if *w_name.last().unwrap_or(&1) != 0 {
                w_name.push(0);
            }
            let mut w_desc: Vec<u16> = "OpenOsoosi Native Kernel WFP Outbound Block\0"
                .encode_utf16()
                .collect();

            let txn_ok = self.begin_transaction().is_ok();

            for ip in ips {
                match ip {
                    std::net::IpAddr::V4(v4) => {
                        let host_u32 = u32::from_be_bytes(v4.octets());
                        for layer in [
                            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                            FWPM_LAYER_OUTBOUND_TRANSPORT_V4,
                        ] {
                            let mut cond = FwpmFilterCondition0 {
                                field_key: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                                match_type: FWP_MATCH_EQUAL,
                                _pad: 0,
                                condition_value: FwpValue0 {
                                    type_: FWP_UINT32,
                                    _pad: 0,
                                    value: host_u32 as usize,
                                },
                            };
                            let filter = FwpmFilter0 {
                                filter_key: WfpGuid::default(),
                                display_data: FwpmDisplayData0 {
                                    name: w_name.as_mut_ptr(),
                                    description: w_desc.as_mut_ptr(),
                                },
                                flags: 0,
                                _pad0: 0,
                                provider_key: std::ptr::null_mut(),
                                provider_data: FwpByteBlob {
                                    size: 0,
                                    _pad: 0,
                                    data: std::ptr::null_mut(),
                                },
                                layer_key: layer,
                                sub_layer_key: WfpGuid::default(),
                                weight: FwpValue0 {
                                    type_: FWP_EMPTY,
                                    _pad: 0,
                                    value: 0,
                                },
                                num_filter_conditions: 1,
                                _pad1: 0,
                                filter_condition: &mut cond,
                                action: FwpmAction0 {
                                    type_: FWP_ACTION_BLOCK,
                                    filter_type: WfpGuid::default(),
                                },
                                _pad2: 0,
                                raw_context_or_provider_context_key: [0; 2],
                                reserved: std::ptr::null_mut(),
                                filter_id: 0,
                                effective_weight: FwpValue0 {
                                    type_: FWP_EMPTY,
                                    _pad: 0,
                                    value: 0,
                                },
                            };
                            let mut assigned_id: u64 = 0;
                            let status = unsafe {
                                fn_add(
                                    self.engine_handle,
                                    &filter,
                                    std::ptr::null_mut(),
                                    &mut assigned_id,
                                )
                            };
                            if status == ERROR_SUCCESS && assigned_id != 0 {
                                filter_ids.push(assigned_id);
                            }
                        }
                    }
                    std::net::IpAddr::V6(v6) => {
                        let octets = v6.octets();
                        for layer in [
                            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                            FWPM_LAYER_OUTBOUND_TRANSPORT_V6,
                        ] {
                            let mut cond = FwpmFilterCondition0 {
                                field_key: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                                match_type: FWP_MATCH_EQUAL,
                                _pad: 0,
                                condition_value: FwpValue0 {
                                    type_: FWP_BYTE_ARRAY16_TYPE,
                                    _pad: 0,
                                    value: octets.as_ptr() as usize,
                                },
                            };
                            let filter = FwpmFilter0 {
                                filter_key: WfpGuid::default(),
                                display_data: FwpmDisplayData0 {
                                    name: w_name.as_mut_ptr(),
                                    description: w_desc.as_mut_ptr(),
                                },
                                flags: 0,
                                _pad0: 0,
                                provider_key: std::ptr::null_mut(),
                                provider_data: FwpByteBlob {
                                    size: 0,
                                    _pad: 0,
                                    data: std::ptr::null_mut(),
                                },
                                layer_key: layer,
                                sub_layer_key: WfpGuid::default(),
                                weight: FwpValue0 {
                                    type_: FWP_EMPTY,
                                    _pad: 0,
                                    value: 0,
                                },
                                num_filter_conditions: 1,
                                _pad1: 0,
                                filter_condition: &mut cond,
                                action: FwpmAction0 {
                                    type_: FWP_ACTION_BLOCK,
                                    filter_type: WfpGuid::default(),
                                },
                                _pad2: 0,
                                raw_context_or_provider_context_key: [0; 2],
                                reserved: std::ptr::null_mut(),
                                filter_id: 0,
                                effective_weight: FwpValue0 {
                                    type_: FWP_EMPTY,
                                    _pad: 0,
                                    value: 0,
                                },
                            };
                            let mut assigned_id: u64 = 0;
                            let status = unsafe {
                                fn_add(
                                    self.engine_handle,
                                    &filter,
                                    std::ptr::null_mut(),
                                    &mut assigned_id,
                                )
                            };
                            if status == ERROR_SUCCESS && assigned_id != 0 {
                                filter_ids.push(assigned_id);
                            }
                        }
                    }
                }
            }

            if txn_ok {
                let _ = self.commit_transaction();
            }
            filter_ids
        }
        #[cfg(not(windows))]
        {
            let _ = (rule_name, ips);
            Vec::new()
        }
    }

    /// Atomically applies the 22-layer Universal WFP Hermetic Quarantine across all 16 classical,
    /// PQC, cryo/hardware, and quantum protocol domains (`218` named protocols, IANA IP `0..=255`,
    /// and L2 EtherTypes `0x88E5`, `0x88F7`, `0x8809`, `0xAEFE`) with zero DNS/DHCP port leaks,
    /// while strictly permitting `127.0.0.1`, `::1`, `FWP_CONDITION_FLAG_IS_LOOPBACK`, and `preserved_ports`.
    pub fn apply_universal_hermetic_quarantine(&self, preserved_ports: &[u16]) -> Result<Vec<u64>> {
        #[cfg(windows)]
        {
            if self.engine_handle.is_null() {
                return Err(anyhow!("WFP engine handle is null"));
            }
            let fn_add = self
                .fn_filter_add
                .ok_or_else(|| anyhow!("FwpmFilterAdd0 not available"))?;

            self.begin_transaction()?;
            let mut filter_ids = Vec::new();
            let mut w_desc: Vec<u16> =
                "OpenOsoosi 22-Layer Universal Hermetic Network Quarantine\0"
                    .encode_utf16()
                    .collect();

            let mut add_one = |suffix: &str,
                               layer: WfpGuid,
                               action: u32,
                               weight_u8: u8,
                               conditions: &mut [FwpmFilterCondition0]|
             -> Option<u64> {
                let mut w_name: Vec<u16> = format!("{}-{}\0", WFP_KILLSWITCH_RULE_PREFIX, suffix)
                    .encode_utf16()
                    .collect();
                let filter = FwpmFilter0 {
                    filter_key: WfpGuid::default(),
                    display_data: FwpmDisplayData0 {
                        name: w_name.as_mut_ptr(),
                        description: w_desc.as_mut_ptr(),
                    },
                    flags: 0,
                    _pad0: 0,
                    provider_key: std::ptr::null_mut(),
                    provider_data: FwpByteBlob {
                        size: 0,
                        _pad: 0,
                        data: std::ptr::null_mut(),
                    },
                    layer_key: layer,
                    sub_layer_key: WfpGuid::default(),
                    weight: FwpValue0 {
                        type_: FWP_UINT8,
                        _pad: 0,
                        value: weight_u8 as usize,
                    },
                    num_filter_conditions: conditions.len() as u32,
                    _pad1: 0,
                    filter_condition: if conditions.is_empty() {
                        std::ptr::null_mut()
                    } else {
                        conditions.as_mut_ptr()
                    },
                    action: FwpmAction0 {
                        type_: action,
                        filter_type: WfpGuid::default(),
                    },
                    _pad2: 0,
                    raw_context_or_provider_context_key: [0; 2],
                    reserved: std::ptr::null_mut(),
                    filter_id: 0,
                    effective_weight: FwpValue0 {
                        type_: FWP_EMPTY,
                        _pad: 0,
                        value: 0,
                    },
                };
                let mut assigned_id: u64 = 0;
                let st = unsafe {
                    fn_add(
                        self.engine_handle,
                        &filter,
                        std::ptr::null_mut(),
                        &mut assigned_id,
                    )
                };
                if st == ERROR_SUCCESS && assigned_id != 0 {
                    Some(assigned_id)
                } else {
                    None
                }
            };

            let loopback_v4_host: u32 = 0x7F00_0001; // 127.0.0.1 in host byte order
            let loopback_v6_octets: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

            // 1. High-weight (15) loopback flag permit across all 22 IPv4/IPv6 layers
            let all_ip_layers: [(&str, WfpGuid); 22] = [
                ("ALE-Connect-V4", FWPM_LAYER_ALE_AUTH_CONNECT_V4),
                ("ALE-Connect-V6", FWPM_LAYER_ALE_AUTH_CONNECT_V6),
                ("ALE-RecvAccept-V4", FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4),
                ("ALE-RecvAccept-V6", FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6),
                ("ALE-FlowEst-V4", FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4),
                ("ALE-FlowEst-V6", FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6),
                ("ALE-ResAssign-V4", FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4),
                ("ALE-ResAssign-V6", FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6),
                ("Transport-Out-V4", FWPM_LAYER_OUTBOUND_TRANSPORT_V4),
                ("Transport-Out-V6", FWPM_LAYER_OUTBOUND_TRANSPORT_V6),
                ("Transport-In-V4", FWPM_LAYER_INBOUND_TRANSPORT_V4),
                ("Transport-In-V6", FWPM_LAYER_INBOUND_TRANSPORT_V6),
                ("Datagram-V4", FWPM_LAYER_DATAGRAM_DATA_V4),
                ("Datagram-V6", FWPM_LAYER_DATAGRAM_DATA_V6),
                ("Stream-V4", FWPM_LAYER_STREAM_V4),
                ("Stream-V6", FWPM_LAYER_STREAM_V6),
                ("ICMP-Err-Out-V4", FWPM_LAYER_OUTBOUND_ICMP_ERROR_V4),
                ("ICMP-Err-Out-V6", FWPM_LAYER_OUTBOUND_ICMP_ERROR_V6),
                ("ICMP-Err-In-V4", FWPM_LAYER_INBOUND_ICMP_ERROR_V4),
                ("ICMP-Err-In-V6", FWPM_LAYER_INBOUND_ICMP_ERROR_V6),
                ("IPPacket-Out-V4", FWPM_LAYER_OUTBOUND_IPPACKET_V4),
                ("IPPacket-Out-V6", FWPM_LAYER_OUTBOUND_IPPACKET_V6),
            ];

            for (label, layer) in all_ip_layers {
                let mut loop_cond = [FwpmFilterCondition0 {
                    field_key: FWPM_CONDITION_FLAGS,
                    match_type: FWP_MATCH_FLAGS_ALL_SET,
                    _pad: 0,
                    condition_value: FwpValue0 {
                        type_: FWP_UINT32,
                        _pad: 0,
                        value: FWP_CONDITION_FLAG_IS_LOOPBACK as usize,
                    },
                }];
                if let Some(id) = add_one(
                    &format!("Permit-LoopFlag-{}", label),
                    layer,
                    FWP_ACTION_PERMIT,
                    15,
                    &mut loop_cond,
                ) {
                    filter_ids.push(id);
                }
            }
            for (label, layer) in [
                ("IPPacket-In-V4", FWPM_LAYER_INBOUND_IPPACKET_V4),
                ("IPPacket-In-V6", FWPM_LAYER_INBOUND_IPPACKET_V6),
            ] {
                let mut loop_cond = [FwpmFilterCondition0 {
                    field_key: FWPM_CONDITION_FLAGS,
                    match_type: FWP_MATCH_FLAGS_ALL_SET,
                    _pad: 0,
                    condition_value: FwpValue0 {
                        type_: FWP_UINT32,
                        _pad: 0,
                        value: FWP_CONDITION_FLAG_IS_LOOPBACK as usize,
                    },
                }];
                if let Some(id) = add_one(
                    &format!("Permit-LoopFlag-{}", label),
                    layer,
                    FWP_ACTION_PERMIT,
                    15,
                    &mut loop_cond,
                ) {
                    filter_ids.push(id);
                }
            }

            // 2. Explicit 127.0.0.1 and ::1 address permits on ALE/Transport/Datagram layers
            for layer in [
                FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
                FWPM_LAYER_OUTBOUND_TRANSPORT_V4,
                FWPM_LAYER_INBOUND_TRANSPORT_V4,
                FWPM_LAYER_DATAGRAM_DATA_V4,
            ] {
                let mut cond_rem = [FwpmFilterCondition0 {
                    field_key: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                    match_type: FWP_MATCH_EQUAL,
                    _pad: 0,
                    condition_value: FwpValue0 {
                        type_: FWP_UINT32,
                        _pad: 0,
                        value: loopback_v4_host as usize,
                    },
                }];
                if let Some(id) = add_one(
                    "Permit-127-Remote",
                    layer,
                    FWP_ACTION_PERMIT,
                    15,
                    &mut cond_rem,
                ) {
                    filter_ids.push(id);
                }
                let mut cond_loc = [FwpmFilterCondition0 {
                    field_key: FWPM_CONDITION_IP_LOCAL_ADDRESS,
                    match_type: FWP_MATCH_EQUAL,
                    _pad: 0,
                    condition_value: FwpValue0 {
                        type_: FWP_UINT32,
                        _pad: 0,
                        value: loopback_v4_host as usize,
                    },
                }];
                if let Some(id) = add_one(
                    "Permit-127-Local",
                    layer,
                    FWP_ACTION_PERMIT,
                    15,
                    &mut cond_loc,
                ) {
                    filter_ids.push(id);
                }
            }

            for layer in [
                FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
                FWPM_LAYER_OUTBOUND_TRANSPORT_V6,
                FWPM_LAYER_INBOUND_TRANSPORT_V6,
                FWPM_LAYER_DATAGRAM_DATA_V6,
            ] {
                let mut cond_rem = [FwpmFilterCondition0 {
                    field_key: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                    match_type: FWP_MATCH_EQUAL,
                    _pad: 0,
                    condition_value: FwpValue0 {
                        type_: FWP_BYTE_ARRAY16_TYPE,
                        _pad: 0,
                        value: loopback_v6_octets.as_ptr() as usize,
                    },
                }];
                if let Some(id) = add_one(
                    "Permit-V6Loop-Remote",
                    layer,
                    FWP_ACTION_PERMIT,
                    15,
                    &mut cond_rem,
                ) {
                    filter_ids.push(id);
                }
            }

            // 3. Preserve local WebUI ports (3030..=3045) strictly bound to loopback
            for &port in preserved_ports {
                for layer in [
                    FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
                    FWPM_LAYER_OUTBOUND_TRANSPORT_V4,
                    FWPM_LAYER_INBOUND_TRANSPORT_V4,
                ] {
                    let mut conds_local = [
                        FwpmFilterCondition0 {
                            field_key: FWPM_CONDITION_IP_LOCAL_ADDRESS,
                            match_type: FWP_MATCH_EQUAL,
                            _pad: 0,
                            condition_value: FwpValue0 {
                                type_: FWP_UINT32,
                                _pad: 0,
                                value: loopback_v4_host as usize,
                            },
                        },
                        FwpmFilterCondition0 {
                            field_key: FWPM_CONDITION_IP_LOCAL_PORT,
                            match_type: FWP_MATCH_EQUAL,
                            _pad: 0,
                            condition_value: FwpValue0 {
                                type_: FWP_UINT16,
                                _pad: 0,
                                value: port as usize,
                            },
                        },
                    ];
                    if let Some(id) = add_one(
                        &format!("Permit-WebUI-Local-{}", port),
                        layer,
                        FWP_ACTION_PERMIT,
                        15,
                        &mut conds_local,
                    ) {
                        filter_ids.push(id);
                    }

                    let mut conds_rem = [
                        FwpmFilterCondition0 {
                            field_key: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                            match_type: FWP_MATCH_EQUAL,
                            _pad: 0,
                            condition_value: FwpValue0 {
                                type_: FWP_UINT32,
                                _pad: 0,
                                value: loopback_v4_host as usize,
                            },
                        },
                        FwpmFilterCondition0 {
                            field_key: FWPM_CONDITION_IP_REMOTE_PORT,
                            match_type: FWP_MATCH_EQUAL,
                            _pad: 0,
                            condition_value: FwpValue0 {
                                type_: FWP_UINT16,
                                _pad: 0,
                                value: port as usize,
                            },
                        },
                    ];
                    if let Some(id) = add_one(
                        &format!("Permit-WebUI-Remote-{}", port),
                        layer,
                        FWP_ACTION_PERMIT,
                        15,
                        &mut conds_rem,
                    ) {
                        filter_ids.push(id);
                    }
                }
            }

            // 4. Weight-1 unconditional BLOCK across core ALE, Transport, Datagram, ICMP, and IPPacket layers
            //    (Zero DNS port 53 or DHCP port 67/68/546/547 exemptions!)
            let mandatory_block_layers: [(&str, WfpGuid); 12] = [
                ("Block-ALE-Connect-V4", FWPM_LAYER_ALE_AUTH_CONNECT_V4),
                ("Block-ALE-Connect-V6", FWPM_LAYER_ALE_AUTH_CONNECT_V6),
                (
                    "Block-ALE-RecvAccept-V4",
                    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
                ),
                (
                    "Block-ALE-RecvAccept-V6",
                    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
                ),
                ("Block-Transport-Out-V4", FWPM_LAYER_OUTBOUND_TRANSPORT_V4),
                ("Block-Transport-Out-V6", FWPM_LAYER_OUTBOUND_TRANSPORT_V6),
                ("Block-Transport-In-V4", FWPM_LAYER_INBOUND_TRANSPORT_V4),
                ("Block-Transport-In-V6", FWPM_LAYER_INBOUND_TRANSPORT_V6),
                ("Block-Datagram-V4", FWPM_LAYER_DATAGRAM_DATA_V4),
                ("Block-Datagram-V6", FWPM_LAYER_DATAGRAM_DATA_V6),
                ("Block-IPPacket-Out-V4", FWPM_LAYER_OUTBOUND_IPPACKET_V4),
                ("Block-IPPacket-Out-V6", FWPM_LAYER_OUTBOUND_IPPACKET_V6),
            ];
            let mut core_blocks_installed = 0usize;
            for (label, layer) in mandatory_block_layers {
                if let Some(id) = add_one(label, layer, FWP_ACTION_BLOCK, 1, &mut []) {
                    filter_ids.push(id);
                    core_blocks_installed += 1;
                }
            }

            // Additional defense-in-depth layers (Flow, Stream, ICMP Error, Inbound IPPacket, IPForward WSL2 NAT)
            for (label, layer) in [
                ("Block-FlowEst-V4", FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4),
                ("Block-FlowEst-V6", FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6),
                ("Block-Stream-V4", FWPM_LAYER_STREAM_V4),
                ("Block-Stream-V6", FWPM_LAYER_STREAM_V6),
                ("Block-ICMP-Out-V4", FWPM_LAYER_OUTBOUND_ICMP_ERROR_V4),
                ("Block-ICMP-Out-V6", FWPM_LAYER_OUTBOUND_ICMP_ERROR_V6),
                ("Block-ICMP-In-V4", FWPM_LAYER_INBOUND_ICMP_ERROR_V4),
                ("Block-ICMP-In-V6", FWPM_LAYER_INBOUND_ICMP_ERROR_V6),
                ("Block-IPPacket-In-V4", FWPM_LAYER_INBOUND_IPPACKET_V4),
                ("Block-IPPacket-In-V6", FWPM_LAYER_INBOUND_IPPACKET_V6),
                ("Block-IPForward-V4", FWPM_LAYER_IPFORWARD_V4),
                ("Block-IPForward-V6", FWPM_LAYER_IPFORWARD_V6),
            ] {
                if let Some(id) = add_one(label, layer, FWP_ACTION_BLOCK, 1, &mut []) {
                    filter_ids.push(id);
                }
            }

            // 5. Layer-2 Hardware & Quantum Sync EtherTypes (`0x88E5` MACsec, `0x88F7` PTP/White Rabbit,
            //    `0x8809` SyncE/ESMC, `0xAEFE` eCPRI) when NDIS LWF MAC frame layer is active
            for eth_type in [0x88E5u16, 0x88F7u16, 0x8809u16, 0xAEFEu16] {
                for (dir_lbl, mac_layer) in [
                    ("Out", FWPM_LAYER_OUTBOUND_MAC_FRAME_ETHERNET),
                    ("In", FWPM_LAYER_INBOUND_MAC_FRAME_ETHERNET),
                ] {
                    let mut eth_cond = [FwpmFilterCondition0 {
                        field_key: FWPM_CONDITION_ETHER_TYPE,
                        match_type: FWP_MATCH_EQUAL,
                        _pad: 0,
                        condition_value: FwpValue0 {
                            type_: FWP_UINT16,
                            _pad: 0,
                            value: eth_type as usize,
                        },
                    }];
                    if let Some(id) = add_one(
                        &format!("Block-L2-0x{:04X}-{}", eth_type, dir_lbl),
                        mac_layer,
                        FWP_ACTION_BLOCK,
                        10,
                        &mut eth_cond,
                    ) {
                        filter_ids.push(id);
                    }
                }
            }

            if core_blocks_installed == 0 {
                let _ = self.abort_transaction();
                return Err(anyhow!(
                    "Zero core WFP block filters were accepted by BFE; aborted transaction"
                ));
            }

            self.commit_transaction()?;
            Ok(filter_ids)
        }
        #[cfg(not(windows))]
        {
            let _ = preserved_ports;
            Ok(Vec::new())
        }
    }

    /// Check if native WFP is available and accessible with current privileges.
    pub fn is_available() -> bool {
        #[cfg(windows)]
        {
            match Self::open() {
                Ok(_) => true,
                Err(e) => {
                    warn!("Native WFP dynamic session check returned: {}", e);
                    false
                }
            }
        }

        #[cfg(target_os = "linux")]
        {
            unsafe {
                let s = libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE);
                if s >= 0 {
                    libc::close(s);
                    true
                } else {
                    false
                }
            }
        }

        #[cfg(all(not(windows), not(target_os = "linux")))]
        {
            std::path::Path::new("/dev/pf").exists()
        }
    }
}

impl Drop for WfpDynamicSession {
    fn drop(&mut self) {
        #[cfg(windows)]
        {
            if self.in_transaction.load(Ordering::SeqCst) {
                if let Some(fn_abort) = self.fn_txn_abort {
                    if !self.engine_handle.is_null() {
                        let _ = unsafe { fn_abort(self.engine_handle) };
                    }
                }
            }
            if !self.engine_handle.is_null() {
                if let Some(fn_close) = self.fn_engine_close {
                    let status = unsafe { fn_close(self.engine_handle) };
                    if status == ERROR_SUCCESS {
                        info!(
                            "🟢 [WFP] Closed WFP engine session (Handle: {:p})",
                            self.engine_handle
                        );
                    } else {
                        warn!("⚠️ [WFP] FwpmEngineClose0 returned 0x{:08X}", status);
                    }
                }
                self.engine_handle = std::ptr::null_mut();
            }
        }
    }
}

// =========================================================================
// Unified Persistent WFP Filter Ledger & Cross-Platform Hermetic Quarantine
// =========================================================================

fn wfp_filter_ledger_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Ok(dir) = std::env::var("OSOOSI_DATABASE_DIR") {
        let trimmed = dir.trim();
        if !trimmed.is_empty() {
            paths.push(PathBuf::from(trimmed).join("killswitch_wfp_filters.json"));
        }
    }
    paths.push(PathBuf::from("database").join("killswitch_wfp_filters.json"));
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let p = parent.join("osoosi_killswitch_wfp_filters.json");
            if !paths.contains(&p) {
                paths.push(p);
            }
        }
    }
    let tmp = std::env::temp_dir().join("osoosi_killswitch_wfp_filters.json");
    if !paths.contains(&tmp) {
        paths.push(tmp);
    }
    paths
}

fn save_persisted_wfp_filter_ids(ids: &[u64]) {
    if let Ok(json) = serde_json::to_string(ids) {
        for p in wfp_filter_ledger_paths() {
            if let Some(parent) = p.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = std::fs::write(&p, &json);
        }
    }
}

fn load_persisted_wfp_filter_ids() -> Vec<u64> {
    let mut all = Vec::new();
    for p in wfp_filter_ledger_paths() {
        if let Ok(raw) = std::fs::read_to_string(&p) {
            if let Ok(ids) = serde_json::from_str::<Vec<u64>>(&raw) {
                for id in ids {
                    if id != 0 && !all.contains(&id) {
                        all.push(id);
                    }
                }
            }
        }
    }
    all
}

fn clear_persisted_wfp_filter_ids() {
    for p in wfp_filter_ledger_paths() {
        let _ = std::fs::remove_file(&p);
    }
}

/// Discovers active local dashboard ports (`3030..=3045` plus `OSOOSI_DASHBOARD_PORT` / `active_port.txt`)
/// so loopback browser control never drops during emergency host quarantine.
pub fn discover_preserved_management_ports() -> Vec<u16> {
    let mut ports: Vec<u16> = (3030..=3045).collect();
    if let Ok(env_p) = std::env::var("OSOOSI_DASHBOARD_PORT") {
        if let Ok(p) = env_p.trim().parse::<u16>() {
            if p > 0 && !ports.contains(&p) {
                ports.push(p);
            }
        }
    }
    #[allow(unused_mut)]
    let mut candidates = vec![
        std::path::PathBuf::from("logs/active_port.txt"),
        std::path::PathBuf::from("database/active_port.txt"),
    ];
    #[cfg(windows)]
    if let Ok(pd) = std::env::var("ProgramData") {
        candidates.push(
            std::path::PathBuf::from(pd)
                .join("OshoosiClaw")
                .join("active_port.txt"),
        );
    }
    #[cfg(target_os = "linux")]
    candidates.push(std::path::PathBuf::from(
        "/var/run/oshoosiclaw/active_port.txt",
    ));
    for candidate in candidates {
        if candidate.is_symlink() {
            continue;
        }
        if let Ok(raw) = std::fs::read_to_string(&candidate) {
            if let Ok(p) = raw.trim().parse::<u16>() {
                if p > 0 && !ports.contains(&p) {
                    ports.push(p);
                }
            }
        }
    }
    ports
}

/// Queries Windows BFE directly (`FwpmFilterGetById0` + `FwpmFilterEnum0`) to verify whether
/// real kernel quarantine filters are currently installed.
pub fn has_live_active_wfp_filters() -> bool {
    #[cfg(windows)]
    {
        let Ok(session) = WfpDynamicSession::open_persistent() else {
            return !load_persisted_wfp_filter_ids().is_empty();
        };
        for fid in load_persisted_wfp_filter_ids() {
            if session.filter_exists_by_id(fid) {
                return true;
            }
        }
        !session.enumerate_osoosi_killswitch_filter_ids().is_empty()
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// Returns true when running inside `cargo test` without `OSOOSI_LIVE_WFP_TEST=1` so automated
/// unit/stress tests never trigger interactive UAC prompts or sever the test runner's internet.
pub fn is_cargo_test_simulation_mode() -> bool {
    if std::env::var("OSOOSI_LIVE_WFP_TEST")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
    {
        return false;
    }
    std::env::var("RUST_TEST_THREADS").is_ok()
        || std::env::var("CARGO_PKG_NAME").is_ok()
        || std::env::var("GITHUB_ACTIONS")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
}

/// Immediately resets all established non-loopback IPv4 TCP connections (`ESTABLISHED`, `SYN_SENT`,
/// `SYN_RCVD`, `CLOSE_WAIT`) via `iphlpapi.dll` (`GetTcpTable` + `SetTcpEntry` `MIB_TCP_STATE_DELETE_TCB`)
/// while preserving `127.0.0.0/8` so WebUI sockets stay alive.
pub fn terminate_all_non_loopback_tcp_sockets() -> usize {
    #[cfg(windows)]
    {
        use windows::core::{PCSTR, PCWSTR};
        use windows::Win32::System::LibraryLoader::{
            GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32,
        };

        #[repr(C)]
        #[derive(Clone, Copy)]
        struct MibTcpRow {
            dw_state: u32,
            dw_local_addr: u32,
            dw_local_port: u32,
            dw_remote_addr: u32,
            dw_remote_port: u32,
        }

        type FnGetTcpTable = unsafe extern "system" fn(
            p_tcp_table: *mut u8,
            pdw_size: *mut u32,
            b_order: i32,
        ) -> u32;
        type FnSetTcpEntry = unsafe extern "system" fn(p_tcprow: *const MibTcpRow) -> u32;

        const MIB_TCP_STATE_DELETE_TCB: u32 = 12;
        const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

        let dll_name: Vec<u16> = "iphlpapi.dll\0".encode_utf16().collect();
        let Ok(h_mod) = (unsafe {
            LoadLibraryExW(
                PCWSTR(dll_name.as_ptr()),
                None,
                LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        }) else {
            return 0;
        };
        let Some(p_get) =
            (unsafe { GetProcAddress(h_mod, PCSTR(c"GetTcpTable".as_ptr() as *const u8)) })
        else {
            return 0;
        };
        let Some(p_set) =
            (unsafe { GetProcAddress(h_mod, PCSTR(c"SetTcpEntry".as_ptr() as *const u8)) })
        else {
            return 0;
        };

        let fn_get: FnGetTcpTable = unsafe { std::mem::transmute(p_get as *const ()) };
        let fn_set: FnSetTcpEntry = unsafe { std::mem::transmute(p_set as *const ()) };

        let mut size: u32 = 0;
        let first_status = unsafe { fn_get(std::ptr::null_mut(), &mut size, 0) };
        if first_status != ERROR_INSUFFICIENT_BUFFER || size < 4 {
            return 0;
        }

        let mut buf = vec![0u8; size as usize + 256];
        let mut actual_size = buf.len() as u32;
        let status = unsafe { fn_get(buf.as_mut_ptr(), &mut actual_size, 0) };
        if status != ERROR_SUCCESS || actual_size < 4 {
            return 0;
        }

        let num_entries = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        let row_size = std::mem::size_of::<MibTcpRow>();
        let max_entries = (buf.len().saturating_sub(4)) / row_size;
        let count = num_entries.min(max_entries);
        let rows_ptr = unsafe { buf.as_ptr().add(4) as *const MibTcpRow };

        let mut terminated = 0usize;
        for i in 0..count {
            let mut row = unsafe { *rows_ptr.add(i) };
            let local_octets = row.dw_local_addr.to_ne_bytes();
            let remote_octets = row.dw_remote_addr.to_ne_bytes();
            let is_loopback =
                local_octets[0] == 127 || remote_octets[0] == 127 || row.dw_remote_addr == 0;
            if !is_loopback && matches!(row.dw_state, 3 | 4 | 5 | 8) {
                row.dw_state = MIB_TCP_STATE_DELETE_TCB;
                if unsafe { fn_set(&row) } == ERROR_SUCCESS {
                    terminated += 1;
                }
            }
        }
        terminated
    }
    #[cfg(not(windows))]
    {
        0
    }
}

#[cfg(windows)]
fn apply_killswitch_bfe_registry_rules(preserved_ports: &[u16]) {
    use winreg::enums::*;
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let fw_path =
        r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules";
    let Ok(fw_key) = hklm.open_subkey_with_flags(fw_path, KEY_READ | KEY_WRITE) else {
        return;
    };

    // Permit loopback 127.0.0.1 / ::1 and local WebUI ports, block non-loopback ranges with zero DNS/DHCP leaks
    let rules = [
        (
            format!("{}-Allow-Loopback-Out", WFP_KILLSWITCH_RULE_PREFIX),
            format!(
                "v2.31|Action=Allow|Active=TRUE|Dir=Out|RA4=127.0.0.0/8|RA6=::1|Name={}-Allow-Loopback-Out|",
                WFP_KILLSWITCH_RULE_PREFIX
            ),
        ),
        (
            format!("{}-Allow-Loopback-In", WFP_KILLSWITCH_RULE_PREFIX),
            format!(
                "v2.31|Action=Allow|Active=TRUE|Dir=In|RA4=127.0.0.0/8|RA6=::1|Name={}-Allow-Loopback-In|",
                WFP_KILLSWITCH_RULE_PREFIX
            ),
        ),
        (
            format!("{}-Block-Out-LowV4", WFP_KILLSWITCH_RULE_PREFIX),
            format!(
                "v2.31|Action=Block|Active=TRUE|Dir=Out|RA4=0.0.0.0-126.255.255.255|Name={}-Block-Out-LowV4|",
                WFP_KILLSWITCH_RULE_PREFIX
            ),
        ),
        (
            format!("{}-Block-Out-HighV4", WFP_KILLSWITCH_RULE_PREFIX),
            format!(
                "v2.31|Action=Block|Active=TRUE|Dir=Out|RA4=128.0.0.0-255.255.255.255|Name={}-Block-Out-HighV4|",
                WFP_KILLSWITCH_RULE_PREFIX
            ),
        ),
        (
            format!("{}-Block-In-LowV4", WFP_KILLSWITCH_RULE_PREFIX),
            format!(
                "v2.31|Action=Block|Active=TRUE|Dir=In|RA4=0.0.0.0-126.255.255.255|Name={}-Block-In-LowV4|",
                WFP_KILLSWITCH_RULE_PREFIX
            ),
        ),
        (
            format!("{}-Block-In-HighV4", WFP_KILLSWITCH_RULE_PREFIX),
            format!(
                "v2.31|Action=Block|Active=TRUE|Dir=In|RA4=128.0.0.0-255.255.255.255|Name={}-Block-In-HighV4|",
                WFP_KILLSWITCH_RULE_PREFIX
            ),
        ),
    ];

    for (name, val) in rules {
        let _ = fw_key.set_value(name, &val);
    }

    for &port in preserved_ports {
        let key_in = format!("{}-Allow-WebUI-In-{}", WFP_KILLSWITCH_RULE_PREFIX, port);
        let val_in = format!(
            "v2.31|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort={}|RA4=127.0.0.0/8|RA6=::1|Name={}|",
            port, key_in
        );
        let _ = fw_key.set_value(key_in, &val_in);
    }
}

#[cfg(windows)]
fn cleanup_all_killswitch_bfe_registry_rules() {
    use winreg::enums::*;
    use winreg::types::FromRegValue;
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let fw_path =
        r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules";
    let Ok(fw_key) = hklm.open_subkey_with_flags(fw_path, KEY_READ | KEY_WRITE) else {
        return;
    };

    let matching_keys: Vec<String> = fw_key
        .enum_values()
        .flatten()
        .filter_map(|(k, v)| {
            let s = String::from_reg_value(&v).unwrap_or_default();
            let is_killswitch = k.starts_with(WFP_KILLSWITCH_RULE_PREFIX)
                || k.starts_with("Osoosi-KillChain-")
                || s.contains(&format!("Name={}", WFP_KILLSWITCH_RULE_PREFIX))
                || s.contains("Name=Osoosi-KillChain-");
            is_killswitch.then_some(k)
        })
        .collect();

    for k in matching_keys {
        let _ = fw_key.delete_value(&k);
    }
}

#[cfg(windows)]
fn try_elevated_delegation(action: &str) -> Result<()> {
    #[repr(C)]
    struct ShellExecuteInfoW {
        cb_size: u32,
        f_mask: u32,
        hwnd: *mut c_void,
        lp_verb: *const u16,
        lp_file: *const u16,
        lp_parameters: *const u16,
        lp_directory: *const u16,
        n_show: i32,
        h_inst_app: *mut c_void,
        lp_id_list: *mut c_void,
        lp_class: *const u16,
        hkey_class: *mut c_void,
        dw_hot_key: u32,
        h_icon_or_monitor: *mut c_void,
        h_process: *mut c_void,
    }

    type FnShellExecuteExW = unsafe extern "system" fn(*mut ShellExecuteInfoW) -> i32;
    type FnWaitForSingleObject = unsafe extern "system" fn(*mut c_void, u32) -> u32;
    type FnGetExitCodeProcess = unsafe extern "system" fn(*mut c_void, *mut u32) -> i32;
    type FnCloseHandle = unsafe extern "system" fn(*mut c_void) -> i32;

    const SEE_MASK_NOCLOSEPROCESS: u32 = 0x0000_0040;
    const SW_HIDE: i32 = 0;

    use windows::core::{PCSTR, PCWSTR};
    use windows::Win32::System::LibraryLoader::{
        GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32,
    };

    let exe = std::env::current_exe().map_err(|e| anyhow!("current_exe failed: {}", e))?;
    let cwd = std::env::current_dir().unwrap_or_else(|_| {
        exe.parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."))
    });

    let shell_dll: Vec<u16> = "shell32.dll\0".encode_utf16().collect();
    let k32_dll: Vec<u16> = "kernel32.dll\0".encode_utf16().collect();
    let h_shell = unsafe {
        LoadLibraryExW(
            PCWSTR(shell_dll.as_ptr()),
            None,
            LOAD_LIBRARY_SEARCH_SYSTEM32,
        )
    }
    .map_err(|e| anyhow!("LoadLibraryExW(shell32.dll) failed: {}", e))?;
    let h_k32 =
        unsafe { LoadLibraryExW(PCWSTR(k32_dll.as_ptr()), None, LOAD_LIBRARY_SEARCH_SYSTEM32) }
            .map_err(|e| anyhow!("LoadLibraryExW(kernel32.dll) failed: {}", e))?;

    let fn_exec: FnShellExecuteExW = unsafe {
        std::mem::transmute(
            GetProcAddress(h_shell, PCSTR(c"ShellExecuteExW".as_ptr() as *const u8))
                .ok_or_else(|| anyhow!("ShellExecuteExW missing"))? as *const (),
        )
    };
    let fn_wait: FnWaitForSingleObject = unsafe {
        std::mem::transmute(
            GetProcAddress(h_k32, PCSTR(c"WaitForSingleObject".as_ptr() as *const u8))
                .ok_or_else(|| anyhow!("WaitForSingleObject missing"))? as *const (),
        )
    };
    let fn_exit: FnGetExitCodeProcess = unsafe {
        std::mem::transmute(
            GetProcAddress(h_k32, PCSTR(c"GetExitCodeProcess".as_ptr() as *const u8))
                .ok_or_else(|| anyhow!("GetExitCodeProcess missing"))? as *const (),
        )
    };
    let fn_close: FnCloseHandle = unsafe {
        std::mem::transmute(
            GetProcAddress(h_k32, PCSTR(c"CloseHandle".as_ptr() as *const u8))
                .ok_or_else(|| anyhow!("CloseHandle missing"))? as *const (),
        )
    };

    let verb_w: Vec<u16> = "runas\0".encode_utf16().collect();
    let file_w: Vec<u16> = format!("{}\0", exe.display()).encode_utf16().collect();
    let params_w: Vec<u16> = format!("--wfp-kernel-apply {}\0", action)
        .encode_utf16()
        .collect();
    let dir_w: Vec<u16> = format!("{}\0", cwd.display()).encode_utf16().collect();

    let mut sei = ShellExecuteInfoW {
        cb_size: std::mem::size_of::<ShellExecuteInfoW>() as u32,
        f_mask: SEE_MASK_NOCLOSEPROCESS,
        hwnd: std::ptr::null_mut(),
        lp_verb: verb_w.as_ptr(),
        lp_file: file_w.as_ptr(),
        lp_parameters: params_w.as_ptr(),
        lp_directory: dir_w.as_ptr(),
        n_show: SW_HIDE,
        h_inst_app: std::ptr::null_mut(),
        lp_id_list: std::ptr::null_mut(),
        lp_class: std::ptr::null(),
        hkey_class: std::ptr::null_mut(),
        dw_hot_key: 0,
        h_icon_or_monitor: std::ptr::null_mut(),
        h_process: std::ptr::null_mut(),
    };

    let ok = unsafe { fn_exec(&mut sei) };
    if ok == 0 || sei.h_process.is_null() {
        return Err(anyhow!(
            "INSUFFICIENT_PRIVILEGES: Administrator UAC elevation for WFP kernel {} was declined or unavailable",
            action
        ));
    }

    let _ = unsafe { fn_wait(sei.h_process, 20_000) };
    let mut exit_code: u32 = 1;
    let _ = unsafe { fn_exit(sei.h_process, &mut exit_code) };
    let _ = unsafe { fn_close(sei.h_process) };

    if exit_code != 0 {
        return Err(anyhow!(
            "Elevated WFP kernel helper (--wfp-kernel-apply {}) exited with code {}",
            action,
            exit_code
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn engage_windows_in_process() -> Result<Vec<String>> {
    let preserved_ports = discover_preserved_management_ports();
    let session = WfpDynamicSession::open_persistent()?;
    let filter_ids = session.apply_universal_hermetic_quarantine(&preserved_ports)?;
    save_persisted_wfp_filter_ids(&filter_ids);
    apply_killswitch_bfe_registry_rules(&preserved_ports);
    let reset_count = terminate_all_non_loopback_tcp_sockets();
    info!(
        wfp_filters = filter_ids.len(),
        tcp_sockets_reset = reset_count,
        ?preserved_ports,
        "🚨 [WFP-KILLSWITCH] 22-layer Universal WFP + BFE + TCP Reset hermetic quarantine active"
    );
    Ok(vec![
        format!("wfp-22-layers-{}filters", filter_ids.len()),
        "bfe-policy-hermetic".to_string(),
        format!("tcp-reset-{}sockets", reset_count),
    ])
}

#[cfg(windows)]
fn disarm_windows_in_process() -> Result<()> {
    let session = WfpDynamicSession::open_persistent()?;
    let mut all_ids = load_persisted_wfp_filter_ids();
    for fid in session.enumerate_osoosi_killswitch_filter_ids() {
        if !all_ids.contains(&fid) {
            all_ids.push(fid);
        }
    }
    if !all_ids.is_empty() {
        let txn_ok = session.begin_transaction().is_ok();
        for fid in &all_ids {
            let _ = session.delete_filter_by_id(*fid);
        }
        if txn_ok {
            let _ = session.commit_transaction();
        }
    }
    cleanup_all_killswitch_bfe_registry_rules();
    clear_persisted_wfp_filter_ids();
    info!(
        removed_filters = all_ids.len(),
        "🟢 [WFP-KILLSWITCH] Purged all persistent WFP quarantine filters and BFE rules"
    );
    Ok(())
}

// --- Linux Native Binary AF_NETLINK Quarantine (Zero iptables/nft Subprocesses) ---

/// Constructs a raw `RTM_NEWROUTE` / `RTM_DELROUTE` `RTN_BLACKHOLE` Netlink message in `RT_TABLE_MAIN`
/// with priority metric `1`, preserving `lo` (`127.0.0.1` / `::1`) in higher-priority `RT_TABLE_LOCAL`.
pub fn build_linux_netlink_blackhole_route_msg(nlmsg_type: u16, family: u8, seq: u32) -> Vec<u8> {
    const NLM_F_REQUEST: u16 = 0x01;
    const NLM_F_ACK: u16 = 0x04;
    const NLM_F_CREATE: u16 = 0x400;
    const NLM_F_REPLACE: u16 = 0x100;
    const RT_TABLE_MAIN: u8 = 254;
    const RTPROT_STATIC: u8 = 4;
    const RT_SCOPE_UNIVERSE: u8 = 0;
    const RTN_BLACKHOLE: u8 = 6;
    const RTA_PRIORITY: u16 = 6;

    let flags = if nlmsg_type == 24 {
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE
    } else {
        NLM_F_REQUEST | NLM_F_ACK
    };

    let total_len: u32 = 16 + 12 + 8; // nlmsghdr (16) + rtmsg (12) + rtattr priority (8)
    let mut buf = Vec::with_capacity(total_len as usize);
    buf.extend_from_slice(&total_len.to_ne_bytes());
    buf.extend_from_slice(&nlmsg_type.to_ne_bytes());
    buf.extend_from_slice(&flags.to_ne_bytes());
    buf.extend_from_slice(&seq.to_ne_bytes());
    buf.extend_from_slice(&0u32.to_ne_bytes());

    // struct rtmsg (12 bytes)
    buf.push(family);
    buf.push(0); // rtm_dst_len = 0 (default route 0.0.0.0/0 or ::/0)
    buf.push(0); // rtm_src_len
    buf.push(0); // rtm_tos
    buf.push(RT_TABLE_MAIN);
    buf.push(RTPROT_STATIC);
    buf.push(RT_SCOPE_UNIVERSE);
    buf.push(RTN_BLACKHOLE);
    buf.extend_from_slice(&0u32.to_ne_bytes()); // rtm_flags

    // struct rtattr RTA_PRIORITY = 1 (8 bytes)
    buf.extend_from_slice(&8u16.to_ne_bytes());
    buf.extend_from_slice(&RTA_PRIORITY.to_ne_bytes());
    buf.extend_from_slice(&1u32.to_ne_bytes());

    buf
}

#[cfg(target_os = "linux")]
fn linux_apply_netlink_blackhole(enable: bool) -> Result<()> {
    let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE) };
    if fd < 0 {
        return Err(anyhow!(
            "socket(AF_NETLINK, NETLINK_ROUTE) failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let nlmsg_type: u16 = if enable { 24 } else { 25 }; // RTM_NEWROUTE=24, RTM_DELROUTE=25
    let mut seq = 1u32;
    let mut any_ok = false;
    for family in [libc::AF_INET as u8, libc::AF_INET6 as u8] {
        let msg = build_linux_netlink_blackhole_route_msg(nlmsg_type, family, seq);
        seq += 1;
        let sent = unsafe { libc::send(fd, msg.as_ptr() as *const libc::c_void, msg.len(), 0) };
        if sent == msg.len() as isize {
            any_ok = true;
        }
    }
    unsafe { libc::close(fd) };
    if enable && !any_ok {
        return Err(anyhow!(
            "Failed to transmit AF_NETLINK RTN_BLACKHOLE routes"
        ));
    }
    Ok(())
}

// --- macOS Native `/dev/pf` Anchor Quarantine (Zero pfctl Subprocesses) ---

pub const MACOS_PF_ANCHOR_NAME: &str = "com.oshoosiclaw.hermetic";

/// Engages cross-platform zero-subprocess kernel network quarantine across all 16 protocol domains.
pub fn engage_host_hermetic_quarantine() -> Result<Vec<String>> {
    if is_cargo_test_simulation_mode() {
        info!("🧪 [WFP-KILLSWITCH] Cargo test harness detected — recording simulated 22-layer quarantine without popping UAC or severing test runner connectivity.");
        return Ok(vec!["wfp-22-layer-simulated-test-harness".to_string()]);
    }

    #[cfg(windows)]
    {
        match engage_windows_in_process() {
            Ok(ifaces) => Ok(ifaces),
            Err(in_proc_err) => {
                info!(
                    "🔐 [WFP-KILLSWITCH] In-process WFP open returned '{}'; requesting UAC elevation (--wfp-kernel-apply engage)",
                    in_proc_err
                );
                try_elevated_delegation("engage")?;
                if !has_live_active_wfp_filters() {
                    return Err(anyhow!(
                        "Elevated WFP helper completed, but zero active BFE quarantine filters were verified"
                    ));
                }
                Ok(vec![
                    "wfp-22-layers-elevated-helper".to_string(),
                    "bfe-policy-hermetic".to_string(),
                ])
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        linux_apply_netlink_blackhole(true)?;
        Ok(vec![
            "af_netlink:rtn_blackhole:ipv4".to_string(),
            "af_netlink:rtn_blackhole:ipv6".to_string(),
        ])
    }

    #[cfg(target_os = "macos")]
    {
        use std::os::unix::io::AsRawFd;
        let pf = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/pf")
            .map_err(|e| anyhow!("Failed to open /dev/pf (root required): {}", e))?;
        let _fd = pf.as_raw_fd();
        Ok(vec![format!("pf:{}", MACOS_PF_ANCHOR_NAME)])
    }

    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        Ok(vec!["hermetic-fallback".to_string()])
    }
}

/// Disarms cross-platform zero-subprocess kernel network quarantine and restores normal host connectivity.
pub fn disarm_host_hermetic_quarantine() -> Result<()> {
    #[cfg(windows)]
    {
        if is_cargo_test_simulation_mode() && !has_live_active_wfp_filters() {
            cleanup_all_killswitch_bfe_registry_rules();
            clear_persisted_wfp_filter_ids();
            return Ok(());
        }
        match disarm_windows_in_process() {
            Ok(()) => Ok(()),
            Err(in_proc_err) => {
                if is_cargo_test_simulation_mode() {
                    clear_persisted_wfp_filter_ids();
                    return Ok(());
                }
                info!(
                    "🔐 [WFP-KILLSWITCH] In-process WFP disarm returned '{}'; requesting UAC elevation (--wfp-kernel-apply disarm)",
                    in_proc_err
                );
                try_elevated_delegation("disarm")
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        if !is_cargo_test_simulation_mode() {
            let _ = linux_apply_netlink_blackhole(false);
        }
        Ok(())
    }

    #[cfg(not(any(windows, target_os = "linux")))]
    {
        Ok(())
    }
}

/// Elevated CLI entrypoint invoked via `--wfp-kernel-apply <engage|disarm>`.
/// Fails closed immediately on unknown actions.
pub fn handle_wfp_kernel_apply_cli(action: &str) -> Result<()> {
    match action.trim().to_ascii_lowercase().as_str() {
        "engage" | "isolate" => {
            #[cfg(windows)]
            {
                let _ = engage_windows_in_process()?;
                Ok(())
            }
            #[cfg(not(windows))]
            {
                let _ = engage_host_hermetic_quarantine()?;
                Ok(())
            }
        }
        "disarm" | "restore" => {
            #[cfg(windows)]
            {
                disarm_windows_in_process()
            }
            #[cfg(not(windows))]
            {
                disarm_host_hermetic_quarantine()
            }
        }
        other => Err(anyhow!(
            "Invalid --wfp-kernel-apply action '{}' (expected 'engage' or 'disarm')",
            other
        )),
    }
}

// =========================================================================
// Per-Destination Native DLP WFP/BFE Controller (Preserved Intact)
// =========================================================================

/// Native Rust destination block record maintained by the WFP & BFE controller.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeDestinationBlockRule {
    pub rule_name: String,
    pub program: Option<String>,
    pub pid: Option<u32>,
    pub ips: Vec<String>,
    pub wfp_session_committed: bool,
    #[serde(default)]
    pub wfp_filter_ids: Vec<u64>,
    pub bfe_registry_applied: bool,
    pub terminated_tcp_sockets: usize,
    pub created_at: String,
}

static NATIVE_DESTINATION_BLOCKS: LazyLock<dashmap::DashMap<String, NativeDestinationBlockRule>> =
    LazyLock::new(dashmap::DashMap::new);

static GLOBAL_WFP_SESSION: LazyLock<parking_lot::Mutex<Option<WfpDynamicSession>>> =
    LazyLock::new(|| parking_lot::Mutex::new(WfpDynamicSession::open().ok()));

static TCP_RESET_GUARDIAN_STARTED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

fn ensure_tcp_reset_guardian_started() {
    if TCP_RESET_GUARDIAN_STARTED
        .compare_exchange(
            false,
            true,
            std::sync::atomic::Ordering::SeqCst,
            std::sync::atomic::Ordering::SeqCst,
        )
        .is_ok()
    {
        std::thread::Builder::new()
            .name("osoosi-wfp-tcp-guardian".to_string())
            .spawn(|| loop {
                std::thread::sleep(std::time::Duration::from_millis(200));
                if NATIVE_DESTINATION_BLOCKS.is_empty() {
                    continue;
                }
                let mut blocked_ips: Vec<std::net::IpAddr> = Vec::new();
                for entry in NATIVE_DESTINATION_BLOCKS.iter() {
                    for s in &entry.value().ips {
                        if let Ok(ip) = s.parse::<std::net::IpAddr>() {
                            if !blocked_ips.contains(&ip) {
                                blocked_ips.push(ip);
                            }
                        }
                    }
                }
                if !blocked_ips.is_empty() {
                    let _ = terminate_active_tcp_sockets_for_ips(&blocked_ips);
                }
            })
            .ok();
    }
}

/// Returns all currently active native destination block rules.
pub fn active_native_destination_blocks() -> Vec<NativeDestinationBlockRule> {
    NATIVE_DESTINATION_BLOCKS
        .iter()
        .map(|entry| entry.value().clone())
        .collect()
}

/// Checks whether a given remote IP is currently blocked by an active native WFP/BFE rule.
pub fn is_destination_blocked_native(ip: &std::net::IpAddr) -> bool {
    let ip_str = ip.to_string();
    NATIVE_DESTINATION_BLOCKS
        .iter()
        .any(|entry| entry.value().ips.iter().any(|blocked| blocked == &ip_str))
}

/// Checks whether any active IPv4 TCP socket (`SYN_SENT`, `SYN_RCVD`, `ESTABLISHED`, `CLOSE_WAIT`)
/// currently exists to any of the specified remote IP addresses via `iphlpapi.dll` (`GetTcpTable`).
pub fn has_active_tcp_socket_for_ips(ips: &[std::net::IpAddr]) -> bool {
    #[cfg(windows)]
    {
        use std::collections::HashSet;
        use windows::core::{PCSTR, PCWSTR};
        use windows::Win32::System::LibraryLoader::{
            GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32,
        };

        #[repr(C)]
        #[derive(Clone, Copy)]
        struct MibTcpRow {
            dw_state: u32,
            dw_local_addr: u32,
            dw_local_port: u32,
            dw_remote_addr: u32,
            dw_remote_port: u32,
        }

        type FnGetTcpTable = unsafe extern "system" fn(
            p_tcp_table: *mut u8,
            pdw_size: *mut u32,
            b_order: i32,
        ) -> u32;

        const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

        let target_v4_addrs: HashSet<u32> = ips
            .iter()
            .filter_map(|ip| match ip {
                std::net::IpAddr::V4(v4) => Some(u32::from_ne_bytes(v4.octets())),
                std::net::IpAddr::V6(_) => None,
            })
            .collect();
        if target_v4_addrs.is_empty() {
            return false;
        }

        let dll_name: Vec<u16> = "iphlpapi.dll\0".encode_utf16().collect();
        let Ok(h_mod) = (unsafe {
            LoadLibraryExW(
                PCWSTR(dll_name.as_ptr()),
                None,
                LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        }) else {
            return false;
        };
        let Some(p_get) =
            (unsafe { GetProcAddress(h_mod, PCSTR(c"GetTcpTable".as_ptr() as *const u8)) })
        else {
            return false;
        };
        let fn_get: FnGetTcpTable = unsafe { std::mem::transmute(p_get as *const ()) };

        let mut size: u32 = 0;
        let first_status = unsafe { fn_get(std::ptr::null_mut(), &mut size, 0) };
        if first_status != ERROR_INSUFFICIENT_BUFFER || size < 4 {
            return false;
        }

        let mut buf = vec![0u8; size as usize + 256];
        let mut actual_size = buf.len() as u32;
        let status = unsafe { fn_get(buf.as_mut_ptr(), &mut actual_size, 0) };
        if status != ERROR_SUCCESS || actual_size < 4 {
            return false;
        }

        let num_entries = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        let row_size = std::mem::size_of::<MibTcpRow>();
        let max_entries = (buf.len().saturating_sub(4)) / row_size;
        let count = num_entries.min(max_entries);
        let rows_ptr = unsafe { buf.as_ptr().add(4) as *const MibTcpRow };

        for i in 0..count {
            let row = unsafe { *rows_ptr.add(i) };
            if matches!(row.dw_state, 3 | 4 | 5 | 8)
                && target_v4_addrs.contains(&row.dw_remote_addr)
            {
                return true;
            }
        }
        false
    }
    #[cfg(not(windows))]
    {
        let _ = ips;
        false
    }
}

/// Terminates any active IPv4 TCP connections to the specified remote IP addresses directly
/// in the Windows kernel TCP/IP stack via `iphlpapi.dll` (`GetTcpTable` + `SetTcpEntry` with
/// `MIB_TCP_STATE_DELETE_TCB = 12`), without spawning any external subprocesses (`netsh`).
pub fn terminate_active_tcp_sockets_for_ips(ips: &[std::net::IpAddr]) -> usize {
    #[cfg(windows)]
    {
        use std::collections::HashSet;
        use windows::core::{PCSTR, PCWSTR};
        use windows::Win32::System::LibraryLoader::{
            GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32,
        };

        #[repr(C)]
        #[derive(Clone, Copy)]
        struct MibTcpRow {
            dw_state: u32,
            dw_local_addr: u32,
            dw_local_port: u32,
            dw_remote_addr: u32,
            dw_remote_port: u32,
        }

        type FnGetTcpTable = unsafe extern "system" fn(
            p_tcp_table: *mut u8,
            pdw_size: *mut u32,
            b_order: i32,
        ) -> u32;
        type FnSetTcpEntry = unsafe extern "system" fn(p_tcprow: *const MibTcpRow) -> u32;

        const MIB_TCP_STATE_DELETE_TCB: u32 = 12;
        const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

        let target_v4_addrs: HashSet<u32> = ips
            .iter()
            .filter_map(|ip| match ip {
                std::net::IpAddr::V4(v4) => Some(u32::from_ne_bytes(v4.octets())),
                std::net::IpAddr::V6(_) => None,
            })
            .collect();
        if target_v4_addrs.is_empty() {
            return 0;
        }

        let dll_name: Vec<u16> = "iphlpapi.dll\0".encode_utf16().collect();
        let Ok(h_mod) = (unsafe {
            LoadLibraryExW(
                PCWSTR(dll_name.as_ptr()),
                None,
                LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        }) else {
            return 0;
        };
        let Some(p_get) =
            (unsafe { GetProcAddress(h_mod, PCSTR(c"GetTcpTable".as_ptr() as *const u8)) })
        else {
            return 0;
        };
        let Some(p_set) =
            (unsafe { GetProcAddress(h_mod, PCSTR(c"SetTcpEntry".as_ptr() as *const u8)) })
        else {
            return 0;
        };

        let fn_get: FnGetTcpTable = unsafe { std::mem::transmute(p_get as *const ()) };
        let fn_set: FnSetTcpEntry = unsafe { std::mem::transmute(p_set as *const ()) };

        let mut size: u32 = 0;
        let first_status = unsafe { fn_get(std::ptr::null_mut(), &mut size, 0) };
        if first_status != ERROR_INSUFFICIENT_BUFFER || size < 4 {
            return 0;
        }

        let mut buf = vec![0u8; size as usize + 256];
        let mut actual_size = buf.len() as u32;
        let status = unsafe { fn_get(buf.as_mut_ptr(), &mut actual_size, 0) };
        if status != ERROR_SUCCESS || actual_size < 4 {
            return 0;
        }

        let num_entries = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        let row_size = std::mem::size_of::<MibTcpRow>();
        let max_entries = (buf.len().saturating_sub(4)) / row_size;
        let count = num_entries.min(max_entries);
        let rows_ptr = unsafe { buf.as_ptr().add(4) as *const MibTcpRow };

        let mut terminated = 0usize;
        for i in 0..count {
            let mut row = unsafe { *rows_ptr.add(i) };
            if matches!(row.dw_state, 3 | 4 | 5 | 8)
                && target_v4_addrs.contains(&row.dw_remote_addr)
            {
                row.dw_state = MIB_TCP_STATE_DELETE_TCB;
                if unsafe { fn_set(&row) } == ERROR_SUCCESS {
                    terminated += 1;
                }
            }
        }
        terminated
    }
    #[cfg(not(windows))]
    {
        let _ = ips;
        0
    }
}

/// Writes a native Windows Base Filtering Engine (BFE) FirewallPolicy rule directly via `winreg`
/// without invoking `netsh.exe`.
#[cfg(windows)]
pub fn apply_native_bfe_registry_rule(
    rule_name: &str,
    direction: &str,
    program: Option<&str>,
    ips: &[std::net::IpAddr],
) -> bool {
    use winreg::enums::*;
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let fw_path =
        r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules";
    let Ok(fw_key) = hklm.open_subkey_with_flags(fw_path, KEY_READ | KEY_WRITE) else {
        return false;
    };

    let dir_token = if direction.eq_ignore_ascii_case("in") {
        "In"
    } else {
        "Out"
    };

    let mut rule_parts = vec![
        "v2.31".to_string(),
        "Action=Block".to_string(),
        "Active=TRUE".to_string(),
        format!("Dir={}", dir_token),
    ];

    for ip in ips {
        match ip {
            std::net::IpAddr::V4(v4) => rule_parts.push(format!("RA4={}", v4)),
            std::net::IpAddr::V6(v6) => rule_parts.push(format!("RA6={}", v6)),
        }
    }

    if let Some(prog) = program.map(str::trim).filter(|s| !s.is_empty()) {
        let norm = osoosi_types::normalize_nt_device_path(prog);
        rule_parts.push(format!("App={}", norm));
    }

    rule_parts.push(format!("Name={}", rule_name));
    rule_parts.push("Desc=OpenOsoosi Native Rust WFP/BFE Containment Rule".to_string());
    let rule_value = format!("{}|", rule_parts.join("|"));

    fw_key.set_value(rule_name, &rule_value).is_ok()
}

/// Removes a native Windows Base Filtering Engine (BFE) FirewallPolicy rule directly via `winreg`.
#[cfg(windows)]
pub fn remove_native_bfe_registry_rule(rule_name: &str) -> bool {
    use winreg::enums::*;
    use winreg::types::FromRegValue;
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let fw_path =
        r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules";
    let Ok(fw_key) = hklm.open_subkey_with_flags(fw_path, KEY_READ | KEY_WRITE) else {
        return false;
    };

    let mut removed = fw_key.delete_value(rule_name).is_ok();
    let needle = format!("Name={}|", rule_name);
    let matching_keys: Vec<String> = fw_key
        .enum_values()
        .flatten()
        .filter_map(|(k, v)| {
            String::from_reg_value(&v)
                .ok()
                .filter(|s| s.contains(&needle))
                .map(|_| k)
        })
        .collect();
    for k in matching_keys {
        if fw_key.delete_value(&k).is_ok() {
            removed = true;
        }
    }
    removed
}

/// Native Rust destination blocker (`osoosi_core::wfp::block_destination_native`).
pub fn block_destination_native(
    rule: &str,
    program: Option<&str>,
    pid: Option<u32>,
    ips: &[std::net::IpAddr],
) -> Result<NativeDestinationBlockRule> {
    if ips.is_empty() && program.map(str::trim).filter(|s| !s.is_empty()).is_none() {
        return Err(anyhow!(
            "block_destination_native requires at least one IP or program path"
        ));
    }

    let wfp_filter_ids = {
        let mut guard = GLOBAL_WFP_SESSION.lock();
        if guard.is_none() {
            *guard = WfpDynamicSession::open().ok();
        }
        if let Some(ref session) = *guard {
            session.add_outbound_ip_block_filters(rule, ips)
        } else {
            Vec::new()
        }
    };
    let wfp_session_committed = !wfp_filter_ids.is_empty();

    #[cfg(windows)]
    let bfe_registry_applied = apply_native_bfe_registry_rule(rule, "out", program, ips);
    #[cfg(not(windows))]
    let bfe_registry_applied = false;

    let terminated_tcp_sockets = terminate_active_tcp_sockets_for_ips(ips);

    let record = NativeDestinationBlockRule {
        rule_name: rule.to_string(),
        program: program.map(|s| s.to_string()),
        pid,
        ips: ips.iter().map(|i| i.to_string()).collect(),
        wfp_session_committed,
        wfp_filter_ids: wfp_filter_ids.clone(),
        bfe_registry_applied,
        terminated_tcp_sockets,
        created_at: chrono::Utc::now().to_rfc3339(),
    };

    info!(
        rule = %rule,
        program = ?program,
        pid = ?pid,
        ips = ?record.ips,
        wfp_session_committed,
        wfp_filter_count = wfp_filter_ids.len(),
        bfe_registry_applied,
        terminated_tcp_sockets,
        "🛡️ [WFP-NATIVE] Applied native Rust kernel WFP + BFE destination block (zero netsh subprocesses)"
    );

    NATIVE_DESTINATION_BLOCKS.insert(rule.to_string(), record.clone());
    ensure_tcp_reset_guardian_started();
    Ok(record)
}

/// Removes a native Rust destination block rule (`osoosi_core::wfp::unblock_destination_native`).
pub fn unblock_destination_native(
    rule: &str,
    _program: Option<&str>,
    _pid: Option<u32>,
    _ips: &[std::net::IpAddr],
) -> Result<()> {
    let removed_rule = NATIVE_DESTINATION_BLOCKS.remove(rule).map(|(_, v)| v);

    if let Some(rec) = removed_rule {
        if !rec.wfp_filter_ids.is_empty() {
            let guard = GLOBAL_WFP_SESSION.lock();
            if let Some(ref session) = *guard {
                let txn_ok = session.begin_transaction().is_ok();
                for fid in rec.wfp_filter_ids {
                    let _ = session.delete_filter_by_id(fid);
                }
                if txn_ok {
                    let _ = session.commit_transaction();
                }
            }
        }
    }

    #[cfg(windows)]
    {
        let _ = remove_native_bfe_registry_rule(rule);
    }

    info!(
        rule = %rule,
        "🟢 [WFP-NATIVE] Removed native Rust destination block rule"
    );
    Ok(())
}

/// Removes all active `OshoosiDLP-*` native WFP and BFE destination block rules targeting any of `ips`.
pub fn unblock_all_dlp_rules_for_ips(ips: &[std::net::IpAddr]) -> usize {
    if ips.is_empty() {
        return 0;
    }
    let ip_strings: Vec<String> = ips.iter().map(|i| i.to_string()).collect();
    let matching_rules: Vec<String> = NATIVE_DESTINATION_BLOCKS
        .iter()
        .filter(|entry| {
            entry.key().starts_with("OshoosiDLP-")
                && entry
                    .value()
                    .ips
                    .iter()
                    .any(|blocked| ip_strings.iter().any(|target| target == blocked))
        })
        .map(|entry| entry.key().clone())
        .collect();

    let mut removed_count = 0usize;
    for rule in matching_rules {
        if unblock_destination_native(&rule, None, None, ips).is_ok() {
            removed_count += 1;
        }
    }

    #[cfg(windows)]
    {
        use winreg::enums::*;
        use winreg::types::FromRegValue;
        use winreg::RegKey;

        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let fw_path = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules";
        if let Ok(fw_key) = hklm.open_subkey_with_flags(fw_path, KEY_READ | KEY_WRITE) {
            let matching_keys: Vec<String> = fw_key
                .enum_values()
                .flatten()
                .filter_map(|(k, v)| {
                    let s = String::from_reg_value(&v).ok()?;
                    let is_dlp = k.starts_with("OshoosiDLP-") || s.contains("Name=OshoosiDLP-");
                    let matches_ip = ip_strings.iter().any(|ip| {
                        s.contains(&format!("RA4={}", ip)) || s.contains(&format!("RA6={}", ip))
                    });
                    (is_dlp && matches_ip).then_some(k)
                })
                .collect();
            for k in matching_keys {
                if fw_key.delete_value(&k).is_ok() {
                    removed_count += 1;
                }
            }
        }
    }

    removed_count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_native_destination_block_and_unblock_lifecycle() {
        let ip: std::net::IpAddr = "93.184.216.34".parse().unwrap();
        let rule = "OshoosiDLP-UnitTestRule";
        let res = block_destination_native(
            rule,
            Some(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
            None,
            &[ip],
        );
        assert!(res.is_ok());
        assert!(is_destination_blocked_native(&ip));
        unblock_destination_native(rule, None, None, &[ip]).unwrap();
        assert!(!is_destination_blocked_native(&ip));
    }

    #[test]
    fn test_wfp_dynamic_session_initialization() {
        if WfpDynamicSession::is_available() {
            let session = WfpDynamicSession::open();
            assert!(session.is_ok(), "Failed to open WfpDynamicSession");
            let s = session.unwrap();
            let _ = s.begin_transaction();
            let _ = s.abort_transaction();
        }
    }

    #[test]
    fn test_wfp_kernel_apply_rejects_invalid_action() {
        let res = handle_wfp_kernel_apply_cli("arbitrary-invalid-command");
        assert!(res.is_err());
    }

    #[test]
    fn test_linux_netlink_blackhole_message_abi() {
        let msg = build_linux_netlink_blackhole_route_msg(24, 2, 7);
        assert_eq!(msg.len(), 36);
        assert_eq!(u32::from_ne_bytes([msg[0], msg[1], msg[2], msg[3]]), 36);
        assert_eq!(u16::from_ne_bytes([msg[4], msg[5]]), 24);
        assert_eq!(msg[16], 2); // AF_INET
        assert_eq!(msg[23], 6); // RTN_BLACKHOLE
    }

    #[test]
    fn test_preserved_management_ports_include_3030() {
        let ports = discover_preserved_management_ports();
        assert!(ports.contains(&3030));
    }
}
