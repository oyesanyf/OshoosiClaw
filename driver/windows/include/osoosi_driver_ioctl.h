#ifndef OSOOSI_DRIVER_IOCTL_H
#define OSOOSI_DRIVER_IOCTL_H

#ifdef _KERNEL_MODE
#include "wdk_abi_compat.h"
#else
#include <windows.h>
#include <winioctl.h>
#endif

// Driver Device Names
#define OSOOSI_DEVICE_NAME          L"\\Device\\OsoosiDriver"
#define OSOOSI_DOS_DEVICE_NAME      L"\\DosDevices\\OsoosiDriver"
#define OSOOSI_USER_DEVICE_NAME     L"\\\\.\\OsoosiDriver"

// ELAM Driver Device & Registry Names
#define OSOOSI_ELAM_SERVICE_NAME    L"OsoosiElam"
#define OSOOSI_MINIFILTER_ALTITUDE  L"385200"

// Driver GUID: {b1df5f37-14e2-45e6-bb7c-38da0efcb02d}
#define OSOOSI_DRIVER_GUID_STRING   "{b1df5f37-14e2-45e6-bb7c-38da0efcb02d}"

// Driver Version: 1.2.0 (PPL + ObRegisterCallbacks + Minifilter + BYOVD + ELAM)
#define OSOOSI_DRIVER_VERSION       0x00010200

// Autonomy Modes
#define OSOOSI_MODE_AUDIT           0
#define OSOOSI_MODE_ACTIVE          1
#define OSOOSI_MODE_LOCKDOWN        2

// Intercept Event Types (stored in intercept_type / _reserved slot)
#define OSOOSI_INTERCEPT_PROCESS_EXEC           0
#define OSOOSI_INTERCEPT_HANDLE_STRIP           1
#define OSOOSI_INTERCEPT_BYOVD_BLOCK            2
#define OSOOSI_INTERCEPT_MINIFILTER_TAMPER      3

// Buffer Limits
#define OSOOSI_MAX_PATH             260
#define OSOOSI_MAX_CMDLINE          512
#define OSOOSI_HASH_SIZE            32
#define OSOOSI_MAX_QUEUED_EVENTS    256

// IOCTL Definitions
#define OSOOSI_IOCTL_BASE           0x800

#define IOCTL_OSOOSI_GET_STATUS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, OSOOSI_IOCTL_BASE + 0, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_OSOOSI_SET_MODE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, OSOOSI_IOCTL_BASE + 1, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define IOCTL_OSOOSI_ADD_BLOCK_PATH \
    CTL_CODE(FILE_DEVICE_UNKNOWN, OSOOSI_IOCTL_BASE + 2, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_OSOOSI_ADD_BLOCK_HASH \
    CTL_CODE(FILE_DEVICE_UNKNOWN, OSOOSI_IOCTL_BASE + 3, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_OSOOSI_CLEAR_RULES \
    CTL_CODE(FILE_DEVICE_UNKNOWN, OSOOSI_IOCTL_BASE + 4, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define IOCTL_OSOOSI_POLL_INTERCEPTIONS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, OSOOSI_IOCTL_BASE + 5, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_OSOOSI_PROTECT_PID \
    CTL_CODE(FILE_DEVICE_UNKNOWN, OSOOSI_IOCTL_BASE + 6, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define IOCTL_OSOOSI_ADD_BYOVD_RULE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, OSOOSI_IOCTL_BASE + 7, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define IOCTL_OSOOSI_GET_EXTENDED_STATUS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, OSOOSI_IOCTL_BASE + 8, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Driver Status Response Structure (16 bytes - backwards-compatible)
typedef struct _OSOOSI_DRIVER_STATUS {
    ULONG version;          // Driver version (e.g., 0x00010200)
    ULONG mode;             // 0=Audit, 1=Active, 2=Lockdown
    ULONG blocked_count;    // Total processes blocked since startup
    ULONG rule_count;       // Active block rules in kernel memory
} OSOOSI_DRIVER_STATUS, *POSOOSI_DRIVER_STATUS;

// Extended Ring-0 Status Structure (48 bytes)
typedef struct _OSOOSI_EXTENDED_DRIVER_STATUS {
    ULONG version;                  // Driver version (0x00010200)
    ULONG mode;                     // 0=Audit, 1=Active, 2=Lockdown
    ULONG blocked_count;            // Total processes blocked since startup
    ULONG rule_count;               // Active block rules in kernel memory
    ULONG protected_pid;            // Protected user-mode sensor PID (osoosi.exe)
    ULONG ob_callbacks_active;      // 1 if ObRegisterCallbacks handle guard is active
    ULONG image_load_notify_active; // 1 if PsSetLoadImageNotifyRoutine BYOVD guard is active
    ULONG minifilter_active;        // 1 if Minifilter / IRP self-defense is active
    ULONG elam_registered;          // 1 if ELAM boot-driver protection is active
    ULONG byovd_blocked_count;      // Total BYOVD vulnerable drivers blocked
    ULONG handle_stripped_count;    // Total untrusted handle open/dup operations stripped
    ULONG minifilter_blocked_count; // Total config/binary tamper attempts blocked
} OSOOSI_EXTENDED_DRIVER_STATUS, *POSOOSI_EXTENDED_DRIVER_STATUS;

// Pre-Execution / Ring-0 Intercept Event Structure (1568 bytes)
typedef struct _OSOOSI_INTERCEPT_EVENT {
    ULONG pid;
    ULONG parent_pid;
    WCHAR image_path[OSOOSI_MAX_PATH];
    WCHAR command_line[OSOOSI_MAX_CMDLINE];
    LARGE_INTEGER timestamp;
    ULONG blocked;          // 1 if blocked/stripped, 0 if audited
    ULONG intercept_type;   // 0=ProcessExec, 1=HandleStrip, 2=ByovdBlock, 3=MinifilterTamper
} OSOOSI_INTERCEPT_EVENT, *POSOOSI_INTERCEPT_EVENT;

// Set Autonomy Mode Request
typedef struct _OSOOSI_SET_MODE_REQUEST {
    ULONG mode;
} OSOOSI_SET_MODE_REQUEST, *POSOOSI_SET_MODE_REQUEST;

// Add Blocked Path Request
typedef struct _OSOOSI_ADD_PATH_REQUEST {
    WCHAR image_path[OSOOSI_MAX_PATH];
} OSOOSI_ADD_PATH_REQUEST, *POSOOSI_ADD_PATH_REQUEST;

// Add Blocked Hash Request
typedef struct _OSOOSI_ADD_HASH_REQUEST {
    UCHAR hash[OSOOSI_HASH_SIZE];
} OSOOSI_ADD_HASH_REQUEST, *POSOOSI_ADD_HASH_REQUEST;

// Protect Sensor PID Request (ObRegisterCallbacks + Minifilter Self-Defense)
typedef struct _OSOOSI_PROTECT_PID_REQUEST {
    ULONG pid;
    ULONG enable_protection;
} OSOOSI_PROTECT_PID_REQUEST, *POSOOSI_PROTECT_PID_REQUEST;

// Add BYOVD Vulnerable Driver Rule Request
typedef struct _OSOOSI_ADD_BYOVD_REQUEST {
    WCHAR driver_name[OSOOSI_MAX_PATH];
    UCHAR sha256[OSOOSI_HASH_SIZE];
    ULONG has_hash;
} OSOOSI_ADD_BYOVD_REQUEST, *POSOOSI_ADD_BYOVD_REQUEST;

#endif // OSOOSI_DRIVER_IOCTL_H
