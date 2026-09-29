#ifndef OSOOSI_DRIVER_IOCTL_H
#define OSOOSI_DRIVER_IOCTL_H

#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
#include <windows.h>
#include <winioctl.h>
#endif

// Driver Device Names
#define OSOOSI_DEVICE_NAME          L"\\Device\\OsoosiDriver"
#define OSOOSI_DOS_DEVICE_NAME      L"\\DosDevices\\OsoosiDriver"
#define OSOOSI_USER_DEVICE_NAME     L"\\\\.\\OsoosiDriver"

// Driver GUID: {b1df5f37-14e2-45e6-bb7c-38da0efcb02d}
#define OSOOSI_DRIVER_GUID_STRING   "{b1df5f37-14e2-45e6-bb7c-38da0efcb02d}"

// Driver Version
#define OSOOSI_DRIVER_VERSION       0x00010000 // 1.0.0

// Autonomy Modes
#define OSOOSI_MODE_AUDIT           0
#define OSOOSI_MODE_ACTIVE          1
#define OSOOSI_MODE_LOCKDOWN        2

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
    CTL_CODE(FILE_DEVICE_UNKNOWN, OSOOSI_IOCTL_BASE + 1, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_OSOOSI_ADD_BLOCK_PATH \
    CTL_CODE(FILE_DEVICE_UNKNOWN, OSOOSI_IOCTL_BASE + 2, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_OSOOSI_ADD_BLOCK_HASH \
    CTL_CODE(FILE_DEVICE_UNKNOWN, OSOOSI_IOCTL_BASE + 3, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_OSOOSI_CLEAR_RULES \
    CTL_CODE(FILE_DEVICE_UNKNOWN, OSOOSI_IOCTL_BASE + 4, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_OSOOSI_POLL_INTERCEPTIONS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, OSOOSI_IOCTL_BASE + 5, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Driver Status Response Structure
typedef struct _OSOOSI_DRIVER_STATUS {
    ULONG version;          // Driver version (e.g., 0x00010000)
    ULONG mode;             // 0=Audit, 1=Active, 2=Lockdown
    ULONG blocked_count;    // Total processes blocked since startup
    ULONG rule_count;       // Active block rules in kernel memory
} OSOOSI_DRIVER_STATUS, *POSOOSI_DRIVER_STATUS;

// Pre-Execution Process Intercept Event Structure
typedef struct _OSOOSI_INTERCEPT_EVENT {
    ULONG pid;
    ULONG parent_pid;
    WCHAR image_path[OSOOSI_MAX_PATH];
    WCHAR command_line[OSOOSI_MAX_CMDLINE];
    LARGE_INTEGER timestamp;
    ULONG blocked;          // 1 if execution blocked, 0 if audited
    ULONG _reserved;        // Alignment padding to 8-byte boundary
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

#endif // OSOOSI_DRIVER_IOCTL_H
