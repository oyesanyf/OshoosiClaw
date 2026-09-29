/*
 * OshoosiClaw Windows Ring-0 Kernel Filter Driver
 * 
 * Provides hardware-enforced pre-operation process execution blocking
 * via PsSetCreateProcessNotifyRoutineEx before Sysmon Event 1 can fire
 * and before the initial thread starts.
 */

#include <ntddk.h>
#include "../include/osoosi_driver_ioctl.h"

#define OSOOSI_POOL_TAG 'sOso'

// Memory node for path block rules
typedef struct _OSOOSI_PATH_RULE {
    LIST_ENTRY ListEntry;
    WCHAR Path[OSOOSI_MAX_PATH];
    ULONG Length;
} OSOOSI_PATH_RULE, *POSOOSI_PATH_RULE;

// Memory node for hash block rules
typedef struct _OSOOSI_HASH_RULE {
    LIST_ENTRY ListEntry;
    UCHAR Hash[OSOOSI_HASH_SIZE];
} OSOOSI_HASH_RULE, *POSOOSI_HASH_RULE;

// Driver global state
typedef struct _OSOOSI_GLOBAL_STATE {
    KSPIN_LOCK Lock;
    ULONG Version;
    ULONG Mode;
    ULONG BlockedCount;
    ULONG RuleCount;
    LIST_ENTRY PathRuleList;
    LIST_ENTRY HashRuleList;

    // Circular ring queue for intercepted events
    OSOOSI_INTERCEPT_EVENT EventQueue[OSOOSI_MAX_QUEUED_EVENTS];
    ULONG EventHead;
    ULONG EventTail;
    ULONG QueuedEventCount;

    PDEVICE_OBJECT DeviceObject;
    BOOLEAN NotifyRoutineRegistered;
} OSOOSI_GLOBAL_STATE, *POSOOSI_GLOBAL_STATE;

static OSOOSI_GLOBAL_STATE g_State;

// Critical infrastructure images protected from blocking
static const PCWSTR g_ProtectedImages[] = {
    L"sysmon64.exe",
    L"sysmon.exe",
    L"osoosi.exe",
    L"msmpeng.exe",
    L"csrss.exe",
    L"smss.exe",
    L"wininit.exe",
    L"services.exe",
    L"lsass.exe"
};

// Forward declarations
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;
_Dispatch_type_(IRP_MJ_CREATE) _Dispatch_type_(IRP_MJ_CLOSE)
DRIVER_DISPATCH OsoosiCreateClose;
_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH OsoosiDeviceControl;

VOID OsoosiCreateProcessNotifyRoutine(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
);

static VOID OsoosiClearRulesLocked(VOID);
static BOOLEAN OsoosiIsCriticalSystemImage(_In_ PCUNICODE_STRING ImageFileName);
static BOOLEAN OsoosiIsPathBlockedLocked(_In_ PCUNICODE_STRING ImageFileName);
static BOOLEAN OsoosiIsHashBlockedLocked(_In_reads_(32) const UCHAR* Hash);

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
) {
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;
    UNICODE_STRING devName;
    UNICODE_STRING dosName;

    RtlZeroMemory(&g_State, sizeof(OSOOSI_GLOBAL_STATE));
    KeInitializeSpinLock(&g_State.Lock);
    g_State.Version = OSOOSI_DRIVER_VERSION;
    g_State.Mode = OSOOSI_MODE_ACTIVE;
    InitializeListHead(&g_State.PathRuleList);
    InitializeListHead(&g_State.HashRuleList);

    RtlInitUnicodeString(&devName, OSOOSI_DEVICE_NAME);
    RtlInitUnicodeString(&dosName, OSOOSI_DOS_DEVICE_NAME);

    status = IoCreateDevice(
        DriverObject,
        0,
        &devName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &g_State.DeviceObject
    );

    if (!NT_SUCCESS(status)) {
        KdPrint(("OsoosiDriver: IoCreateDevice failed with 0x%08X\n", status));
        return status;
    }

    status = IoCreateSymbolicLink(&dosName, &devName);
    if (!NT_SUCCESS(status)) {
        KdPrint(("OsoosiDriver: IoCreateSymbolicLink failed with 0x%08X\n", status));
        IoDeleteDevice(g_State.DeviceObject);
        return status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = OsoosiCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = OsoosiCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = OsoosiDeviceControl;
    DriverObject->DriverUnload = DriverUnload;

    // Register process pre-creation callback (Ex)
    status = PsSetCreateProcessNotifyRoutineEx(OsoosiCreateProcessNotifyRoutine, FALSE);
    if (!NT_SUCCESS(status)) {
        KdPrint(("OsoosiDriver: PsSetCreateProcessNotifyRoutineEx failed with 0x%08X\n", status));
        IoDeleteSymbolicLink(&dosName);
        IoDeleteDevice(g_State.DeviceObject);
        return status;
    }

    g_State.NotifyRoutineRegistered = TRUE;
    KdPrint(("OsoosiDriver: Ring-0 Driver loaded successfully. Pre-exec blocking active.\n"));
    return STATUS_SUCCESS;
}

VOID DriverUnload(
    _In_ PDRIVER_OBJECT DriverObject
) {
    UNICODE_STRING dosName;
    KLOCK_QUEUE_HANDLE lockHandle;

    UNREFERENCED_PARAMETER(DriverObject);

    if (g_State.NotifyRoutineRegistered) {
        PsSetCreateProcessNotifyRoutineEx(OsoosiCreateProcessNotifyRoutine, TRUE);
        g_State.NotifyRoutineRegistered = FALSE;
    }

    RtlInitUnicodeString(&dosName, OSOOSI_DOS_DEVICE_NAME);
    IoDeleteSymbolicLink(&dosName);

    KeAcquireInStackQueuedSpinLock(&g_State.Lock, &lockHandle);
    OsoosiClearRulesLocked();
    KeReleaseInStackQueuedSpinLock(&lockHandle);

    if (g_State.DeviceObject != NULL) {
        IoDeleteDevice(g_State.DeviceObject);
        g_State.DeviceObject = NULL;
    }

    KdPrint(("OsoosiDriver: Ring-0 Driver unloaded.\n"));
}

NTSTATUS OsoosiCreateClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
) {
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS OsoosiDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
) {
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG controlCode = stack->Parameters.DeviceIoControl.IoControlCode;
    ULONG inputLength = stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outputLength = stack->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID buffer = Irp->AssociatedIrp.SystemBuffer;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG_PTR bytesReturned = 0;
    KLOCK_QUEUE_HANDLE lockHandle;

    switch (controlCode) {
    case IOCTL_OSOOSI_GET_STATUS: {
        if (outputLength < sizeof(OSOOSI_DRIVER_STATUS)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        POSOOSI_DRIVER_STATUS pStatus = (POSOOSI_DRIVER_STATUS)buffer;
        KeAcquireInStackQueuedSpinLock(&g_State.Lock, &lockHandle);
        pStatus->version = g_State.Version;
        pStatus->mode = g_State.Mode;
        pStatus->blocked_count = g_State.BlockedCount;
        pStatus->rule_count = g_State.RuleCount;
        KeReleaseInStackQueuedSpinLock(&lockHandle);

        bytesReturned = sizeof(OSOOSI_DRIVER_STATUS);
        break;
    }

    case IOCTL_OSOOSI_SET_MODE: {
        if (inputLength < sizeof(OSOOSI_SET_MODE_REQUEST)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        POSOOSI_SET_MODE_REQUEST pReq = (POSOOSI_SET_MODE_REQUEST)buffer;
        if (pReq->mode > OSOOSI_MODE_LOCKDOWN) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        KeAcquireInStackQueuedSpinLock(&g_State.Lock, &lockHandle);
        g_State.Mode = pReq->mode;
        KeReleaseInStackQueuedSpinLock(&lockHandle);

        bytesReturned = 0;
        break;
    }

    case IOCTL_OSOOSI_ADD_BLOCK_PATH: {
        if (inputLength < sizeof(OSOOSI_ADD_PATH_REQUEST)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        POSOOSI_ADD_PATH_REQUEST pReq = (POSOOSI_ADD_PATH_REQUEST)buffer;
        // Ensure null-termination within buffer
        pReq->image_path[OSOOSI_MAX_PATH - 1] = L'\0';

        // Normalize forward slashes to backslashes
        for (ULONG k = 0; k < OSOOSI_MAX_PATH && pReq->image_path[k] != L'\0'; ++k) {
            if (pReq->image_path[k] == L'/') {
                pReq->image_path[k] = L'\\';
            }
        }

        POSOOSI_PATH_RULE rule = (POSOOSI_PATH_RULE)ExAllocatePoolWithTag(
            NonPagedPoolNx,
            sizeof(OSOOSI_PATH_RULE),
            OSOOSI_POOL_TAG
        );

        if (rule == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        RtlZeroMemory(rule, sizeof(OSOOSI_PATH_RULE));
        wcsncpy(rule->Path, pReq->image_path, OSOOSI_MAX_PATH - 1);
        rule->Length = (ULONG)wcslen(rule->Path);

        KeAcquireInStackQueuedSpinLock(&g_State.Lock, &lockHandle);
        InsertTailList(&g_State.PathRuleList, &rule->ListEntry);
        g_State.RuleCount++;
        KeReleaseInStackQueuedSpinLock(&lockHandle);

        bytesReturned = 0;
        break;
    }

    case IOCTL_OSOOSI_ADD_BLOCK_HASH: {
        if (inputLength < sizeof(OSOOSI_ADD_HASH_REQUEST)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        POSOOSI_ADD_HASH_REQUEST pReq = (POSOOSI_ADD_HASH_REQUEST)buffer;

        POSOOSI_HASH_RULE rule = (POSOOSI_HASH_RULE)ExAllocatePoolWithTag(
            NonPagedPoolNx,
            sizeof(OSOOSI_HASH_RULE),
            OSOOSI_POOL_TAG
        );

        if (rule == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        RtlZeroMemory(rule, sizeof(OSOOSI_HASH_RULE));
        RtlCopyMemory(rule->Hash, pReq->hash, OSOOSI_HASH_SIZE);

        KeAcquireInStackQueuedSpinLock(&g_State.Lock, &lockHandle);
        InsertTailList(&g_State.HashRuleList, &rule->ListEntry);
        g_State.RuleCount++;
        KeReleaseInStackQueuedSpinLock(&lockHandle);

        bytesReturned = 0;
        break;
    }

    case IOCTL_OSOOSI_CLEAR_RULES: {
        KeAcquireInStackQueuedSpinLock(&g_State.Lock, &lockHandle);
        OsoosiClearRulesLocked();
        KeReleaseInStackQueuedSpinLock(&lockHandle);

        bytesReturned = 0;
        break;
    }

    case IOCTL_OSOOSI_POLL_INTERCEPTIONS: {
        if (outputLength < sizeof(OSOOSI_INTERCEPT_EVENT)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        ULONG maxEvents = outputLength / sizeof(OSOOSI_INTERCEPT_EVENT);
        ULONG copiedEvents = 0;
        POSOOSI_INTERCEPT_EVENT outEvents = (POSOOSI_INTERCEPT_EVENT)buffer;

        KeAcquireInStackQueuedSpinLock(&g_State.Lock, &lockHandle);
        while (g_State.QueuedEventCount > 0 && copiedEvents < maxEvents) {
            RtlCopyMemory(
                &outEvents[copiedEvents],
                &g_State.EventQueue[g_State.EventHead],
                sizeof(OSOOSI_INTERCEPT_EVENT)
            );
            g_State.EventHead = (g_State.EventHead + 1) % OSOOSI_MAX_QUEUED_EVENTS;
            g_State.QueuedEventCount--;
            copiedEvents++;
        }
        KeReleaseInStackQueuedSpinLock(&lockHandle);

        bytesReturned = copiedEvents * sizeof(OSOOSI_INTERCEPT_EVENT);
        break;
    }

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesReturned;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

static VOID OsoosiClearRulesLocked(VOID) {
    while (!IsListEmpty(&g_State.PathRuleList)) {
        PLIST_ENTRY entry = RemoveHeadList(&g_State.PathRuleList);
        POSOOSI_PATH_RULE rule = CONTAINING_RECORD(entry, OSOOSI_PATH_RULE, ListEntry);
        ExFreePoolWithTag(rule, OSOOSI_POOL_TAG);
    }

    while (!IsListEmpty(&g_State.HashRuleList)) {
        PLIST_ENTRY entry = RemoveHeadList(&g_State.HashRuleList);
        POSOOSI_HASH_RULE rule = CONTAINING_RECORD(entry, OSOOSI_HASH_RULE, ListEntry);
        ExFreePoolWithTag(rule, OSOOSI_POOL_TAG);
    }

    g_State.RuleCount = 0;
}

static WCHAR OsoosiToUpper(WCHAR c) {
    if (c >= L'a' && c <= L'z') {
        return c - (L'a' - L'A');
    }
    return c;
}

static BOOLEAN OsoosiContainsSubstrInsensitive(
    _In_reads_(haystackLen) PCWSTR haystack,
    _In_ ULONG haystackLen,
    _In_reads_(needleLen) PCWSTR needle,
    _In_ ULONG needleLen
) {
    if (haystack == NULL || needle == NULL || needleLen == 0 || haystackLen < needleLen) {
        return FALSE;
    }

    ULONG maxStart = haystackLen - needleLen;
    for (ULONG i = 0; i <= maxStart; ++i) {
        BOOLEAN match = TRUE;
        for (ULONG j = 0; j < needleLen; ++j) {
            if (OsoosiToUpper(haystack[i + j]) != OsoosiToUpper(needle[j])) {
                match = FALSE;
                break;
            }
        }
        if (match) {
            return TRUE;
        }
    }
    return FALSE;
}

static BOOLEAN OsoosiIsCriticalSystemImage(_In_ PCUNICODE_STRING ImageFileName) {
    if (ImageFileName == NULL || ImageFileName->Buffer == NULL || ImageFileName->Length == 0) {
        return FALSE;
    }

    ULONG imgChars = ImageFileName->Length / sizeof(WCHAR);

    for (ULONG i = 0; i < sizeof(g_ProtectedImages) / sizeof(g_ProtectedImages[0]); ++i) {
        ULONG protLen = (ULONG)wcslen(g_ProtectedImages[i]);
        if (OsoosiContainsSubstrInsensitive(ImageFileName->Buffer, imgChars, g_ProtectedImages[i], protLen)) {
            return TRUE;
        }
    }

    return FALSE;
}

static BOOLEAN OsoosiIsPathBlockedLocked(_In_ PCUNICODE_STRING ImageFileName) {
    if (ImageFileName == NULL || ImageFileName->Buffer == NULL || ImageFileName->Length == 0) {
        return FALSE;
    }

    ULONG imgChars = ImageFileName->Length / sizeof(WCHAR);

    PLIST_ENTRY curr = g_State.PathRuleList.Flink;
    while (curr != &g_State.PathRuleList) {
        POSOOSI_PATH_RULE rule = CONTAINING_RECORD(curr, OSOOSI_PATH_RULE, ListEntry);
        if (rule->Length > 0) {
            PCWSTR checkPath = rule->Path;
            ULONG checkLen = rule->Length;

            // If rule has a DOS drive prefix (e.g., "C:\..."), strip the drive letter and colon
            // because kernel ImageFileName is an NT device path (e.g., "\Device\HarddiskVolume3\...")
            if (checkLen >= 2 && checkPath[1] == L':') {
                checkPath += 2;
                checkLen -= 2;
            }

            if (checkLen > 0 && OsoosiContainsSubstrInsensitive(ImageFileName->Buffer, imgChars, checkPath, checkLen)) {
                return TRUE;
            }
        }
        curr = curr->Flink;
    }

    return FALSE;
}

static BOOLEAN OsoosiIsHashBlockedLocked(_In_reads_(32) const UCHAR* Hash) {
    if (Hash == NULL) {
        return FALSE;
    }

    PLIST_ENTRY curr = g_State.HashRuleList.Flink;
    while (curr != &g_State.HashRuleList) {
        POSOOSI_HASH_RULE rule = CONTAINING_RECORD(curr, OSOOSI_HASH_RULE, ListEntry);
        if (RtlCompareMemory(rule->Hash, Hash, OSOOSI_HASH_SIZE) == OSOOSI_HASH_SIZE) {
            return TRUE;
        }
        curr = curr->Flink;
    }

    return FALSE;
}

VOID OsoosiCreateProcessNotifyRoutine(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
) {
    UNREFERENCED_PARAMETER(Process);
    KLOCK_QUEUE_HANDLE lockHandle;

    // Only process creation is intercepted (CreateInfo == NULL indicates process exit)
    if (CreateInfo == NULL) {
        return;
    }

    ULONG pid = HandleToULong(ProcessId);
    ULONG parentPid = HandleToULong(CreateInfo->ParentProcessId);

    // Safeguard: Never block system processes (PIDs 0, 4)
    if (pid <= 4 || parentPid == 0) {
        return;
    }

    // Safeguard: Never block core infrastructure binaries
    if (OsoosiIsCriticalSystemImage(CreateInfo->ImageFileName)) {
        return;
    }

    KeAcquireInStackQueuedSpinLock(&g_State.Lock, &lockHandle);

    BOOLEAN isBlockedPath = OsoosiIsPathBlockedLocked(CreateInfo->ImageFileName);
    BOOLEAN shouldBlock = isBlockedPath && (g_State.Mode >= OSOOSI_MODE_ACTIVE);

    if (shouldBlock || (isBlockedPath && g_State.Mode == OSOOSI_MODE_AUDIT)) {
        // Enqueue event for user-space telemetry
        if (g_State.QueuedEventCount < OSOOSI_MAX_QUEUED_EVENTS) {
            POSOOSI_INTERCEPT_EVENT ev = &g_State.EventQueue[g_State.EventTail];
            RtlZeroMemory(ev, sizeof(OSOOSI_INTERCEPT_EVENT));
            ev->pid = pid;
            ev->parent_pid = parentPid;
            ev->blocked = shouldBlock ? 1 : 0;
            KeQuerySystemTime(&ev->timestamp);

            if (CreateInfo->ImageFileName != NULL && CreateInfo->ImageFileName->Buffer != NULL) {
                USHORT charsToCopy = CreateInfo->ImageFileName->Length / sizeof(WCHAR);
                if (charsToCopy >= OSOOSI_MAX_PATH) {
                    charsToCopy = OSOOSI_MAX_PATH - 1;
                }
                RtlCopyMemory(ev->image_path, CreateInfo->ImageFileName->Buffer, charsToCopy * sizeof(WCHAR));
                ev->image_path[charsToCopy] = L'\0';
            }

            if (CreateInfo->CommandLine != NULL && CreateInfo->CommandLine->Buffer != NULL) {
                USHORT cmdChars = CreateInfo->CommandLine->Length / sizeof(WCHAR);
                if (cmdChars >= OSOOSI_MAX_CMDLINE) {
                    cmdChars = OSOOSI_MAX_CMDLINE - 1;
                }
                RtlCopyMemory(ev->command_line, CreateInfo->CommandLine->Buffer, cmdChars * sizeof(WCHAR));
                ev->command_line[cmdChars] = L'\0';
            }

            g_State.EventTail = (g_State.EventTail + 1) % OSOOSI_MAX_QUEUED_EVENTS;
            g_State.QueuedEventCount++;
        }

        if (shouldBlock) {
            g_State.BlockedCount++;
            // Pre-operation execution block: stops the process before thread creation
            // and before Sysmon Event 1 or any other user-mode EDR hook can execute!
            CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
            KdPrint(("OsoosiDriver: BLOCKED process creation: PID=%lu, Image=%wZ\n", pid, CreateInfo->ImageFileName));
        }
    }

    KeReleaseInStackQueuedSpinLock(&lockHandle);
}
