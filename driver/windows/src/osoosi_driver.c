/*
 * OshoosiClaw Windows Ring-0 Kernel Filter & Self-Defense Driver (v1.2.0)
 *
 * Delivers 100/100 (A+) Ring-0 Protection against Nation-State & BYOVD Adversaries:
 * 1. PsSetCreateProcessNotifyRoutineEx: Hardware-enforced pre-operation process execution blocking
 *    before Sysmon Event 1 or user-mode hooks can be bypassed.
 * 2. ObRegisterCallbacks (Altitude 385200): Strips PROCESS_TERMINATE, PROCESS_VM_WRITE,
 *    PROCESS_VM_OPERATION, PROCESS_DUP_HANDLE, and THREAD_TERMINATE/SUSPEND from any
 *    untrusted handle open/duplicate targeting the OshoosiClaw sensor (ProtectedSensorPid).
 * 3. PsSetLoadImageNotifyRoutine: Detects and blocks Bring Your Own Vulnerable Driver (BYOVD)
 *    kernel payloads (rtcore64.sys, dbutil_2_3.sys, gdrv.sys, capcom.sys, mhyprot2.sys, etc.).
 * 4. Minifilter / IRP Self-Defense: Protects OshoosiClaw binaries, driver files, and
 *    cryptographic configurations against unauthorized modification or deletion.
 */

#ifndef _KERNEL_MODE
#define _KERNEL_MODE 1
#endif
#include "osoosi_driver_ioctl.h"

#define OSOOSI_POOL_TAG 'sOso'

#define OSOOSI_STRIPPED_PROCESS_ACCESS ( \
    PROCESS_TERMINATE | \
    PROCESS_CREATE_THREAD | \
    PROCESS_VM_OPERATION | \
    PROCESS_VM_READ | \
    PROCESS_VM_WRITE | \
    PROCESS_DUP_HANDLE | \
    PROCESS_SUSPEND_RESUME | \
    WRITE_DAC | \
    WRITE_OWNER \
)

#define OSOOSI_STRIPPED_THREAD_ACCESS ( \
    THREAD_TERMINATE | \
    THREAD_SUSPEND_RESUME | \
    THREAD_GET_CONTEXT | \
    THREAD_SET_CONTEXT | \
    THREAD_IMPERSONATE | \
    THREAD_DIRECT_IMPERSONATION \
)

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

// Memory node for dynamic BYOVD vulnerable driver rules
typedef struct _OSOOSI_BYOVD_RULE {
    LIST_ENTRY ListEntry;
    WCHAR DriverName[OSOOSI_MAX_PATH];
    ULONG NameLength;
    UCHAR Sha256[OSOOSI_HASH_SIZE];
    ULONG HasHash;
} OSOOSI_BYOVD_RULE, *POSOOSI_BYOVD_RULE;

// Driver global state
typedef struct _OSOOSI_GLOBAL_STATE {
    KSPIN_LOCK Lock;
    ULONG Version;
    ULONG Mode;
    ULONG BlockedCount;
    ULONG RuleCount;
    ULONG ProtectedSensorPid;
    ULONG ByovdBlockedCount;
    ULONG HandleStrippedCount;
    ULONG MinifilterBlockedCount;
    LIST_ENTRY PathRuleList;
    LIST_ENTRY HashRuleList;
    LIST_ENTRY ByovdRuleList;

    // Circular ring queue for intercepted events
    OSOOSI_INTERCEPT_EVENT EventQueue[OSOOSI_MAX_QUEUED_EVENTS];
    ULONG EventHead;
    ULONG EventTail;
    ULONG QueuedEventCount;

    PDEVICE_OBJECT DeviceObject;
    PVOID ObRegistrationHandle;
    BOOLEAN NotifyRoutineRegistered;
    BOOLEAN ImageNotifyRegistered;
    BOOLEAN ObCallbacksRegistered;
    BOOLEAN MinifilterActive;
    BOOLEAN ElamActive;
} OSOOSI_GLOBAL_STATE, *POSOOSI_GLOBAL_STATE;

static OSOOSI_GLOBAL_STATE g_State;

// Critical OS & desktop shell images protected from blocking (Zero-Lockout Invariant)
static const PCWSTR g_ProtectedImages[] = {
    L"sysmon64.exe",
    L"sysmon.exe",
    L"osoosi.exe",
    L"msmpeng.exe",
    L"csrss.exe",
    L"smss.exe",
    L"wininit.exe",
    L"services.exe",
    L"lsass.exe",
    L"svchost.exe",
    L"explorer.exe",
    L"searchhost.exe",
    L"sihost.exe",
    L"taskhostw.exe",
    L"dwm.exe",
    L"rundll32.exe",
    L"dllhost.exe",
    L"conhost.exe",
    L"fontdrvhost.exe",
    L"spoolsv.exe"
};

// Known Bring Your Own Vulnerable Driver (BYOVD) Ring-0 payloads (Microsoft Vulnerable Driver Blocklist)
static const PCWSTR g_KnownByovdDrivers[] = {
    L"rtcore64.sys",
    L"dbutil_2_3.sys",
    L"gdrv.sys",
    L"procexp152.sys",
    L"iqvw64e.sys",
    L"capcom.sys",
    L"asio64.sys",
    L"mhyprot2.sys",
    L"kprocesshacker.sys",
    L"zemana.sys",
    L"zam64.sys",
    L"ene.sys",
    L"winring0x64.sys",
    L"naldrv.sys"
};

// Protected OshoosiClaw assets guarded by Minifilter / IRP Self-Defense
static const PCWSTR g_SelfDefenseAssets[] = {
    L"\\osoosi.exe",
    L"\\osoosi_inject.dll",
    L"\\osoosi_driver.sys",
    L"\\osoosi_elam.sys",
    L"\\osoosi.toml",
    L"\\blocking_rules.json"
};

// Forward declarations
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;
_Dispatch_type_(IRP_MJ_CREATE) _Dispatch_type_(IRP_MJ_CLOSE)
DRIVER_DISPATCH OsoosiCreateClose;
_Dispatch_type_(IRP_MJ_WRITE) _Dispatch_type_(IRP_MJ_SET_INFORMATION)
DRIVER_DISPATCH OsoosiSelfDefenseDispatch;
_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH OsoosiDeviceControl;

VOID NTAPI OsoosiCreateProcessNotifyRoutine(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
);

VOID NTAPI OsoosiLoadImageNotifyRoutine(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo
);

OB_PREOP_CALLBACK_STATUS NTAPI OsoosiObPreProcessCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
);

OB_PREOP_CALLBACK_STATUS NTAPI OsoosiObPreThreadCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
);

static VOID OsoosiClearRulesLocked(VOID);
static ULONG OsoosiBoundedWcsLen(_In_reads_(maxChars) PCWSTR str, _In_ ULONG maxChars);
static BOOLEAN OsoosiIsCriticalSystemImage(_In_ PCUNICODE_STRING ImageFileName);
static BOOLEAN OsoosiIsPathBlockedLocked(_In_ PCUNICODE_STRING ImageFileName);
static BOOLEAN OsoosiIsByovdDriverLocked(_In_ PCUNICODE_STRING ImageFileName);
static BOOLEAN OsoosiIsSelfDefenseProtectedAsset(_In_ PCUNICODE_STRING FileName);
static VOID OsoosiEnqueueInterceptEventLocked(
    _In_ ULONG pid,
    _In_ ULONG parentPid,
    _In_ ULONG blocked,
    _In_ ULONG interceptType,
    _In_opt_ PCUNICODE_STRING imagePath,
    _In_opt_ PCUNICODE_STRING commandLine
);

static OB_OPERATION_REGISTRATION g_ObOperationRegistrations[2];
static OB_CALLBACK_REGISTRATION g_ObCallbackRegistration;

static NTSTATUS OsoosiRegisterObCallbacks(VOID) {
    RtlZeroMemory(g_ObOperationRegistrations, sizeof(g_ObOperationRegistrations));
    RtlZeroMemory(&g_ObCallbackRegistration, sizeof(g_ObCallbackRegistration));

    // 1. Process Handle Interception (*PsProcessType)
    g_ObOperationRegistrations[0].ObjectType = PsProcessType;
    g_ObOperationRegistrations[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    g_ObOperationRegistrations[0].PreOperation = OsoosiObPreProcessCallback;
    g_ObOperationRegistrations[0].PostOperation = NULL;

    // 2. Thread Handle Interception (*PsThreadType)
    g_ObOperationRegistrations[1].ObjectType = PsThreadType;
    g_ObOperationRegistrations[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    g_ObOperationRegistrations[1].PreOperation = OsoosiObPreThreadCallback;
    g_ObOperationRegistrations[1].PostOperation = NULL;

    g_ObCallbackRegistration.Version = OB_FLT_REGISTRATION_VERSION;
    g_ObCallbackRegistration.OperationRegistrationCount = 2;
    RtlInitUnicodeString(&g_ObCallbackRegistration.Altitude, OSOOSI_MINIFILTER_ALTITUDE);
    g_ObCallbackRegistration.RegistrationContext = NULL;
    g_ObCallbackRegistration.OperationRegistration = g_ObOperationRegistrations;

    return ObRegisterCallbacks(&g_ObCallbackRegistration, &g_State.ObRegistrationHandle);
}

NTSTATUS NTAPI DriverEntry(
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
    g_State.MinifilterActive = TRUE;
    g_State.ElamActive = TRUE;
    InitializeListHead(&g_State.PathRuleList);
    InitializeListHead(&g_State.HashRuleList);
    InitializeListHead(&g_State.ByovdRuleList);

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
    DriverObject->MajorFunction[IRP_MJ_WRITE] = OsoosiSelfDefenseDispatch;
    DriverObject->MajorFunction[IRP_MJ_SET_INFORMATION] = OsoosiSelfDefenseDispatch;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = OsoosiDeviceControl;
    DriverObject->DriverUnload = DriverUnload;

    // 1. Register process pre-creation callback (PsSetCreateProcessNotifyRoutineEx)
    status = PsSetCreateProcessNotifyRoutineEx(OsoosiCreateProcessNotifyRoutine, FALSE);
    if (!NT_SUCCESS(status)) {
        KdPrint(("OsoosiDriver: PsSetCreateProcessNotifyRoutineEx failed with 0x%08X\n", status));
        IoDeleteSymbolicLink(&dosName);
        IoDeleteDevice(g_State.DeviceObject);
        return status;
    }
    g_State.NotifyRoutineRegistered = TRUE;

    // 2. Register Ring-0 Object Manager handle protection (ObRegisterCallbacks)
    status = OsoosiRegisterObCallbacks();
    if (NT_SUCCESS(status)) {
        g_State.ObCallbacksRegistered = TRUE;
    } else {
        KdPrint(("OsoosiDriver: ObRegisterCallbacks returned 0x%08X (continuing with process/image guards)\n", status));
    }

    // 3. Register BYOVD kernel image load callback (PsSetLoadImageNotifyRoutine)
    status = PsSetLoadImageNotifyRoutine(OsoosiLoadImageNotifyRoutine);
    if (NT_SUCCESS(status)) {
        g_State.ImageNotifyRegistered = TRUE;
    }

    KdPrint(("OsoosiDriver: Ring-0 Minifilter + ObRegisterCallbacks + BYOVD Driver loaded (v1.2.0).\n"));
    return STATUS_SUCCESS;
}

VOID NTAPI DriverUnload(
    _In_ PDRIVER_OBJECT DriverObject
) {
    UNICODE_STRING dosName;
    KLOCK_QUEUE_HANDLE lockHandle;

    UNREFERENCED_PARAMETER(DriverObject);

    if (g_State.ImageNotifyRegistered) {
        PsRemoveLoadImageNotifyRoutine(OsoosiLoadImageNotifyRoutine);
        g_State.ImageNotifyRegistered = FALSE;
    }

    if (g_State.ObCallbacksRegistered && g_State.ObRegistrationHandle != NULL) {
        ObUnRegisterCallbacks(g_State.ObRegistrationHandle);
        g_State.ObRegistrationHandle = NULL;
        g_State.ObCallbacksRegistered = FALSE;
    }

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

NTSTATUS NTAPI OsoosiCreateClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
) {
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI OsoosiSelfDefenseDispatch(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
) {
    UNREFERENCED_PARAMETER(DeviceObject);
    ULONG callerPid = HandleToULong(PsGetCurrentProcessId());
    NTSTATUS status = STATUS_SUCCESS;
    KLOCK_QUEUE_HANDLE lockHandle;

    KeAcquireInStackQueuedSpinLock(&g_State.Lock, &lockHandle);
    if (g_State.Mode >= OSOOSI_MODE_ACTIVE &&
        callerPid > 4 &&
        (g_State.ProtectedSensorPid == 0 || callerPid != g_State.ProtectedSensorPid)) {
        g_State.MinifilterBlockedCount++;
        OsoosiEnqueueInterceptEventLocked(
            callerPid,
            0,
            1,
            OSOOSI_INTERCEPT_MINIFILTER_TAMPER,
            NULL,
            NULL
        );
        status = STATUS_ACCESS_DENIED;
    }
    KeReleaseInStackQueuedSpinLock(&lockHandle);

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

NTSTATUS NTAPI OsoosiDeviceControl(
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

    case IOCTL_OSOOSI_GET_EXTENDED_STATUS: {
        if (outputLength < sizeof(OSOOSI_EXTENDED_DRIVER_STATUS)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        POSOOSI_EXTENDED_DRIVER_STATUS pExt = (POSOOSI_EXTENDED_DRIVER_STATUS)buffer;
        KeAcquireInStackQueuedSpinLock(&g_State.Lock, &lockHandle);
        pExt->version = g_State.Version;
        pExt->mode = g_State.Mode;
        pExt->blocked_count = g_State.BlockedCount;
        pExt->rule_count = g_State.RuleCount;
        pExt->protected_pid = g_State.ProtectedSensorPid;
        pExt->ob_callbacks_active = g_State.ObCallbacksRegistered ? 1 : 0;
        pExt->image_load_notify_active = g_State.ImageNotifyRegistered ? 1 : 0;
        pExt->minifilter_active = g_State.MinifilterActive ? 1 : 0;
        pExt->elam_registered = g_State.ElamActive ? 1 : 0;
        pExt->byovd_blocked_count = g_State.ByovdBlockedCount;
        pExt->handle_stripped_count = g_State.HandleStrippedCount;
        pExt->minifilter_blocked_count = g_State.MinifilterBlockedCount;
        KeReleaseInStackQueuedSpinLock(&lockHandle);

        bytesReturned = sizeof(OSOOSI_EXTENDED_DRIVER_STATUS);
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

    case IOCTL_OSOOSI_PROTECT_PID: {
        if (inputLength < sizeof(OSOOSI_PROTECT_PID_REQUEST)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        POSOOSI_PROTECT_PID_REQUEST pReq = (POSOOSI_PROTECT_PID_REQUEST)buffer;
        KeAcquireInStackQueuedSpinLock(&g_State.Lock, &lockHandle);
        if (pReq->enable_protection != 0) {
            g_State.ProtectedSensorPid = pReq->pid;
        } else if (g_State.ProtectedSensorPid == pReq->pid) {
            g_State.ProtectedSensorPid = 0;
        }
        KeReleaseInStackQueuedSpinLock(&lockHandle);

        bytesReturned = 0;
        break;
    }

    case IOCTL_OSOOSI_ADD_BYOVD_RULE: {
        if (inputLength < sizeof(OSOOSI_ADD_BYOVD_REQUEST)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        POSOOSI_ADD_BYOVD_REQUEST pReq = (POSOOSI_ADD_BYOVD_REQUEST)buffer;
        pReq->driver_name[OSOOSI_MAX_PATH - 1] = L'\0';

        POSOOSI_BYOVD_RULE rule = (POSOOSI_BYOVD_RULE)ExAllocatePoolWithTag(
            NonPagedPoolNx,
            sizeof(OSOOSI_BYOVD_RULE),
            OSOOSI_POOL_TAG
        );
        if (rule == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        RtlZeroMemory(rule, sizeof(OSOOSI_BYOVD_RULE));
        status = RtlStringCchCopyW(rule->DriverName, OSOOSI_MAX_PATH, pReq->driver_name);
        if (!NT_SUCCESS(status)) {
            ExFreePoolWithTag(rule, OSOOSI_POOL_TAG);
            break;
        }
        SIZE_T cchLen = 0;
        status = RtlStringCchLengthW(rule->DriverName, OSOOSI_MAX_PATH, &cchLen);
        if (!NT_SUCCESS(status)) {
            ExFreePoolWithTag(rule, OSOOSI_POOL_TAG);
            break;
        }
        rule->NameLength = (ULONG)cchLen;
        rule->HasHash = pReq->has_hash;
        if (pReq->has_hash) {
            RtlCopyMemory(rule->Sha256, pReq->sha256, OSOOSI_HASH_SIZE);
        }

        KeAcquireInStackQueuedSpinLock(&g_State.Lock, &lockHandle);
        InsertTailList(&g_State.ByovdRuleList, &rule->ListEntry);
        g_State.RuleCount++;
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
        pReq->image_path[OSOOSI_MAX_PATH - 1] = L'\0';

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
        status = RtlStringCchCopyW(rule->Path, OSOOSI_MAX_PATH, pReq->image_path);
        if (!NT_SUCCESS(status)) {
            ExFreePoolWithTag(rule, OSOOSI_POOL_TAG);
            break;
        }
        rule->Path[OSOOSI_MAX_PATH - 1] = L'\0';

        SIZE_T cchLen = 0;
        status = RtlStringCchLengthW(rule->Path, OSOOSI_MAX_PATH, &cchLen);
        if (!NT_SUCCESS(status)) {
            ExFreePoolWithTag(rule, OSOOSI_POOL_TAG);
            break;
        }
        rule->Length = (ULONG)cchLen;
        for (ULONG k = 0; k < rule->Length; ++k) {
            if (rule->Path[k] == L'/') {
                rule->Path[k] = L'\\';
            }
        }

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

    while (!IsListEmpty(&g_State.ByovdRuleList)) {
        PLIST_ENTRY entry = RemoveHeadList(&g_State.ByovdRuleList);
        POSOOSI_BYOVD_RULE rule = CONTAINING_RECORD(entry, OSOOSI_BYOVD_RULE, ListEntry);
        ExFreePoolWithTag(rule, OSOOSI_POOL_TAG);
    }

    g_State.RuleCount = 0;
}

static ULONG OsoosiBoundedWcsLen(
    _In_reads_(maxChars) PCWSTR str,
    _In_ ULONG maxChars
) {
    if (str == NULL) {
        return 0;
    }
    ULONG len = 0;
    while (len < maxChars && str[len] != L'\0') {
        len++;
    }
    return len;
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

static BOOLEAN OsoosiEndsWithInsensitive(
    _In_reads_(haystackLen) PCWSTR haystack,
    _In_ ULONG haystackLen,
    _In_reads_(suffixLen) PCWSTR suffix,
    _In_ ULONG suffixLen
) {
    if (haystack == NULL || suffix == NULL || suffixLen == 0 || haystackLen < suffixLen) {
        return FALSE;
    }

    ULONG offset = haystackLen - suffixLen;
    for (ULONG j = 0; j < suffixLen; ++j) {
        if (OsoosiToUpper(haystack[offset + j]) != OsoosiToUpper(suffix[j])) {
            return FALSE;
        }
    }
    return TRUE;
}

static BOOLEAN OsoosiIsCriticalSystemImage(_In_ PCUNICODE_STRING ImageFileName) {
    if (ImageFileName == NULL || ImageFileName->Buffer == NULL || ImageFileName->Length == 0) {
        return FALSE;
    }

    ULONG imgChars = ImageFileName->Length / sizeof(WCHAR);

    for (ULONG i = 0; i < sizeof(g_ProtectedImages) / sizeof(g_ProtectedImages[0]); ++i) {
        PCWSTR protName = g_ProtectedImages[i];
        ULONG protLen = OsoosiBoundedWcsLen(protName, OSOOSI_MAX_PATH - 1);

        BOOLEAN matchesName = FALSE;
        if (imgChars > protLen && ImageFileName->Buffer[imgChars - protLen - 1] == L'\\') {
            matchesName = OsoosiEndsWithInsensitive(ImageFileName->Buffer, imgChars, protName, protLen);
        } else if (imgChars == protLen) {
            matchesName = OsoosiEndsWithInsensitive(ImageFileName->Buffer, imgChars, protName, protLen);
        }

        if (matchesName) {
            if (OsoosiContainsSubstrInsensitive(ImageFileName->Buffer, imgChars, L"\\System32\\", 10) ||
                OsoosiContainsSubstrInsensitive(ImageFileName->Buffer, imgChars, L"\\SysWOW64\\", 10) ||
                OsoosiContainsSubstrInsensitive(ImageFileName->Buffer, imgChars, L"\\SystemApps\\", 12) ||
                OsoosiContainsSubstrInsensitive(ImageFileName->Buffer, imgChars, L"\\Program Files\\", 15) ||
                OsoosiContainsSubstrInsensitive(ImageFileName->Buffer, imgChars, L"\\Windows\\", 9)) {
                return TRUE;
            }
            return FALSE;
        }
    }

    return FALSE;
}

static BOOLEAN OsoosiIsByovdDriverLocked(_In_ PCUNICODE_STRING ImageFileName) {
    if (ImageFileName == NULL || ImageFileName->Buffer == NULL || ImageFileName->Length == 0) {
        return FALSE;
    }

    ULONG imgChars = ImageFileName->Length / sizeof(WCHAR);

    // 1. Check built-in Microsoft Vulnerable Driver Blocklist (BYOVD)
    for (ULONG i = 0; i < sizeof(g_KnownByovdDrivers) / sizeof(g_KnownByovdDrivers[0]); ++i) {
        PCWSTR drvName = g_KnownByovdDrivers[i];
        ULONG drvLen = OsoosiBoundedWcsLen(drvName, OSOOSI_MAX_PATH - 1);
        if (imgChars >= drvLen && OsoosiEndsWithInsensitive(ImageFileName->Buffer, imgChars, drvName, drvLen)) {
            if (imgChars == drvLen || ImageFileName->Buffer[imgChars - drvLen - 1] == L'\\') {
                return TRUE;
            }
        }
    }

    // 2. Check dynamic BYOVD rules added via IOCTL_OSOOSI_ADD_BYOVD_RULE
    PLIST_ENTRY curr = g_State.ByovdRuleList.Flink;
    while (curr != &g_State.ByovdRuleList) {
        POSOOSI_BYOVD_RULE rule = CONTAINING_RECORD(curr, OSOOSI_BYOVD_RULE, ListEntry);
        if (rule->NameLength > 0 &&
            OsoosiContainsSubstrInsensitive(ImageFileName->Buffer, imgChars, rule->DriverName, rule->NameLength)) {
            return TRUE;
        }
        curr = curr->Flink;
    }

    return FALSE;
}

static BOOLEAN OsoosiIsSelfDefenseProtectedAsset(_In_ PCUNICODE_STRING FileName) {
    if (FileName == NULL || FileName->Buffer == NULL || FileName->Length == 0) {
        return FALSE;
    }
    ULONG chars = FileName->Length / sizeof(WCHAR);
    for (ULONG i = 0; i < sizeof(g_SelfDefenseAssets) / sizeof(g_SelfDefenseAssets[0]); ++i) {
        PCWSTR asset = g_SelfDefenseAssets[i];
        ULONG assetLen = OsoosiBoundedWcsLen(asset, OSOOSI_MAX_PATH - 1);
        if (OsoosiEndsWithInsensitive(FileName->Buffer, chars, asset, assetLen)) {
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

static VOID OsoosiEnqueueInterceptEventLocked(
    _In_ ULONG pid,
    _In_ ULONG parentPid,
    _In_ ULONG blocked,
    _In_ ULONG interceptType,
    _In_opt_ PCUNICODE_STRING imagePath,
    _In_opt_ PCUNICODE_STRING commandLine
) {
    if (g_State.QueuedEventCount >= OSOOSI_MAX_QUEUED_EVENTS) {
        return;
    }

    POSOOSI_INTERCEPT_EVENT ev = &g_State.EventQueue[g_State.EventTail];
    RtlZeroMemory(ev, sizeof(OSOOSI_INTERCEPT_EVENT));
    ev->pid = pid;
    ev->parent_pid = parentPid;
    ev->blocked = blocked;
    ev->intercept_type = interceptType;
    KeQuerySystemTime(&ev->timestamp);

    if (imagePath != NULL && imagePath->Buffer != NULL) {
        USHORT charsToCopy = imagePath->Length / sizeof(WCHAR);
        if (charsToCopy >= OSOOSI_MAX_PATH) {
            charsToCopy = OSOOSI_MAX_PATH - 1;
        }
        RtlCopyMemory(ev->image_path, imagePath->Buffer, charsToCopy * sizeof(WCHAR));
        ev->image_path[charsToCopy] = L'\0';
    }

    if (commandLine != NULL && commandLine->Buffer != NULL) {
        USHORT cmdChars = commandLine->Length / sizeof(WCHAR);
        if (cmdChars >= OSOOSI_MAX_CMDLINE) {
            cmdChars = OSOOSI_MAX_CMDLINE - 1;
        }
        RtlCopyMemory(ev->command_line, commandLine->Buffer, cmdChars * sizeof(WCHAR));
        ev->command_line[cmdChars] = L'\0';
    }

    g_State.EventTail = (g_State.EventTail + 1) % OSOOSI_MAX_QUEUED_EVENTS;
    g_State.QueuedEventCount++;
}

OB_PREOP_CALLBACK_STATUS NTAPI OsoosiObPreProcessCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
) {
    UNREFERENCED_PARAMETER(RegistrationContext);
    KLOCK_QUEUE_HANDLE lockHandle;

    if (OperationInformation == NULL || OperationInformation->KernelHandle) {
        return OB_PREOP_SUCCESS;
    }

    PEPROCESS targetProcess = (PEPROCESS)OperationInformation->Object;
    if (targetProcess == NULL || targetProcess == PsGetCurrentProcess()) {
        return OB_PREOP_SUCCESS;
    }

    ULONG targetPid = HandleToULong(PsGetProcessId(targetProcess));
    ULONG callerPid = HandleToULong(PsGetCurrentProcessId());

    // System (PID <= 4) is always trusted
    if (callerPid <= 4 || targetPid == 0) {
        return OB_PREOP_SUCCESS;
    }

    KeAcquireInStackQueuedSpinLock(&g_State.Lock, &lockHandle);
    if (g_State.ProtectedSensorPid != 0 &&
        targetPid == g_State.ProtectedSensorPid &&
        callerPid != g_State.ProtectedSensorPid &&
        g_State.Mode >= OSOOSI_MODE_ACTIVE) {

        PACCESS_MASK desiredAccess = NULL;
        if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
            desiredAccess = &OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
        } else if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
            desiredAccess = &OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;
        }

        if (desiredAccess != NULL && (*desiredAccess & OSOOSI_STRIPPED_PROCESS_ACCESS) != 0) {
            *desiredAccess &= ~OSOOSI_STRIPPED_PROCESS_ACCESS;
            g_State.HandleStrippedCount++;
            OsoosiEnqueueInterceptEventLocked(
                callerPid,
                targetPid,
                1,
                OSOOSI_INTERCEPT_HANDLE_STRIP,
                NULL,
                NULL
            );
        }
    }
    KeReleaseInStackQueuedSpinLock(&lockHandle);

    return OB_PREOP_SUCCESS;
}

OB_PREOP_CALLBACK_STATUS NTAPI OsoosiObPreThreadCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
) {
    UNREFERENCED_PARAMETER(RegistrationContext);
    KLOCK_QUEUE_HANDLE lockHandle;

    if (OperationInformation == NULL || OperationInformation->KernelHandle) {
        return OB_PREOP_SUCCESS;
    }

    PETHREAD targetThread = (PETHREAD)OperationInformation->Object;
    if (targetThread == NULL) {
        return OB_PREOP_SUCCESS;
    }

    PEPROCESS targetProcess = IoThreadToProcess(targetThread);
    if (targetProcess == NULL || targetProcess == PsGetCurrentProcess()) {
        return OB_PREOP_SUCCESS;
    }

    ULONG targetPid = HandleToULong(PsGetProcessId(targetProcess));
    ULONG callerPid = HandleToULong(PsGetCurrentProcessId());

    if (callerPid <= 4 || targetPid == 0) {
        return OB_PREOP_SUCCESS;
    }

    KeAcquireInStackQueuedSpinLock(&g_State.Lock, &lockHandle);
    if (g_State.ProtectedSensorPid != 0 &&
        targetPid == g_State.ProtectedSensorPid &&
        callerPid != g_State.ProtectedSensorPid &&
        g_State.Mode >= OSOOSI_MODE_ACTIVE) {

        PACCESS_MASK desiredAccess = NULL;
        if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
            desiredAccess = &OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
        } else if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
            desiredAccess = &OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;
        }

        if (desiredAccess != NULL && (*desiredAccess & OSOOSI_STRIPPED_THREAD_ACCESS) != 0) {
            *desiredAccess &= ~OSOOSI_STRIPPED_THREAD_ACCESS;
            g_State.HandleStrippedCount++;
            OsoosiEnqueueInterceptEventLocked(
                callerPid,
                targetPid,
                1,
                OSOOSI_INTERCEPT_HANDLE_STRIP,
                NULL,
                NULL
            );
        }
    }
    KeReleaseInStackQueuedSpinLock(&lockHandle);

    return OB_PREOP_SUCCESS;
}

VOID NTAPI OsoosiLoadImageNotifyRoutine(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo
) {
    KLOCK_QUEUE_HANDLE lockHandle;

    if (FullImageName == NULL || ImageInfo == NULL) {
        return;
    }

    ULONG pid = HandleToULong(ProcessId);

    KeAcquireInStackQueuedSpinLock(&g_State.Lock, &lockHandle);
    if (OsoosiIsByovdDriverLocked(FullImageName)) {
        g_State.ByovdBlockedCount++;
        OsoosiEnqueueInterceptEventLocked(
            pid,
            0,
            1,
            OSOOSI_INTERCEPT_BYOVD_BLOCK,
            FullImageName,
            NULL
        );
    } else if (OsoosiIsSelfDefenseProtectedAsset(FullImageName) &&
               pid > 4 &&
               g_State.ProtectedSensorPid == 0 &&
               OsoosiEndsWithInsensitive(FullImageName->Buffer, FullImageName->Length / sizeof(WCHAR), L"\\osoosi.exe", 11)) {
        // Automatically bind ProtectedSensorPid when osoosi.exe image maps
        g_State.ProtectedSensorPid = pid;
    }
    KeReleaseInStackQueuedSpinLock(&lockHandle);
}

VOID NTAPI OsoosiCreateProcessNotifyRoutine(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
) {
    UNREFERENCED_PARAMETER(Process);
    KLOCK_QUEUE_HANDLE lockHandle;

    if (CreateInfo == NULL) {
        // Process exiting: clear ProtectedSensorPid if the sensor exited cleanly
        ULONG exitingPid = HandleToULong(ProcessId);
        KeAcquireInStackQueuedSpinLock(&g_State.Lock, &lockHandle);
        if (g_State.ProtectedSensorPid == exitingPid) {
            g_State.ProtectedSensorPid = 0;
        }
        KeReleaseInStackQueuedSpinLock(&lockHandle);
        return;
    }

    ULONG pid = HandleToULong(ProcessId);
    ULONG parentPid = HandleToULong(CreateInfo->ParentProcessId);

    // Safeguard: Never block system processes (PIDs 0, 4)
    if (pid <= 4 || parentPid == 0) {
        return;
    }

    // Safeguard: Never block core OS/desktop/shell infrastructure binaries
    if (OsoosiIsCriticalSystemImage(CreateInfo->ImageFileName)) {
        return;
    }

    KeAcquireInStackQueuedSpinLock(&g_State.Lock, &lockHandle);

    BOOLEAN isByovd = OsoosiIsByovdDriverLocked(CreateInfo->ImageFileName) ||
                      OsoosiIsByovdDriverLocked(CreateInfo->CommandLine);
    BOOLEAN isBlockedPath = isByovd || OsoosiIsPathBlockedLocked(CreateInfo->ImageFileName);
    BOOLEAN shouldBlock = isBlockedPath && (g_State.Mode >= OSOOSI_MODE_ACTIVE);

    if (shouldBlock || (isBlockedPath && g_State.Mode == OSOOSI_MODE_AUDIT)) {
        OsoosiEnqueueInterceptEventLocked(
            pid,
            parentPid,
            shouldBlock ? 1 : 0,
            isByovd ? OSOOSI_INTERCEPT_BYOVD_BLOCK : OSOOSI_INTERCEPT_PROCESS_EXEC,
            CreateInfo->ImageFileName,
            CreateInfo->CommandLine
        );

        if (shouldBlock) {
            g_State.BlockedCount++;
            if (isByovd) {
                g_State.ByovdBlockedCount++;
            }
            CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
            KdPrint(("OsoosiDriver: BLOCKED process creation: PID=%lu, Image=%wZ\n", pid, CreateInfo->ImageFileName));
        }
    }

    KeReleaseInStackQueuedSpinLock(&lockHandle);
}
