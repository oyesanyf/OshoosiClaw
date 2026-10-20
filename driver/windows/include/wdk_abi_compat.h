#ifndef OSOOSI_WDK_ABI_COMPAT_H
#define OSOOSI_WDK_ABI_COMPAT_H

/*
 * OshoosiClaw Windows Ring-0 WDK x64 ABI Compatibility Layer
 *
 * Uses official WDK <ntddk.h> / <fltKernel.h> when present in INCLUDE path,
 * or exact Windows x64 Kernel (ntoskrnl.exe / fltmgr.sys) ABI definitions
 * when compiling under standard MSVC + Windows 10 SDK environments.
 */

#if defined(__has_include) && __has_include(<ntddk.h>)
#include <ntddk.h>
#include <ntstrsafe.h>
#else

#pragma warning(disable: 4201) // nameless struct/union (standard in Windows headers)

#ifndef _AMD64_
#define _AMD64_ 1
#endif

typedef void VOID, *PVOID;
typedef char CHAR, *PCHAR;
typedef short SHORT, *PSHORT;
typedef unsigned char UCHAR, *PUCHAR, BOOLEAN, *PBOOLEAN;
typedef unsigned short USHORT, *PUSHORT, WCHAR, *PWCHAR;
typedef const WCHAR *PCWSTR;
typedef unsigned long ULONG, *PULONG, ACCESS_MASK, *PACCESS_MASK;
typedef long LONG, NTSTATUS;
typedef unsigned long long ULONGLONG, ULONG_PTR, SIZE_T;
typedef long long LONGLONG, LONG_PTR;
typedef void *HANDLE, **PHANDLE;
typedef UCHAR KIRQL, *PKIRQL;
typedef ULONG_PTR KSPIN_LOCK, *PKSPIN_LOCK;

#ifndef NULL
#define NULL ((void*)0)
#endif
#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

#ifndef _In_
#define _In_
#define _In_opt_
#define _Out_
#define _Inout_
#define _Inout_opt_
#define _In_reads_(x)
#define _Dispatch_type_(x)
#define UNREFERENCED_PARAMETER(P) ((void)(P))
#endif

#define NTAPI __stdcall
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL              ((NTSTATUS)0xC0000001L)
#define STATUS_INVALID_PARAMETER         ((NTSTATUS)0xC000000DL)
#define STATUS_INVALID_DEVICE_REQUEST    ((NTSTATUS)0xC0000010L)
#define STATUS_ACCESS_DENIED             ((NTSTATUS)0xC0000022L)
#define STATUS_BUFFER_TOO_SMALL          ((NTSTATUS)0xC0000023L)
#define STATUS_INSUFFICIENT_RESOURCES    ((NTSTATUS)0xC000009AL)

#define FILE_DEVICE_UNKNOWN              0x00000022
#define FILE_DEVICE_SECURE_OPEN          0x00000100
#define METHOD_BUFFERED                  0
#define FILE_ANY_ACCESS                  0
#define FILE_READ_ACCESS                 0x0001
#define FILE_WRITE_ACCESS                0x0002
#define IO_NO_INCREMENT                  0

#define CTL_CODE(DeviceType, Function, Method, Access) \
    (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))

#define IRP_MJ_CREATE                    0x00
#define IRP_MJ_CLOSE                     0x02
#define IRP_MJ_READ                      0x03
#define IRP_MJ_WRITE                     0x04
#define IRP_MJ_SET_INFORMATION           0x06
#define IRP_MJ_DEVICE_CONTROL            0x0E
#define IRP_MJ_MAXIMUM_FUNCTION          0x1B

// Process and Thread Access Rights (for ObRegisterCallbacks handle stripping)
#define PROCESS_TERMINATE                0x0001
#define PROCESS_CREATE_THREAD            0x0002
#define PROCESS_SET_SESSIONID            0x0004
#define PROCESS_VM_OPERATION             0x0008
#define PROCESS_VM_READ                  0x0010
#define PROCESS_VM_WRITE                 0x0020
#define PROCESS_DUP_HANDLE               0x0040
#define PROCESS_CREATE_PROCESS           0x0080
#define PROCESS_SET_QUOTA                0x0100
#define PROCESS_SET_INFORMATION          0x0200
#define PROCESS_QUERY_INFORMATION        0x0400
#define PROCESS_SUSPEND_RESUME           0x0800
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#define WRITE_DAC                        0x00040000L
#define WRITE_OWNER                      0x00080000L

#define THREAD_TERMINATE                 0x0001
#define THREAD_SUSPEND_RESUME            0x0002
#define THREAD_GET_CONTEXT               0x0008
#define THREAD_SET_CONTEXT               0x0010
#define THREAD_SET_INFORMATION           0x0020
#define THREAD_IMPERSONATE               0x0100
#define THREAD_DIRECT_IMPERSONATION      0x0200

typedef union _LARGE_INTEGER {
    struct {
        ULONG LowPart;
        LONG HighPart;
    };
    LONGLONG QuadPart;
} LARGE_INTEGER, *PLARGE_INTEGER;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWCHAR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;

typedef struct _LIST_ENTRY {
    struct _LIST_ENTRY *Flink;
    struct _LIST_ENTRY *Blink;
} LIST_ENTRY, *PLIST_ENTRY;

typedef struct _KLOCK_QUEUE_HANDLE {
    struct {
        struct _KSPIN_LOCK_QUEUE *Next;
        PKSPIN_LOCK Lock;
    } LockQueue;
    KIRQL OldIrql;
} KLOCK_QUEUE_HANDLE, *PKLOCK_QUEUE_HANDLE;

typedef enum _POOL_TYPE {
    NonPagedPool = 0,
    PagedPool = 1,
    NonPagedPoolNx = 512
} POOL_TYPE;

typedef struct _EPROCESS *PEPROCESS;
typedef struct _ETHREAD *PETHREAD;
typedef struct _OBJECT_TYPE *POBJECT_TYPE;
typedef struct _DEVICE_OBJECT DEVICE_OBJECT, *PDEVICE_OBJECT;
typedef struct _DRIVER_OBJECT DRIVER_OBJECT, *PDRIVER_OBJECT;
typedef struct _FILE_OBJECT *PFILE_OBJECT;
typedef struct _IRP IRP, *PIRP;

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef struct _IO_STACK_LOCATION {
    UCHAR MajorFunction;
    UCHAR MinorFunction;
    UCHAR Flags;
    UCHAR Control;
    union {
        struct {
            PVOID SecurityContext;
            ULONG Options;
            USHORT FileAttributes;
            USHORT ShareAccess;
            ULONG EaLength;
        } Create;
        struct {
            ULONG OutputBufferLength;
            ULONG _pad1;
            ULONG InputBufferLength;
            ULONG _pad2;
            ULONG IoControlCode;
            ULONG _pad3;
            PVOID Type3InputBuffer;
        } DeviceIoControl;
    } Parameters;
    PDEVICE_OBJECT DeviceObject;
    PFILE_OBJECT FileObject;
} IO_STACK_LOCATION, *PIO_STACK_LOCATION;

struct _IRP {
    SHORT Type;
    USHORT Size;
    PVOID MdlAddress;
    ULONG Flags;
    union {
        struct _IRP *MasterIrp;
        LONG IrpCount;
        PVOID SystemBuffer;
    } AssociatedIrp;
    LIST_ENTRY ThreadListEntry;
    IO_STATUS_BLOCK IoStatus;
    CHAR RequestorMode;
    BOOLEAN PendingReturned;
    CHAR StackCount;
    CHAR CurrentLocation;
    BOOLEAN Cancel;
    KIRQL CancelIrql;
    CHAR ApcEnvironment;
    UCHAR AllocationFlags;
    PIO_STATUS_BLOCK UserIosb;
    PVOID UserEvent;
    union {
        struct {
            PVOID UserApcRoutine;
            PVOID UserApcContext;
        } AsynchronousParameters;
        LARGE_INTEGER AllocationSize;
    } Overlay;
    PVOID CancelRoutine;
    PVOID UserBuffer;
    struct {
        struct {
            PVOID DriverContext[4];
        } Overlay;
        PETHREAD Thread;
        PVOID AuxiliaryBuffer;
        LIST_ENTRY ListEntry;
        PIO_STACK_LOCATION CurrentStackLocation;
        PFILE_OBJECT OriginalFileObject;
    } Tail;
};

typedef NTSTATUS (NTAPI DRIVER_INITIALIZE)(
    _In_ struct _DRIVER_OBJECT *DriverObject,
    _In_ PUNICODE_STRING RegistryPath
);
typedef DRIVER_INITIALIZE *PDRIVER_INITIALIZE;

typedef VOID (NTAPI DRIVER_UNLOAD)(
    _In_ struct _DRIVER_OBJECT *DriverObject
);
typedef DRIVER_UNLOAD *PDRIVER_UNLOAD;

typedef NTSTATUS (NTAPI DRIVER_DISPATCH)(
    _In_ struct _DEVICE_OBJECT *DeviceObject,
    _Inout_ struct _IRP *Irp
);
typedef DRIVER_DISPATCH *PDRIVER_DISPATCH;

struct _DEVICE_OBJECT {
    SHORT Type;
    USHORT Size;
    LONG ReferenceCount;
    struct _DRIVER_OBJECT *DriverObject;
    struct _DEVICE_OBJECT *NextDevice;
    struct _DEVICE_OBJECT *AttachedDevice;
    struct _IRP *CurrentIrp;
    PVOID Timer;
    ULONG Flags;
    ULONG Characteristics;
    PVOID Vpb;
    PVOID DeviceExtension;
    ULONG DeviceType;
    CHAR StackSize;
};

struct _DRIVER_OBJECT {
    SHORT Type;
    SHORT Size;
    PDEVICE_OBJECT DeviceObject;
    ULONG Flags;
    PVOID DriverStart;
    ULONG DriverSize;
    PVOID DriverSection;
    PVOID DriverExtension;
    UNICODE_STRING DriverName;
    PUNICODE_STRING HardwareDatabase;
    PVOID FastIoDispatch;
    PDRIVER_INITIALIZE DriverInit;
    PVOID DriverStartIo;
    PDRIVER_UNLOAD DriverUnload;
    PDRIVER_DISPATCH MajorFunction[IRP_MJ_MAXIMUM_FUNCTION + 1];
};

// PsSetCreateProcessNotifyRoutineEx structures
typedef struct _PS_CREATE_NOTIFY_INFO {
    SIZE_T Size;
    union {
        ULONG Flags;
        struct {
            ULONG FileOpenNameAvailable : 1;
            ULONG IsSubsystemProcess : 1;
            ULONG Reserved : 30;
        };
    };
    HANDLE ParentProcessId;
    struct {
        HANDLE UniqueProcess;
        HANDLE UniqueThread;
    } CreatingThreadId;
    PFILE_OBJECT FileObject;
    PCUNICODE_STRING ImageFileName;
    PCUNICODE_STRING CommandLine;
    NTSTATUS CreationStatus;
} PS_CREATE_NOTIFY_INFO, *PPS_CREATE_NOTIFY_INFO;

typedef VOID (NTAPI *PCREATE_PROCESS_NOTIFY_ROUTINE_EX)(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
);

// PsSetLoadImageNotifyRoutine structures (for BYOVD interception)
typedef struct _IMAGE_INFO {
    union {
        ULONG Properties;
        struct {
            ULONG ImageAddressingMode  : 8;
            ULONG SystemModeImage      : 1;  // 1 if loading into Ring-0 kernel space
            ULONG ImageMappedToAllPids : 1;
            ULONG ExtendedInfoPresent  : 1;
            ULONG MachineTypeMismatch  : 1;
            ULONG ImageSignatureLevel  : 4;
            ULONG ImageSignatureType   : 3;
            ULONG ImagePartialMap      : 1;
            ULONG Reserved             : 12;
        };
    };
    PVOID ImageBase;
    ULONG ImageSelector;
    SIZE_T ImageSize;
    ULONG ImageSectionNumber;
} IMAGE_INFO, *PIMAGE_INFO;

typedef VOID (NTAPI *PLOAD_IMAGE_NOTIFY_ROUTINE)(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo
);

// ObRegisterCallbacks structures (for Ring-0 Process & Thread Handle Protection)
#define OB_FLT_REGISTRATION_VERSION_0100  0x0100
#define OB_FLT_REGISTRATION_VERSION       OB_FLT_REGISTRATION_VERSION_0100

typedef ULONG OB_OPERATION;
#define OB_OPERATION_HANDLE_CREATE        0x00000001
#define OB_OPERATION_HANDLE_DUPLICATE     0x00000002

typedef enum _OB_PREOP_CALLBACK_STATUS {
    OB_PREOP_SUCCESS = 0
} OB_PREOP_CALLBACK_STATUS;

typedef struct _OB_PRE_CREATE_HANDLE_INFORMATION {
    ACCESS_MASK DesiredAccess;
    ACCESS_MASK OriginalDesiredAccess;
} OB_PRE_CREATE_HANDLE_INFORMATION, *POB_PRE_CREATE_HANDLE_INFORMATION;

typedef struct _OB_PRE_DUPLICATE_HANDLE_INFORMATION {
    ACCESS_MASK DesiredAccess;
    ACCESS_MASK OriginalDesiredAccess;
    PVOID SourceProcess;
    PVOID TargetProcess;
} OB_PRE_DUPLICATE_HANDLE_INFORMATION, *POB_PRE_DUPLICATE_HANDLE_INFORMATION;

typedef union _OB_PRE_OPERATION_PARAMETERS {
    OB_PRE_CREATE_HANDLE_INFORMATION CreateHandleInformation;
    OB_PRE_DUPLICATE_HANDLE_INFORMATION DuplicateHandleInformation;
} OB_PRE_OPERATION_PARAMETERS, *POB_PRE_OPERATION_PARAMETERS;

typedef struct _OB_PRE_OPERATION_INFORMATION {
    OB_OPERATION Operation;
    union {
        ULONG Flags;
        struct {
            ULONG KernelHandle : 1;
            ULONG Reserved : 31;
        };
    };
    PVOID Object;
    POBJECT_TYPE ObjectType;
    PVOID CallContext;
    POB_PRE_OPERATION_PARAMETERS Parameters;
} OB_PRE_OPERATION_INFORMATION, *POB_PRE_OPERATION_INFORMATION;

typedef struct _OB_POST_OPERATION_INFORMATION {
    OB_OPERATION Operation;
    ULONG Flags;
    PVOID Object;
    POBJECT_TYPE ObjectType;
    PVOID CallContext;
    NTSTATUS ReturnStatus;
    PVOID Parameters;
} OB_POST_OPERATION_INFORMATION, *POB_POST_OPERATION_INFORMATION;

typedef OB_PREOP_CALLBACK_STATUS (NTAPI *POB_PRE_OPERATION_CALLBACK)(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
);

typedef VOID (NTAPI *POB_POST_OPERATION_CALLBACK)(
    _In_ PVOID RegistrationContext,
    _In_ POB_POST_OPERATION_INFORMATION OperationInformation
);

typedef struct _OB_OPERATION_REGISTRATION {
    POBJECT_TYPE *ObjectType;
    OB_OPERATION Operations;
    POB_PRE_OPERATION_CALLBACK PreOperation;
    POB_POST_OPERATION_CALLBACK PostOperation;
} OB_OPERATION_REGISTRATION, *POB_OPERATION_REGISTRATION;

typedef struct _OB_CALLBACK_REGISTRATION {
    USHORT Version;
    USHORT OperationRegistrationCount;
    UNICODE_STRING Altitude;
    PVOID RegistrationContext;
    OB_OPERATION_REGISTRATION *OperationRegistration;
} OB_CALLBACK_REGISTRATION, *POB_CALLBACK_REGISTRATION;

// Early Launch Anti-Malware (ELAM) Boot Driver Callback structures
typedef enum _BDCB_CALLBACK_TYPE {
    BdCbStatusUpdate = 0,
    BdCbInitializeImage = 1
} BDCB_CALLBACK_TYPE;

typedef enum _BDCB_CLASSIFICATION {
    BdCbClassificationUnknownImage = 0,
    BdCbClassificationKnownGoodImage = 1,
    BdCbClassificationKnownBadImage = 2,
    BdCbClassificationKnownBadImageBootCritical = 3
} BDCB_CLASSIFICATION;

typedef enum _BDCB_STATUS_UPDATE_TYPE {
    BdCbStatusPrepareForDependencyLoad = 0,
    BdCbStatusPrepareForDriverLoad = 1,
    BdCbStatusPrepareForUnload = 2
} BDCB_STATUS_UPDATE_TYPE;

typedef struct _BDCB_STATUS_UPDATE_CONTEXT {
    BDCB_STATUS_UPDATE_TYPE StatusType;
} BDCB_STATUS_UPDATE_CONTEXT, *PBDCB_STATUS_UPDATE_CONTEXT;

typedef struct _BDCB_IMAGE_INFORMATION {
    BDCB_CLASSIFICATION Classification;
    ULONG ImageFlags;
    UNICODE_STRING ImageName;
    UNICODE_STRING RegistryPath;
    UNICODE_STRING CertificatePublisher;
    UNICODE_STRING CertificateIssuer;
    PVOID ImageHash;
    ULONG ImageHashLength;
    PVOID CertificateThumbprint;
    ULONG CertificateThumbprintLength;
    ULONG ImageHashAlgorithm;
    ULONG CertificateThumbprintAlgorithm;
} BDCB_IMAGE_INFORMATION, *PBDCB_IMAGE_INFORMATION;

typedef VOID (NTAPI *PBOOT_DRIVER_CALLBACK_FUNCTION)(
    _In_opt_ PVOID CallbackContext,
    _In_ BDCB_CALLBACK_TYPE Classification,
    _Inout_ PVOID ImageInformation
);

// Kernel Exports from ntoskrnl.exe
extern __declspec(dllimport) POBJECT_TYPE *PsProcessType;
extern __declspec(dllimport) POBJECT_TYPE *PsThreadType;

__declspec(dllimport) VOID NTAPI RtlInitUnicodeString(
    _Out_ PUNICODE_STRING DestinationString,
    _In_opt_ PCWSTR SourceString
);
__declspec(dllimport) SIZE_T NTAPI RtlCompareMemory(
    _In_ const VOID *Source1,
    _In_ const VOID *Source2,
    _In_ SIZE_T Length
);
__declspec(dllimport) VOID NTAPI KeInitializeSpinLock(_Out_ PKSPIN_LOCK SpinLock);
__declspec(dllimport) VOID NTAPI KeAcquireInStackQueuedSpinLock(
    _Inout_ PKSPIN_LOCK SpinLock,
    _Out_ PKLOCK_QUEUE_HANDLE LockHandle
);
__declspec(dllimport) VOID NTAPI KeReleaseInStackQueuedSpinLock(
    _In_ PKLOCK_QUEUE_HANDLE LockHandle
);
__declspec(dllimport) VOID NTAPI KeQuerySystemTime(_Out_ PLARGE_INTEGER CurrentTime);
__declspec(dllimport) PVOID NTAPI ExAllocatePoolWithTag(
    _In_ POOL_TYPE PoolType,
    _In_ SIZE_T NumberOfBytes,
    _In_ ULONG Tag
);
__declspec(dllimport) VOID NTAPI ExFreePoolWithTag(
    _In_ PVOID P,
    _In_ ULONG Tag
);
__declspec(dllimport) NTSTATUS NTAPI IoCreateDevice(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ ULONG DeviceExtensionSize,
    _In_opt_ PUNICODE_STRING DeviceName,
    _In_ ULONG DeviceType,
    _In_ ULONG DeviceCharacteristics,
    _In_ BOOLEAN Exclusive,
    _Out_ PDEVICE_OBJECT *DeviceObject
);
__declspec(dllimport) VOID NTAPI IoDeleteDevice(_In_ PDEVICE_OBJECT DeviceObject);
__declspec(dllimport) NTSTATUS NTAPI IoCreateSymbolicLink(
    _In_ PUNICODE_STRING SymbolicLinkName,
    _In_ PUNICODE_STRING DeviceName
);
__declspec(dllimport) NTSTATUS NTAPI IoDeleteSymbolicLink(
    _In_ PUNICODE_STRING SymbolicLinkName
);
__declspec(dllimport) VOID NTAPI IoCompleteRequest(
    _In_ PIRP Irp,
    _In_ CHAR PriorityBoost
);
__declspec(dllimport) NTSTATUS NTAPI PsSetCreateProcessNotifyRoutineEx(
    _In_ PCREATE_PROCESS_NOTIFY_ROUTINE_EX NotifyRoutine,
    _In_ BOOLEAN Remove
);
__declspec(dllimport) NTSTATUS NTAPI PsSetLoadImageNotifyRoutine(
    _In_ PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine
);
__declspec(dllimport) NTSTATUS NTAPI PsRemoveLoadImageNotifyRoutine(
    _In_ PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine
);
__declspec(dllimport) HANDLE NTAPI PsGetProcessId(_In_ PEPROCESS Process);
__declspec(dllimport) HANDLE NTAPI PsGetCurrentProcessId(VOID);
__declspec(dllimport) PEPROCESS NTAPI PsGetCurrentProcess(VOID);
__declspec(dllimport) PEPROCESS NTAPI IoThreadToProcess(_In_ PETHREAD Thread);
__declspec(dllimport) NTSTATUS NTAPI ObRegisterCallbacks(
    _In_ POB_CALLBACK_REGISTRATION CallbackRegistration,
    _Out_ PVOID *RegistrationHandle
);
__declspec(dllimport) VOID NTAPI ObUnRegisterCallbacks(
    _In_ PVOID RegistrationHandle
);
__declspec(dllimport) PVOID NTAPI IoRegisterBootDriverCallback(
    _In_ PBOOT_DRIVER_CALLBACK_FUNCTION CallbackFunction,
    _In_opt_ PVOID CallbackContext
);
__declspec(dllimport) VOID NTAPI IoUnregisterBootDriverCallback(
    _In_ PVOID CallbackHandle
);

// Inline helpers matching WDK macros
#define KdPrint(_x_) ((void)0)
#define HandleToULong(h) ((ULONG)(ULONG_PTR)(h))
#define CONTAINING_RECORD(address, type, field) \
    ((type *)((char *)(address) - (ULONG_PTR)(&((type *)0)->field)))

struct _FILE_OBJECT {
    SHORT Type;
    SHORT Size;
    PDEVICE_OBJECT DeviceObject;
    PVOID Vpb;
    PVOID FsContext;
    PVOID FsContext2;
    PVOID SectionObjectPointer;
    PVOID PrivateCacheMap;
    NTSTATUS FinalStatus;
    struct _FILE_OBJECT *RelatedFileObject;
    BOOLEAN LockOperation;
    BOOLEAN DeletePending;
    BOOLEAN ReadAccess;
    BOOLEAN WriteAccess;
    BOOLEAN DeleteAccess;
    BOOLEAN SharedRead;
    BOOLEAN SharedWrite;
    BOOLEAN SharedDelete;
    ULONG Flags;
    UNICODE_STRING FileName;
};

typedef union _FS_FILTER_PARAMETERS {
    struct {
        ULONG SyncType;
        ULONG PageProtection;
        PVOID Flags;
    } AcquireForSectionSynchronization;
    struct {
        PVOID Argument1;
        PVOID Argument2;
        PVOID Argument3;
        PVOID Argument4;
        PVOID Argument5;
    } Others;
} FS_FILTER_PARAMETERS, *PFS_FILTER_PARAMETERS;

typedef struct _FS_FILTER_CALLBACK_DATA {
    ULONG SizeOfFsFilterCallbackData;
    UCHAR Operation;
    UCHAR Reserved;
    PDEVICE_OBJECT DeviceObject;
    PFILE_OBJECT FileObject;
    FS_FILTER_PARAMETERS Parameters;
} FS_FILTER_CALLBACK_DATA, *PFS_FILTER_CALLBACK_DATA;

typedef NTSTATUS (NTAPI *PFS_FILTER_CALLBACK)(
    _In_ PFS_FILTER_CALLBACK_DATA Data,
    _Out_ PVOID *CompletionContext
);

typedef VOID (NTAPI *PFS_FILTER_COMPLETION_CALLBACK)(
    _In_ PFS_FILTER_CALLBACK_DATA Data,
    _In_ NTSTATUS OperationStatus,
    _In_ PVOID CompletionContext
);

typedef struct _FS_FILTER_CALLBACKS {
    ULONG SizeOfFsFilterCallbacks;
    ULONG Reserved;
    PFS_FILTER_CALLBACK PreAcquireForSectionSynchronization;
    PFS_FILTER_COMPLETION_CALLBACK PostAcquireForSectionSynchronization;
    PFS_FILTER_CALLBACK PreReleaseForSectionSynchronization;
    PFS_FILTER_COMPLETION_CALLBACK PostReleaseForSectionSynchronization;
    PFS_FILTER_CALLBACK PreAcquireForCcFlush;
    PFS_FILTER_COMPLETION_CALLBACK PostAcquireForCcFlush;
    PFS_FILTER_CALLBACK PreReleaseForCcFlush;
    PFS_FILTER_COMPLETION_CALLBACK PostReleaseForCcFlush;
    PFS_FILTER_CALLBACK PreAcquireForModifiedPageWriter;
    PFS_FILTER_COMPLETION_CALLBACK PostAcquireForModifiedPageWriter;
    PFS_FILTER_CALLBACK PreReleaseForModifiedPageWriter;
    PFS_FILTER_COMPLETION_CALLBACK PostReleaseForModifiedPageWriter;
} FS_FILTER_CALLBACKS, *PFS_FILTER_CALLBACKS;

__declspec(dllimport) NTSTATUS NTAPI FsRtlRegisterFileSystemFilterCallbacks(
    _In_ struct _DRIVER_OBJECT *FilterDriverObject,
    _In_ PFS_FILTER_CALLBACKS Callbacks
);

static __inline PIO_STACK_LOCATION IoGetCurrentIrpStackLocation(_In_ PIRP Irp) {
    return Irp->Tail.CurrentStackLocation;
}

static __inline VOID RtlZeroMemory(PVOID Destination, SIZE_T Length) {
    volatile UCHAR *p = (volatile UCHAR *)Destination;
    while (Length--) {
        *p++ = 0;
    }
}

static __inline VOID RtlCopyMemory(PVOID Destination, const VOID *Source, SIZE_T Length) {
    UCHAR *d = (UCHAR *)Destination;
    const UCHAR *s = (const UCHAR *)Source;
    while (Length--) {
        *d++ = *s++;
    }
}

static __inline VOID InitializeListHead(_Out_ PLIST_ENTRY ListHead) {
    ListHead->Flink = ListHead->Blink = ListHead;
}

static __inline BOOLEAN IsListEmpty(_In_ const LIST_ENTRY *ListHead) {
    return (BOOLEAN)(ListHead->Flink == ListHead);
}

static __inline PLIST_ENTRY RemoveHeadList(_Inout_ PLIST_ENTRY ListHead) {
    PLIST_ENTRY Entry = ListHead->Flink;
    PLIST_ENTRY NextEntry = Entry->Flink;
    ListHead->Flink = NextEntry;
    NextEntry->Blink = ListHead;
    return Entry;
}

static __inline VOID InsertTailList(_Inout_ PLIST_ENTRY ListHead, _Inout_ PLIST_ENTRY Entry) {
    PLIST_ENTRY PrevEntry = ListHead->Blink;
    Entry->Flink = ListHead;
    Entry->Blink = PrevEntry;
    PrevEntry->Flink = Entry;
    ListHead->Blink = Entry;
}

static __inline NTSTATUS RtlStringCchCopyW(PWCHAR pszDest, SIZE_T cchDest, PCWSTR pszSrc) {
    if (pszDest == NULL || pszSrc == NULL || cchDest == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    SIZE_T i = 0;
    while (i + 1 < cchDest && pszSrc[i] != L'\0') {
        pszDest[i] = pszSrc[i];
        i++;
    }
    pszDest[i] = L'\0';
    return STATUS_SUCCESS;
}

static __inline NTSTATUS RtlStringCchLengthW(PCWSTR psz, SIZE_T cchMax, SIZE_T *pcchLength) {
    if (psz == NULL || pcchLength == NULL || cchMax == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    SIZE_T i = 0;
    while (i < cchMax && psz[i] != L'\0') {
        i++;
    }
    if (i == cchMax) {
        *pcchLength = 0;
        return STATUS_INVALID_PARAMETER;
    }
    *pcchLength = i;
    return STATUS_SUCCESS;
}

#endif // __has_include(<ntddk.h>)

#endif // OSOOSI_WDK_ABI_COMPAT_H
