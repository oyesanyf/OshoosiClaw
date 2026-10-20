/*
 * OshoosiClaw Early Launch Anti-Malware (ELAM) Boot-Start Kernel Driver (osoosi_elam.sys)
 *
 * Loaded at SERVICE_BOOT_START (0) in LoadOrderGroup "Early-Launch" before any
 * third-party boot drivers initialize.
 *
 * 1. Registers IoRegisterBootDriverCallback to classify every incoming boot-start
 *    kernel driver image before initialization.
 * 2. Blocks known BYOVD (Bring Your Own Vulnerable Driver) payloads (rtcore64.sys,
 *    dbutil_2_3.sys, gdrv.sys, capcom.sys, mhyprot2.sys, winring0x64.sys, zam64.sys)
 *    with BdCbClassificationKnownBadImage so Windows Kernel refuses to map them.
 * 3. Embeds MicrosoftElamCertificateInfo resource table authorizing OsoosiEDR
 *    to run as Protected Process Light (SERVICE_LAUNCH_PROTECTED_ANTIMALWARE_LIGHT).
 */

#ifndef _KERNEL_MODE
#define _KERNEL_MODE 1
#endif
#include "osoosi_driver_ioctl.h"

static PVOID g_BootCallbackHandle = NULL;

static const PCWSTR g_ElamBlockedBootDrivers[] = {
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

static WCHAR ElamToUpper(WCHAR c) {
    if (c >= L'a' && c <= L'z') {
        return c - (L'a' - L'A');
    }
    return c;
}

static ULONG ElamBoundedWcsLen(PCWSTR str, ULONG maxChars) {
    if (str == NULL) {
        return 0;
    }
    ULONG len = 0;
    while (len < maxChars && str[len] != L'\0') {
        len++;
    }
    return len;
}

static BOOLEAN ElamEndsWithInsensitive(
    PCWSTR haystack,
    ULONG haystackLen,
    PCWSTR suffix,
    ULONG suffixLen
) {
    if (haystack == NULL || suffix == NULL || suffixLen == 0 || haystackLen < suffixLen) {
        return FALSE;
    }
    ULONG offset = haystackLen - suffixLen;
    for (ULONG j = 0; j < suffixLen; ++j) {
        if (ElamToUpper(haystack[offset + j]) != ElamToUpper(suffix[j])) {
            return FALSE;
        }
    }
    return TRUE;
}

static BOOLEAN ElamIsKnownByovdBootDriver(PCUNICODE_STRING ImageName) {
    if (ImageName == NULL || ImageName->Buffer == NULL || ImageName->Length == 0) {
        return FALSE;
    }
    ULONG imgChars = ImageName->Length / sizeof(WCHAR);
    for (ULONG i = 0; i < sizeof(g_ElamBlockedBootDrivers) / sizeof(g_ElamBlockedBootDrivers[0]); ++i) {
        PCWSTR badName = g_ElamBlockedBootDrivers[i];
        ULONG badLen = ElamBoundedWcsLen(badName, OSOOSI_MAX_PATH - 1);
        if (imgChars >= badLen && ElamEndsWithInsensitive(ImageName->Buffer, imgChars, badName, badLen)) {
            if (imgChars == badLen || ImageName->Buffer[imgChars - badLen - 1] == L'\\') {
                return TRUE;
            }
        }
    }
    return FALSE;
}

VOID NTAPI OsoosiElamBootDriverCallback(
    _In_opt_ PVOID CallbackContext,
    _In_ BDCB_CALLBACK_TYPE Classification,
    _Inout_ PVOID ImageInformation
) {
    UNREFERENCED_PARAMETER(CallbackContext);

    if (ImageInformation == NULL) {
        return;
    }

    if (Classification == BdCbInitializeImage) {
        PBDCB_IMAGE_INFORMATION imgInfo = (PBDCB_IMAGE_INFORMATION)ImageInformation;
        if (ElamIsKnownByovdBootDriver(&imgInfo->ImageName)) {
            imgInfo->Classification = BdCbClassificationKnownBadImage;
        } else {
            imgInfo->Classification = BdCbClassificationKnownGoodImage;
        }
    }
}

VOID NTAPI ElamDriverUnload(
    _In_ PDRIVER_OBJECT DriverObject
) {
    UNREFERENCED_PARAMETER(DriverObject);
    if (g_BootCallbackHandle != NULL) {
        IoUnregisterBootDriverCallback(g_BootCallbackHandle);
        g_BootCallbackHandle = NULL;
    }
}

NTSTATUS NTAPI DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
) {
    UNREFERENCED_PARAMETER(RegistryPath);
    DriverObject->DriverUnload = ElamDriverUnload;
    g_BootCallbackHandle = IoRegisterBootDriverCallback(OsoosiElamBootDriverCallback, NULL);
    return STATUS_SUCCESS;
}
