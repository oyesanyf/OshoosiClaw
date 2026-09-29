# OshoosiClaw Windows Ring-0 Kernel Driver

The `OsoosiDriver` is a Windows Ring-0 kernel-mode filter driver designed to deliver **hardware-enforced pre-operation process execution blocking** via `PsSetCreateProcessNotifyRoutineEx`.

By intercepting process creation before the primary thread begins and setting `CreateInfo->CreationStatus = STATUS_ACCESS_DENIED`, malicious execution is blocked **before Sysmon Event 1 can fire and before user-mode hooks can be bypassed or tampered with**.

---

## Architecture Overview

- **Pre-Operation Interception**: Hooks Windows process creation routines via `PsSetCreateProcessNotifyRoutineEx(..., FALSE)`.
- **Pre-Event 1 Containment**: Sets `CreateInfo->CreationStatus = STATUS_ACCESS_DENIED`. The process handle is closed by the OS kernel without executing any instruction in the target address space.
- **Fast Ring Queue**: Intercepted metadata (PID, Parent PID, Image Path, Command Line, Timestamp) is written to a spinlock-protected circular ring buffer and retrieved asynchronously by user-mode agent via `IOCTL_OSOOSI_POLL_INTERCEPTIONS`.
- **Zero-Latency In-Memory Blocklist**: Fast in-kernel path and hash matching with case-insensitive evaluation.
- **Self-Defense Safeguards**: Hardcoded immunity for critical OS components (PIDs 0, 4, `sysmon64.exe`, `osoosi.exe`, `msmpeng.exe`, `csrss.exe`, `lsass.exe`, `services.exe`).

---

## Compilation

To compile `osoosi_driver.sys` using the Windows Driver Kit (WDK) and MSBuild:

```cmd
cd driver\windows
msbuild /p:Configuration=Release /p:Platform=x64
```

Alternatively, from the Visual Studio Developer Command Prompt:
```cmd
cl /O2 /W4 /WX /kernel /c src\osoosi_driver.c /Iinclude
link /driver /subsystem:native /entry:DriverEntry osoosi_driver.obj /out:osoosi_driver.sys
```

---

## Test-Signing & Development Setup

Windows 64-bit strictly enforces Kernel-Mode Driver Signing (KMCS). For development and testing environments:

1. **Enable Test-Signing Mode** (elevated command prompt):
   ```cmd
   bcdedit /set testsigning on
   shutdown /r /t 0
   ```

2. **Generate a Self-Signed Test Certificate**:
   ```cmd
   makecert -r -pe -ss PrivateCertStore -n "CN=OshoosiTestCert" osoosi_test.cer
   certmgr /add osoosi_test.cer /s /r localMachine root
   certmgr /add osoosi_test.cer /s /r localMachine trustedpublisher
   ```

3. **Sign the Driver Binary**:
   ```cmd
   signtool sign /v /s PrivateCertStore /n "OshoosiTestCert" /t http://timestamp.digicert.com driver\windows\osoosi_driver.sys
   ```

---

## Service Installation & Registration

### Method 1: Using `pnputil` (Recommended for INF)
```cmd
pnputil /add-driver driver\windows\osoosi_driver.inf /install
```

### Method 2: Using Service Control Manager (`sc.exe`)
```cmd
:: Create the kernel service
sc create OsoosiDriver type= kernel binPath= "C:\Program Files\OshoosiClaw\driver\osoosi_driver.sys" start= demand

:: Start the driver
sc start OsoosiDriver

:: Query status
sc query OsoosiDriver

:: Stop and delete service
sc stop OsoosiDriver
sc delete OsoosiDriver
```

---

## ELAM (Early Launch Anti-Malware) Registration

For production deployment as an Early Launch Anti-Malware (ELAM) driver:
1. Obtain an EV Code Signing Certificate enrolled in the Microsoft Hardware Developer Program (WHQL).
2. Set `StartType = 0` (`SERVICE_BOOT_START`) in `osoosi_driver.inf`.
3. Set `Group = "Early-Launch"` in registry.
4. Microsoft signs the catalog with the ELAM Enhanced Key Usage (EKU `1.3.6.1.4.1.311.61.4.1`).
