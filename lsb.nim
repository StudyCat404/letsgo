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
import nimPNG
import nimcrypto
import nimcrypto/sysrand
import strutils
import stew/byteutils except toHex
import os

type
  Image* = ref object
    ## Main image object that holds the bitmap data.
    filePath*: string
    width*, height*: int
    data*: seq[uint8]

proc loadImageB*(imgFile: string): Image =
    var mypng = Image()
    let png = loadPNG32(imgFile)
    mypng.width = png.width
    mypng.height = png.height
    mypng.data = cast[seq[uint8]](png.data)  
    return mypng
    
proc loadImage*(rawData: string): Image =
    var mypng = Image()
    #let png = loadPNG32(imgFile)
    let png = decodePNG32(rawData)
    mypng.width = png.width
    mypng.height = png.height
    mypng.data = cast[seq[uint8]](png.data)  
    return mypng    
    
proc saveFile*(image: Image, fileName: string) =
    discard savePNG32(fileName, image.data, image.width, image.height)

proc encodeMessage*(image: Image, rawdata: string) =
  let filesize = cast[uint64](len(rawdata))
  let header = filesize.toHex(8)
  var data = header & rawdata 
  
  ## Hide data inside an image
  echo "[*] Input image size: ", image.width, "x", image.height, " pixels."
  echo "[*] Usable payload size: ", image.width * image.height, "B."
  echo "[+] Encrypted payload size: ", len(data), "B."
  
  if len(data) > image.width * image.height :
    echo "[-] Cannot embed. File too large"
    quit(-1)
    
  for i in 0..data.len:
    var dataByte: uint8
    if i < data.len:
      dataByte = uint8(data[i])
    image.data[i*4+0] = (image.data[i*4+0] and 0b11111100) + (dataByte and 0b00000011) shr 0
    image.data[i*4+1] = (image.data[i*4+1] and 0b11111100) + (dataByte and 0b00001100) shr 2
    image.data[i*4+2] = (image.data[i*4+2] and 0b11111100) + (dataByte and 0b00110000) shr 4
    image.data[i*4+3] = (image.data[i*4+3] and 0b11111100) + (dataByte and 0b11000000) shr 6
  echo "[+] Embedded successfully!"
  
proc decodeMessage*(image: Image): string =
  ## Extract hidden data in the image
  echo "[*] Input image size: ", image.width, "x", image.height, " pixels."
  
  result = ""
  
  for i in 0..<(image.data.len div 4):
    var dataByte: uint8
    dataByte += (image.data[i*4+0] and 0b11) shl 0
    dataByte += (image.data[i*4+1] and 0b11) shl 2
    dataByte += (image.data[i*4+2] and 0b11) shl 4
    dataByte += (image.data[i*4+3] and 0b11) shl 6
    result.add char(dataByte)

  var header = result[0..7]
  var filesize = fromHex[uint64](header) + 7
  return result[8..filesize]



func toByteSeq*(str: string): seq[byte] {.inline.} =
  ## Converts a string to the corresponding byte sequence.
  @(str.toOpenArrayByte(0, str.high))

proc encryptFile*(fileName: string, envkey: string): string =
    var
        data: seq[byte] = toByteSeq(readFile(fileName))
        ectx: CTR[aes256]
        key: array[aes256.sizeKey, byte]
        iv: array[aes256.sizeBlock, byte]
        plaintext = newSeq[byte](len(data))
        enctext = newSeq[byte](len(data))
       
    #discard randomBytes(addr iv[0], 16)
    iv = [byte 39, 215, 183, 62, 212, 75, 101, 46, 85, 66, 92, 49, 164, 183, 14, 146]
    copyMem(addr plaintext[0], addr data[0], len(data))
    var expandedkey = sha256.digest(envkey)
    copyMem(addr key[0], addr expandedkey.data[0], len(expandedkey.data))

    ectx.init(key, iv)
    ectx.encrypt(plaintext, enctext)
    ectx.clear()    
        
    var res = newString(len(enctext))
    copyMem(addr res[0], addr enctext[0], len(enctext))
    result = res

proc decrypt*(data: string, envkey: string): seq[byte] =
    var 
        dctx: CTR[aes256]
        key: array[aes256.sizeKey, byte]
        iv: array[aes256.sizeBlock, byte]
        enctext = newSeq[byte](len(data))
        dectext = newSeq[byte](len(data))
        
    iv = [byte 39, 215, 183, 62, 212, 75, 101, 46, 85, 66, 92, 49, 164, 183, 14, 146]
    enctext = toByteSeq(data)
    
    var expandedkey = sha256.digest(envkey)
    copyMem(addr key[0], addr expandedkey.data[0], len(expandedkey.data))
    
    dctx.init(key, iv)
    dctx.decrypt(enctext, dectext)
    dctx.clear()
    #writeFile(fileName, dectext)
    return dectext

proc help() =
    let pathSplit = splitPath(paramStr(0))
    echo "Usage:"
    echo "  ", pathSplit.tail, " en pngFile embedFile password"
    echo "  ", pathSplit.tail, "de pngFile outFile password"
    echo ""
    echo "Example:"
    echo "  Embed a file into an image."
    echo "  ", pathSplit.tail, " en logo.png beacon.bin 12345678"
    echo "  Extract hidden data in the image."
    echo "  ", pathSplit.tail, " de logo_out.png beacon.bin 12345678"
    
proc main() =
    if paramCount() > 0:
        var p1 = paramStr(1)
        if paramCount() < 2 or p1 in ["/?","-h","--help"]:
            help()
        else:
            var 
                mode = paramStr(1)
                imgFile = paramStr(2)
                userFile = paramStr(3)
                password = paramStr(4)
            if mode == "en":
                var enctext = encryptFile(userFile, password)
                var mypng = loadImage(readFile(imgFile))
                var fileName = ""
                
                let fileSplit = splitFile(imgFile)
                fileName = joinPath(fileSplit.dir, fileSplit.name & "_out" & fileSplit.ext)
                encodeMessage(mypng, enctext)
                mypng.saveFile(fileName)
                echo "[+] fileName: ", fileName
            if mode == "de":
                var mypng = loadImage(readFile(imgFile))
                var enctext = decodeMessage(mypng)
                var dectext = decrypt(enctext, password)
                writeFile(userFile, dectext)
                echo "[+] Written extracted data to ", userFile
    else:
        help()

when isMainModule:
    main()