---
title: Likely Belarus-Nexus Threat Actor Delivers Downloader to Poland
by: dmpdump
tags: malware chm belarus poland apt
---

On June 30, 2025, a file named `deklaracja.chm` ("declaration.chm") was uploaded to VirusTotal from Poland.

![sshot](/assets/images/Belarus_Poland/vtsubmission.png)

The file is a Microsoft Compiled HTML Help file, a proprietary online help format which consists of a binary that contains a collection of compressed files, including HTML files and other objects. Decompressing `deklaracja.chm`, we can see the following files:

![sshot](/assets/images/Belarus_Poland/content.png)

The files with the `#` prefix are standard CHM files. The rest of the files are malicious and lead to an infection chain that drops, extracts, and executes a C++ downloader.
* `index.htm` is an HTML file with an obfuscated JS script that starts the infection chain
* `desktop.mp3` is cabinet file which contains a downloader DLL
* `deklaracja.png` is a decoy image of a bank transfer receipt from PKO Bank, a Polish bank

CHM files are executed by `hh.exe` by default. When `deklaracja.chm` is executed, we see a decoy image displayed to the victim. We can also observer a series of processes that lead to the extraction and execution of a DLL named `unt32.dll`.

![sshot](/assets/images/Belarus_Poland/decoy.png)

![sshot](/assets/images/Belarus_Poland/infectionchain.png)

# Infection chain

Reviewing the content of `index.htm`, we can immediately see a common pattern in code obfuscated with [obfuscator.io](https://obfuscator.io/), including the presence of `_0x` in and runtime string retrieval from array indices.

![sshot](/assets/images/Belarus_Poland/html1.png)

After deobfuscating that script, we get a simple hex decoder for a large hex string (truncated for readability). The hexadecimal string is decoded with function `a0_0x22e3bf` and subsequently processed with `document.write`.

![sshot](/assets/images/Belarus_Poland/html2.png)

Hex decoding the string, we can see the HTML content that is executed when the CHM is run by the victim:

![sshot](/assets/images/Belarus_Poland/html3.png)

This is a simple but clever HTML file. It does the following:
* Creates an iframe to load the decoy image
* Attempts to load `desktop.mp3` via the deprecated `<bgsound>` tag, primarily supported by Internet Explorer. I suspect this is used to have the file downloaded as a .tmp file for subsequent extraction. The .mp3 file is a CAB file which contains `uNT32.dll`, the payload.

![sshot](/assets/images/Belarus_Poland/cab.png)

* Creates an ActiveX object with CLSID `adb880a6-d8ff-11cf-9377-00aa003b7a11`, which is associated with the HTML Help ActiveX Control (`hhctrl.ocx`), documented [here](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/htmlhelp/html-help-activex-control-overview). We can confirm this in the registry:

![sshot](/assets/images/Belarus_Poland/registry.png)

* A button is created with the value `Bitmap::Shortcut` and the target command is listed in the `Item1` parameter. Finally, the button is clicked via `Click()`, leading to the command execution.
The command executed by the CHM:

* Starts a minimized cmd prompt
* Navigates to the `%temp%` folder
* Uses the `forfiles.exe` native executable. The use of this LOLbin is common in the indirect execution of commands, potentially breaking the detection of suspicious parent/child process relationships. The parameter `/M` is used to search for .tmp files
* A command is then executed to check if the size of the identified .tmp files is 180738 bytes, which is the size of `desktop.mp3`
* If the .tmp file is exactly of 180738 bytes, the DLL within the CAB file is extracted using `expand`
* Finally, the extracted DLL (`uNT32.dll`) is loaded via rundll32.exe, invoking an exported function with ordinal #1

# Downloader

`uNT32.dll` is a C++ downloader with XOR-encrypted strings. The core download functionality of this DLL is implemented at offset `0x421487`, followed by a PE header validation function which, if unsuccessful, leads to program termination.

![sshot](/assets/images/Belarus_Poland/dll1.png)

![sshot](/assets/images/Belarus_Poland/dll2.png)

The string decryption is implemented using a 128 byte buffer as a rotating key. Strings are XOR decrypted in chunks of varying lenghts, depending on the string length. For example, the User-Agent string used for the payload download is decrypted in 5 byte chunks.

![sshot](/assets/images/Belarus_Poland/dll3.png)

The downloader uses the WinHTTP APIs to download and read payload delivered in the following file from the threat actor infrastructure: `hxxps://rustyquill[.]top/shw/the-magnus-protoco1.jpg`. The domain and file name refer to the Magnus Protocol podcast from [Rusty Quill](https://rustyquill.com/show/the-magnus-protocol/).

![sshot](/assets/images/Belarus_Poland/dll4.png)

The downloaded payload is read into a buffer which is size checked. The size check validates if the payload is bigger than 289109 bytes. If it is, it strips the first 289109 bytes and XOR decrypts the remainder using the same 128 byte key buffer used for the string decryption. The decrypted payload is saved to disk for execution.

![sshot](/assets/images/Belarus_Poland/dll5.png)

Unfortunately, I could not retrieve a copy of `the-magnus-protoco1.jpg` with payload. I found an image with the same name and delivered from the same infrastructure, however, the size of that image is 289109 bytes, with no anomalies after the .jpg end marker (`FF D9`). Based on the DLL's size verification code, no decryption would take place if the size of the image is exactly 289109 bytes. This leads me to believe that at some point the threat actor may have hosted benign images, either temporarily or for unintended downloaders (e.g. if geolocation was implemented). A malicious image delivering payload is very likely the same image that I found with content added after the `FF D9` end marker. This is likely because the downloader strips the exact same number of bytes that the image I found has.
The benign image is related to Rusty Quill:

![sshot](/assets/images/Belarus_Poland/goodimage.png)

I attempted to find the same image but with payload using a YARA rule with the following attributes:
* A JPEG header
* Sequential bytes from the image I found
* Size greater than 289109 bytes

```
rule findbadimage
{
    strings:
        $jpgheader = {FF D8 FF E0 00 10 4A 46 49 46 }
        $pattern1 = {89 8A 92 93 94 95 96 97 98 99 9A A2 A3 A4 A5 A6 A7 A8 A9 AA B2 B3 B4 B5 B6 B7 B8 B9 BA C2 C3 C4 C5 C6 C7 C8 C9 CA D2 D3 D4 D5 D6 D7 D8 D9 DA E2 E3 E4 E5 E6 E7 E8 E9 EA F2 F3 F4 F5 F6 F7 F8 F9 FA FF DA 00 0C 03 01 00 02 11 03 11 00 3F 00 FC 7B F0 EF 81 E6 FD 9D F4 EF 3B 7D AE AF E3 9D 71 7E CD 67 67 6C 45 C1 80 37 07 6B 29}
        $pattern2 = {3A 9E 9D A7 68 6D 67 65 76 64 80 32 24 72 00 51 64 DA D2 B1 2D 83 80 9E D4 01 FA 21 FB 40 7E CA DE 30 F1 9F FC 17 D7 E0 17 C4 EB 0F 0F CF 75 E0 5F 0D FC 3A D6 B4 AD 67 54 F3 10 43 6F 34 A2 E4 45 11 52 77 33 31 99 7A 0C 73 CD 7E 48 7F C1 E6 FE 2C D3 BC 51 FF 00 05 0F F8 71 A0 58 DC 41 77 AC E8 9E 08 86 2D 41 22 6C B4 2F 3D}
    condition:
        $jpgheader at 0 
        and filesize > 289109
        and $pattern1 and $pattern2
}
```

Unfortunately, I still have not been able to find any images that match this criteria. There is always a possibility that the threat actor delivered other images which do not share the byte sequence. However, given the exact number of stripped bytes, I suspect the image I found is the same image that had encrypted payload appended to it.

The downloaded and decrypted payload is a DLL saved to a newly created folder under: `C:\Users\%user%\AppData\Local\TaskSync\net32.dll`. The payload is executed with rundll32.exe, calling an exported function with ordinal #1. A Scheduled Task is created for the DLL execution using the TaskScheduler API via COM.


![sshot](/assets/images/Belarus_Poland/dll6.png)


![sshot](/assets/images/Belarus_Poland/schtask.png)


# Previous Samples and attribution

The `rustyquill[.]top` domain is also associated with a previous CHM file shared by [@MalwareHunterTeam](https://x.com/malwrhunterteam/status/1909235735850279070) on April 7, 2025.
* Zip file name: `dowód_wpłaty.zip` ("proot of payment")
* Zip SHA2: 4d09fad2630ec33ab6bb45b85455c6a6ac7b52f8dae9b90736db4a5f00f72ea9
* File name: `dowod.chm` ("evidence")
* File SHA2: 0631696f484633f4aeb8f817af2a668806ab4dca70f006dc56fc9cd9dcda4dbe 

These CHM files are very likely associated with a threat actor tracked as `FrostyNeighbor` and `UNC1151`, historically attributed to Belarus. Previous targeting documented in reports such as the [following](https://cloud.google.com/blog/topics/threat-intelligence/unc1151-linked-to-belarus-government/) suggest an interest in Ukraine, Lithuania, Latvia, Poland, and Germany, which is consistent with the upload geography for these malicious CHM files.

# IOCs
* deklaracja.chm: 0d3dbaa764acb2b87ae075aa2f5f924378991b39587b0c5e67a93b10db39ddd9
* index.htm: 156ad4975e834355b2140d3c8fe62798fe6883364b8af1a1713f8b76c7b33947
* desktop.mp3: be5a40b5622d21b46cbc87fd6c3f8ebcb536ec8480491a651c1625ee03ae2c6f
* deklaracja.png: f55e06a87e2a20989ddb76d9f2e3ebb303659ad306ba54e3ed7f8dcc4456d71b
* Payload: hxxps://rustyquill[.]top/shw/the-magnus-protoco1.jpg