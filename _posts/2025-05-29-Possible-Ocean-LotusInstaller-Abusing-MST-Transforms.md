---
title: Possible APT32/Ocean Lotus Installer abusing MST Transforms
by: dmpdump
tags: cti malware mst oceanlotus vietnam
---

While monitoring new threats, I came across an interesting ISO image (ced7fe9c5ec508216e6dd9a59d2d5193a58bdbac5f41a38ea97dd5c7fceef7a5) uploaded to VirusTotal from Taiwan on May 20, 2025. The ISO contained 3 files:
* 脱密 中央国安办.pdf.lnk (Declassified Central National Security Office.pdf.lnk)
* WindowsPCHealthCheckSetup.msi (hidden)
* 5ACXP.mst (hidden)

Upon review of the files, I found strong similarities with a [sample](https://ti.qianxin.com/blog/articles/new%20-trend-in-msi-file-abuse-new-oceanlotus-group-first-to-use-mst-files-to-deliver-special-trojan-en/) initially reported by QiAnxin Threat Intelligence Center on November 24, 2024. QiAnxin's 2024 report appears to be the first report of an abused MST transform, but there may be previous cases that I am not aware of.

`Note: The attribution to Ocean Lotus / APT32 is solely based on QiAnXin's previous attribution`

# Infection Chain Analysis

The victim is expected to run the only visible file in the ISO, 脱密 中央国安办.pdf.lnk, a shortcut file disguised as a PDF via double extension.

![sshot](/assets/images/apt32_mst/iso.png)

The shortcut file reveals the execution of the hidden files: an MSI installer with an MST transform.

![sshot](/assets/images/apt32_mst/lnk.png)

MST transforms are a collection of changes applied to an installation package, applied during the installation process. There are 3 types of transforms:
* `Embedded Transforms`, embedded within the MSI installer
* `Secured Transforms`,  stored locally in a directory where only administrators have write access
* `Unsecured Transforms`, not secured with the control used in Secured Transforms, and can be passed as an argument in the command line of the MSI file execution using the `TRANSFORMS=` property
 
[Here](https://learn.microsoft.com/en-us/windows/win32/msi/about-transforms) is Microsoft's documentation on MSI Transforms.

As seen in the LNK file used by this threat actor, a suspicious Unsecured Transform is passed as an argument during the execution of the MSI installer. We can apply the transform manually and compare the MSI tables before and after the transform to see how the installation process is modified.

![sshot](/assets/images/apt32_mst/msi_pre.png)

![sshot](/assets/images/apt32_mst/msi_post.png)

A custom action is added, using a new DLL named `Transforms.dll`. Two exported functions within the DLL are called, `LogSetupBeforeInstall` and `LogSetupAfterInstall`. In order to review if any malicious activity is implemented via the MST, we need to review the `Transforms.dll`.

The DLL exists within the MST file:

![sshot](/assets/images/apt32_mst/mst_transforms.png)

It contains the 2 expected exported functions:

![sshot](/assets/images/apt32_mst/transforms_fun.png)

Reviewing the DLL, we can confirm the following capabilities:
* Drops and opens a decoy PDF  
The LogSetupBeforeInstall exported function extracts an embedded PDF of 33460 bytes and saves it to `%USERPROFILE%\Documents\`. The PDF is named `脱密 中央国安办.pdf (Declassified Central National Security Office.pdf)`. The PDF is opened with the `ShellExecuteExW` WinAPI.

![sshot](/assets/images/apt32_mst/open_pdf.png)

![sshot](/assets/images/apt32_mst/embedded_pdf.png)

The PDF content is consistent with the theme used in the file names. Machine translation suggests that the content is related to a National Security Office reorganization. The PDF looks truncated, possibly a deliberate action by the threat actor.

![sshot](/assets/images/apt32_mst/pdf_content.png)

* Contains an embedded DLL, which is subsequently dropped to disk  
The DLL contains an embedded DLL in the `.rdata` section named `tbs.dll`. The DLL is dropped to disk during the installation of the MSI package. As we will see later, the execution of the final payload relies on this DLL.

![sshot](/assets/images/apt32_mst/embedded_dll.png)

* Establishes persistence via a registry run key  
The DLL establishes persistence via a registry run key. Persistence is established for the following executable: `%LocalAppData%\PCHealthCheck\PCHealthCheck.exe`.

![sshot](/assets/images/apt32_mst/persist_1.png)

![sshot](/assets/images/apt32_mst/persist_2.png)

Upon the execution of the MST-transformed `WindowsPCHealthCheckSetup.msi` via the `脱密 中央国安办.pdf.lnk` shortcut, we end up with the legitimate PcHealthCheck executable along with the malicious `tbs.dll` dropped by the MST transform under `%LocalAppData%\PCHealthCheck\`. As expected, `tbs.dll` is side-loaded by `PcHealthCheck.exe`.

![sshot](/assets/images/apt32_mst/sideload.png)

# Function Hooking

The malicious execution of `tbs.dll` via DLL side-loading triggers an interesting sequence of events which involves function hooking and patching of a DLL in memory, as well as a multi-stage sequence of shellcodes that leads to the execution of the final payload in memory.
The first step in the infection process is the implementation of a hook in the `RtlUserThreadStart` function. First, the malware resolves the `ntdll.dll` and `kernel32.dll` modules using the `djb2` algorithm for the module name resolution. Then, it resolves the `RtlUserThreadStart` function (hooking target) and the `GetModuleHandle` function, used to implement the hook. The core of the function hook resides in:
* Resolving the base address of the current executable
* Using that base address to locate the entry point
* Getting the stack base for the current thread
* Scanning the [CONTEXT](https://www.vergiliusproject.com/kernels/x64/windows-10/22h2/_CONTEXT) structure to validate when the `rip` instruction pointer (offset 0xF8 in the structure) is in `RtlUserThreadStart`
* Updating `rip` to point to the malicious function, which I renamed to `fn_pload_load`

Essentially, the hook is implemented via `thread context manipulation`, redirecting execution to malicious code.

![sshot](/assets/images/apt32_mst/hook.png)

Inspecting `fn_pload_load`, we can see that this is a trampoline hook. After executing the malicious logic in the function I named `fn_pload_decrypt_dll_patch`, it calls the legitimate `RtlUserThreadStart`.

![sshot](/assets/images/apt32_mst/trampoline.png)

# Shellcode Decryption and DLL Patching

The function I named `fn_pload_decrypt_dll_patch` implements a custom decryption algorithm for the next stage shellcode. First, it copies 803489 bytes from an encrypted blob to a newly allocated buffer and sets up a 32-byte key `0x5f7b41cb6c68699def80c3a916b760e27396f55765c9c38db174999e2efa165c`.

![sshot](/assets/images/apt32_mst/enc_blob.png)

The blob is subsequently decrypted using a combination of AES-256 in ECB mode with XOR, in 16-byte blocks. The decryption algorithm does the following:
* It AES decrypts the first 16 bytes of the encrypted blob but does not apply XOR decryption. This will be the header of the decrypted buffer
* The second 16-byte block is AES-decrypted, using that decrypted block as the XOR key for the first 16-byte block of the encrypted blob
* The third 16-byte block is AES-decrypted, using those bytes as the XOR key for the second 16-byte block of the encrypted blob
* It continues incrementing the blocks applying AES-decryption and using the decrypted bytes as the XOR key for the previous 16-byte block
![sshot](/assets/images/apt32_mst/decrypt.png)

The result is a decrypted buffer with the following header: `5D 00 00 80 00 60 32 0C 00 00 00 00 00 00`. This header is indicative of the `Lempel-Ziv-Markov (LZMA)` algorithm. LZMA decompression is subsequently applied to the buffer, decompressing a shellcode.

![sshot](/assets/images/apt32_mst/decrypted_blob.png)

Once the shellcode is decrypted and decompressed, a new function is called passing a pointer to the string `xpsservices.dll` and a pointer to the decrypted shellcode. This function resolves the `LoadLibraryExA` and `ZwProtectVirtualMemory` APIs via API hashing.

![sshot](/assets/images/apt32_mst/loadlib.png)
![sshot](/assets/images/apt32_mst/zwprotect.png)

The legitimate `xpsservices.dll` is then loaded with `LoadLibraryExA` and the DLL is patched in memory, copying the shellcode to the `.text` section. For that, the function searches for the `.text` section, converting the string `.tex_` into `.text` at runtime, replacing the last character in an attempt to avoid static detection of the string.

![sshot](/assets/images/apt32_mst/text_replace.png)

Once the `.text` section is found, memory protection is changed to `PAGE_READWRITE` using `ZwProtectVirtualMemory`. The shellcode is copied to that section, and memory protection is changed to `PAGE_EXECUTE_READWRITE`.

![sshot](/assets/images/apt32_mst/patch.png)

Finally, when this function returns, the shellcode is executed from the patched DLL.

![sshot](/assets/images/apt32_mst/shellcode_exec.png)

The next-stage shellcode contains a self-unpacking stub that decompresses and executes a blob of LZMA-compressed data. The LZMA compression is again recognized thanks to its distinctive `5D 00 00 80 00 60 32 0C 00 00 00 00 00 00` header. The decompressed payload is executed as shellcode with a call to `rbx`.

![sshot](/assets/images/apt32_mst/shellcode_decompression.png)

![sshot](/assets/images/apt32_mst/shellcode_execution.png)

The last stage is another shellcode. This final implant is written in Rust, it has a statically linked `libcurl` library, and connects to the following command and control: `http://194.87.108[.]94:80/users/b97fc88c-cff5-4433-a784-df2a5e094452/profile/information` and uses a forged User-Agent string to impersonate a Huawei Android device: `Mozilla/5.0 (Linux; Android 12; JAD-AL00 Build/HUAWEIJAD-AL00; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/114.0.5735.196 Mobile Safari/537.36`.

![sshot](/assets/images/apt32_mst/final0.png)

At a high level, we can summarize the complete infection chain with the following diagram:

![sshot](/assets/images/apt32_mst/Diagram.png)


# Related Samples

A few likely related samples were shared in social media by MalwareHunterTeam [here](https://x.com/malwrhunterteam/status/1918410442860576875) and [here](https://x.com/malwrhunterteam/status/1920384329814863992). 

The abuse and trojanization of MST transforms is a rare technique. The samples that appeared in the wild in May 2025 seem to be a continuation to the activity originally reported by QiAnXin in November 2024.


# IOCs
* ISO: ced7fe9c5ec508216e6dd9a59d2d5193a58bdbac5f41a38ea97dd5c7fceef7a5
* 脱密 中央国安办.pdf.lnk: c430f5388a36be5a3b18a382c4a5e1f25f28a2db1ebd22009885ec1ec92bd061
* WindowsPCHealthCheckSetup.msi: f87bf57756049015686b7769b5a8db32026d310bf853e7d132424f7513fe316c
* 5ACXP.mst: 2f32ca6358a57531c04c640625f2b30a3c1bdbcbfd896107597fcdcbab3153e0
* Transforms.dll: 20c8b797b614f574070d591248edcaa764ecfb95eba3f58a98bf2e40b4d91ffe
* tbs.dll: 20c8b797b614f574070d591248edcaa764ecfb95eba3f58a98bf2e40b4d91ffe
* C2: http://194.87.108[.]94:80/users/b97fc88c-cff5-4433-a784-df2a5e094452/profile/information
