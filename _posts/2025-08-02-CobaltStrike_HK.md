---
title: SLOW#TEMPEST Cobalt Strike Loader
by: dmpdump
tags: malware hongkong cobaltstrike
---

On July 17, 2025, an ISO image with moderate detection was updated to VirusTotal from Hong Kong.

![sshot](/assets/images/hkcobaltstrike/vtsubmission.png)

ISO SHA2: 6573136f9b804ddc637f6be3a4536ed0013da7a5592b2f3a3cd37c0c71926365

The ISO image has a structure which I have seen multiple times in threat activity targeting Chinese-speaking users. Once the ISO is mounted, the victim sees a shortcut (LNK) file with a deceiving folder icon. Additionally, hidden folders within the ISO lead to a legitimate executable, a malicious DLL, and a decoy PDF.

![sshot](/assets/images/hkcobaltstrike/mounted.png)

![sshot](/assets/images/hkcobaltstrike/tree.png)

The LNK file that triggers the infection chain is named `郑州商品交易所基础设施运维问题Review.lnk`, which translates to `Zhengzhou Commodity Exchange Infrastructure Operation and Maintenance Issues Review.lnk`. Zhengzhou Commodity Exchange is a Chinese [futures exchange](https://en.wikipedia.org/wiki/Zhengzhou_Commodity_Exchange) based in Zhengzhou, China.

Inspecting the LNK file we can see that its main objective is to execute `config.exe`, an executable within the hidden nested folders.

```text
[String Data]
Relative path (UNICODE):                ..\..\..\..\..\..\Windows\SysWOW64\explorer.exe
Arguments (UNICODE):                    ".\__MACOSX\__MACOSX\__MACOSX\__MACOSX\config.exe"
```

Reviewing the LNK's timestamps and metadata, we can see that the LNK was likely reused to execute `DingTalkSnippingTool.exe` in previous activity. Some of the timestamps point to 2024, which supports the hypothesis of LNK reuse. Additionally, we can see paths related to user `rehea` and a subfolder named `evil`. Finally, we can see that the machine name associated with the creation of this LNK file is `desktop-rl06167`.

```text
[Header]
Date created:                           08/04/2024 (09:30:30.652) [UTC]
Last accessed:                          11/14/2024 (03:02:09.60) [UTC]
Last modified:                          08/04/2024 (09:30:30.730) [UTC]
File size:                              5052928 bytes

[Metadata Property Store]
Property set GUID:                      dabd30ed-0043-4789-a7f8-d013a4736622
ID:                                     System.ItemFolderPathDisplayNarrow
Value:                                  0x001f (VT_LPWSTR)      __MACOSX (C:\??\rehea\??\x64????????\dingding???\evil\__MACOSX\__MACOSX\__MACOSX)

Property set GUID:                      b725f130-47ef-101a-a5f1-02608c9eebac
ID:                                     System.ItemTypeText
Value:                                  0x001f (VT_LPWSTR)      DingTalkSnippingTool.exe
ID:                                     System.DateCreated
Value:                                  0x0040 (VT_FILETIME)    07/23/2024 (07:29:30.0) [UTC]
ID:                                     System.Size
Value:                                  0x0015 (VT_UI8)         0x0000000000193530 = 1652016
ID:                                     System.ItemTypeText
Value:                                  0x001f (VT_LPWSTR)      ????
ID:                                     System.DateModified
Value:                                  0x0040 (VT_FILETIME)    05/06/2024 (14:50:49.569) [UTC]

Property set GUID:                      28636aa6-953d-11d2-b5d6-00c04fd918d0
ID:                                     System.ParsingPath
Value:                                  0x001f (VT_LPWSTR)      C:\Users\rehea\Desktop\x64????????\dingding???\evil\__MACOSX\__MACOSX\__MACOSX\__MACOSX\DingTalkSnippingTool.exe

[Distributed Link Tracker Properties]
Version:                                0
NetBIOS name:                           desktop-rl06167
Droid volume identifier:                47b41472-5a80-400f-8f27-2b06d2a24a4d
Droid file identifier:                  a025eadc-9fe7-11ef-b2f7-347df6183a61
Birth droid volume identifier:          47b41472-5a80-400f-8f27-2b06d2a24a4d
Birth droid file identifier:            a025eadc-9fe7-11ef-b2f7-347df6183a61
MAC address:                            34:7d:f6:18:3a:61
UUID timestamp:                         11/11/2024 (04:44:24.487) [UTC]
UUID sequence number:                   13047

```

# Cobalt Strike Loader

As observed in the LNK file, its sole objective is to execute `config.exe`. This file is a legitimate, signed, Alibaba executable originally named `arphaCrashReport`.

![sshot](/assets/images/hkcobaltstrike/arpha.png)

Whenever we see a legitimate executable in such a suspicious execution chain, we immediately think of DLL sideloading, so we need to inspect DLLs within the same folder. Looking at the imports in `config.exe`, we can see that it loads `arphadump64.dll`.

![sshot](/assets/images/hkcobaltstrike/import.png)

`arphadump64.dll`is a malicious loader with significant amount of junk code to confuse analysis and delay execution. The core functionality of the loader is located at offset `0x180002A61`. The junk code consists primarily in a great number of string assignment functions which take a dummy string such as `examp564654654654646465465465456465165165465465le4` or `param[number]` as a parameter.

![sshot](/assets/images/hkcobaltstrike/junk.png)

However, if we look closely, anti-analysis controls and loader functionalities can be identified among the junk code. The loader calls the `GlobalMemoryStatusEx` API to retrieve the amount of RAM memory from the `ullTotalPhys` member of the `MEMORYSTATUSEX` structure. It subsequently checks if the infected system has 6GB of RAM memory or more to proceed with the loader functionality.

![sshot](/assets/images/hkcobaltstrike/memstat.png)

![sshot](/assets/images/hkcobaltstrike/memcheck.png)

Further down the execution of the main logic function, we can see that this loader DLL builds a path to `base.dll` and implements a function to open the DLL. We subsequently see a file offset (`0x1B9CA8`) passed as an argument to a function. Upon review, this ended up being an offset within `base.dll`. This code suggests that `base.dll` is not loaded as a DLL to execute code. Instead, it simply has embedded content read by the loader DLL.

![sshot](/assets/images/hkcobaltstrike/getbase.png)

Inspecting offset `0x1B9CA8` in `base.dll` we see content that does not look like valid code. In fact, we can observe a repeating pattern (`jdk`), suggesting the possibility of XOR encryption with a short key.

![sshot](/assets/images/hkcobaltstrike/base.png)

The code that follows confirms our hypothesis. The payload read from `base.dll` is XOR decrypted with a 3-byte rolling XOR key (`0x6A646B` = `jdk`). The decrypted payload is subsequently copied into newly-allocated memory with `PAGE_EXECUTE_READWRITE` permissions, and a new thread is created for the payload execution. Additionally, a new thread is also created to execute `4.pdf`, which is a decoy PDF.

![sshot](/assets/images/hkcobaltstrike/decryptload.png)

The decrypted payload is executed in a new thread via a function pointer:

![sshot](/assets/images/hkcobaltstrike/fnptr.png)

The decoy PDF is opened with the `ShellExecuteA` API and it contains a one line string: `文档信息损坏` (`Document information is damaged`).

![sshot](/assets/images/hkcobaltstrike/openpdf.png)

![sshot](/assets/images/hkcobaltstrike/pdf.png)

Looking at the first bytes of the decrypted payload, the custom `MZARUH` header stands out - this is highly indicative of Cobalt Strike.

![sshot](/assets/images/hkcobaltstrike/customhead.png)

With that in mind, we can attempt to parse its configuration, and, indeed, we can confirm that this is an HTTP Cobalt Strike Beacon using `m.123huodong.com.cloud.cdntip.com.s2-web.dogedns[.]com` as the C2. Some of the Beacon network attributes, such as POST URI and metadata, have the objective of disguising the traffic as [`Bilibili`](https://en.wikipedia.org/wiki/Bilibili) traffic, a Chinese online video sharing website. The watermark in this beacon is `666666666`, likely associated with a cracked version of Cobalt Strike.

```
Beacon configuration:
BeaconType                       - HTTP
Port                             - 80
SleepTime                        - 15000
MaxGetSize                       - 2097210
Jitter                           - 47
MaxDNS                           - Not Found
PublicKey_MD5                    - af1e45058dca830b095da6dd8c15b116
C2Server                         - m.123huodong.com.cloud.cdntip.com.s2-web.dogedns[.]com,/x/space/user/setting/list
UserAgent                        - Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko)
HttpPostUri                      - /x/internal/gaia-gateway/ExClimbWuzhi
Malleable_C2_Instructions        - Remove 18 bytes from the end
                                   Remove 18 bytes from the beginning
                                   Remove 18 bytes from the beginning
                                   XOR mask w/ random key
HttpGet_Metadata                 - ConstHeaders
                                        Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
                                        Host: api.bilibili[.]com
                                        Referer: https://static.microsoft.com/
                                        Accept-Encoding: gzip, deflate
                                   Metadata
                                        base64url
                                        prepend "ANID="
                                        prepend "__Secure-3PAPISID=noskin;"
                                        append ";CONSENT=YES+CN.zh-CN+20210917-09-0"
                                        header "Cookie"
HttpPost_Metadata                - ConstHeaders
                                        Content-Type: application/json;charset=UTF-8
                                        Priority: u=1, i
                                        Accept: */*
                                        Host: api.bilibili[.]com
                                   ConstParams
                                        template_code=zVVNqfra
                                        cash_min=TdLRLMuYIApT
                                   SessionId
                                        base64url
                                        parameter "__formid"
                                   Output
                                        base64url
                                        prepend "aid_=522005705&accver=1&showtype=embed&ua="
                                        print
PipeName                         - Not Found
DNS_Idle                         - Not Found
DNS_Sleep                        - Not Found
SSH_Host                         - Not Found
SSH_Port                         - Not Found
SSH_Username                     - Not Found
SSH_Password_Plaintext           - Not Found
SSH_Password_Pubkey              - Not Found
SSH_Banner                       - Host: m.123huodong.com.cloud.cdntip[.]com

HttpGet_Verb                     - GET
HttpPost_Verb                    - POST
HttpPostChunk                    - 0
Spawnto_x86                      - %windir%\syswow64\gpupdate.exe
Spawnto_x64                      - %windir%\sysnative\gpupdate.exe
CryptoScheme                     - 0
Proxy_Config                     - Not Found
Proxy_User                       - Not Found
Proxy_Password                   - Not Found
Proxy_Behavior                   - Use IE settings
Watermark_Hash                   - Vbi/d5GsmtZldELooLqdHw==
Watermark                        - 666666666
bStageCleanup                    - True
bCFGCaution                      - True
KillDate                         - 0
bProcInject_StartRWX             - False
bProcInject_UseRWX               - False
bProcInject_MinAllocSize         - 17500
ProcInject_PrependAppend_x86     - Empty
ProcInject_PrependAppend_x64     - Empty
ProcInject_Execute               - ntdll:RtlUserThreadStart
                                   CreateThread
                                   NtQueueApcThread-s
                                   CreateRemoteThread
                                   RtlCreateUserThread
ProcInject_AllocationMethod      - NtMapViewOfSection
bUsesCookies                     - True
HostHeader                       - Host: m.123huodong.com.cloud.cdntip[.]com

headersToRemove                  - Not Found
DNS_Beaconing                    - Not Found
DNS_get_TypeA                    - Not Found
DNS_get_TypeAAAA                 - Not Found
DNS_get_TypeTXT                  - Not Found
DNS_put_metadata                 - Not Found
DNS_put_output                   - Not Found
DNS_resolver                     - Not Found
DNS_strategy                     - round-robin
DNS_strategy_rotate_seconds      - -1
DNS_strategy_fail_x              - -1
DNS_strategy_fail_seconds        - -1
Retry_Max_Attempts               - 0
Retry_Increase_Attempts          - 0
Retry_Duration                   - 0
```

# Entry Point Patching

After creating the threads for the Beacon and decoy PDF, the loader implements an infinite loop patch in the entry point of the loading executable (`config.exe`). The patch is implemented by calling `K32GetModuleInformation` and getting a pointer to the `MODULEINFO` structure. A patch with bytes that implement an infinite loop is then written to the entry point of `config.exe`, locating it via the `EntryPoint` member of `MODULEINFO`.

![sshot](/assets/images/hkcobaltstrike/entrypatch.png)

The infinite loop patch to the entry point, for better visualization:

```
0:  eb 00                   jmp    0x2
2:  eb fd                   jmp    0x1
4:  50                      push   rax
5:  58                      pop    rax
6:  eb f9                   jmp    0x1 
```

Locking the loader executable with an infinite patch likely serves the purpose of blocking the normal execution flow of `config.exe` while maintaining the persistent execution of the malicious Cobalt Strike thread. The infinite patch likely avoids thread synchronization issues or early termination/crashes due to the execution of the malicious DLL. This Cobalt Strike loader was compiled on July 16, 2025 (one day before the sample was uploaded to VirusTotal) and its original name is `ldrunlock.dll`. The original DLL name was likely derived from the infinite patch implemented in the loader executable. 

![sshot](/assets/images/hkcobaltstrike/dllheader.png)

![sshot](/assets/images/hkcobaltstrike/ldrunlock.png)


# Similarities with previously reported SLOW#TEMPEST activity

Accurate attribution is hard and requires significant amounts of data and a solid analytical model. While I am not in a position to attempt attribution, I can observe that multiple aspects of this activity overlap with a campaign [previously reported](https://www.securonix.com/blog/from-cobalt-strike-to-mimikatz-slowtempest/) as `SLOW#TEMPEST` by Securonix in August 2024:
* Targeting of Chinese-speaking users
* Folder structure similarities ('__MACOS' nested folders)
* The presence of the `evil` subfolder in the metadata of one of their reported LNK files (28030E8CF4C9C39665A0552E82DA86781B00F099E240DB83F1D1A3AE0E990AB6)
* DLL sideloading of Cobalt Strike beacons executed from an LNK file
* Use of the same Cobalt Strike Watermark (666666666)


Another related report was [published by Palo Alto Unit42](https://unit42.paloaltonetworks.com/slow-tempest-malware-obfuscation/) in July 2025. In this report they reviewed the obfuscation techniques of a loader sideloaded by `DingTalk.exe`. This legitimate executable is similar to the legacy artifact identified in our LNK file (`DingTalkSnippingTool.exe`). The loader in question, although not fully analyzed in the report, also seems to check for a minimum of 6GB of memory, just like our loader.


# IOCs
* ISO: 6573136f9b804ddc637f6be3a4536ed0013da7a5592b2f3a3cd37c0c71926365 
* 郑州商品交易所基础设施运维问题Review.lnk: c28bd1a57e80861fce2597b1f5155a687bef434b0001632c8a53243718f5f287
* base.dll: 5efbd54a3a51d96fbc8e65815df2f0d95af21a34b99b8dc9a38590fb6d2094f8
* config.exe: 1cb0560f614cc850422171ffe6b0b9f6b9ceaec4fe3516bc8493f253076470ab
* 4.pdf: 50fbe429848e16f08a6dbf6ce6d5bbff44db1e009f560e8b8c4cde6cff0a768b
* arphadump64.dll: a41c06ad948f3a21496e4d1f6b622ca84a365dd2087b710ed3e7f057e7a2a3f8
* C2: m.123huodong.com.cloud.cdntip.com.s2-web.dogedns[.]com


