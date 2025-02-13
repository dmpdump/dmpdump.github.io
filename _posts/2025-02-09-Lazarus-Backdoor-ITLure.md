---
title: Lazarus Backdoor with IT Lure
by: dmpdump
tags: cti malware apt dprk cti
---

On January 27, 2025, [@smica83](https://x.com/smica83/status/1883855708963442892) shared a sample on X indicating that it looked like Lazarus malware. I reviewed the sample and concluded that, indeed, it is a North Korean backdoor, likely the latest version of a backdoor publicly tracked as PEBBLEDASH.

![sshot](/assets/images/dprk_itsector/smica83.png)

The file shared by @smica83 is a portable executable named `iconcache.tmp.pif`, with SHA2:`d0a41dfe8f5b5c8ba6a5d0bdc3754543210ec2d36290564d9a774e9d22e3ad97 `. Reviewing connected samples in VirusTotal, I could see 2 droppers leading to this executable:

![sshot](/assets/images/dprk_itsector/pivot.png)

Taking `6744ca5d49833c9b90aee0f3be39d28dec94579b028b05c647354ec5e1ab53e1` as a sample dropper, we can see it is a 64-bit portable executable with a PDF icon as a lure. The dropper is obfuscated and it drops and opens a decoy PDF named `2025년 01월 오라클 정기점검(서명완).pdf`, which translates to `Oracle Scheduled Maintenance in January 2025 (Seo Myeong-wan)`. It also drops the executable shared by @smica83, `iconcache.tmp.pif`, both under `C:\ProgramData`.

![sshot](/assets/images/dprk_itsector/drop1.png)

The PDF seems to be a monthly inspection report from South Korean IT comany DBWorks, potentially for their client Unison Co Ltd., a South Korean wind turbine manufacturer. The report is dated 2025-01-23, which coincides with the VirusTotal upload date of `iconcache.tmp.pif` and its dropper. It is unclear which of the two companies were targeted, but Unison was likely the target.

![sshot](/assets/images/dprk_itsector/pdf.png)

Upon execution, the dropper runs `iconcache.tmp.pif`, setting its persistence via a registry run key:

![sshot](/assets/images/dprk_itsector/drop2.png)

# Backdoor

`iconcache.tmp.pif` is a backdoor that implements an argument check to determine its execution path:

![sshot](/assets/images/dprk_itsector/initial_decision.png)

If the backdoor is executed with the `--start` argument, it skips the execution of its main logic and establishes persistence for itself via the registry run key, as observed in the initial execution. If the backdoor is executed without any arguments (as is the case during persistence), the main backdoor logic is executed.

Across the backdoor, we can see the resolution of APIs via the computation of FNV1-a hashes using embedded strings, as can be seen during the creation of the malware persistence:

![sshot](/assets/images/dprk_itsector/fnv1a-res.png)

![sshot](/assets/images/dprk_itsector/persist_debug.png)

![sshot](/assets/images/dprk_itsector/persist.png)

When the main backdoor logic is executed, it sets up a connection to the C2 via the initialization of Winsock structures using `WSAStartup`.

![sshot](/assets/images/dprk_itsector/initializewinsock.png)

It then proceeds to decrypt the C2 domain: `http://www.addfriend[.]kr/board/userfiles/temp/index.html`

![sshot](/assets/images/dprk_itsector/decryptc2.png)

The backdoor uses the following User Agent string, obfuscated via stack strings: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.102 Safari/537.36`

![sshot](/assets/images/dprk_itsector/uastring.png)

Connections to the command and control use the following values: `sep`, a hard-coded string, `uid`, based on the volume drive information, and `sid`, random.

![sshot](/assets/images/dprk_itsector/postreq.png)

After decrypting the C2 URL and connecting to the C2, the backdoor parses an HTML response before entering a loop to accept remote commands.

![sshot](/assets/images/dprk_itsector/mainloop1.png)

The backdoor implements 14 commands, some of which were not very clear to me. It makes extensive use of files with the "PMS" prefix written to AppData\Local\Temp. These files are used by the backdoor to save the output of commands executed remotely, to save screenshots, and for the registration of DLLs.

| Command | Action |
|----------|----------|
| 3 | Changes/sets the current directory |
| 4 | Creates a process |
| 5 | Creates a process impersonating a token |
| 6 | Writes a file with the "PMS" prefix in AppData\Local\Temp, registers it with regsvr32.exe /s |
| 7 | Loads a DLL |
| 8 | Reads a file |
| 9 | Writes a file |
| 10 | Gets System time and updates a global variable, possibly introducing a delay |
| 11 | Gets System time and updates a global variable, possibly introducing a delay |
| 12 | Deletes persistence in the registry and runs a self-deletion batch file |
| 13 | Gets the hostname, computer name, and adapters information |
| 14 | Executes shell commands with cmd.exe, writing the output to a file with the "PMS" prefix|
| 15 | Makes new request to the C2, unclear what the purpose is |
| 16 | Takes a screenshot and saves it to a file with the "PMS" prefix in AppData\Local\Temp |

The batch file dropped by command 12 is named `ico.bat` and it is dropped to `AppData\Local\Temp`. It contains the following self-deleting batch script.

```batch
@echo off
:L1
del %path_to_malware%
if exist %path_to_malware% goto L1
del "C:\Users\%user%\AppData\Local\Temp\ico.bat"
```

When the backdoor sends data to the C2, it uses the following values: `sep=`, choosing a hard-coded string, `sid=`, which is random, and `data=`, with the response data. The response data seems to be AES encrypted with key `aqjNWSmPkmpYnZJT` and then base64-encoded.

![sshot](/assets/images/dprk_itsector/encryptencode.png)

We can test this by reversing the `data=` value when a screenshot is exfiltrated:

![sshot](/assets/images/dprk_itsector/cyberchef.png)

# Previous reports

There are multiple reports documenting the use of PEBBLEDASH in the past, including great work from [Ahnlab](https://asec.ahnlab.com/en/30022/). One of the most detailed reports I could find was from [Qianxing Threat Intelligence](https://ti.qianxin.com/blog/articles/Kimsuky-Weapon-Update:-Analysis-of-Attack-Activity-Targeting-Korean-Region/). The backdoor described in their report is very similar to the one analyzed here, although it uses different string encryption and there are differences in the commands. This leads me to believe that this backdoor is the latest version of a backdoor that has been in use for some years.

# IOCs
* Dropper: 6744ca5d49833c9b90aee0f3be39d28dec94579b028b05c647354ec5e1ab53e1
* Backdoor: d0a41dfe8f5b5c8ba6a5d0bdc3754543210ec2d36290564d9a774e9d22e3ad97
* C2: http://www.addfriend[.]kr/board/userfiles/temp/index.html