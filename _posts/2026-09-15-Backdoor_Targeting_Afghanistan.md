---
title: Possible Pakistan-nexus Backdoor Targeting Afghanistan
by: dmpdump
tags: backdoor afghanistan pakistan
---

On August 29, 2026, a ZIP file containing an executable named `Special Job Opportunities and Recruitment Information in Various Ministries of Afghanistan.exe` and a DLL named `dgxi.dll` was uploaded to Virus Total from Afghanistan. The executable name and the upload origin suggest the likely targeting of an Afghanistan government agency. As expected, the executable is a legitimate executable (`ApplicationHost.exe`, a Windows IIS executable), and the DLL is a malicious library that is side-loaded by the renamed executable.

![Zip Content](/assets/images/bdoorafg/zipcontent.png)
*Figure 1: Zip content.*

A review of the side-loaded DLL revealed a targeted backdoor using the following C2: `185.235.137[.]35:9000`.

## Backdoor Overview

The DLL establishes persistence by making a copy of the renamed ApplicationHost.exe executable using `GetModuleFileNameW` to retrieve its own path and copying itself and the accompanying DLL to `%AppData%\Microsoft\ApplicationHost\`. The executable is copied with its original name (`ApplicationHost.exe`). Persistent execution is established using the common registry run key `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.

![Persist2](/assets/images/bdoorafg/persist2.png)
*Figure 2: Registry run key.*

The main backdoor logic is implemented in an exported function named `DXGIDeclareAdapterRemovalSupport()`. First, this function implements anti-debugging and anti-analysis checks:

* It detects debuggers with `CheckRemoteDebuggerPresent()` and `OutputDebugStringA()` timing.
* It detects the presence of common analysis tools: ida.exe, ida64.exe, x64dbg.exe, x32dbg.exe, windbg.exe, ollydbg.exe 
* It performs timing and integrity checks. 

![antia1](/assets/images/bdoorafg/antia1.png)
*Figure 3: Sample anti-debugging.*

![antia2](/assets/images/bdoorafg/antia2.png)
*Figure 4: Sample anti-analysis.*

The backdoor checks if it is being executed with the `--startup` argument. If it is not, it drops and opens an embedded decoy PDF named `Document_<4digits>.pdf` under `AppData\Roaming\`. The `--startup` argument is likely used by the malware developer to avoid dropping the PDF with each test run.

![embedded pdf](/assets/images/bdoorafg/embeddedpdf.png)
*Figure 5: Argument check and execution of embedded PDF.*

The embedded dropped PDF is in Pashto and is titled `ریاست الوزراء  - د دفتر لوی ریاست - د مسؤلینو لست ` (machine translation: Office of the Prime Minister - The Office of the Director General  - List of Officials ). The PDF contains a list of individual names and their corresponding position name, salary, department, and phone number.

![decoypdf](/assets/images/bdoorafg/decoypdf.png)
*Figure 6: Decoy PDF.*

The backdoor configuration is XOR encrypted with key `thisscert23$SecretKey206`. Upon decryption, we obtain the following C2 infrastructure: `185.235.137.35:9000`. This IP address is owned by HZ Hosting Ltd.

![encryptedconfig](/assets/images/bdoorafg/encryptedconfig.png)
*Figure 7: Encrypted configuration.*

![ipinfo](/assets/images/bdoorafg/ipinfo.png)
*Figure 8: Encrypted configuration.*

After decrypting the C2 configuration, the backdoor initiates a connection loop to the C2. The first connection sends a registration beacon with basic system information. The following victim machine details are sent in JSON format:

* `clientId`: Uses the MachineGuid from HKLM\SOFTWARE\Microsoft\Cryptography.
* `machineName`: Uses `GetComputerNameA`.
* `osVersion`: Uses `RtlGetVersion` from ntdll.dll.
* `clientVersion`: Uses a hard-coded value of `1.0.0`, suggesting this is one of the first releases of this backdoor.

Sample registration beacon:

```json
{
    "clientId": "<MachineGuid>",
    "machineName": "<MachineName>",
    "osVersion": "Windows 10 (Build X)",
    "clientVersion": "1.0.0"
}
```

The backdoor supports the following 13 commands. The communication with the C2 is mostly in JSON format.

| Command  |                        Action                     | 
|---|---|---|
| 0xA   |  Send system profile (cpu, memory, disks, network information, uptime)   |                  
| 0x14  |  Directory and drive listing                                  | 
| 0x16  |  Read files in chunks (download victim -> C2)       | 
| 0x18  |  File upload (C2-> victim) as a .tmp                |
| 0x19  |  File write                     |                   |
| 0x1A  |  Finalize write, including renaming .tmp to actual extension   |
| 0x1B  |  Process execution, receives path and argument. Uses "cmd.exe /c start" for non-executables  |  
| 0x1D  |  Delete file/directory                               |  
| 0x1E  |  Process listing, retrieves pids, parent process pids, number of threads, working set size, and path    |             
| 0x20  |  Process termination by pid (with TerminateProcess)          |            
| 0x28  |  Create a shell (Spawns hidden cmd with anonymous pipes)            |
| 0x29  |  Kill the shell                                      |              
| 0x2A  |  Input to shell (raw C2 payload for cmd stdin )      |

All packets include the `0xDEADBEEF` magic number, protocol version, message type, and payload length. The payload is typically JSON, but some commands, like file transfer and shell commands use a mixed binary format containing a JSON header followed by raw binary data.

![deadbeefmagiccheck](/assets/images/bdoorafg/beefcheck.png)
*Figure 9: Checks for the 0xDEADBEEF magic number in the code.*


![deadbeefinpacket](/assets/images/bdoorafg/beefpacket.png)
*Figure 10: Sample magic number in a packet.*



## IOCs  
* ZIP file: `d69d27a94c78889fc8694e13c122438125eb3d3e6023e0624b3137c7f982a852`
* dgxi.dll: `a6ceacda670b88e8a8ec9ff5da6a77d9f1c896d6479b2dadb700474a8c408f80`
* C2: `185.235.137[.]35:9000`