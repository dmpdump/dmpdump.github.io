---
title: Modified XWORM Distribution by Chinese-Speaking Threat Actor
by: dmpdump
tags: cti malware xworm
---

While hunting for MSI installers that typically distribute Gh0stRAT and RATs that share some of the Gh0stRAT code, such as WinOS/ValleyRAT, I came across an infection chain leading to a slightly modified `XWORM RAT`:  
`whats-install.msi` (37e42839ea6f1c97c7256eeec99e420e46e4d920bf629cb84aa260e78ee7f60f)

This MSI was created with Advanced Installer and its comments are in Chinese: `此安装数据库包含了安装 whats-install 所需的逻辑和数据。` ("This installation database contains the logic and data required to install whats-install."). It masquerades as a legitimate WhatsApp installer.

![sshot](/assets/images/modified_xworm/msi_comments.png)

Several fields in the installer are also in Chinese, suggesting that it was likely created by a Chinese-speaking threat actor.

![sshot](/assets/images/modified_xworm/excerptmsi.png)

The MSI contains files that lead to an infection chain that loads a modified `XWORM RAT` in memory. 

![sshot](/assets/images/modified_xworm/msi_contents.png)

When the MSI is executed, one execution chain runs `xmplay.exe`, leading to the `XWORM` infection, while the other (through files in `installer.exe_1`) leads to a Chromium-based desktop application that is supposed to be a custom WhatsApp application. This WhatsApp application is not reviewed here.

![sshot](/assets/images/modified_xworm/execchain.png)

When the legitimate `xmplay.exe` is executed, it side-loads a malicious DLL named `xmpcd.dll`. The DLL first executes a function called `AccurateRemote()` which runs an embedded PowerShell script to create a Scheduled Task with a random name for persistence. The Scheduled Task runs `xmplay.exe` during logon from `C:\Program Files (x86)\whats-install\whats-install\6000\xmplay.exe`, the folder in which the MSI drops content.

![sshot](/assets/images/modified_xworm/schtask.png)

After creating the Scheduled Task, the `installer.exe` executable is run from the same folder.

![sshot](/assets/images/modified_xworm/runinstaller.png)

`installer.exe` is a simple shellcode loader. This loader:
* Reads the content after the `IEND` delimeter from `resource_data.png` (IEND marks the end of the image data stream in a PNG image). The content read is an encrypted shellcode
* It allocates memory with PAGE_READWRITE permissions
* It copies the encrypted shellcode to the newly allocated memory
* It modifies the memory protection to PAGE_EXECUTE_READ
* It executes the shellcode and creates a delay with a function called `verify_system_compatibility()`

Shellcode loader function:

![sshot](/assets/images/modified_xworm/installer.png)

Encrypted shellcode in `resource_data.png`:

![sshot](/assets/images/modified_xworm/png.png)

Function copying the shellcode after the `IEND` delimeter:

![sshot](/assets/images/modified_xworm/read_sc.png)

Delay via the creation and subsequent deletion of a .tmp file in `verify_system_compatibility()`:

![sshot](/assets/images/modified_xworm/delay.png)

The shellcode loaded by `installer.exe` is encrypted with the [Donut](https://github.com/TheWover/donut) loader. After decrypting the loaded payload, we can see that it's an easily recognizable `XWORM RAT` client configured with the following C2: `27.124.2[.]138:6000`. This C2 is unusually embedded in cleartext, and not encrypted in the Settings section, as it is usually the case in XWORM.

![sshot](/assets/images/modified_xworm/xworm.png)

The following configuration settings are decrypted from the Settings (with the standard AES in ECB mode decryption from XWORM)

* Key: `<123456789>`
* SPL (delimeter): `<Underbytemm>`
* Groub (version): `Underbyte V5.6` 
* USBNM: `USB.exe`

The configuration is decrypted using key `0xBC44ABB3B3EE67C0480855A9681079BC44ABB3B3EE67C0480855A96810791E00`. When we look at the Settings section, we can decrypt a different, unused C2: `45.125.216[.]54:7000`. The mutex configured in the sample is `sKGCo7sB9Ni6uaEY`. The configuration suggests that the threat actor replaced the common `XWORM v5.6` version with their own `Underbyte` version, also used as the delimeter (SPL).

In addition to the custom hard-coded C2 in cleartext, this XWORM version includes a custom Telegram identification and reporting function, suggesting that the threat actor is interested in checking if the victim has Telegram installed, potentially for further targeting.

The `Info()` function calls the standard `Spread()` function.

![sshot](/assets/images/modified_xworm/info.png)

However, unlike the typical XWORM `Spread()` function, which verifies if the current file name matches the 'spread' file name (typically `USB.exe`), this `Spread()` function validates if Telegram is installed on the host, returning `是的` ('Yes') if it is, and `不` ('No') if it is not.

![sshot](/assets/images/modified_xworm/spread.png)

`Spread()` uses the `SearchForAnyTelegram()` function to locate Telegram on disk.

![sshot](/assets/images/modified_xworm/searchforanytelegram.png)

For comparison, this is the `Spread()` function that I observed in other XWORM samples:

![sshot](/assets/images/modified_xworm/spreadorig.png)

Pivoting on the `Underbyte` version used by this threat actor, we can see a group of XWORM RATs submitted to VirusTotal, including other trojanized installers. At least some of the other distributions include similar Donut-encrypted shellcodes embedded into PNG files. Some of the XWORM samples below have minor customizations, but they don't target Telegram. Some examples are:

`ChromeSetup.zip` (2d32a0d7709b7ebf8494647a76be24dcca8e1fa31d10fc08f9dcacbaa27182c1), uploaded on June 11, 2025.

![sshot](/assets/images/modified_xworm/chromesetup.png)

`Installer.zip` (e39609faa71c659305a9bd198127a2739f7525e7f735850703e52b2237af5906), uploaded on June 10, 2025.

![sshot](/assets/images/modified_xworm/installerzip.png)

`b9df4ccaacc76552b39a2168829c39ab89fb4cea9aad0883ab89bc9d1938c537`, uploaded on May 18, 2025.

![sshot](/assets/images/modified_xworm/ziphash.png)

A quick search based on the decrypted `Underbyte V5.6` RAT version reveals the following samples:

b9df4ccaacc76552b39a2168829c39ab89fb4cea9aad0883ab89bc9d1938c537
8ddf9ebe6d54f0f873fe72436ecedfea6c0024afdc3dc1c1c64dbcaa0639f3ee
51b45a7b31a79fde698bd96d051e9531a485f5b24c6fedb1d4a924732ebb2e79
866b2c51286e69beb098313d70281a6c6fad9cbba3389edf2baff345fe6ab731
1135d5278b29f48734fe0afc15fe19acc5b483ec1779d93b0f0e6396a0e5b592
da64d6adc33a94ba12c6e3b043302db7941aaeeb93f359d030ba5f0f3bbc0a35
79dbd0c68337b3224d792cba4286efa4d923247d85ecb4126b85baf0d58ad1a2
455927cdeb322aca851ca17b1e0bf126b53ed855fd2a4032c28e8dff3365d8b3
154f174cfeb900ce69caa69b67b5bf8ed6fc343c3ce2f1d0e0efb0e2412b36a0
873b72e4be654db40e463874631fee0f4f217c6f8df304736c50c10590a6f4a7
0fc7f01d22f3d39c789466dd780e6db0ccf8172eba0b33125c43129f9b8bd421
373e48b87d87750c80a4c464f8a36d54a8057deb5f2e6a89e640cd8059f3c698
bb22eceef64a6e8641d9221db9355598c905671b36ea34d83f00cfe453ad1777
1c4a93b8cbb1026dffeec5aad2e30edb5010c1ce8f844c1944d69bcb7c165bed

The samples seem to be configured with C2s in East/South East Asia, following similar patterns in the infection chain. Various attributes in this modified XWORM distribution are similar to activity I have seen in the past associated with Chinese-speaking threat actors distributing Gh0stRAT and WinOS, including:
* The use of trojanized installers, including Chrome and WhatsApp installers
* The use of Donut-encrypted shellcodes
* The use of DLL side-loading
* Targeting of Telegram
* C2s in East/South East Asia

The commonalities that I observed are, however, weak for a meaningful link. Additional analysis would be required to confirm or refute a potential link with other activity, as the similarities may be coincidental and common patterns in threat activity originating from the region.

# IOCs
* whats-install.msi: 37e42839ea6f1c97c7256eeec99e420e46e4d920bf629cb84aa260e78ee7f60f
* xmplay.exe: ebc41dbef6867a7e505864d9fccd167c0d0bd9742f8ea4278c675aa78522b4d2
* xmpcd.dll: 4af573b1b9d2b107d08acd82b639637e7991c4a98bfe998714f82d703c01c26a
* resource_data.png: c74482352b8c7c36783704936c41bdc1a8482135c4f0fe920bcc289ddaafb848
* XWORM: a0bd05d481591889b83772632f860398345dc0f4daf2d004fba3639882e8b2b6
* C2: 27.124.2[.]138:6000
* C2 (unused): 45.125.216[.]54:7000