---
title: Havoc Demon Targeting Pakistan International Airlines
by: dmpdump
tags: malware havoc apt
---

Back in January 2025, I reviewed a [campaign](https://dmpdump.github.io/posts/Havoc/) delivering Havoc Demon to targets in Bangladesh, Pakistan, and China via LNK files. While hunting for new threats this month, I came across an malicious Word document uploaded from Pakistan which leads to a very similar infection chain, very likely attributable to the same threat actor. It is rare to find malicious macro-enabled Office documents these days, but I felt nostalgic and decided to take a look.

* File names: `HTCL_Report.doc` and `Aircraft_Modification.doc`  
* SHA2: a27f2936eb86674120cd54f293670362d51f4784cecb7cf60bf8b78752f24b70 

The Word document was uploaded to VirusTotal on June 25, 2025 from Pakistan. The document was uploaded 4 times by 2 distinct submitters.

![sshot](/assets/images/demonpia/vt.png)

The document metadata shows that it was created on May 5, 2025 and last modified on June 25,2025 (the same day of the VirusTotal upload) by user `kali`. Tooling is also revealed in the metadata. We can see that `WPS Office`, a Microsoft Office alternative, was likely used.

![sshot](/assets/images/demonpia/metadata.png)

When the Word document is opened, we can see that it has macros and a lure that suggests targeting of Pakistan International Airlines (PIA). The document title is `TMS Data - June 2025`. It contains a lure to entice the victim into enabling macros to view the document correctly. 

![sshot](/assets/images/demonpia/maldoc.png)

Anomalous activity stands out as soon as macros are enabled. A new `WINWORD.exe` process is created, with allocated RWX memory containing a portable executable. This is typically a good sign of process injection.

![sshot](/assets/images/demonpia/winword_inject.png)

Extracting the Word macros, we can immediately see a common obfuscation technique consisting of concatenation of hex encoded data blobs, using the `ObjectExceed` function as a hex decoder.

![sshot](/assets/images/demonpia/badmacro1.png)


![sshot](/assets/images/demonpia/objexceed.png)

Additionally, we can see that the concatenated hex blob is base64 decoded.

![sshot](/assets/images/demonpia/b64.png)

In order to speed up analysis, we can modify the macro so that it concatenates the hex-encoded blob for us and dumps it to a file for analysis.

![sshot](/assets/images/demonpia/dumper1.png)

After dumping the file, we can base64 decode it and analyze the malicious macro code. A quick review of the macro shows that it executes payload from memory. We can see this in a function named `RightAmex`, which modifies memory permissions to `PAGE_EXECUTE_READWRITE` and subsequently invokes payload in that executable memory with the low level Invoke API `DispCallFunc`.

![sshot](/assets/images/demonpia/rightamex.png)

Tracing the payload executed in memory, we can see that it is executed from function `ModelTransaction`.

![sshot](/assets/images/demonpia/modeltransaction.png)

Tracing back that function, we can see that it is executed from a series of functions that determine if the architecture is 64 bit or 32 bit. Specifically, the function `TheKeogh` is responsible for determining the system architecture.

![sshot](/assets/images/demonpia/thekeogh.png)

`TheKeogh` is used by `ThisCost`, which decides which payload will be executed via `ModelTransaction`.

![sshot](/assets/images/demonpia/archdecide.png)

Looking at the embedded 64 bit and 32 bit payloads, we can see that the same obfuscation technique used previously is also used here - concatenation of hex encoded blobs:

![sshot](/assets/images/demonpia/objblob2.png)

We can therefore use the same technique to dump the payload. We can modify the macro, removing the functions loading the payload, and adding a function to dump the concatenated blob. In this case, I chose the `ModelAsset` function to concatenate the payload before dumping it.

![sshot](/assets/images/demonpia/dumper2.png)

# Final payload: Havoc Demon

Reviewing the dumped payload, we can see that it the same [shellcode](https://dmpdump.github.io/posts/Havoc/) that was delivered in the activity that I reviewed in January 2025. The shellcode also loads an embedded Havoc Demon reflectively.

In the beginning of the dumped payload we see the start of the shellcode, which loads the embedded portable executable.

![sshot](/assets/images/demonpia/sc1.png)

The portable executable embedded in the shellcode:

![sshot](/assets/images/demonpia/sc2.png)

Like the previous shellcode, this one also uses the `djb2` algorithm to resolve APIs via hashes.

![sshot](/assets/images/demonpia/apihashing.png)

`djb2` implementation for API hashing:

![sshot](/assets/images/demonpia/apihashing2.png)

The shellcode is a typical reflective loader which performs the following actions:
* Searches for a portable executable (in memory) by locating the DOS Header ('MZ'), validating that a PE header ('PE') exists
* Resolves native APIs for memory allocation (`NtAllocateVirtualMemory`) and memory protection updates (`NtProtectVirtualMemory`)
* Allocates memory
* Copies sections of the portable executable to the newly allocated memory
* Updates section permissions
* Executes the portable executable

The base address of the embedded PE is located with the following loop:

![sshot](/assets/images/demonpia/locatepe.png)

The following is an overview of the decompiled code with the overall shellcode functionality:

It locates the base address of the PE, resolves APIs, and allocates memory:
![sshot](/assets/images/demonpia/scdemon1.png)

It copies the sections of the PE, updates permissions, and finally executes the PE:
![sshot](/assets/images/demonpia/scdemon2.png)

A quick triage of the payload loaded by the shellcode reveals that its original name is `demon.x64.dll`, suggesting that we are dealing with a Havoc demon.

![sshot](/assets/images/demonpia/demon.png)

The configuration of the demon is not encrypted, so we can retrieve the C2 easily. In this case, the threat actor decided to use Microsoft's [dev tunnels](https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview), which allows developers to share local environments over the internet (via Microsoft's infrastructure). This feature is supposed to be used for ad-hoc/testing use cases. The C2 configured in the demon is `hxxp://djlmwd9b-80.euw.devtunnels[.]ms/`. The main advantage of using a service such as dev tunnels for C2 redirection is that threat actors do not need to worry about setting up C2 domains that may end up being blocked. The C2 traffic will be generated towards legitimate Microsoft infrastructure, therefore increasing the chances of evading detection and blocks. The use of dev tunnels has been documented before, even for Havoc demons, such as in the [following](https://medium.com/@manan07/microsoft-devtunnel-with-havoc-c2-f72de5fcd9ba) article.

![sshot](/assets/images/demonpia/demonconfig.png)

Given the many overlaps with the previous activity (in targeting, shellcode, and payload), this new malicious Word document is very likely attributed to the same threat actor that I (and others) reviewed in January 2025.

# IOCs
* Word document: a27f2936eb86674120cd54f293670362d51f4784cecb7cf60bf8b78752f24b70
* Shellcode: b0af124bf9643b0c0af2eceafc0b45e84ce19ea4f6f02cdc978afe80b1180730
* Havoc demon: fc43e225568af992cf9784fba4d5c2288bf013a5a22b0fc11cf9502dad3c9292
* C2: hxxp://djlmwd9b-80.euw.devtunnels[.]ms/