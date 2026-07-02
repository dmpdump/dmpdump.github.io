---
title: Linux Backdoor Targeting iKuai Routers
by: dmpdump
tags: backdoor iKuai ELF Linux
---

On July 1, 2026, [MalwareHunterTeam](https://x.com/malwrhunterteam) shared an ELF uploaded to VirusTotal from Japan with 0 detection. After a quick code inspection, it was evident that the ELF was a backdoor targeting specific Linux-based devices.

* File name: `libjson_script.so.0`
* SHA2: `4e6276cc400b3b9e9616d04474b64a8fa0c35375b9673ab41a92a6d5bce72d8d`
* First uploaded to VirusTotal from Japan on 2026-06-08 

![sshot](/assets/images/ikuai/vt.png)

The ELF impersonates the legitimate `libjson_script.so`, which is part of the OpenWrt Project, specifically part of [libubox](https://github.com/openwrt/libubox/blob/master/json_script.c). This impersonation is relevant because, as we will see next, the backdoor seems to target the Chinese [iKuai](https://www.ikuai8.com/en/shop-products.php?productType=router) routers.


# Backdoor Overview

The main routine of the backdoor performs the following actions:
* After executing `acquire_lock()` to ensure there is only one instance of the backdoor running, it proceeds to decrypt the configuration.
* Creates the `/var/tmp` directory and changes directories to it.
* Initializes an MbedTLS AES-GCM context with a 256-bit key. The backdoor uses a statically-linked MbedTLS library.
* Initializes an mbedTLS HTTPS client without certificate validation.
* Initializes a task scheduler thread for tasks sent from the C2.
* Attempts to get a `GWID`, or creates and sets a new one if none can be found. This `GWID` is likely a `Gateway ID` associated with iKuai routers.
* Gets the process ID.
* Enters an infinite loop that beacons to the C2 to receive tasks. The loop has a sleep interval which is obtained from the C2. A default sleep time of 3600 seconds (1 hour) is set by default as part of the configuration decryption.

![sshot](/assets/images/ikuai/mainroutine.png)


## Configuration decryption

The backdoor uses an XOR decryption algorithm with a single byte key to decrypt configuration strings (with a function named `xor_decode`). The byte used as key is `0x5A`.

![sshot](/assets/images/ikuai/xor.png)

The strings decrypted as part of the configuration decryption are: 

* `https://47.80.111[.]129:7380`, the C2 address.
* `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36`, the User Agent string used by the backdoor.
* `/cdn-cgi/trace`, a C2 URI.
* `/cdn-cgi/bm/cv/result`, a C2 URI.
* `/cdn-cgi/challenge-platform/generate/ov1`, a C2 URI.
* `en-US,en;q=0.9`, the Accept-Language value for the backdoor HTTP request.
* `application/octet-stream`, the Content-Type value for the backdoor HTTP request.
* `https://raw.githubusercontent.com/pnzzuv09911cast11/googlehub/refs/heads/main/readme.txt`, this Github repository is no longer available, and it does not seem to be used by the backdoor.
* `3600`, the default sleep interval in seconds for the C2 communications.
* `8fc4cdd44e1d2baee2d8915c3a3651f452da877565a3ee4d43fb44ee28a4ee8c`, an AES-256 key used for subsequent encryption and decryption.

![sshot](/assets/images/ikuai/configdecrypt.png)

## Obtaining the Device GWID

The `get_gwid()` function is interesting because it indicates that the backdoor is targeting a specific custom Linux version. This function attempts to get the `GWID`, or `Gateway ID` of the device by checking a `GWID=` field in `/etc/release`, checking `/usr/share/misc/.runlevel.cache` for a previously generated ID, or, if needed, creating a random `GWID` value and writing it to a newly created `/usr/share/misc/.runlevel.cache` file.

![sshot](/assets/images/ikuai/getgwid.png)

The `GWID` is a value that is referenced in the official [iKuai documentation](https://www.ikuai8.com/support/cjwt/xs/2019-07-26-05-38-00.html).

## C2 Task Loop

The main C2 task loop first obtains the hostname, the local IP address (excluding localhost), and once again it attempts to access `/etc/release`, this time to obtain the `VERSTRING=` field. 

![sshot](/assets/images/ikuai/verstring.png)

Reviewing [Chinese forums](https://web.archive.org/web/20260514000343/https://forum.naixi.net/thread-11395-1-1.html
), I found that this field is present in the `release` file of iKuai routers, providing additional evidence that these routers are being targeted.

![sshot](/assets/images/ikuai/release.png)

A JSON object is then created using the embedded cJSON library and profiling information is added to it. This information includes GWID, architecture, hostname, pid, current working  directory, a version set to 1.4, ip address information and the verstring information from the `release` file. This information is AES-encrypted before it is sent to `https://47.80.111[.]129:7380/cdn-cgi/trace`.

![sshot](/assets/images/ikuai/send.png)

The backdoor receives an encrypted JSON from the C2. After decrypting and parsing the C2 response, it retrieves the top-level "sleep" and "tasks" members. It then iterates over each object in the "tasks" array, extracting the "id" and "command" fields for processing.

![sshot](/assets/images/ikuai/jsondecrypt.png)

The backdoor supports the following 6 commands:

| Command | Action |
|----------|----------|
|\_\_sched\_\_                 | Downloads payload from a url and executes as a 'scheduled task'     |
| \_\_sched\_cancel\_\_          | Cancels a scheduled task                                          |
| \_\_uu\_\_                    | Downloads, executes, and deletes an ELF                            |
| \_\_dd\_\_                    | Reads a file, base64 encodes it, and exfiltrates it                |
| cd                         | Changes directory                                                     |
| exec\_cmd\_async (default)   | Executes shell commands                                             |


### \_\_sched\_\_

The `__sched__` command receives data to download and execute additional payload as a file. This command will get a download url, a destination directory, execution time and execution repetition data to the previously initialized `sched_start` thread. The `sched_start` thread will parse the data and will download, decrypt, and execute payload as a forked process. The default destination location for the downloaded payload is `/var/tmp/.<random hex>`.

![sshot](/assets/images/ikuai/schtask1.png)

![sshot](/assets/images/ikuai/schtask2.png)

### \_\_sched\_cancel\_\_

This command dequeues a task based on a task id. 

### \_\_uu\_\_ 

This command runs `exec_elf`. The code in this command mirrors the ELF download and execution code used in the `__sched__` command. The endpoint used to download payload with this command is `https://47.80.111[.]129:7380/cdn-cgi/challenge-platform/generate/ov1`.

![sshot](/assets/images/ikuai/uu.png)

### \_\_dd\_\_ 

This command reads files, base64 encodes the content and sends them back to the C2. This function is designed to exfiltrate small files, as it has a limit of 512 KB.

![sshot](/assets/images/ikuai/dd.png)

### cd  

This command changes directories via chdir().

### exec_cmd_async  

The default action in the C2 tasking loop is `exec_cmd_async`. This command runs shell commands (with '/bin/sh -c') and pipes the result back to the C2.

![sshot](/assets/images/ikuai/execcmd.png)

## Report function

All the results from the executed commands are sent back to the C2 using the `report_result` function. The results are sent as an encrypted JSON to the following endpoint: 
`https://47.80.111[.]129:7380/cdn-cgi/bm/cv/result`.

![sshot](/assets/images/ikuai/report.png)

## Hunting for Additional Samples

I created a deliberately broad Yara rule to see if I could find any other samples of this backdoor, but I could not find any. To the best of my knowledge, this backdoor seems to be rare. If you have seen it before (e.g. reported somewhere else), feel free to reach out and I'll happily add references to previous work, or to your findings.

```plaintext
rule ikuai_bdoor {
    meta:
        reference_hash = "4e6276cc400b3b9e9616d04474b64a8fa0c35375b9673ab41a92a6d5bce72d8d"

    strings:
        $s1 = "__sched__|"
        $s2 = "__sched_cancel__|"
        $s3 = "__uu__:"
        $s4 = "__dd__:"
        $s5 = "exec_elf"
        $c2_1 = "/cdn-cgi/bm/cv/result"
        $c2_2 = "/cdn-cgi/trace"
        $c2_3 = "/cdn-cgi/challenge-platform/generate/ov1"
        $beacon1 = "gwid"
        $beacon2 = "eips"
        $beacon3 = "VERSTRING="

    condition:
        uint32(0) == 0x464c457f and
        filesize < 10MB and
        (
            (3 of ($s*)) or
            (2 of ($c2*)) or
            (all of ($beacon*))
        )
}
```

# IOCs  
* `libjson_script.so.0`: 4e6276cc400b3b9e9616d04474b64a8fa0c35375b9673ab41a92a6d5bce72d8d
* C2: https://47.80.111[.]129:7380