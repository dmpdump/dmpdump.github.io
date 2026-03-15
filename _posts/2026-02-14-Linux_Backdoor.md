---
title: Low Detection Linux and macOS Backdoor
by: dmpdump
tags: linux backdoor
---

In early March, [MalwareHunterTeam](https://x.com/malwrhunterteam) shared a hash associated with a Linux backdoor with 0 detection in VirusTotal. It is well known that AV engines in VirusTotal do not implement the full capability of AV solutions, however, the presence of obviously malicious unobfuscated code made it an interesting finding. The backdoor has been in VirusTotal since January 27, 2026 with 2 distinct submissions, one from the US and another from Vietnam.

The backdoor is contained within a tar file named `out_linux.tar`. The tar file contains 2 files, `netd` and `netd.lck`.

* `out_linux.tar`: 8e4f33722c16a5e922a81a4be61db804bbf2e899d89902085e854b7f0a0d587f
* `netd`: be0f36ee071a9c0c200dcdaed98fce7fadc31305d0a5f24a244a3af7833d21dd
* `netd.lck`: 78e145fcc9f099a1dec49f9001bfbb06366fcf30f66a7cc9e6605b36019dfac4

![sshot](/assets/images/linuxbackdoor/tarcontent.png)

# Backdoor Analysis

`netd` is a 64-bit ELF backdoor. It is statically linked, and not stripped. `netd.lck`, on the other hand, is an encrypted configuration file used by the backdoor. This configuration file can be retrieved and updated remotely by the threat actor via backdoor commands.

When the backdoor is initialized, it implements the `lock_process` and a `load_config` functions.

![sshot](/assets/images/linuxbackdoor/lock_conf.png)

`lock_process` uses a named semaphore (`KoqiItPtTbsntsoTspaltsT`) that acts as a mutex to prevent repeated execution of the backdoor. This lock can be bypassed by running the backdoor with the `skip` argument.

![sshot](/assets/images/linuxbackdoor/semaphore.png)

The `load_config` function reads the configuration file from `<backdoor_path>.lck`. The backdoor expects the .lck file to exist in its same path and have the same file name as the backdoor, so it is retrieved by parsing the backdoor path, retrieving the backdoor file name, and appending the .lck extension, resulting in `netd.lck`. The backdoor reads 810 bytes (the size of `netd.lck`) and decrypts the first byte with XOR key `0x38`. The rest of the configuration file is XOR decrypted with key `0x384E65296D662467273B2B3D3474316B2D334E79634D4557662C414F496B6E7433776E5566674B644646746E4C2C53643569`.

After decryption, we can see 2 domains:

* `chopaw.camdvr[.]org`
* `drawpin.accesscam[.]org`

![sshot](/assets/images/linuxbackdoor/decryptedconfig.png)

The backdoor has an additional default hard-coded C2:

* `mefng.giize[.]com:443`

![sshot](/assets/images/linuxbackdoor/configdefc2.png)

After locking the process and loading the configuration, the backdoor forks to daemonize itself, acquiring a new session. Within the daemon, it allocates a PTY pair via `forkPty`. It then forks again. The child executes an interactive shell (`$SHELL` or `/bin/sh -i`) and the parent spawns `recv_thread` as a thread to manage RC4-encrypted C2 communication.

![sshot](/assets/images/linuxbackdoor/forks.png)

Previously initialized shell:

![sshot](/assets/images/linuxbackdoor/shell.png)

Execution of the interactive shell:
![sshot](/assets/images/linuxbackdoor/shellexec.png)

The `recv_thread` function initializes the connection to the C2 and handles the operator's commands. The 2 main functions within `recv_thread` are `connect_peer` and `main_proc`.

![sshot](/assets/images/linuxbackdoor/connectmainproc.png)

The `connect_peer` function implements an interesting function named `resolve_name`. This function uses the Google DNS (8.8.8.8), it makes a DNS request to `www.google.com`, likely a decoy, and then makes a DNS request against the C2 to retrieve its IP address using `getaddress()`. The retrieved IP address is subsequently XOR decrypted with key `0xC7852752`. The domains used in this backdoor (`camdvr[.]org`, `accesscam[.]org`, `giize[.]com`) are associated with the `Dynu Systems` Dynamic DNS service, so the IP that is XOR decrypted can be updated dynamically by the threat actor.

![sshot](/assets/images/linuxbackdoor/resolve_name.png)

Once the IP address is retrieved and decrypted, a TCP socket connection is established via `connect_ex`. The connection is followed by a custom RC4 challenge-response protocol implemented in a function named `auth_response`:

![sshot](/assets/images/linuxbackdoor/connsequence.png)

The `auth_response` function implements the following challenge-response mechanism:
* It generates 100 random bytes to be sent to the C2.
* The bytes to be sent are random, but one specific byte is set to `0x7C` (offset 23 based on static analysis).
* The random bytes are encrypted using RC4 with the following key: `0x5D84EFD639604BB295FC270E715883EA`.
* A response from the C2 is received and decrypted with the same RC4 key.
* A byte is checked for the presence of value `0xC7` at a specific offset (offset 77 based on static analysis).
* A new request is made to the C2, using the previously checked byte with value `0xC7`.

If the byte with value `0xC7` is received at the expected offset, a new request with fresh random bytes is sent to the C2 with byte value `0xC7` explicitly set at the same hardcoded offset.

![sshot](/assets/images/linuxbackdoor/challengeresponse.png)

The backdoor commands are handled in a command dispatcher function named `main_proc`. Before implementing the command dispatching capabilities, the backdoor sends victim information to the C2. All the traffic between the victim and the C2 is RC4 encrypted with the key referenced before. Before implementing the command dispatching capabilities, the backdoor sends system information to the C2 with a function appropriately named `send_systeminfo`. The information is sent with the following format:

`generated uid|hostname|connection state|unknown_value|sysname|nodename|release|version|machine|domain name|`

The uid generated for each victim will be based on the mac address. If the mac address cannot be obtained, a random per-victim uid is generated. The majority of the system information is retrieved from the [utsname](https://man7.org/linux/man-pages/man2/uname.2.html) struct, as can be seen below:

![sshot](/assets/images/linuxbackdoor/systeminfo.png)

 The following interactive commands are implemented by this backdoor:

| Command | Function Name | Capability |
|---------|---------|---------|
| 0   | do_upload   | C2 to victim file transfer |
| 1   | do_download   | Victim to C2 file transfer |
| 2   | popen   | Execute arbitrary shell command |
| 3   | do_dir   | Directory listing |
| 4   | do_rm_file   | Delete file (rm -f) |
| 5   | N/A   | Interactive shell input |
| 7   | N/A   | Sleep |
| 8   | N/A   | 'continue'. Possible keepalive |
| 9   | N/A   | Self-delete / cleanup by setting connection state to 6 |
| 0xA  | request_config  | Send current configuration to the C2 |
| 0xB  | update_config  | Receive a new configuration from the C2 |
| 0xC  | do_get_process  | Process list (ps -eo pid,ppid,command) |
| 0xD  | do_kill_process  | Kill process (kill -9 pid) |

Excerpt from `main_proc` implementing the `send_systeminfo` function and the command dispatcher:

![sshot](/assets/images/linuxbackdoor/dispatcher.png)

The following connection states are implemented in the backdoor:

| Connection State | Description |
|---------|---------|
| 2   | Send system info |
| 3   | Receive commands |
| 4   | error / default |
| 5   | sleep |
| 6   | self-destroy |

For self-deletion purposes, when command 9 is received, the connection state is set to 6. This state is associated with the removal of the backdoor and the configuration file:

![sshot](/assets/images/linuxbackdoor/selfdestroy.png)

# Possible C2 IP

Based on the `resolve_name` address resolution, the actual C2 IP address will be retrieved from the domain used by the backdoor (e.g. `mefng.giize[.]com:443`), and it will be subsequently XOR decrypted with key `0xC7852752`. Currently, `mefng.giize[.]com` resolves to IP address `138.89.104[.]8`. This is a Verizon IP address.

![sshot](/assets/images/linuxbackdoor/verizon.png)

 XOR decrypting this IP address with the hard-coded key:

 ```python
import socket, struct

ip = "138.89.104[.]8"
key = 0xC7852752

ip_int = struct.unpack(">I", socket.inet_aton(ip))[0]

xor_ip_int = ip_int ^ key

print(socket.inet_ntoa(struct.pack(">I", xor_ip_int)))
```
...we obtain the following IP address: `77.220.79[.]90`. I did not interact with this IP address, and I cannot confirm if it is an actual C2 or not. The IP, however, was associated with a Mikrotik router that could have been compromised and used as a C2. Interestingly, the router seems to have exposed port 8291, which has been associated with exploitation in the past.

![sshot](/assets/images/linuxbackdoor/mikrotik.png)

# Mac version of the backdoor

In addition to the ELF copy of the backdoor, a Mach-O copy exists in Virus Total. The Mach-O version has the following attributes:
* FileName: ChromeUpdates
* SHA2: bcffe674c4425634d4750bb21a505be9ce35e31413d2e6cce75ad0c609563cc5 


# IOCs
* out_linux.tar: 8e4f33722c16a5e922a81a4be61db804bbf2e899d89902085e854b7f0a0d587f
* netd: be0f36ee071a9c0c200dcdaed98fce7fadc31305d0a5f24a244a3af7833d21dd
* netd.lck: 78e145fcc9f099a1dec49f9001bfbb06366fcf30f66a7cc9e6605b36019dfac4
* ChromeUpdates: bcffe674c4425634d4750bb21a505be9ce35e31413d2e6cce75ad0c609563cc5 
* chopaw.camdvr[.]org
* drawpin.accesscam[.]org
* mefng.giize[.]com:443