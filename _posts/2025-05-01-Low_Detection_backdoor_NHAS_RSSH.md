---
title: Likely Chinese Threat Actor Uses Low Detection Linux Backdoor and NHAS Reverse SSH
by: dmpdump
tags: cti malware elf linux
---

On April 22, 2025, [MalwareHunterTeam](https://x.com/malwrhunterteam/status/1914632170129309952) shared a hash for a low detection Linux ELF with 2 hard-coded IP addresses: 43.159.18[.]135 and 119.42.148[.]187. Upon review of the executable (ea41b2bf1064efcb6196bb79b40c5158fc339a36a3d3ddee68c822d797895b4e), I found an interesting backdoor written in C that uses a local proxy to execute payload from attacker infrastructure via an external SOCKS5 proxy. The ELF is a 64-bit executable, has stripped symbols and was compiled with GCC.

![sshot](/assets/images/elf_nhas/elfinfo.png)

The ELF was uploaded from China and Singapore, with both submissions very close to each other.

![sshot](/assets/images/elf_nhas/submissions.png)

# Backdoor analysis

The backdoor uses the environment variable `_PROXY_SERVICE_CHILD` to detect if it is running as a child process. If the environment variable is not set (it's not running as a child process), it starts the malicious logic. The malware forks a new process using `kworker/0:0` as an argument to look like a legitimate kernel worker thread (likely modifying the process name). If the fork suceeds, it sets the `_PROXY_SERVICE_CHILD` environment variable to 1 and executes itself with `/proc/self/exe`.

![sshot](/assets/images/elf_nhas/code1.png)

The malware checks if the environment variable `BUILD_VER` is set. This environment variable is used to keep track of a port number, subsequently created (if needed) to connect to a local proxy. If the environment variable is not set, it generates a random port number. The malware then creates a thread to establish a tunnel via a proxy. This proxy acts as intermediate infrastructure between the infected host and the attacker-controlled infrastructure, likely serving payloads. The malware binds a socket to localhost (127.0.0.1), connecting to it using the previously generated random port number. By making requests to the local proxy, the requests are forwarded to the external proxy, receiving payload from the target IP address and executing it in memory. 

![sshot](/assets/images/elf_nhas/proxy_flow.png)

At a very high level, the architecture of the backdoor looks like this:

![sshot](/assets/images/elf_nhas/architecture.png)

Connections to the remote proxy are implemented in a continuous loop:

![sshot](/assets/images/elf_nhas/code3.png)

The remote proxy is hosted at `43.159.18[.]135:2333` (a SOCKS5 proxy), and the target infrastructure, likely used as command and control, is `119.42.148[.]187:2443`. The use of the SOCKS5 proxy has the objective of hiding the command and control infrastructure behind 'benign' infrastructure.

![sshot](/assets/images/elf_nhas/code4.png)

Looking at the function that generates the user name for the proxy authentication on `43.159.18[.]135:2333`, we can see following user name format:

![sshot](/assets/images/elf_nhas/code5.png)

This code will generate a user name that looks like this: `"ipideatj10011_2952-zone-custom-region-HK-session-" + <10 random characters> + "-sessTime-60"`. This suggests that the threat actor is using the `ipidea[.]net` residential proxy service provider. In the proxy connection function, we can see that the generated user name is sent together with the `ipideatj10011_2952Aa1024` password for authentication purposes.

![sshot](/assets/images/elf_nhas/auth.png)

A machine translation of the 'About' section of the `ipidea` website suggests that the company was founded in 2019 in Xuzhou, China.

![sshot](/assets/images/elf_nhas/ipidea.png)

Additional information on the proxy server from Censys confirms the `ipidea` suspicion, also showing that the proxy is hosted in Singapore and associated with Tencent ASN AS132203.

![sshot](/assets/images/elf_nhas/censys1.png)

`119.42.148[.]187`, the command and control, is accessible via SSH, and hosted in Hong Kong.

![sshot](/assets/images/elf_nhas/censys2.png)

After the connection to the remote proxy, a connection to the localhost proxy will monitor if payload is received for execution. The function that connects to the local proxy takes 2 arguments, 127.0.0.1 and the random port number.

![sshot](/assets/images/elf_nhas/loc_prox_fcall.png)

It then creates a socket and connects to it. A memory file descriptor is created, which is subsequently used for code execution in memory. A loop is implemented to receive payload, setting 104857600 bytes as the payload size limit. The received payload is written to the recently created memory file descriptor.

![sshot](/assets/images/elf_nhas/down_exec1.png)

Once the complete payload has been received, the backdoor uses the `lseek` syscall to reposition the file offset in the memory file descriptor to the beginning of the file. The malware then creates a new fork, reusing the `kworker/0:0` process name for the child process, executing the payload in the memory file descriptor with the `execveat` syscall.

![sshot](/assets/images/elf_nhas/down_exec2.png)

# NHAS Reverse SSH

Pivoting on the command and control IP address, `119.42.148[.]187`, I found another ELF (28096799c02d198149a7de0e7d6001554fc0c0907a4cfff5fcfa29f8cd93a4c3) contacting the same IP address.

![sshot](/assets/images/elf_nhas/pivot.png)

The first VirusTotal upload date of this file, April 14, 2025, is very close to the first upload time of the previous backdoor. Upload locations include the UK and Turkey.

![sshot](/assets/images/elf_nhas/upload_nhas.png)

A quick review of this executable shows that it was created in Golang, compiled for Linux, and it is a publicly available project that implements a reverse shell via native SSH syntax. The project is available in the following [GitHub](https://github.com/NHAS/reverse_ssh) repository. This reverse_ssh client is configured with the same C2 and port as the backdoor described before: `119.42.148[.]187:2443`

![sshot](/assets/images/elf_nhas/nhas_c2.png)


# IOCs:
* ELF backdoor: ea41b2bf1064efcb6196bb79b40c5158fc339a36a3d3ddee68c822d797895b4e
* NHAS reverse_ssh: 28096799c02d198149a7de0e7d6001554fc0c0907a4cfff5fcfa29f8cd93a4c3
* Proxy server: 43.159.18[.]135:2333
* C2: 119.42.148[.]187:2443