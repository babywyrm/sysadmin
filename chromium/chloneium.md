
# 🔐 Chromium Cookie State Key Tradecraft (..2025 Update..)

## 📖 Background

Since **Chromium/Chrome 80**, cookies are encrypted with **AES-256-GCM** using a per-profile *state key*.  

- On **Windows**, the state key is wrapped with **DPAPI**.  
- On **Linux**, the state key is wrapped with **Gnome Keyring** or **KWallet**.  
- On **macOS**, the state key is wrapped with the **Keychain**.  

Once the state key is decrypted, the entire cookie database can be decrypted **offline**.  
This makes cookie DBs effectively **portable** — you can copy `Cookies` + the state key and reuse them later.

---

## ⚔️ Red Team Guidance

### State Key Collection
- **Windows**  
  - Dump the state key from `Local State` (`%LOCALAPPDATA%\Google\Chrome\User Data\Local State`).  
  - Use `DPAPI` via Mimikatz (`dpapi::chrome`), SharpDPAPI, or Chlonium.  

- **Linux**  
  - Extract key from `Local State` JSON, then unwrap via Keyring APIs (`libsecret`).  
  - Tools: `pycookiecheat`, custom `os_crypt` Python modules.  

- **macOS**  
  - Extract key from `Local State`.  
  - Use Keychain to unwrap. (`security find-generic-password -wa 'Chrome'` or custom code).  

### Cookie Reuse Workflow
1. Dump **state key** once.  
2. Periodically exfiltrate `Cookies` SQLite DB.  
3. Decrypt cookies offline with saved state key.  
4. For reuse on another machine:  
   - Either re-encrypt with the target profile’s state key (DB Importer method).  
   - Or re-encrypt the **state key** itself (StateKey Importer method — schema-agnostic).  

### Passwords
- Same logic applies to `Login Data` DB.  
- State key decrypts saved passwords offline.  
- Chlonium and SharpChrome support password export/import.

### OPSEC Tips
- Prefer **one-time state key dump** → repeated offline DB pulls.  
- Avoid repeated in-memory execution (increases detection surface).  
- Use **StateKey Importer** where possible → avoids schema breakage.

---

## 🛡️ Blue Team Guidance

### Detection Opportunities
- **File Access Monitoring**  
  - Watch for **non-browser processes** opening:  
    - `Cookies` DB  
    - `Local State`  
    - `Login Data`  
    - `History`  
  - Tools:  
    - **Windows** → SACLs, ETW, Sysmon Event ID 11 (file access).  
    - **Linux** → auditd, eBPF probes.  
    - **macOS** → Endpoint Security Framework.  

- **Process Anomalies**  
  - Flag suspicious access by PowerShell, `rundll32`, C# loaders.  
  - Unusual execution of `chromedriver` or non-standard Chromium builds.  

- **Persistence/OPSEC Indicators**  
  - Repeated cookie DB reads from the same system account.  
  - Cookie DB copies staged in unusual directories.  
  - Modified or missing backup files (created by tools like ChloniumUI).  

### Hardening / Mitigation
- Use **enterprise policies** to restrict cookie storage or enforce partitioned cookies.  
- Enforce **MFA** — reduces impact of stolen cookies.  
- Deploy **browser isolation / containerization** to reduce persistence of cookies.  
- Monitor for **anomalous web sessions** (user agent mismatch, location drift, reused session IDs).

---

## 🆚 Importer Types

- **Database Importer**  
  - Decrypt → Re-encrypt each cookie/password entry.  
  - Relies on SQLite schema → fragile to updates.  

- **StateKey Importer**  
  - Re-encrypts the state key itself.  
  - Schema-agnostic, faster, preferred in 2025.  
  - Tradeoff: old cookie DB becomes unusable.  

---

## 📌 TL;DR (2025)

- **Yes, this is still legit tradecraft.**  
- **Red Teams**:  
  - Dump state key once, exfil cookie DBs offline.  
  - Prefer StateKey Importer for schema resilience.  
  - Avoid noisy in-memory execution.  
- **Blue Teams**:  
  - Monitor file access (Cookies, Local State).  
  - Detect non-browser processes touching browser artifacts.  
  - Flag cookie re-import or odd Chromium/ChromeDriver usage.  
- **Both**: recognize schema churn and cross-OS differences in key unwrapping.

---

## 🔗 References

- [Chlonium](https://github.com/rxwx/chlonium)  
- [cookies.txt importer](https://github.com/zhad3/cookies.txt-importer-for-chrome)  
- [BeEF Issue #2069](https://github.com/beefproject/beef/issues/2069)  
- [Mimikatz DPAPI module](https://github.com/gentilkiwi/mimikatz/wiki/module-~-dpapi)  
- [SharpChromium](https://github.com/djhohnstein/SharpChromium)  
- [SharpDPAPI](https://github.com/GhostPack/SharpDPAPI)  
- [Operational Guidance for Offensive User DPAPI Abuse](https://www.harmj0y.net/blog/redteaming/operational-guidance-for-offensive-user-dpapi-abuse/)  
- [Cryps1s blog on SACL detection](https://medium.com/@cryps1s/detecting-windows-endpoint-compromise-with-sacls-cd748e10950)  

---


##
##
##
#
https://github.com/rxwx/chlonium
#
https://github.com/zhad3/cookies.txt-importer-for-chrome
#
https://github.com/beefproject/beef/issues/2069
#
##

Chlonium is an application designed for cloning Chromium Cookies.

From Chromium 80 and upwards, cookies are encrypted using AES-256 GCM, with a state key which is stored in the Local State file. This state key is encrypted using DPAPI. This is a change from older versions, which used DPAPI to encrypt each cookie item in the cookie database. What this means is that if you have the state key, you will always be able to decrypt the cookie database offline, without needing continual access to DPAPI keys.

This essentially makes cookie databases "portable", meaning they can be moved from machine to machine, provided you have dumped the state key. The cookies themselves need to be re-encrypted when they are imported, because the state keys will differ on each user profile & machine. This can be done using the same process as decryption, by first decrypting the state key from the "target" browser, and then re-encrypting each item with the new key.

The project is written in C# and has two separate components to it. The first component, chlonium.exe is the collector binary. It simply decrypts the state key and prints it. Keep a note of this key and you can decrypt cookies in the future by downloading the Cookies database file whenever you need updated cookies. By default it will attempt to decrypt the Chrome state key. If you want to dump the state key for another browser (e.g. Edge), you can specify a path to the key.

For example:

> Chlonium.exe "c:\users\user\AppData\Local\Microsoft\Edge\User Data\Local State"
[+] Statekey = 3Cms3YxFXVyJRUbulYCnxqY2dO/jubDkYBQBoYIvqfc=

The second component, ChloniumUI.exe is the "importer" tool. This takes care of decrypting a given Cookies database file with a given state key, re-encrypting the values with the current users state key, and importing the cookies into your chosen browser. You run this on the machine you want to import the cookies into.

To use it, run the ChloniumUI.exe executable. Enter the previously extracted state key, choose the Cookies file you wish to import, and select the browser you wish the import the cookies into. Now click "Import Cookies" and the cookies will be imported.

ChloniumUI currently supports three Chromium based browsers: Edge, Chrome and Vivaldi. Additional browsers can be added in Browsers.cs. This adds the unintended benefit of being able to import an Edge cookie file into Chrome, or vice versa (for example), though it's probably not a good idea given that the user-agent will mismatch.

Important Note: When importing the cookie file into your browser, all old cookies are cleared! A backup is copied to the current directory (with relevant time stamp). If you need to restore the previous cookies, simply copy the backup file over the Cookies file.
Why

Tools such as Mimikatz and SharpChromium already have the capability to dump Chrome 80 cookies, why another tool?

This tool is specifically aimed at making it easier to import cookies into another browser. Whilst these tools do a great job of dumping Chromium cookies (and more!), I wanted to have something that let me easily import into another browser. Third-party cookie manager plugins exist, but I've always found these fiddly and prone to failure. CloniumUI is designed to make this process easier by importing the cookies directly into your browser's sqlite database.

Whilst this project comes with the chlonium.exe collector, which aids in dumping the state key, this is really only an example. Other tools such as Mimikatz will also dump the state key for you, in a potentially stealthier way (depending on your operating environment, execution method etc.). Additionally, SharpDPAPI will allow you to decrypt the Chromium state key file if you have DPAPI state keys, current password, or domain backup key - allowing you to dump cookies remotely over SMB!

When carrying out Red Teaming, I sometimes need to dump a user's cookies multiple times over a sustained period (e.g. daily/weekly). Using a .NET assembly, Reflective DLL or other in-memory execution technique to extract individual cookies from the cookie file directly on the target system is unneccesary and exposes the operator to increased risk of detection. Instead you can simply dump the state key once, and copy the Cookies database file off whenever you need fresh cookies, without requiring additional execution.
Demo

See here for a video demo.
Password Import/Export

ChloniumUI also supports password import and export. To use this feature, simply supply the Login Data database path instead of the Cookies db, along with the state key, and select the browser you wish to import them into (for export this doesn't matter). This allows you to either export passwords in plaintext to a file, or import them into your browser. As with cookies, you can import Chrome passwords into Edge, Edge passwords into Vivaldi etc.
Offline Statekey Decryption

Chlonium supports offline state key decryption whereby you can decrypt the users statekey offline if you have all of the following files:

    The Local State file from: C:\Users\<user>\AppData\Local\<browser>\User Data\Local State
    The DPAPI masterkey files from: C:\Users\<user>\AppData\Roaming\Microsoft\Protect\<SID>\

and one of the following:

    Domain backup key .pvk file (e.g. from NTDS.dit)
    Domain backup key in base64 (e.g. from Mimikatz/SharpDPAPI LsaRetrievePrivateData API method)
    The user's password

Now simply provide these values under the "Offline statekey decryption" tab, and Chlonium will attempt to decrypt the encrypted statekey by first decrypting the DPAPI masterkeys (using the backup key or password), and then using these keys to decrypt the statekey. Once the statekey is decrypted, this can be used in the "Import or Export Database" tab to retrieve cookies/passwords.

Usage Note: When using the user's password to decrypt the DPAPI masterkey, Chlonium will first attempt to extract the user's SID from the BK-<NETBIOSDOMAINNAME> file from within the DPAPI masterkey folder. If this fails (or if the file does not exist), it will try to get the SID from the DPAPI masterkey folder name instead (which by default will be named after the user's SID). If you have renamed the folder, or do not have a copy of the BK file, you will not be able to decrypt the masterkey using a password.

This feature makes use of the excellent SharpChrome and SharpDPAPI projects by @harmj0y. Full credit goes to the original authors of SharpDPAPI.
Importer Types

When importing a Cookie or Login database, Chlonium provides an option to choose an "Importer". You can choose from either Database Importer (the default) or StateKey Importer. The deafult Database Importer will decrypt each item in the source database, re-encrypt it with your current State Key and then import into your current browser's database. This usually works fine, however; if a browser update causes the Database schema to be changed - then Chlonium may need updating to handle the new schema. To try and workaround this issue, the StateKey Importer was created. Instead of re-encrypting each item in the database (and being reliant on knowing the DB schema), instead we can simply re-encrypt (with DPAPI) the StateKey stored in the Local State file to match that of the source database. At which point we can just swap the Cookie DB file out without having to mess with the database contents via SQL. Whilst this method should be more resilient to schema changes, it does have the side-effect of meaning that you will not be able to use the old Cookie file - since the StateKey will no longer be valid. To avoid any issues with restoration, the Local State file is backed up in the current directory along with the original Cookie/Login database. These can be manually restored if required. Additionally, because we don't need to re-encrypt each database item, the StateKey Importer is much faster!

TL;DR: If you are having issues with the Database Importer, try selecting StateKey Importer instead :)
Detection

Set a SACL on the Chrome Local State and Cookies files (as well as other sensitive files such as Login Data and History). Look for suspicious (e.g. non browser related) processes opening any of these files.

Take a look at this great blog post from @cryps1s about setting up SACLs for detection.

For AV vendors that use a file system filter driver, consider blocking non browser-related processes from opening these files. e.g. PowerShell opening the Cookies file.
References

    https://github.com/gentilkiwi/mimikatz/wiki/module-~-dpapi
    https://github.com/djhohnstein/SharpChromium
    https://github.com/GhostPack/SharpDPAPI
    https://www.harmj0y.net/blog/redteaming/operational-guidance-for-offensive-user-dpapi-abuse/
    https://medium.com/@cryps1s/detecting-windows-endpoint-compromise-with-sacls-cd748e10950
