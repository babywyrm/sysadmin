Basic Information

##
#
https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/web-api-pentesting
#
##



How To Hack API In 60 Minutes With Open Source Tools
How to Hack API in 60 minutes with Open Source Tools
What is API?

API is the abbreviation for Application Programming Interface, which is a product middle person that permits two applications to converse with one another.

Useful link:

API security guide for beginners and professionals
What Is API Testing: Benefits, Types, How To Start
‍OpenAPI tutorial: What is, Example, Tools.
‍

Learning Objectives
API for different folks look really different
What’s the difference between Attack Simulation and Fuzzing?
Open Source API Security Tools
How to Fuzz
API Fuzzer Examples
API simulation best practices
API Attacks Simulation using Open Source GoTestWAF tool
Webinar - “Workshop - API Threat Simulations with open-source tools”
Resume

Subscribe for the latest news
Subscribe
API work
API for different folks look really different
This section explains API and how it functions from different perspectives, and people who use API for different purposes.

Back-end developer

Framework: A unified way of how to operate things
Specification: It is swagger-based in terms of REST or open API like circuit version 3 technically or a different schema for GraphQL or protobuf or descriptions for geo pc.
No HTML markup anymore, just data and business logic: 10 years ago, it was impossible to split data and markup and everything was always together at that time. But these days, back-end developers technically put a border between clients whether from the mobile app or browser javascript their single page application or business to business integration, basically custom integration.
Unified back-ends for mobile, web, integrations
API for Back-end developer
DevOps

Specification meets production: should this endpoint return 502 that often? All the things should be mitigated.
Scaling: which microservice and how should I scale to solve 504 on this endpoint? Whether REST API info GraphQL or whatever orientation.
Security

New protocols: All my tools like firewalls  and scanners doesn’t work!
East-west security: They are talking to each other inside my network?!
New compliance
‍

What’s the difference between Attack Simulation and Fuzzing?
If you are familiar with the API security tools available in open source, you can easily tell that a lot of them are fuzzing. They are technically the fuzzing tools of others.

Fuzzing payloads

The basic difference is the fuzzing payloads.

Comparing fuzzing and attack simulation is synonymous to comparing any particular planet to the universe as a whole. There is an infinite amount of fuzzing payloads growing like the universe expansion – which means you can apply more ideas, more templates, random data and random fields.

The fuzzing is technically like an infinite universe or a particular planet or piece that we can cover as an attack simulator. But the amount of payloads is not the only difference between fuzzing and attack simulation;

Attack behavior

The sum of attacks could also be behavioral for example, it is difficult to make fuzzing test and find risk conditions. It can be caught or triggered but pretty hard to check if it can happen or it already happened as well as credential stuff and brute force attack, API, business logic abuse and others. Fuzzing requires deep integration and deep understanding with the application business logic. Unfortunately, even with the API schema, or open API, it’s hard to tell how the API endpoints and calls should interference with each other – you cannot basically define the policies.

Attack payloads

This includes templates, presets, known attacks, etc known attacks only.



Open Source API Security Tools
They can be split into 3 different types:
The fuzzing:

The fuzzing is a method that is compatible with stateless endpoints. For instance, if you can guarantee that a certain endpoint will behave in a certain manner without any changes to the states in it, you can make use of these tools. However, if you are interested in doing more than just that. For instance, keep some items in the cart before deleting some of them. When you do this, these tools will be unable to help because they are too simply too simple to focus on sending data from certain endpoints or a list of endpoints. They will be unable to use the information they get from figures and GraphQL descriptions.

Speed limit attacks:

Application programming interface restriction, also referred to as rate limiting, is an important part of Internet security since a DDoS attack has the capacity to overwhelm a worker with unrestricted API requests. Rate limiting will also ensure that your API is fully adaptable. There may be sharp strikes as a result of the rush hour jam, leading to more slack time, if your API is not powerful enough.

Known statement attacks:

A known statement attack is one when you know that a particular thing is supposed to be sent and a particular trigger should be unleashed when an attack happens.

Fuzzing one stateless endpoint	Speed limit attacks (bruteforce, race-like)	Known stateless attacks simulation
REST	RESTler, Dredd, schemathesis, ZAP	ZAP, ab, curl	ZAP, GoTestWAF
GraphQL	Schemathesis, ZAP	ZAP, ab, curl	ZAP, GoTestWAF
gRPC	-	-	GoTestWAF
WebSocket	ZAP	ZAP, ab, curl	ZAP, GoTestWAF
XMLRPC	ZAP	ZAP, ab, curl	ZAP, GoTestWAF
SOAP	ZAP	ZAP, ab, curl	ZAP, GoTestWAF
Custom API	ZAP with extensions	ZAP, ab, curl with row requests	ZAP, GoTestWAF
Summary of API security test tools
ZAP

An effective and powerful proxy with a clear Graphic User Interface (GUI), no gRPC support, and challenging for automation. It requires some sample generation to run properly.

RESTler, Dredd

These are Swagger/OpenAPI based fuzzers. They are designed to be good, effective and useful for testing single stateless endpoints.

Dredd logo
Schemathesis

These are RESTler/Dredd with GraphQL support

ab/jmeter/yandex-tank

This is a load generator that can be utilized to rate limit checks, credential stuffing, race conditions and bruteforce attacks.

GoTestWAF

This is an impressive attack simulation CLI tool. It’s designed with out-of-the-box PDF reports, gRPC, GraphQL, WebSocket and Rest Support. It’s the only gRPC attack generators that we are familiar with.

How to Fuzz
All you need to know about fuzzing

Methods scrapping (/user/debug, SET / HTTP/1.1, etc)
This is the first step because we should be sure to check everything, you have to check for slash, bugs and other things. You should also play with the https request methods like REST or the http based APIs (it works all the time). You can’t actually trust the documentation you have to check because these checks are better than playing with random characters.

Type miscasting ({"login":true})
Type miscasting is a very powerful attack that poses as the standard de facto of security testing for any APIs we have so far because first of all, we have to count that we technically enclose the functional call by some kind of request, technically the string or binary representation of the request. There, we do have the five types of casting, for example; making the true to the particular Boolean value inside the application business logic as well as areas and different other possibilities related to the data protocol, you have to count them and play with them.

Last byte modification: ?username=admi%00
This is a very powerful fuzzing approach that is related to the last byte due to various reasons like the memory issues. Although it functions perfectly, it is very tiny because we just have to modify one byte of the end and achieve the significant result

Random byte modification: ?username=ad%00in
Random byte in a random place can be covered by one or two places but the last byte should be fast always.

Add payload to the end: ?username=admin%27
The fifth step is to add payloads to the end, for example, codes or payload you know, like xss or the particular serialization payload specifically related to the particular API.

Parameters from other requests (password to logout)
The parameters from other requests is a brilliant idea to mutate different data between different requests because developers define for one endpoint and sometimes by request or mistake.

Numbers increasing/decreasing: /user/100001/status
This deals specifically with negative numbers, for example, manipulation by multiplying by zillions.

Filenames by fuzz.txt
This is just the file names from the fuzz.txt which you can easily find on Github.

steps of Fuzz Testing
Benefits of Fuzz Testing
Fluff testing further develops programming Security Testing.
Bugs found in fluffing are once in a while serious and more often than not utilized by programmers including crashes, memory spill, unhandled exemption, and so forth
On the off chance that any of the bugs neglect to get seen by the analyzers because of the limit of time and assets those bugs are additionally found in Fuzz testing. 
Faults of Fuzz Testing
Fluff testing alone can't give a total image of a general security danger or bugs.
Fluff testing is less powerful for managing security dangers that don't cause program crashes, for example, some infections, worms, Trojan, and so forth
Fluff testing can recognize just basic deficiencies or dangers.
To perform successfully, it will require critical time.
Defining a limit esteem condition with irregular sources of info is extremely risky yet presently utilizing deterministic calculations dependent on clients inputs the vast majority of the analyzers take care of this issue.
Fuzzing optimizations for lists
You need to know your data contexts first. And then:

Machine learning (everything you can from HMM to RNN)
Linguistic patterns (verbs and nouns)
Templates (RegExp, syllable)
API Fuzzer Examples
Example 1. 1-byte fuzzer

?ref=http://aaa/%00aaaaaaaaaaaaaaaaaaa aa
memory corruption inside of the Nginx module. Random memory reading (heartbleed analogue)

In proxied answers, there is a vulnerability in the handling of HTTP headers. An information leak happens when the key or value contains NULL bytes.

ngx http proxy process header calls ngx http parse header line, which handles NULL bytes in HTTP headers correctly. However, ngx http proxy process header calls ngx cpystrn to copy the header key/value to the header list, which stops at the first NULL byte, leaving the REST of the (properly sized) data buffer untouched, potentially leaking information.

I saw this in action on a financial website; altering a GET parameter causes the nginx-proxied server to return a Location header with a NULL byte. I've seen this leak cookie headers, log outputs, and (I'm guessing) body content from other requests.

Example 2. 1-byte fuzzer

{"method":"test%26method%3ddeleteUser"}
SSRF inside the URL string to the backend API
727 call('/api/?method='+$data) …
GET /api/?method=test&method=deleteUser
HOST internal.api.host
‍Example 3. 1-byte fuzzer

<Image><![CDATA[http://test.com\n
rm -rf / ;]]</Image>
RCE by newline injection

Also, Yandex RCE (2014) Re: [Ticket#13111203410381979]

Market feedparser - yet another RCE (#3) in python

Does not covered by standard payloads such as: `id` $((id)) |id|

This example was discovered about seven years ago, Wallarm's CEO  found out that the Yandex infrastructure was related to the code execution which was based in xml or pc at the time. Just one byte of the newline allowed the sending of more than the url, and the data was placed to the python script and the python script executed that this is a remote code execution attack.

Example 4. 1-byte fuzzer

https://research.facebook.com/search?q=a%20 HTTP 200

https://research.facebook.com/search?q=a%22 HTTP 500

$1000 reward for injection into JSON to ElasticSearch But it might be RCE...

This is another example of a one-byte fuzzer but related to facebook. When it was discovered, it was like a jax API related to API security because that request under the hood of research facebook, it was an internal JSON request to zeroelastic search and the particular double quote character broke that request and it was possible to inject the arbitrary JSON fields inside this API request to the elastic search.

Example 5. 1-byte fuzzer

GET / HTTP/1.1
COOKIE: sessionid=a8cf5d724a7f56e490cab37%0a
Newline byte is a trigger for server timeout 504

%0aset+key+0+1+3600+10%0a1234567890%0a
https://www.blackhat.com/docs/us-14/materials/us-14-Novikov-The-New-Page-Of-Injections-Book-Memcached-Injections-WP.pdf

This is more related to memcache. The particular service was vulnerable and also founded by a single character fuzzer.

Example 6. List-based fuzzer

Example 6. List-based fuzzer
This is a good example from Salesforce. It was possible to discover the errors endpoint basically undisclosed endpoint of their API that returns back the detailed log with an internal API data. This was about 4 years ago.

Example 7. List-based fuzzer

SET /user/data HTTP/1.1
Host: api.test.com
This is related to REST and non-crude APIs. With this, it is sometimes possible to send or set or delete or draft http request methods to the APIs and achieve something technically unpredictable. It happens due to many reasons, sometimes, the developers basically implement something under the foot of the framework, sometimes it’s just features of the framework, and sometimes just because we can’t find the real reason. This is a powerful fuzzing idea for legacy APIs.

Example 8. Fuzzing nouns

https://github.com/wallarm/fast-detects/blob/master/spring-cloud-infoleaks.yaml

also related to Jolokia by Artsploit (Veracode) CVE-2019-xxx

POST /endpoint/env HTTP/1.1
This example is related to an unpredicted endpoint. We discovered it about two years ago before the covid-19 pandemic. Some other guy from Veracode found a way to exploit the jukla. To find vulnerabilities here, we just send the method to any endpoint and achieve back the data dump.

Example 9. Type casting

POST /user/login HTTP/1.1
HOST: api.somethings.com
{"token":true, ...}
{"token":{} [] ...
When we talk about REST, or JSON, or other pc elements we have to count the JSON allowed to send areas and objects and their Boolean trues plus numbers. Also, whenever we talk about string perimeters, we have to play with them, replace them, and we have to check how the particular endpoint will react. You cannot find this in this figure, you also cannot find it if you don’t know that you should do that. It works all the time, sometimes, it produces errors, sometimes logic bypasses and workflows bypasses which is perfect for authentication.

Example 10. Type casting

PUT /api/v1/user HTTP/1.1
Content-Type: application/JSON
PUT /api/v1/user HTTP/1.1
Content-Type: application/xml
The type casting is related to API frameworks, sometimes it is possible to switch from JSON to XML or from XML to JSON and send the data with the arrays and objects to the endpoint that wasn’t initially designed and the developers never understood because of the framework or API gateway, the particular endpoint he developed and the public function that he developed and released can be used in this way and the data in the function and the arguments could be completely different so it is important that we check this.

HTTP non-CRUD methods, CRUD aliases and WebDAVish things
SET
REMOVE (instead of DELETE, I don’t know why)
DEBUG
TRACK
FORWARD
MOVE
INFO
How to find? Just run fuzzing by all the verbs list

Hackers points of view on API requests
GET /user/7456438/add HTTP/1.1
<verb> <dlm><noun><dlm><idn><dlm><verb> HTTP/1.1</verb></dlm></idn></dlm></noun></dlm></verb>
This is very important because each time we look at any string or any data point, or any input. You have to look at this technically as a hacker. In fact, if you see the string and it’s a verb, define the verb and apply the verb dictionary. If it’s a delimeter, you should count it as a delimeter not as a slash, and apply different fuzzing styles. If it’s a noun, count it as a noun and apply the noun dictionary. If it is an identifier r a number, apply negative numbers or specific scenarios and templates relate to numbers, and if you run the test again, you would be able to achieve fuzzing better.

In addition, the tools presented earlier can help with that. However, like templates, payloads, etc, this is one of the things that should be defined well. This is a personal cheatsheet of how to look at the REST API endpoints.

Analysing the results
Scanners produce vulnerabilities and false positives

Fuzzers produce abnormalities

How to analyze this data?

Who will do this work?

Collaborating/integration problem Testing policy examples

No 5xx errors
No 1+ms response
The fuzzers produce a lot of locks and we have to find different things to analyse the locks.



API simulation best practices
The best way to take advantage of the danger is by displaying advancing security understanding for the whole group. It’s the first move you make towards making security important to everyone. Basically, demonstrating the presence of danger is a basic concept. So, take a look at these fundamental accepted procedures that can be adopted when creating or retesting a danger model:

Characterize the degree and profundity of investigation

Determine the degree of the danger with partners. Then, you should separate the ambiguous investigation goals between individual groups. This would allow them more effective check the threat of the product.

Gain a visual comprehension of what you're danger displaying

Create an outline of the significant aspects of the framework (e.g., application worker, information distribution center, thick customer, data set) and the interaction between individual parts.

Model the assault prospects.

The next step is to make a difference between programming resources, danger specialists, security controls. All you have to do is make a graph of their work to create a security model framework. As soon as you display the framework, it’s easy to point out what could turn out poorly by using tactics such as STRIDE.

Distinguish dangers.

To give a report of any likely attacks to the system, and create inquiries like these:

Is there a way that a danger specialist can gain access to a resource without using the appropriate control?

Can a danger specialist beat this security control?

How should a danger specialist deal with this type of attack?

Make a discernibility grid of absent or frail security controls.

Keep the danger specialists in mind and follow their tips closely. There is a likely chance that you will get the resources without using the right security protocols. This is a sign of a potential assault. If it happens that you have to go through a control, think of whether it would stop an attacker or if he has strategies to beat these security control.

‍



API Security Checklist
Not sure where you stand with API security? The checklist can serve as a starting point for Engineering and Security teams looking to keep APIs compliant and secure.
Download free checklist->
‍

API Attacks Simulation using Open Source GoTestWAF tool
Now, we would have a demonstration of the tools that have been developed specifically to simulate attacks simply without getting overloaded by payloads and without worrying about fuzzing templates. There are simple tools that can be run and used to check to see if we have enough security for our API. It will also check for the vulnerability of a system to particle attacks. Next we will talk about how to hack API with GoTestWAF.

GoTestWAF - API/WAF testing automation

Open-source:

These are open-source tools that are easy to download and run.

Testing for false negatives and false positives both:

These are tools that are designed to check for paths and to understand if a proxy such as a web application firewall works effectively.

REST, GraphQL, SOAP/XML, WebSocket, JSON, gRPC:

As time went on, we included a variety of API features and the tools that have been developed to form a framework for API attack simulation was related to these uncovered cases in a similar manner to gRPC.

Multiple stacked encoding support (base64 under JSON, etc):

This provides support for all protocols and users are allowed to add more protocols if they consider it to be necessary.

Codeless checks (YAML files):

This tool is designed to work on codeless checks that are found in the YAML file. You’re also free to choose whatever you wish to check and decide the tool that would choose the file as an example before generating requests that are designed for this purpose.

The tool is defined to use codeless checks, in the YAML file, you can define whatever you want to check and the tool will use the file as an example and then generate requests specifically based on that.

Dockerized:

It’s stored in dockers, i.e dockerised.

Out-of-the-box PDF reports:

This program functions out of the box and provides pdf reports that are useful when negotiating with developers or developer teams. For instance, if they are unable to read, the security logs can transmit the pdf report.

Community payloads (thanks vulners):

These are some of the tools setup by the community. As a result of Vulners team’s hardwork for using many community payloads.

How it works

./testcase →
      testcase →
         testset (yaml file) →
           [ [payload], [encoder], [placeholder] ]
This is the basic structure of the test case including the name of the test case, before testing the set name with 3 unique parameters namely the placeholder, payload and encoder.

This means that the payload test (pernicious assault test, for example, a XSS string like "<script>alert(1)</script>") will be initially encoded or another will be positioned into an HTTP demand. There is another similar choice where you get to use a plain encoder that maintains the strings without any guarantees.

In order to make tests easy to understand, we have put forward a YAML DSL with a very similar construction (payload->encoder->placeholder). Here, each of the fields are exhibits and run tests in stages through them separately.

Payload

The string you’ll be sending is referred to as a payload. For instance, <script>alert(111)</script> or a more advanced string. Basically, there are no macros, but it makes it to our to-do list. If you intend to utilize binary codes because of its YAML string, make sure you do so.

Encoder

The payload should be encoded with this tool. There are Base64, JSON unicode (u0027 rather than '), and many formats that are available at the same time.

Placeholder

The encoded payload has to be store here, within the HTTP request. The URL parameter, URI POST form parameter, or JSON POST makeup different examples of URL parameters.

Testing for false positives

The next step is to check for false positives using more stringent protocols than when checking for false negatives. It’s the best way to avoid unpredictable variables that may show up during production.

An effective way to address false positives is to detect it quite early before the real customer is denied access. To examine obvious false positives for ModSecurity, an libinjection library and an open-source WAF based on regular expression, we choose to download and use split by lines 899 books from Gutenberg library.

The next folder is designed to identify and root out false positives:

./testcases / <testcase-name>/ <test-set>.yaml

false-posis the reserved name for the false positive test case

testcases/false-pos:

texts.yml

testcases/owasp:

ldap-injection.yml nosql-injection.yml shell-injection.yml ss-include.yml xml-injection.yml

mail-injection.yml path-traversal.yml sql-injection.yml sst-injection.yml xss-scripting.yml

testcases/owasp-api:

graphql.yml rest.yml soap.yml

Every test includes a YAML file that has 3 simple sections:

Payload
Encoder
Placeholder
The amount of requests that the GoTestWAF is capable of sending will depend on the multiplication of these factors: 1 payload, 2 encoders, and 3 placeholders. This will result in 1x2x3x6 testing requests.

PDF and console output reports

#
##############
##############
#

Main:
Web Services (SOAP/XML)
The documentation uses WSDL format and is usually saved in the ?wsdl path like https://api.example.com/api/?wsdl
An example of this documentation can be found in http://www.dneonline.com/calculator.asmx (WSDL document in http://www.dneonline.com/calculator.asmx?wsdl) and you can see an example request calling the Add method in http://www.dneonline.com/calculator.asmx?op=Add
For parsing these files and create example requests you and use the tool SOAPUI or the WSDLer Burp Suite Extension.
REST APIs (JSON)
The standard documentation is the WADL file. Find an example here: https://www.w3.org/Submission/wadl/. However, there are other more developer friendly API representation engines like https://swagger.io/tools/swagger-ui/ (check the demo in the page)
For parsing these files and create example requests you an use the tool Postman
GraphQL
Tricks
SOAP/XML
These kind of APIs may be vulnerable to XXE, but usually DTD Declarations are disallowed in the input from the user.
You could also try to use CDATA tags to insert payloads (as long as the XML is valid)

Check Access
Usually some API endpoints are gong to need more privileges that others. Always try to access the more privileged endpoints from less privileged (unauthorized) accounts to see if it's possible.
CORS
Always check the CORS configuration of the API, as if its allowing to end request with the credentials from the attacker domain, a lot of damage can be done via CSRF from authenticated victims.
Patterns
Search for API patterns inside the api and try to use it to discover more.
If you find /api/albums/<album_id>/photos/<photo_id>** ** you could try also things like /api/posts/<post_id>/comment/. Use some fuzzer to discover this new endpoints.
Add parameters
Something like the following example might get you access to another user’s photo album:
/api/MyPictureList → /api/MyPictureList?user_id=<other_user_id>
Replace parameters
You can try to fuzz parameters or use parameters you have seen in a different endpoints to try to access other information
For example, if you see something like: /api/albums?album_id=<album id>
You could replace the album_id parameter with something completely different and potentially get other data: /api/albums?account_id=<account id>
Parameter pollution
/api/account?id=<your account id> → /api/account?id=<your account id>&id=<admin's account id>
Wildcard parameter
Try to use the following symbols as wildcards: *, %, _, .
/api/users/*
/api/users/%
/api/users/_
/api/users/.
HTTP request method change
You can try to use the HTTP methods: GET, POST, PUT, DELETE, PATCH, INVENTED to try check if the web server gives you unexpected information with them.
Request content-type
Try to play between the following content-types (bodifying acordinly the request body) to make the web server behave unexpectedly:
x-www-form-urlencoded --> user=test
application/xml --> <user>test</user>
application/json --> {"user": "test"}
Parameters types
If JSON data is working try so send unexpected data types like:
{"username": "John"}
{"username": true}
{"username": null}
{"username": 1}
{"username": [true]}
{"username": ["John", true]}
{"username": {"$neq": "lalala"}}
any other combination you may imagine
If you can send XML data, check for XXE injections.
If you send regular POST data, try to send arrays and dictionaries:
username[]=John
username[$neq]=lalala
Play with routes
/files/..%2f..%2f + victim ID + %2f + victim filename
Check possible versions
Old versions may be still be in use and be more vulnerable than latest endpoints
/api/v1/login
/api/v2/login\
/api/CharityEventFeb2020/user/pp/<ID>
/api/CharityEventFeb2021/user/pp/<ID>

Security Skills as a Service platform bridges the current skill set gap by combining global offensive security talent with smart automation, providing real-time data you need to make informed decisions.

🛡️ API Security Empire Cheat Sheet

Cheat Sheet Author: Momen Eldawakhly (Cyber Guy)

In this repository you will find: Mindmaps, tips & tricks, resources and every thing related to API Security and API Penetration Testing. Our mindmaps and resources are based on OWASP TOP 10 API, our expereince in Penetration testing and other resources to deliver the most advanced and accurate API security and penetration testing resource in the WEB!!
🚪 First gate: {{Recon}}
The first gate to enter the API Security Empire is to know how to gather information about the API infrastructure and how to perform a powerfull recon on API to extract the hidden doors which made you compromise the whole infrastructure from, so, we provide this updated API Recon mindmap with the latest tools and methodologies in API recon:


PDF Version | XMind Version
⚔️ Weapons you will need:
BurpSuite
FFUF
Arjun
Postman
SecLists
FuzzDB
SoapUI
GraphQL Voyager
Kiterunner
unfurl
🏋️ Test your abilities and weapons:
vapi
Generic-University
🚪 Second gate: {{Attacking}}
Attacking RESTful & SOAP:

PDF Version | XMind Version\
Attacking GraphQL:
Due to the limited attacks in the GraphQL we tried to generate all the possible attacks due to our experience in testing APIs in the coming mindmap:

PDF Version | XMind Version\
Owasp API Security Top 10
Read this document to learn how to search and exploit Owasp Top 10 API vulnerabilities: https://github.com/OWASP/API-Security/blob/master/2019/en/dist/owasp-api-security-top-10.pdf
API Security Checklist

List of possible API endpoints
https://gist.github.com/yassineaboukir/8e12adefbd505ef704674ad6ad48743d
Tools
kiterunner: Great tool to discover API endpoints.
kr scan https://domain.com/api/ -w routes-large.kite -x 20 # Downloaded from kiterunner repo
kr scan https://domain.com/api/ -A=apiroutes-220828 -x 20
kr brute https://domain.com/api/ -A=raft-large-words -x 20 -d=0
kr brute https://domain.com/api/ -w /tmp/lang-english.txt -x 20 -d=0
automatic-api-attack-tool: Imperva's customizable API attack tool takes an API specification as an input, generates and runs attacks that are based on it as an output.
Astra: Another tool for api testing to find several different web vulnerabilities.
Susanoo: Vulnerability API scanner.
restler-fuzzer: RESTler is the first stateful REST API fuzzing tool for automatically testing cloud services through their REST APIs and finding security and reliability bugs in these services. For a given cloud service with an OpenAPI/Swagger specification, RESTler analyzes its entire specification, and then generates and executes tests that exercise the service through its REST API.
TnT-Fuzzer: TnT-Fuzzer is an OpenAPI (swagger) fuzzer written in python.
APIFuzzer: APIFuzzer reads your API description and step by step fuzzes the fields to validate if you application can cope with the fuzzed parameters.
API-fuzzer: API_Fuzzer gem accepts a API request as input and returns vulnerabilities possible in the API.
race-the-web: Tests for race conditions in web applications by sending out a user-specified number of requests to a target URL (or URLs) simultaneously, and then compares the responses from the server for uniqueness.
