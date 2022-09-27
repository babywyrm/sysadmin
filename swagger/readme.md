Basic Information

##
#
https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/web-api-pentesting
#
##


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
