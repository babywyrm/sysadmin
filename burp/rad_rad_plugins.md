19 Most Useful Plugins For Burp Suite [Penetration Testing]
June 24, 2018H4ck0Comments Offon 19 Most Useful Plugins for Burp Suite [Penetration Testing]
Burp Suite is an intercepting HTTP Proxy, and it is the defacto tool for performing web application security testing.  Burp is highly functional and provides an intuitive and user-friendly interface. Its proxy function allows configuration of very fine-grained interception rules, and clear analysis of HTTP messages structure and contents. The proxy can also be configured to perform automated matching and replacement of message headers, and provides an in-browser interface for viewing the proxy cache and reissuing individual requests.

Of all the integrated tool suites, Burp is the only one that implements a fully functional web application spider, which parses forms and JavaScript, and allows automated and user-guided submission of form parameters.

Below we’ve listed out the top 19 plugins which are open source and can be integrated under Burp as an extenders which are as follows:

1. AuthMatrix
AuthMatrix is an extension to Burp Suite that provides a simple way to test authorization in web applications and web services. With AuthMatrix, testers focus on thoroughly defining tables of users, roles, and requests for their specific target application upfront. These tables are structured in a similar format to that of an access control matrix common in various threat modeling methodologies.

Github Link – https://github.com/SecurityInnovation/AuthMatrix
AuthMatrix requires configuring Burp Suite to use Jython. Be sure to use Jython version 2.7.0 or greater to ensure compatibility.

2. Autorize
Autorize is an automatic authorization enforcement detection extension for Burp Suite. It was written in Python by Barak Tawily, an application security expert, and Federico Dotta, a security expert at Mediaservice.net. Autorize was designed to help security testers by performing automatic authorization tests. With the last release now Autorize also perform automatic authentication tests.

Github Link – https://github.com/Quitten/Autorize
3. backslash-powered-scanner
This extension complements Burp’s active scanner by using a novel approach capable of finding and confirming both known and unknown classes of server-side injection vulnerabilities. Evolved from classic manual techniques, this approach reaps many of the benefits of manual testing including casual WAF evasion, a tiny network footprint, and flexibility in the face of input filtering.

Github Link – https://github.com/PortSwigger/backslash-powered-scanner
4. burp-rest-api
A REST/JSON API to the Burp Suite security tool. Upon successfully building the project, an executable JAR file is created with the Burp Suite Professional JAR bundled in it. When the JAR is launched, it provides a REST/JSON endpoint to access the Scanner, Spider, Proxy and other features of the Burp Suite Professional security tool.

Github Link – https://github.com/vmware/burp-rest-api
5. BurpSmartBuster
A Burp Suite content discovery plugin that add the smart into the Buster through which you can easily find all the hidden resources in a web application! Basically this plugin checks for directories/files, in current URL directories, replace and add extension to current files etc.

Github Link – https://github.com/pathetiq/BurpSmartBuster
6. BurpKit
BurpKit is a BurpSuite plugin which helps in assessing complex web apps that render the contents of their pages dynamically. It also provides a bi-directional Script bridge API which allows users to create quick one-off BurpSuite plugin prototypes which can interact directly with the DOM and Burp’s extender API.

Github Link – https://github.com/allfro/BurpKit
7. collaborator-everywhere
A Burp Suite Pro extension which augments your proxy traffic by injecting non-invasive headers designed to reveal backend systems by causing pingbacks to Burp Collaborator.

Github Link – https://github.com/PortSwigger/collaborator-everywhere
8. C02
Co2 includes several useful enhancements bundled into a single Java-based Burp Extension. The extension has it’s own configuration tab with multiple sub-tabs (for each Co2 module). Modules that interact with other Burp tools can be disabled from within the Co2 configuration tab, so there is no need to disable the entire extension when using just part of the functionality.

Github Link – https://github.com/JGillam/burp-co2
CO2 is comprised of both a suite of modules as well as standalone versions of some of these modules, either due to popular request or while still in early development prior to being added to the suite. The objectives of all CO2 modules include:

9. distribute-damage
Designed to make Burp evenly distribute load across multiple scanner targets, this extension introduces a per-host throttle, and a context menu to trigger scans from. It may also come in useful for avoiding detection.

Github Link – https://github.com/PortSwigger/distribute-damage
10. HUNT
HUNT is a Burp Suite extension which identifies common parameters vulnerable to certain vulnerability classes and also organize the testing methodologies inside of Burp Suite.

Github Link – https://github.com/bugcrowd/HUNT
11. IntruderPayloads
A collection of Burpsuite Intruder payloads and fuzz lists and pentesting methodology. To pull down all 3rd party repos, you need to run install.sh in the same directory of the IntruderPayloads folder.

Github Link – https://github.com/1N3/IntruderPayloads/blob/master/README.md
12. Office Open XML Editor
Office Open XML Editor is a burp extension written in Python 2.7 that will allow you to edit Office Open XML(OOXML) file directly in Burp Suite. It will detect request with Office Open XML(docx,xlsx,pptx) and provide you tab to edit XML content which is present inside the document which will futher used to test the XXE attacks.

Github Link – https://github.com/maxence-schmitt/OfficeOpenXMLEditor
13. PwnBack
Burp Extender plugin that generates a sitemap of a website using Wayback Machine. PwnBack also requires PhantomJS to run. You can download it from here.

Github Link – https://github.com/P3GLEG/PwnBack
14. SAML Raider
SAML Raider is a Burp Suite extension for testing SAML infrastructures. It contains two core functionalities: Manipulating SAML Messages and manage X.509 certificates.

Github Link – https://github.com/SAMLRaider/SAMLRaider
15. swurg
Parses Swagger files into the BurpSuite for automating RESTful API testing – approved by Burp for inclusion in their official BApp Store.

Github Link – https://github.com/AresS31/swurg
16. Burp-molly-pack
Burp-molly-pack is Yandex security checks pack for Burp. The main goal of Burp-molly-pack is to extend Burp checks. Plugins contains Active and Passive security checks.

Github Link – https://github.com/yandex/burp-molly-pack
17. NoPE Proxy
This extension is for those times when Burp just says ‘Nope, i’m not gonna deal with this.’. It’s actually an acronym for Non-HTTP Protocol Extension Proxy for Burp Suite.

Github Link – https://github.com/summitt/Burp-Non-HTTP-Extension
Nope Proxy also has a port monitor that will only display tcp ports that a remote client is attempting to connect on. This combined with the DNS history can help you find which hosts and ports a mobile app or thin client is attempting to contact so that you can create interceptors for this traffic and proxy it to the real servers.

18. AutoRepeater
AutoRepeater, an open source Burp Suite extension that automates and streamlines web application authorization testing, and provides security researchers with an easy-to-use tool for automatically duplicating, modifying, and resending requests within Burp Suite while quickly evaluating the differences in responses.

Github Link – https://github.com/nccgroup/AutoRepeater
AutoRepeater will only resend requests which are changed by a defined replacement. When AutoRepeater receives a request that matches the conditions set for a given tab, AutoRepeater will first apply every defined base replacement to the request, then will copy the request with the base replacements performed for each defined replacement and apply the given replacement to the request.

19. Uniqueness plugin for Burp Suite
Makes requests unique based on regular expressions. Handy for registration forms and any other endpoint that requires unique values upon every request.

Github Link – https://github.com/silentsignal/burp-uniqueness
