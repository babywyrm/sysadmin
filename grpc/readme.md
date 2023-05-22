
##
#
https://www.trendmicro.com/en_us/research/20/h/how-unsecure-grpc-implementations-can-compromise-apis.html
#
##

Enterprises are turning to microservice architecture to build future-facing applications. Microservices allow enterprises to efficiently manage infrastructure, easily deploy updates or improvements, and help IT teams innovate, fail, and learn faster. It also allows enterprises to craft applications that can easily scale with demand. Additionally, as enterprises switch architectures — jumping from the traditional monolithic to microservices — the need for efficient communication between microservices arises. This critical and complex communication between client and server applications can be handled by gRPC, a universal remote procedure call (RPC) framework that facilitates the transparent and efficient communication between connected systems. Although quite new (having only been developed by Google in 2015), it has quickly gained popularity and adoption.

In this blog, we will discuss the security pitfalls that developers might face when shifting to gRPC and implementing gRPC in their projects. Because secure gRPC APIs play a pivotal role in overall application security, we provide recommendations on how to protect gRPC implementations from threats and mitigate against risks.

What is gRPC?
gRPC can be used to design new protocols that require accuracy, efficiency, and language independence as it supports multiple languages for both servers and clients. It is a Cloud Native Computing (CNCF) project and has been adopted by major companies such as popular video-streaming site Netflix, financial services company Square, and platform as a Service (PaaS) company Docker.

gRPC is compared to other RPC frameworks, such as SOAP and REST. Though RESTful APIs are widely used and typically use HTTP to exchange information between apps or services and the JavaScript Object Notation (JSON) data format, they have performance and text-based orientation limitations.

Many organizations have migrated their APIs from REST to gRPC to take advantage of gRPC’s binary protocol that is better suited for interservice communications. gRPC uses the HTTP/2, a binary-based protocol, as an underlayer by default. HTTP/2 supports multiple streams and requests within one TCP connection, unlike its predecessor, HTTP/1.0, which was designed to have a “single request, single reply” scheme. HTTP pipelining addressed this issue in HTTP/1.1; however, HTTP 2.0 is still more performant and supported.

Visualization of difference of HTTP/1.0 and HTTP/2 when it comes to requests and replies
Figure 1. A visualization of how HTTP/1.0 differs from HTTP/2 when it comes to requests and replies
The gRPC is built on top of protocol buffers (or protobuf),  Google’s platform- and language-neutral mechanism for serializing structured data. Serialization is a process of converting in-memory objects into a byte stream that can be easily saved into a file or transmitted through the network for other applications. Developers describe the data interface once and then compile it using a protocol buffer compiler for a chosen language. In the case of gRPC, protocol buffers are also used for defining the RPC interface.

Illustration of how the gRPC framework works
Figure 2. An illustration of how the gRPC framework works in an online retail application that has the product and payment services interacting via APIs
example of  a gRPC “HelloWorld” demonstration. Image credit: gRPC Quick Start
Figure 3. An example of a gRPC “HelloWorld” demonstration sending a string message. Image credit: gRPC Quick Start
Potential Threats and Risks to gRPC

Vulnerabilities

gRPC supports multiple programming languages. There are two types of implementations used within the supported languages: a) implementation using the language itself, and b) wrappers around the gRPC C-core written code. These wrappers enable the translation of calls written in different supported languages into C calls. Though the C language implementations generally perform well, there is a higher chance that a developer will introduce a vulnerability into the system as there is a need to implement more functionalities together with memory management capabilities. On the other hand, using languages such as Java or Go, which already have a lot of functionalities implemented and also take care of memory management concerns, reduces the chances of a developer introducing high-impact bugs to the system. Notably, the importance of choosing suitable languages might play a significant role in keeping systems more secure.

Supported Programming Languages	Actual Implementation
C/C++	Yes
C#	Yes*
Dart	Yes
Go	Yes
Java	Yes
Kotlin/JVM	Yes
Node.js	Yes**
Objective-C	No
PHP	No
Python	No
Ruby	No
WebJS	Yes
* It is possible to have a purely C# implementation or a C# wrapper around C
** Purely JavaScript implementation as well as bindings to gRPC C-core (using a C++ add-on)


Unsecure data transmission channels and channel credentials

It is highly probable that during a remote procedure call, data will be transferred to the target server. This is why developers should prioritize setting up secure channels for data transmission. Doing this not only prevents data leaks but also limits Man-in-the-Middle (MiTM) attacks, as skilled attackers may leak service data or inject malicious data to the connection that will interfere with the server.

A data leak can reveal implementation details about your service or infrastructure that can enable further attacks and even lead to service or infrastructure compromise. Here’s an example of a packet capture from an insecure gRPC call:
Example of a packet capture from an unsecure gRPC call
Figure 4. An example of a packet capture from an unsecure gRPC call
gRPC supports TLS over the whole underlying HTTP/2 protocol as well as various authentication mechanisms. It’s a developer’s responsibility to choose a secure implementation. Copying and pasting patterns with keywords like “InsecureChannelCredentials” should be avoided for obvious reasons.

We have performed a Github.com code search for  the “InsecureChannelCredentials”  keyword together with a C++ language limitation (which is common to gRPC usage). The search yielded over 11,000 code results.  We believe that the significant number of search occurrences are associated with demos and examples. However, there are still some projects that use them.

Code search results for “InsecureChannelCredentials”
Figure 5. “InsecureChannelCredentials” code search results
Procedure implementation concerns

Similarly, for AWS Lambda functions, the biggest vulnerability surface is hidden inside the actual remote procedure implementation. Because gRPC supports multiple languages, we suggest that novice developers use memory-safe languages in order to avoid high-impact memory management bugs such as buffer overflows or use-after-free (UaF) bugs leading to the remote code execution (RCE).

However, using memory-safe languages will still not be able to mitigate the logical bugs that might appear in the code. For that purpose, developers should set a high standard for developing processes, consistently follow the secure software development best practices, and implement proactive controls by using the OWASP Top 10 Proactive Controls recommendations in the OWASP Secure Coding Practices.

Having a centralized authentication mechanism for critical parts of the system is highly recommended even inside isolated networks or private clouds. In the case of misconfigurations, vulnerability exploitation inside the environment may serve as an entry point for unauthorized access that could significantly interfere with the gRPC service.

We also suggest not to hard-code or commit gRPC authentication details to supply chain management (SCM) systems, especially public-facing ones. Just like any other credential information, those should be stored inside a secure location and accessed only when needed. Here’s an example of a gRPC credential leakage we found just by searching on GitHub:

Example of gRPC service credentials found on GitHub
Figure 6. An example of gRPC service credentials found on GitHub
Denial of service attacks

Lastly, we would like to discuss our denial of service (DoS) attack findings. gRPC can serve as a “hidden” messaging service inside isolated environment as well as an API replacement to public-facing REST API services using the JSON format.

We would like to warn C/C++ gRPC users of an already known yet still unfixed bug that effectively denies service calls until the service is restarted. The bug is triggered when a higher number of connections is opened within a short period of time. In fact, this is due to the limitation on the number of opened file descriptors on Linux systems.

Example of a DoS attack inside a C/C++ implementation of a gRPC library
Figure 7. An example of a DoS attack inside a C/C++ implementation of a gRPC library
Based on our research, the bug is triggered when socket connections are opened within a short amount of time and even after the opened socket has been closed. We tested this implementation in other languages that are not C-wrapped such as Java and Go and discovered that they are not affected by this issue.

We propose the following workarounds to help mitigate the risk of DoS attacks in case switching from one platform to another is not an option:

Increase the limit of file descriptors by executing “sudo ulimit -n increasedNumber”.
Use an external load balancer and service watchdogs to reduce the load for a single instance and to keep an eye on status of the service.

Security Recommendations for gRPC

As the number of enterprises using the gRPC framework continues to increase because of its reliability and scalability of services, there should be a more widespread awareness of how the protocol must be kept protected against risks and threats.

Though gRPC enables the efficient communications between systems, it must be emphasized that it is the developer’s responsibility to ensure that the communications between these systems are kept secure. gRPC has a comprehensive guide on the supported authentication mechanisms that will work with the protocol, such as SSL/TLS with or without Google token-based authentication, that developers should follow. Developers also have the option of plugging in their own authentication system via the Credentials plugin API.

Developers should also use security solutions that will validate content, ensuring that no malicious payload will be able to infiltrate the system through the messages that are transferred from the client to the server and vice versa.

Solutions that will ensure that critical data is kept secure in transit, keep an eye on the status of a service, and enforce authentication and authorization to keep data secure will also be vital for enterprises.

The gRPC framework is an effective tool for developers and enterprises to build APIs, applications, and microservices. But like its predecessors, it is likewise not impervious to risks and threats — hence the need for security solutions, checks, and controls should be highlighted.

Trend Micro solutions

The Trend Micro Cloud One™ security services platform, which powers Trend Micro™ Hybrid Cloud Security, enables software developers to build and run applications their way. It has security controls that work across existing infrastructure or modern code streams, development toolchains, and multiplatform requirements.

Application Security, which is offered by Cloud One, provides full diagnostic details about code vulnerabilities and runtime protection against automated attacks and the most common threats like SQL injection and RCE. It also offers complete coverage and reporting of every attack instance, as well as insight into an attacker’s identity and attack methodology.

Cloud One also offers the following cloud security technologies to further help developers identify and resolve security issues sooner and improve delivery time for DevOps teams:

