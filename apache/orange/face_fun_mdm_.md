

2020年9月12日 星期六
How I Hacked Facebook Again! Unauthenticated RCE on MobileIron MDM

##
#
https://blog.orange.tw/2020/09/how-i-hacked-facebook-again-mobileiron-mdm-rce.html
#
##


![1599655683992](https://github.com/user-attachments/assets/b7b7e015-4b2e-47fb-b9df-c4fbcbdb14f4)


Author: Orange Tsai

This is a cross-post blog from DEVCORE. 中文版請參閱這裡



Hi, it’s a long time since my last article. This new post is about my research this March, which talks about how I found vulnerabilities on a leading Mobile Device Management product and bypassed several limitations to achieve unauthenticated RCE. All the vulnerabilities have been reported to the vendor and got fixed in June. After that, we kept monitoring large corporations to track the overall fixing progress and then found that Facebook didn’t keep up with the patch for more than 2 weeks, so we dropped a shell on Facebook and reported to their Bug Bounty program!

This research is also presented at HITCON 2020. You can check the slides HERE


As a Red Teamer, we are always looking for new paths to infiltrate the corporate network from outside. Just like our research in Black Hat USA last year, we demonstrated how leading SSL VPNs could be hacked and become your Virtual “Public” Network! SSL VPN is trusted to be secure and considered the only way to your private network. But, what if your trusted appliances are insecure?

Based on this scenario, we would like to explore new attack surfaces on enterprise security, and we get interested in MDM, so this is the article for that!



What is MDM?
Mobile Device Management, also known as MDM, is an asset assessment system that makes the employees’ BYOD more manageable for enterprises. It was proposed in 2012 in response to the increasing number of tablets and mobile devices. MDM can guarantee that the devices are running under the corporate policy and in a trusted environment. Enterprise could manage assets, install certificates, deploy applications and even lock/wipe devices remotely to prevent data leakage as well.

UEM (Unified Endpoint Management) is a newer term relevant to MDM which has a broader definition for managed devices. Following we use MDM to represent similar products!



Our target
MDM, as a centralized system, can manage and control all employees’ devices. It is undoubtedly an ideal asset assessment system for a growing company. Besides, MDM must be reachable publicly to synchronize devices all over the world. A centralized and public-exposing appliance, what could be more appealing to hackers?

Therefore, we have seen hackers and APT groups abusing MDM these years! Such as phishing victims to make MDM a C&C server of their mobile devices, or even compromising the corporate exposed MDM server to push malicious Trojans to all devices. You can read the report Malicious MDM: Let’s Hide This App by Cisco Talos team and First seen in the wild - Malware uses Corporate MDM as attack vector by CheckPoint CPR team for more details!

From previous cases, we know that MDM is a solid target for hackers, and we would like to do research on it. There are several MDM solutions, even famous companies such as Microsoft, IBM and Apple have their own MDM solution. Which one should we start with?

We have listed known MDM solutions and scanned corresponding patterns all over the Internet. We found that the most prevalent MDMs are VMware AirWatch and MobileIron!

So, why did we choose MobileIron as our target? According to their official website, more than 20,000 enterprises chose MobileIron as their MDM solution, and most of our customers are using that as well. We also know Facebook has exposed the MobileIron server since 2016. We have analyzed Fortune Global 500 as well, and found more than 15% using and exposing their MobileIron server to the public! Due to above reasons, it became our main target!



Where to Start
From past vulnerabilities, we learned there aren’t too many researchers diving into MobileIron. Perhaps the attack vector is still unknown. But we suspect the main reason is that the firmware is too hard to obtain. When researching an appliance, turning a pure BlackBox testing into GrayBox, or WhiteBox testing is vital. We spent lots of time searching for all kinds of information on the Internet, and ended up with an RPM package. This RPM file is supposed to be the developer’s testing package. The file is just sitting on a listable WebRoot and indexed by Google Search.







Anyway, we got a file to research. The released date of the file is in early 2018. It seems a little bit old but still better than nothing!

P.S. We have informed MobileIron and the sensitive files has been removed now.



Finding Vulnerabilities
After a painful time solving the dependency hell, we set the testing package up finally. The component is based on Java and exposed three ports:

443 - the user enrollment interface
8443 - the appliance management interface
9997 - the MobileIron device synchronization protocol (MI Protocol)


All opened ports are TLS-encrypted. Apache is in the front of the web part and proxies all connections to backend, a Tomcat with Spring MVC inside.







Due to the Spring MVC, it’s hard to find traditional vulnerabilities like SQL Injection or XSS from a single view. Therefore, examining the logic and architecture is our goal this time!

Talking about the vulnerability, the root cause is straightforward. Tomcat exposed a Web Service that deserializes user input with Hessian format. However, this doesn’t mean we can do everything! The main effort of this article is to solve that, so please see the exploitation below.

Although we know the Web Service deserializes the user input, we can not trigger it. The endpoint is located on both:

User enrollment interface - https://mobileiron/mifs/services/
Management interface - https://mobileiron:8443/mics/services/


We can only touch the deserialization through the management interface because the user interface blocks the Web Service access. It’s a critical hit for us because most enterprises won’t expose their management interface to the Internet, and a management-only vulnerability is not useful to us so that we have to try harder. :(

Scrutinizing the architecture, we found Apache blocks our access through Rewrite Rules. It looks good, right?

RewriteRule ^/mifs/services/(.*)$ https://%{SERVER_NAME}:8443/mifs/services/$1 [R=307,L]
RewriteRule ^/mifs/services [F]


MobileIron relied on Apache Rewrite Rules to block all the access to Web Service. It’s in the front of a reverse-proxy architecture, and the backend is a Java-based web server.

Have you recalled something?




Yes, the Breaking Parser Logic! It’s the reverse proxy attack surface I proposed in 2015, and presented at Black Hat USA 2018. This technique leverage the inconsistency between the Apache and Tomcat to bypass the ACL control and reaccess the Web Service. BTW, this excellent technique is also applied to the recently F5 BIG-IP TMUI RCE vulnerability!

https://mobileiron/mifs/.;/services/someService

Exploiting Vulnerabilities
OK, now we have access to the deserialization wherever it’s on enrollment interface or management interface. Let’s go back to exploitations!

Moritz Bechler has an awesome research which summarized the Hessian deserialization vulnerability on his whitepaper, Java Unmarshaller Security. From the marshalsec source code, we learn the Hessian deserialization triggers the equals() and hashcode() while reconstructing a HashMap. It could also trigger the toString() through the XString, and the known exploit gadgets so far are:

Apache XBean
Caucho Resin
Spring AOP
ROME EqualsBean/ToStringBean


In our environment, we could only trigger the Spring AOP gadget chain and get a JNDI Injection.

Name	Effect
x	Apache XBean	JNDI Injection
x	Caucho Resin	JNDI Injection
√	Spring AOP	JNDI Injection
x	ROME EqualsBean	RCE


Once we have a JNDI Injection, the rest parts of exploitations are easy! We can just leverage Alvaro Muñoz and Oleksandr Mirosh’s work, A Journey From JNDI/LDAP to Remote Code Execution Dream Land, from Black Hat USA 2016 to get the code execution… Is that true?







Since Alvaro Muñoz and Oleksandr Mirosh introduced this on Black Hat, we could say that this technique helps countless security researchers and brings Java deserialization vulnerability into a new era. However, Java finally mitigated the last JNDI/LDAP puzzle in October 2018. After that, all java version higher than 8u181, 7u191, and 6u201 can no longer get code execution through JNDI remote URL-Class loading. Therefore, if we exploit the Hessian deserialization on the latest MobileIron, we must face this problem!

Java changed the default value of com.sun.jndi.ldap.object.trustURLCodebase to False to prevent attackers from downloading remote URL-Class to get code executions. But only this has been prohibited. We can still manipulate the JNDI and redirect the Naming Reference to a local Java Class!

The concept is a little bit similar to Return-Oriented Programming, utilizing a local existing Java Class to do further exploitations. You can refer to the article Exploiting JNDI Injections in Java by Michael Stepankin in early 2019 for details. It describes the attack on POST-JNDI exploitations and how to abuse the Tomcat’s BeanFactory to populate the ELProcessor gadget to get code execution. Based on this concept, researcher Welkin also provides another ParseClass gadget on Groovy. As described in his (Chinese) article:

除了 javax.el.ELProcessor，当然也还有很多其他的类符合条件可以作为 beanClass 注入到 BeanFactory 中实现利用。举个例子，如果目标机器 classpath 中有 groovy 的库，则可以结合之前 Orange 师傅发过的 Jenkins 的漏洞实现利用



It seems the Meta Programming exploitation in my previous Jenkins research could be used here as well. It makes the Meta Programming great again :D


The approach is fantastic and looks feasible for us. But both gadgets ELProcessor and ParseClass are unavailable due to our outdated target libraries. Tomcat introduced the ELProcessor since 8.5, but our target is 7. As for the Groovy gadget, the target Groovy version is too old (1.5.6 from 2008) to support the Meta Programming, so we still have to find a new gadget by ourselves. We found a new gadget on GroovyShell in the end. If you are interested, you can check the Pull Request I sent to the JNDI-Injection-Bypass project!



Attacking Facebook
Now we have a perfect RCE by chaining JNDI Injection, Tomcat BeanFactory and GroovyShell. It’s time to hack Facebook!

Aforementioned, we knew the Facebook uses MobileIron since 2016. Although the server’s index responses 403 Forbidden now, the Web Service is still accessible!






Everything is ready and wait for our exploit! However, several days before our scheduled attack, we realized that there is a critical problem in our exploit. From our last time popping shell on Facebook, we noticed it blocks outbound connections due to security concerns. The outbound connection is vital for JNDI Injection because the idea is to make victims connecting to a malicious server to do further exploitations. But now, we can’t even make an outbound connection, not to mention others.







So far, all attack surfaces on JNDI Injection have been closed, we have no choice but to return to Hessian deserialization. But due to the lack of available gadgets, we must discover a new one by ourselves!






Before discovering a new gadget, we have to understand the existing gadgets’ root cause properly. After re-reading Moritz Bechler’s paper, a certain word interested me:

Cannot restore Groovy’s MethodClosure as readResolve() is called which throws an exception.



A question quickly came up in my mind: Why did the author leave this word here? Although it failed with exceptions, there must have been something special so that the author write this down.

Our target is running with a very old Groovy, so we are guessing that the readResolve() constrain might not have been applied to the code base yet! We compared the file groovy/runtime/MethodClosure.java between the latest and 1.5.6.

$ diff 1_5_6/MethodClosure.java 3_0_4/MethodClosure.java

>     private Object readResolve() {
>         if (ALLOW_RESOLVE) {
>             return this;
>         }
>         throw new UnsupportedOperationException();
>     }


Yes, we are right. There is no ALLOW_RESOLVE in Groovy 1.5.6, and we later learned CVE-2015-3253 is just for that. It’s a mitigation for the rising Java deserialization vulnerability in 2015. Since Groovy is an internally used library, developers won’t update it if there is no emergency. The outdated Groovy could also be a good case study to demonstrated how a harmless component can leave you compromised!

Of course we got the shell on Facebook in the end. Here is the video:






Vulnerability Report and Patch
We have done all the research on March and sent the advisory to MobileIron at 4/3. The MobileIron released the patch on 6/15 and addressed three CVEs for that. You can check the official website for details!

CVE-2020-15505 - Remote Code Execution
CVE-2020-15506 - Authentication Bypass
CVE-2020-15507 - Arbitrary File Reading


After the patch has been released, we start monitoring the Internet to track the overall fixing progress. Here we check the Last-Modified header on static files so that the result is just for your information. (Unknown stands for the server closed both 443 and 8443 ports)







At the same time, we keep our attentions on Facebook as well. With 15 days no-patch confirm, we finally popped a shell and report to their Bug Bounty program at 7/2!



Conclusion
So far, we have demonstrated a completely unauthenticated RCE on MobileIron. From how we get the firmware, find the vulnerability, and bypass the JNDI mitigation and network limitation. There are other stories, but due to the time, we have just listed topics here for those who are interested:

How to take over the employees’ devices from MDM
Disassemble the MI Protocol
And the CVE-2020-15506, an interesting authentication bypass


I hope this article could draw attention to MDM and the importance of enterprise security! Thanks for reading. :D

