Basic Tomcat Info
☁️ HackTricks Cloud ☁️ -🐦 Twitter 🐦 - 🎙️ Twitch 🎙️ - 🎥 Youtube 🎥


Find vulnerabilities that matter most so you can fix them faster. Intruder tracks your attack surface, runs proactive threat scans, finds issues across your whole tech stack, from APIs to web apps and cloud systems. Try it for free today.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

Avoid to run with root
In order to not run Tomcat with root a very common configuration is to set an Apache server in port 80/443 and, if the requested path matches a regexp, the request is sent to Tomcat running on a different port.
```
Default Structure
├── bin
├── conf
│   ├── catalina.policy
│   ├── catalina.properties
│   ├── context.xml
│   ├── tomcat-users.xml
│   ├── tomcat-users.xsd
│   └── web.xml
├── lib
├── logs
├── temp
├── webapps
│   ├── manager
│   │   ├── images
│   │   ├── META-INF
│   │   └── WEB-INF
|   |       └── web.xml
│   └── ROOT
│       └── WEB-INF
└── work
    └── Catalina
        └── localhost
```
The bin folder stores scripts and binaries needed to start and run a Tomcat server.
The conf folder stores various configuration files used by Tomcat.
The tomcat-users.xml file stores user credentials and their assigned roles.
The lib folder holds the various JAR files needed for the correct functioning of Tomcat.
The logs and temp folders store temporary log files.
The webapps folder is the default webroot of Tomcat and hosts all the applications. The work folder acts as a cache and is used to store data during runtime.
Each folder inside webapps is expected to have the following structure.
```
webapps/customapp
├── images
├── index.jsp
├── META-INF
│   └── context.xml
├── status.xsd
└── WEB-INF
    ├── jsp
    |   └── admin.jsp
    └── web.xml
    └── lib
    |    └── jdbc_drivers.jar
    └── classes
        └── AdminServlet.class
```
The most important file among these is WEB-INF/web.xml, which is known as the deployment descriptor. This file stores information about the routes used by the application and the classes handling these routes.
All compiled classes used by the application should be stored in the WEB-INF/classes folder. These classes might contain important business logic as well as sensitive information. Any vulnerability in these files can lead to total compromise of the website. The lib folder stores the libraries needed by that particular application. The jsp folder stores Jakarta Server Pages (JSP), formerly known as JavaServer Pages, which can be compared to PHP files on an Apache server.

Here’s an example web.xml file.```

<?xml version="1.0" encoding="ISO-8859-1"?>

<!DOCTYPE web-app PUBLIC "-//Sun Microsystems, Inc.//DTD Web Application 2.3//EN" "http://java.sun.com/dtd/web-app_2_3.dtd">

<web-app>
  <servlet>
    <servlet-name>AdminServlet</servlet-name>
    <servlet-class>com.inlanefreight.api.AdminServlet</servlet-class>
  </servlet>

  <servlet-mapping>
    <servlet-name>AdminServlet</servlet-name>
    <url-pattern>/admin</url-pattern>
  </servlet-mapping>
</web-app>   
```
The web.xml configuration above defines a new servlet named AdminServlet that is mapped to the class com.inlanefreight.api.AdminServlet. Java uses the dot notation to create package names, meaning the path on disk for the class defined above would be:

classes/com/inlanefreight/api/AdminServlet.class
Next, a new servlet mapping is created to map requests to /admin with AdminServlet. This configuration will send any request received for /admin to the AdminServlet.class class for processing. The web.xml descriptor holds a lot of sensitive information and is an important file to check when leveraging a Local File Inclusion (LFI) vulnerability.

tomcat-users
The tomcat-users.xml file is used to allow or disallow access to the /manager and host-manager admin pages.

<?xml version="1.0" encoding="UTF-8"?>

<SNIP>
  
<tomcat-users xmlns="http://tomcat.apache.org/xml"
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
              xsi:schemaLocation="http://tomcat.apache.org/xml tomcat-users.xsd"
              version="1.0">
<!--
  By default, no user is included in the "manager-gui" role required
  to operate the "/manager/html" web application.  If you wish to use this app,
  you must define such a user - the username and password are arbitrary.

  Built-in Tomcat manager roles:
    - manager-gui    - allows access to the HTML GUI and the status pages
    - manager-script - allows access to the HTTP API and the status pages
    - manager-jmx    - allows access to the JMX proxy and the status pages
    - manager-status - allows access to the status pages only

  The users below are wrapped in a comment and are therefore ignored. If you
  wish to configure one or more of these users for use with the manager web
  application, do not forget to remove the <!.. ..> that surrounds them. You
  will also need to set the passwords to something appropriate.
-->

   
 <SNIP>
  
!-- user manager can access only manager section -->
<role rolename="manager-gui" />
<user username="tomcat" password="tomcat" roles="manager-gui" />

<!-- user admin can access manager and admin section both -->
<role rolename="admin-gui" />
<user username="admin" password="admin" roles="manager-gui,admin-gui" />


</tomcat-users>
The file shows us what each of the roles manager-gui, manager-script, manager-jmx, and manager-status provide access to. In this example, we can see that a user tomcat with the password tomcat has the manager-gui role, and a second weak password admin is set for the user account admin

References



Apache Tomcat
Apache Tomcat exploit and Pentesting guide for penetration tester

Default credentials
The most interesting path of Tomcat is /manager/html, inside that path you can upload and deploy war files (execute code). But this path is protected by basic HTTP auth, the most common credentials are:
```
admin:admin
tomcat:tomcat
admin:<NOTHING>
admin:s3cr3t
tomcat:s3cr3t
admin:tomcat
Bruteforce
hydra -L users.txt -P /usr/share/seclists/Passwords/darkweb2017-top1000.txt -f 10.10.10.64 http-get /manager/html
vulnerability
Example Scripts Information Leakage
The following example scripts that come with Apache Tomcat v4.x - v7.x and can be used by attackers to gain information about the system. These scripts are also known to be vulnerable to cross site scripting (XSS) injection.

/examples/jsp/num/numguess.jsp
/examples/jsp/dates/date.jsp
/examples/jsp/snp/snoop.jsp
/examples/jsp/error/error.html
/examples/jsp/sessions/carts.html
/examples/jsp/checkbox/check.html
/examples/jsp/colors/colors.html
/examples/jsp/cal/login.html
/examples/jsp/include/include.jsp
/examples/jsp/forward/forward.jsp
/examples/jsp/plugin/plugin.jsp
/examples/jsp/jsptoserv/jsptoservlet.jsp
/examples/jsp/simpletag/foo.jsp
/examples/jsp/mail/sendmail.jsp
/examples/servlet/HelloWorldExample
/examples/servlet/RequestInfoExample
/examples/servlet/RequestHeaderExample
/examples/servlet/RequestParamExample
/examples/servlet/CookieExample
/examples/servlet/JndiServlet
/examples/servlet/SessionExample
/tomcat-docs/appdev/sample/web/hello.jsp
Path Traversal (..;/)
http://www.vulnerable.com/;param=value/manager/html
Apache Tomcat Snoop Servlet Remote Information Disclosure
https://target:ip/examples/jsp/snp/snoop.jsp
Apache Tomcat - Cross-Site Scripting
nuclei -u target  -t CVE-2019-0221.yaml
Apache Tomcat Remote Command Execution
nuclei -u target  -t CVE-2020-9484.yaml
tomcat scanning tools
sudo python3 -m pip install apachetomcatscanner
apachetomcatscanner -tt target_ip -tp port    --no-check-certificate

