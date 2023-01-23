
```
Using Netcat for File Transfers

Netcat is like a swiss army knife for geeks. It can be used for just about anything involving TCP or UDP. One of its most practical uses is to transfer files. Non *nix people usually don't have SSH setup, and it is much faster to transfer stuff with netcat then setup SSH. netcat is just a single executable, and works across all platforms (Windows,Mac OS X, Linux).

On the receiving end running,

nc -l -p 1234 > out.file

will begin listening on port 1234.

On the sending end running,

nc -w 3 [destination] 1234 < out.file

will connect to the receiver and begin sending file.

For faster transfers if both sender and receiver has some basic *nix tools installed, you can compress the file during sending process,

On the receiving end,

nc -l -p 1234 | uncompress -c | tar xvfp -

On the sending end,

tar cfp - /some/dir | compress -c | nc -w 3 [destination] 1234

A much cooler but less useful use of netcat is, it can transfer an image of the whole hard drive over the wire using a command called dd.

On the sender end run,

dd if=/dev/hda3 | gzip -9 | nc -l 3333

On the receiver end,

nc [destination] 3333 | pv -b > hdImage.img.gz

```




Login | Register
VK9 Security

    Home
    Red Team
    Blue-Team
    Labs
    About Us

Transfer files using Netcat

by Vry4n_ | Jan 13, 2021 | Linux Commands | 0 comments

This time we will transfer a file using netcat, we will see examples from machine vk9-sec to lab-kali
Bind connection

1. CLIENT: First, we will create a random file

    echo “Vry4n has been here.” > sample.txt
    cat sample.txt

2. SERVER: we will open a port in the remote machine waiting for a connection to come in, lab-kali machine

    nc -lvp 4455 > sample.txt

3. CLIENT: We will start a connection from our local machine server to the remote machine, in this case vk9-sec to lab-kali machine

    nc -w 3 192.168.0.19 4455 < sample.txt

4. SERVER: At the remote end, we will see the connection, and once, terminates the file shows as downloaded

    ls -l
    cat sample.txt

Reverse connection

1. You could do it the other way, from listening on attacker machine and have the server contact you for the file. Start a listener on Kali (vk9-sec)

    nc -lvp 4455 < 26368.c

2. From the server (victim) reach our kali machine

    nc 192.168.0.13 4455 > exploit.c
    ls
    cat exploit.c

Submit a Comment

You must be logged in to post a comment.

VK9 Security.
