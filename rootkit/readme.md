# Rkhunter (Rootkit Hunter) Installation and Monitoring for Linux.md

###### Last Updated 2020-04-13 by Kevin Roth

Detection of rootkit and other intrusions for Linux with rkhunter.  Installation and nightly email reports.

### Install rkhunter
```
$ sudo yum install rkhunter
```

### First Run
```
$ sudo rkhunter --update
$ sudo rkhunter --check
```

### Edit config if needed
```
$ sudo cp /etc/rkhunter.conf /etc/rkhunter.conf.local
$ sudo nano /etc/rkhunter.conf.local
```

Items to check:

```
ALLOW_SSH_ROOT_USER=no

ALLOW_SSH_PROT_V1=0

PKGMGR=RPM

SCRIPTWHITELIST=/usr/bin/whatis
SCRIPTWHITELIST=/usr/bin/ldd
SCRIPTWHITELIST=/usr/bin/groups
SCRIPTWHITELIST=/usr/bin/GET
SCRIPTWHITELIST=/sbin/ifup
SCRIPTWHITELIST=/sbin/ifdown
SCRIPTWHITELIST=/usr/bin/locate
SCRIPTWHITELIST=/usr/bin/su

ALLOWHIDDENFILE=/usr/sbin/.sshd.hmac
ALLOWHIDDENFILE="/usr/share/man/man1/..1.gz"
ALLOWHIDDENFILE=/lib*/.libcrypto.so.*.hmac
ALLOWHIDDENFILE=/lib*/.libssl.so.*.hmac
ALLOWHIDDENFILE=/usr/bin/.fipscheck.hmac
ALLOWHIDDENFILE=/usr/bin/.ssh.hmac
ALLOWHIDDENFILE=/usr/bin/.ssh-keygen.hmac
ALLOWHIDDENFILE=/usr/bin/.ssh-keyscan.hmac
ALLOWHIDDENFILE=/usr/bin/.ssh-add.hmac
ALLOWHIDDENFILE=/usr/bin/.ssh-agent.hmac
ALLOWHIDDENFILE=/usr/lib*/.libfipscheck.so.*.hmac
ALLOWHIDDENFILE=/usr/lib*/.libgcrypt.so.*.hmac
ALLOWHIDDENFILE=/usr/lib*/hmaccalc/sha1hmac.hmac
ALLOWHIDDENFILE=/usr/lib*/hmaccalc/sha256hmac.hmac
ALLOWHIDDENFILE=/usr/lib*/hmaccalc/sha384hmac.hmac
ALLOWHIDDENFILE=/usr/lib*/hmaccalc/sha512hmac.hmac
ALLOWHIDDENFILE=/usr/sbin/.sshd.hmac
ALLOWHIDDENFILE=/dev/.mdadm.map
ALLOWHIDDENFILE=/usr/share/man/man5/.k5login.5.gz
ALLOWHIDDENFILE=/usr/share/man/man5/.k5identity.5.gz
ALLOWHIDDENFILE=/usr/sbin/.ipsec.hmac
# etckeeper
ALLOWHIDDENFILE=/etc/.etckeeper
ALLOWHIDDENFILE=/etc/.gitignore
ALLOWHIDDENFILE=/etc/.bzrignore
# systemd
ALLOWHIDDENFILE=/etc/.updated
```

Also, check the following in your SSH configuration (/etc/ssh/sshd_config)

```
Protocol 2

PermitRootLogin no
```

### After First Run

Baseline your configuration by running:

```
$ sudo rkhunter --propupd
```

### Monitoring
Create a file called rkhunter.sh under /etc/cron.daily/, which then scans your file system every day and sends email notifications to your email address. Create following file with the help of your favourite editor.

```
$ sudo nano /etc/cron.daily/rkhunter.sh
```
##
## Add the following lines of code to it and replace “your@email.com” with your email address.
##



```
#!/bin/sh

OUTPUT=`/usr/bin/rkhunter --update --cronjob --report-warnings-only --nocolors --skip-keypress`

if [ "$OUTPUT" != "" ]
then
    echo -e "$OUTPUT" > /tmp/rkhunter_warnings.txt
    echo "Please inspect this machine, because it may be infected." | /bin/mail -s "[rkhunter] Warnings found for $(hostname)" -a /tmp/rkhunter_warnings.txt your@email.com
fi
```

Set execute permission on the file.

```
$ sudo chmod 755 /etc/cron.daily/rkhunter.sh
```

Deactivate the default daily task

```
$ sudo chmod -x /etc/cron.daily/rkhunter
```

Test that the script runs and an email is delivered to the specified address with a readable attachment.

```
$ sudo /etc/cron.daily/rkhunter.sh
```

####################
##
##
