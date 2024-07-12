# Distributions: RHEL_6+7 CentOS_6+7
##########################################################################
##
## https://gist.github.com/richardsonlima/2bc8dee9a029402d87f4457fed5f37a9
##
##

# Standard rsync command
##########################################################################

- Useful when live cloning servers.
rsync -avX --one-file-system --hard-links --numeric-ids -e 'ssh -c arcfour' /source dest:/nation
(remember to run --delete for the last sync)

# Find out the WAN IP address
##########################################################################
curl http://checkip.dyndns.com:8245

# Iptables 
##########################################################################

- Redirect port
iptables -t nat -A PREROUTING -p tcp --dport 587 -j REDIRECT --to-ports 25
- Redirect incoming port to another host
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A PREROUTING -p tcp -m tcp --dport 587 -j DNAT --to-destination 1.2.3.4:587
iptables -t nat -A POSTROUTING -j MASQUERADE

- Redirect outgoing connections to another host
iptables -t nat -I OUTPUT --dst 1.2.3.4 -p tcp --dport 25 -j DNAT --to-destination 4.5.6.7:25

# 
##########################################################################
- Find parent PID
ps -o user,pid,ppid,command -ax

- Server stuck in TIME_WAIT all the time?
net.ipv4.tcp_fin_timeout=15
net.ipv4.tcp_tw_reuse=1
net.ipv4.tcp_tw_recycle=1

* Generate heat
for cpu in {1..8}; do ( while true; do true; done ) & done

# MySQL stuff
##########################################################################

* MySQL database sizes (CPU intensive, prefer starting off your MySQL installations with innodb_file_per_table)
SELECT @schema := table_schema, SUM(data_length+index_length)/1024/1024 AS total_mb FROM information_schema.tables GROUP BY table_schema ORDER BY 2;

* MySQL table sizes:
SHOW TABLE STATUS order by 'Data_length';

* MySQL which tables using InnoDB:
SELECT table_schema, table_name FROM INFORMATION_SCHEMA.TABLES WHERE engine = 'innodb';

MySQL kill thead:
SHOW PROCESSLIST;
KILL 27;

* Reset MySQL root password (from redhat docs)
service mysqld stop
/usr/bin/mysqld_safe --skip-grant-tables &
mysql -u root mysql
mysql> UPDATE user SET Password=PASSWORD('new_password') WHERE user='root';
mysql> FLUSH PRIVILEGES;
mysql> exit;
mysqladmin -u root -pnew_password shutdown
service mysqld start
Scan for new LUNs without rebooting

* Instead of doing it manually...

echo "1" > /sys/class/fc_host/host/issue_lip

* For every hostN:
echo "- - -"  >  /sys/class/fc_host/hostX/device/scsi_host/hostX/scan #Fibre
echo "- - -" > /sys/class/scsi_host/hostX/scan

...just yum install sg3_utils and run rescan-scsi-bus.sh.

# RPM tips
##########################################################################

    Which RPM a file belongs to: rpm -qf /etc/rsyslog.conf
    View RPM contents: rpm -q --filesbypkg -p fiklename.rpm
    Unzip an RPM: rpm2cpio bash-123.rpm | cpio -idmv
    List all files an installed package: rpm -ql rsyslog
    List all files in an RPM: rpm -qlp someapp.rpm
    Note that you can't guess the effect an RPM can have on a system just based on it's files; you need to also find out the scripts it'd execute during the installation: rpm -qp --scripts someapp.rpm or as a trigger: rpm -qp --triggers someapp.rpm. If you don't like the look of the script, but you can still install an RPM bypassing the scripts with rpm --noscripts -ivh someapps.rpm
    List all config file: rpm -qc rsyslog
    List dependencies of an installed package: rpm -qR bash
    List dependencies of an RPM: rpm -qRp someapp.rpm
    Show info of an installed package: rpm -qi screen
    Show info of an RPM: rpm -qip someapp.rpm
    Verify GPG key (assuming you did an rpm --import): rpm -K someapp.rpm
    Check if a file has been tampered: rpm -Vf /usr/bin/bash or rpm -V bash
    Check all files (very slow, prone to false positives): rpm -Va

# yum-security (RHEL only, not CentOS)
##########################################################################

    Summary of the number of security and bugfix updates: yum updateinfo
    List of advisories with the packages affected: yum updateinfo list
    Details of a Red Hat advisory: yum updateinfo RHSA-2014:1293
    List all the updates needed to resolve a CVE: yum updateinfo list --cve=CVE-2013-0775
    List of security related updates: yum --security list updates
    Huge ass list of all security update details: yum info-sec
    Update security related packages only: yum --security update
    Note that doing a yum --security update would update an affected package to the latest one available in the repositories. As an example, say you have deo-1.3 installed, and there is a security vulnerability fixed in deo-1.4, and a bug fixed in deo-1.5, and a feature added in deo-1.6. A yum --security update deo would push your deo from 1.3 to 1.6. If, instead, you want to update to just the amount required to fix a bug, use update-minimal, which would update deo to 1.4 only:
    yum update-minimal --security
    Update packages that fix a bugzilla ID: yum --bz 1011219 update
    Update packages related to a Red Hat advisory: yum update --advisory=RHSA-2014:0159
    Update only critical packages (not documented in the man page or red hat docs): yum update --security --sec-severity=Critical
    Update only important packages (not documented in the man page or red hat docs): yum update --security --sec-severity=Important

# Which processes are responsible for the load:
##########################################################################

Very few people I've met, even some those working in Red Hat support, realize how the load is calculated, with many thinking it's only based on the CPU usage, and some understanding that disk access is involved too somehow but aren't sure how the numbers work. Simplified, the load is just the average number of processes that are in a running (=CPU intensive), or uninterrupted sleep (=Waiting for I/O) state. So if you run this command several times:
ps -eo stat,pid,ppid,size,pcpu,user,args | grep '^D\|^R'
you can see that the number of processes excluding the ps process represents the load on the system, with 'R' meaning it's using up the CPU, and 'D' probably meaning it's using your disk, though in cases like a stuck NFS or GFS2 mountpoint, just mean that it's stuck in an uninterruptable sleep waiting for I/O.
Hard soft-reboot a server having IO issues

It's rare, and I don't know why it happened to me this often, but there are situations where you happen to have a terminal open on a very old test server, and it's RAID controller or I/O completely freezes up which could be fixed by a reboot, but you can't type it reboot or shutdown because that would need to read the disk to find those binaries. So to save you the trouble of accessing the IPMI, you could use this, which doesn't need to read the disk, to reboot:

echo 1 > /proc/sys/kernel/sysrq
echo b > /proc/sysrq-trigger

* Hang/freeze a system
This is extremely useful, or even crucial, in cluster testing to simulate OS or system freezes
# echo c > /proc/sysrq-trigger # Freeze system

# UNIX timestamps to normal time & back
##########################################################################

date -d @1338636201
date --date="Wed Aug 22 07:51:04 UTC 2007" +%s

# Encrypted block device
##########################################################################

cryptsetup --verbose --verify-passphrase luksFormat /dev/vg_rhel6/LogEncrypted
cryptsetup luksOpen /dev/vg_rhel6/LogEncrypted encrypted_stuff
mkfs.ext4 -m 0 /dev/mapper/encrypted_stuff
/etc/crypttab

        encrypted_stuff /dev/vg_rhel6/LogEncrypted none

/etc/fstab:

        /dev/mapper/encrypted_stuff /mnt/encrypted      ext4    defaults        0 0

cryptsetup luksClose encrypted_stuff

#Rebuild initrd:
##########################################################################

RHEL 5: cd /boot; mv initrd-2.6.18-238.5.1.el5.img initrd-2.6.18-238.5.1.el5.img.orig ; mkinitrd -f /boot/initrd-$(uname -r).img $(uname -r)
RHEL 6: dracut -f /boot/initramfs-$(uname -r).img $(uname -r)
Find the original MD5sum of a binary that was prelinked:

prelink -y --md5 /usr/bin/cifsiostat
Speed up ext3/ext4 filesystem at the expense of safety:

* FS Mount options: defaults,noatime,data=writeback,barrier=0,nobh
New pc with old kernel boot options

linux pci=nommconf noapic acpi=off

Fix scrolling in GNU screen

Edit /etc/screenrc and append:
termcapinfo xterm* ti@:te@

* GNU screen mirror

screen -S hello #user 1
screen -x hello #user 2

* VI backspace for old servers

:set backspace=indent,eol,start

* Random password
tr -dc A-Za-z0-9 < /dev/urandom | head -c 16 ; echo

# Network clone hard drive
##########################################################################

* Assuming both machines are booted off a live disc
nc -l -p 9000 | dd of=/dev/sdx # destination PC
dd if=/dev/sda | nc 192.168.1.2 9000 # source server

* Though you might want to involve gzip or better yet, lzop if you have it.

* Delete huge number of files on an old server
find /path -type f -print0 | xargs -0 rm

* Color BASH prompt
export PS1="[\u@\[\e[1;31m\]\h\[\e[0m\] \W]$ "
Red: 31m, Green: 32m, Blue: 34m
BASH floating point calcuations

* Use it like calculate "239422 / 1024"
`function calculate() { echo -n `echo scale=2\; "$1" | bc` }`

* BASH write log function

Use it like write_log "Some text here"

LOGFILE=/some/where.log
function write_log {
    echo `date +"[%d/%b/%Y:%k:%M:%S]"` $1 >> $LOG
}

# BASH function to display coloured INFO or ERROR messages
##########################################################################

function printInfo() {
        if [ -t 1 ] ; then
                echo -e "\e[1m\e[32mINFO: \e[0m${1}"
        else
                echo "INFO: $1"
        fi
}
# (same thing but with 31m for red)

# SSH client config to avoid timeouts
##########################################################################

/etc/ssh/ssh_config

ServerAliveInterval 10
ServerAliveCountMax 3

# TCP dump for SMTP ASCII chat
##########################################################################

tcpdump -n -N -A -s 1024 -i eth0 port 25 > out

#md RAID disk replacement
##########################################################################

Assume /dev/sdb failed:

    cat /proc/mdstat
    md0 : active raid1 sda1[0] sdb1[2](F)   <---- F means failed
       12345 blocks [2/1] [U_]  <--- _ means inactive. 
    mdadm --manage /dev/md0 --fail /dev/sdb1
    mdadm --manage /dev/md0 --remove /dev/sdb1
    # poweroff and plug the replacement drive. Make sure its sdb, otherwise switch the commands

    # For DOS partitions:
    sfdisk -d /dev/sda | sfdisk /dev/sdb
    If it comlains or if the sizes are different, do it manually

    # For GPT partitions:
    yum install gdisk
    sgdisk --backup=/root/backups/sda.sgdisk /dev/sda # working drive
    sgdisk --load-backup=/root/backups/sda.sgdisk /dev/sdx # new drive
    sgdisk -G /dev/sdx # new drive

    mdadm --manage /dev/md0 --add /dev/sdb1
    cat /proc/mdstat # wait until sync finishes
    mv /boot/grub/device.map /boot/grub/device.map.old
    grub --device-map=/boot/grub/device.map # boot MBR copy
       find /grub/stage1
       root (hd1,0)
       setup (hd1)
       quit

# MD RAID expand volume
##########################################################################

Here's how I expanded a RAID5/RAID6 volume:

# Backup your data. Expanding RAID volumes stress the existing drives for a day or more

# Add the drives physically 

# Do a check of the existing drives/RAID just in case:
echo check > /sys/block/md0/md/sync_action
cat /sys/block/md0/md/mismatch_cnt # should be 0

# Check the current situation, make sure all existing drives are active:
cat /proc/mdstat
mdadm --detail /dev/mdX

# You can use and even write to the array as it's rebuilding
# but if you can afford days of downtime on this RAID, you
# can unmount the filesystem to be extra safe

# Optionally partition your drives if you did so in your previous drives

# Speed up rebuilding by increasing the stripe cache (uses some RAM)
echo 32768 > /sys/block/md0/md/stripe_cache_size

# Add new drives or partitions. You can add multiple drives to md RAIDs at a time.
mdadm --add /dev/mdX /dev/sdX1
mdadm --add /dev/mdX /dev/sdY1

# You need to disable write-intent bitmap, if /proc/mdstat mentions 'bitmap:'
mdadm --grow /dev/mdX --bitmap=none

# You need to know the number of devices you want to end up with (the active devices in mdadm --detail /dev/md0
# plus the number of new drives you are adding.
# Keep the optional --backup file somewhere NOT in the RAID array in question (eg. on a USB or /boot)
# This backup file will only be a few megabytes for a few seconds and is used in case the power fails during a critical stage.
mdadm --grow --raid-devices=7 --backup-file=/root/mdadm-resize-backup /dev/md0

# Watch the expansion and estimated time to finish with:
cat /proc/mdstat

# Don't forget to add the write-intent bitmap back on:
mdadm --grow /dev/mdX --bitmap=internal

# If MD is settled, it's time to expand the filesystem. If you use LVM, do a :
pvresize /dev/mdX
lvm vgs
lvextend --size +1.23T /dev/yourVG/yourLV # or --extents 100%FREE

# If you use volume encryption, open the volume with luksOpen and run:
cryptsetup --verbose resize your_cryptname

# Then finally resize the filesystem with
# resize2fs -p /dev/...
# or
# mount ... && xfs_growfs /dev/...

MD RAID unwanted spare

If you have an /proc/mdstat output similar to:

md2 : inactive sda4[0](S)
      1897733208 blocks super 1.2

after a power failure, and it's not letting you mount the drive or even re-add the missing drive, try deactivating and re-activating the RAID:
mdadm --stop /dev/md2
mdadm -A /dev/md2
Grep match IP address

'[[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}'

# Tune NFS 3 mounts
##########################################################################

mount -o rsize=32768,wsize=32768,nfsvers=3,tcp,async server:/mnt/stuff /mnt/nfs
Speed up SSH transfers

ssh -c arcfour ...
scp -c arcfour ...
SSH masters

This is useful, in that it allows you to log in to a server without a password if you've authenticated once in an existing session.
Add this to your ~/.ssh/config:

Host *
ControlMaster auto
ControlPath ~/.ssh/master-%r@%h:%p

Note that if your main session closes, all other sessions would disconnect.
HP servers: find the RAID status

hpacucli (or hpssacli)
controller all show config
Check an HP server's temperature and fan status

hpasmcli
show server
show temp
show powersupply
HP RAID add spare

hpacucli (or hpssacli)
controller all show config
controller slot=1 array all add spares=1I:1:9
HP expand RAID5 with new disk (needs battery backed cache

hpacucli (or hpssacli)
controller all show config detail (check if there's a battery/flash module)
controller slot=1 array A add drives=1I:1:9
controller all show config (until the transforming % is gone)
controller slot=1 ld 1 modify size=max
You will need to reboot if it's RHEL5. RHEL6 may have a /sys rescan option. Then fdisk, pvcreate, vgextend, lvresize & resize2fs.
HP create a new logical drive & expand LVM

hpacucli (or hpssacli)
controller all show config
controller slot=0 create type=ld drives=2I:1:6,2I:1:7 raid=1
fdisk /dev/cciss/c0d1
...

# HP RAID controller SMART info
##########################################################################

RHEL5: smartctl -a -d cciss,0 /dev/cciss/c0d0
RHEL6: smartctl -a -d cciss,1 /dev/sg0
Check IBM/Adaptec RAID controller info

/usr/StorMan/arcconf GETCONFIG 1 AL
/usr/StorMan/arcconf getlogs 1 EVENT tabular

# Create an IBM/Adaptec RAID logical drive
##########################################################################

Read the docs; it's quite confusing. Get the ID of the new drives with:
/usr/StorMan/arcconf GETCONFIG 1 PD
The unallocated ones will have a "State" of "Ready". then see the "Reported Channel,Device" line, and ignore the numbers in the brackets.
Then create the logitcal drive, the syntax is:
arcconf CREATE <Controller#> LOGICALDRIVE [Options] <Size> <RAID#> <Channel# ID#> [Channel# ID#]
so, for example, to create a logical drive with RAID 1:
arcconf CREATE 1 LOGICALDRIVE NAME NewDrives WCACHE WBB MAX 1 0 4 0 5
with the drives being underlined.
(The RAID level can be set to simple_volume, which will just be one drive. That can later be convered to a RAID1 drive once you get a matching pair)
Expanding an old IBM/Adaptec RAID 5 volume

Similar to the above steps.
/usr/StorMan/arcconf GETCONFIG 1 AL

where "1" is your controller number, probably 1. In the display, the unallocated physical drives will have a "State" of "Ready". note down the the "Reported Channel,Device" line for each drive, and ignore the numbers in the brackets.
Y
ou need to first initialize the drive, if you don't, you can get an error about there being not enough space on the disk when trying to expand. Double and triple check the drive pair number (Reported channel + device), and initialize the drive:
/usr/StorMan/arcconf TASK START 1 DEVICE 0 9 initialize
After that's done, get the "Logical device number" from the "GETCONFIG" output. Then type the expansion command; the syntax is:
/usr/StorMan/arcconf MODIFY <Controller#> FROM <LogicalDrive#> TO <Size> <RAID#> [old CHANNEL# DRIVE#] [old CHANNEL# DRIVE#] [old CHANNEL# DRIVE#] [new CHANNEL# DRIVE#]
<Size> should be the size in megabytes, or just use MAX.
As you can see, the command isn't about putting just the drive you want to add, you have to include the old drives too. If you miss one, the drive will be deleted from the array causing all sorts of trouble. This is an example run in one of my expansions, don't copy it word for word:
#/usr/StorMan/arcconf MODIFY 1 FROM 0 TO MAX 5 0 0 0 1 0 3 0 2
Check your MegaRAID status with MegaCli

    Logical drive status: MegaCli64 -LDInfo -Lall -aALL
    Physical drives: MegaCli64 -PDList -aALL
    Battery status: MegaCli64 -AdpBbuCmd -aAll
    Controller info: MegaCli64 -AdpAllInfo -aALL

# Adding a MegaRAID array
##########################################################################

Add the drives physically, and look at MegaCli64 -PDList -aALL. Pay close attention to the "Firmware state". "Online, Spin Up" are used drives and should not be touched. Keep track of the Enclosure Device ID (just before the drive details) and the Slot number of drives that have the firmware status of "Unconfigured (good)". Also make sure you know the adapter (hopefully you will only have one adapter which would simplify things, find out with MegaCli64 -PDList -aALL | grep Adap).

The drive syntax is enclosureID:slot. So to create an array with two drives in RAID1 on adapter 0, type:
MegaCli64 -CfgLdAdd -r1'[252:5,252:6]' -a0
For RAID 5, just replace r1 with r5.
Quickly benchmark write performance

dd of=bigfile if=/dev/zero bs=1M count=4000 oflag=direct,sync conv=fsync,sync
Cache might still be involved.
Quickly benchmark single core encryption performance

openssl speed
rsync over ssh chroot

It's easy to set up an SFTP chroot, but not obvious what to do when you need rsync to work too. Here's a quick way to set it up for a secure transfer (assuming you have a recent version of SSHd that supports ChrootDirectory):
Add this to /etc/ssh/sshd_config :

Match User rsyncuser
   X11Forwarding no
   AllowTcpForwarding no
   ChrootDirectory /home/rsyncuser

Then set up the user and chroot:

USER=rsyncuser
adduser $USER
mkdir -p /home/$USER/{usr/bin,lib64,bin,share}
chown root:root /home/$USER
chown $USER:$USER /home/$USER/share
cp -av /bin/bash /home/$USER/bin
cp -av /usr/bin/rsync /home/$USER/usr/bin

Then either just copy/hardlink everything in /lib64 to /home/rsyncuser/lib64, or selectively copy (with cp -L) libraries that are actually used by bin/bash and usr/bin/rsync by using the output of ldd.

Test it by SSHing into the box as $USER, and making sure bash works with no commands except rsync. You should then be able rsync as usual to /share:
rsync -av ./ rsyncuser@yourserver.com:/share
Make iptraf ignore SSH traffic

iptraf is really useful when trying to figure out what's taking up the bandwidth, but it wastes a lot of bandwidth trying to show the byte usage of the SSH session (which causes it to update, and use more SSH traffic to show up in iptraf).
Ignoring SSH is quite tricky unless you know how; the key is that by default applying an empty filter will make it show nothing; so you need to have an explicit rule to show all traffic in the end :
- Go to Filters -> IP -> Make sure there aren't any filters already in Edit filter.
- Define a new filter-> Ignore SSH.
- Press A to add to list. Make the IP address & widcard mask 0.0.0.0 on both destination & source. Source port is 0 to 0, destination port is 22 (or 2251) to 0. Then make sure you put a 'Y' in All IP and TCP. Then put 'E' in Include/Exclude. Enter to accept.
- Press A to add to list again. Make everything 0.0.0.0 or 'Y', and make sure it's the default 'I' for include.
- You then need to apply the filter.
If you ever edit the filter, it won't apply automatically. You have to detch and apply the filter again.
SOCKS proxy with SSH

You may already know of ssh -D 33333 server1 , which creates a dynamic SOCKS proxy on your local machine which you can use in firefox to browse the network from server1's perspective.
However, if you need more than just a browser, like say ssh or some app, you can use tsocks, which is in EPEL. Create a /etc/tsocks.conf in your machine with:

server = 127.0.0.1
server_port = 33333

Then just use: tsocks yourApp . Eg. tsocks ssh 192.168.113.1
Standard IMAPSYNC command

(ext3/4) Because of how much imapsync gobbles up inodes, unless you have a huge (>600GB) /tmp, you may first want to create a separate imapsync folder, either in an existing large (>600GB) mount point, or in a new temporary logical volume formatted to maximize inodes with mkfs.ext4 -m 0 -i 4096 /dev/yourdevice.

You don't need everyone's password if your mail server supports imap admin accounts (like Zimbra, Cyrus, Dovecot, etc). Use something like this script:

#!/bin/bash

USER="$1"
TMPDIR="/mnt/mailstore/imapsync"

SOURCE_IP="192.168.0.6"
SOURCE_PORT="143"
SOURCE_ADMIN_USER="admin"
SOURCE_ADMIN_PASSWORD="yourpass"

DESTINATION_IP="127.0.0.1"
DESTINATION_PORT="143"
DESTINATION_ADMIN_USER="admin"
DESTINATION_ADMIN_PASSWORD="yourpass"

if [[ "$USER" != *@* ]]; then
        echo "Usage: imapsync_user.sh username@domain"
        exit 2
fi

if [ ! -d "$TMPDIR" ]; then
        echo "Error: $TMPDIR does not exist"
        exit 2
fi

/root/apps/imapsync-master/imapsync --nolog --tmpdir $TMPDIR --usecache --useuid --nofoldersizes --nofoldersizesatend  --subscribe --syncinternaldates\
        --host1 $SOURCE_IP --port1 $SOURCE_PORT --user1 $USER --authuser1 $SOURCE_ADMIN_USER --password1 "$SOURCE_ADMIN_PASSWORD" \
        --host2 $DESTINATION_IP --port2 $DESTINATION_PORT --user2 $USER --authuser2 $DESTINATION_ADMIN_USER --password2 $DESTINATION_ADMIN_PASSWORD --delete2 --expunge2 | grep "^-"

If you are imapsyncing from Google, you need everyone's password, and can use:

#!/bin/bash

USER="$1"
PASSWORD="$2"
TMPDIR="/opt/imapsync"

SOURCE_IP="imap.googlemail.com"
SOURCE_PORT="993"

DESTINATION_IP="127.0.0.1"
DESTINATION_PORT="143"
DESTINATION_ADMIN_USER="admin"
DESTINATION_ADMIN_PASSWORD="xxx"

if [[ "$USER" != *@* || -z "$PASSWORD" ]]; then
        echo "Usage: imapsync_user.sh username@domain password"
        exit 2
fi
if [ ! -d "$TMPDIR" ]; then
        echo "Error: $TMPDIR does not exist"
        exit 2
fi

# Gmail has a 2500 MB per day limit, so download 2GB at most, and run this script every day

/root/apps/imapsync-master/imapsync --nolog --tmpdir $TMPDIR --usecache --useuid --nofoldersizes --nofoldersizesatend  --subscribe --syncinternaldates \
        --host1 $SOURCE_IP --port1 $SOURCE_PORT --user1 $USER --password1 "$PASSWORD" --ssl1 \
        --host2 $DESTINATION_IP --port2 $DESTINATION_PORT --user2 $USER --authuser2 $DESTINATION_ADMIN_USER --password2 $DESTINATION_ADMIN_PASSWORD \
        --skipcrossduplicates --folderlast "[Gmail]/All Mail" --noexpungeaftereach --exitwhenover 2000000000 \
        --delete2 --expunge2

You can then have a script to go through a user list to run the above script like:

#!/bin/bash

trap "exit" INT

INPUT="priority-list"

TOTAL=$(wc -l $INPUT | cut -d ' ' -f 1)
CURRENT=1

while read user; do
        echo "Currently in $CURRENT of $TOTAL, working on $user..."
        /root/scripts/migration/imapsync_user.sh $user
        let CURRENT=CURRENT+1
done < $INPUT

If you're running zimbra, be sure to
telnet IMAP

x login rizvir thepass
x LIST "" "*"
x SELECT INBOX
x IDLE
done
x logout

telnet SMTP with AUTH

You need the base64 version of the username and password; you can convert it using:

perl -MMIME::Base64 -e 'print encode_base64("username\@domain.com");'
perl -MMIME::Base64 -e 'print encode_base64("thepass");'

Be sure to escape special perl characters like @ and $.

EHLO test.com
AUTH LOGIN
<enter the username in base64>
<enter the password in base64>
MAIL FROM: rizvir@rizvir.com
RCPT TO: some@where.com
DATA
From: rizvir@rizvir.com
To: some@where.com
Subject: Test

Just a test
.

telnet SMTP with TLS

openssl s_client -ign_eof -starttls smtp -crlf -connect mail.thedomain.com:25
Then use the standard SMTP chat in the previous point.
telnet POP3/IMAP with SSL

openssl s_client -connect mail.thedomain.com:995 -crlf
```
Zimbra stuff

Search & export email with a certain criteria:
zmmailbox -z -m theuser@domain.com -t 0 getRestURL '//?fmt=tgz&query=tocc:"ma-friend@gmail.com" after:"01/03/13"' > mails.tar.gz
Date format is in mm/dd/yy. -t 0 is to disable any timeouts

To import:
zmmailbox -z -m theuser@domain.com -t 0 postRestURL '//?fmt=tgz&resolve=skip' mails.tar.gz

The REST resolve variable can be skip (ignore duplcates), modify (presumably changes existing items on conflicts), replace (presumbly delete and re-add things that conflicts), and finally the most dangerous one, reset, which deletes the entire folder (or the whole mailbox if you are restoring anything in the root).

Move messages older than X date to a (created) folder called oldmail (it's limited to 1000 search results, so repeat this in a loop until all are done):
zmmailbox -z -m theuser@domain.com search -t message -l 1000 "in:/Inbox (before:04/15/09)" | awk '{ print "mm " $2 " /oldmail"}' | tail -n +5 | head -n -1 > /tmp/zmmailbox-move
zmmailbox -z -m theuser@domain.com < /tmp/zmmailbox-move
