##
#
https://www.baeldung.com/linux/auditd-monitor-file-access
#
##

The Baeldung LogoLinux Sublogo
Start Here
About ▼
Guides ▼
Topics ▼
Monitoring Linux File Access With auditd

Last updated: June 12, 2022
Written by: Hiks Gerganov
Reviewed by: Michal Aibin

    AdministrationFiles 

1. Introduction

Linux systems often have multiple users. Auditing is a vital part of such multi-user environments. In particular, as the atomic parts of filesystems, files are usually the monitored units.

In this tutorial, we’ll explore how to perform file access monitoring under Linux. First, we go through a refresher of file access permissions. Next, we jump to the general topic of auditing. After that, we delve into auditing under Linux. Specifically, we discuss installing, configuring, and monitoring file access with a broadly-used auditing component.

We tested the code in this tutorial on Debian 11 (Bullseye) with GNU Bash 5.1.4. It should work in most POSIX-compliant environments.
2. Find the Actor

Finding out who did what in any system is non-trivial.

For example, let’s assume a simple case: a file goes missing in a multi-user Linux environment. Normally, an administrator can check who owned or had access to that file via ls:

$ ls -l /dir/file
-rwxr--r-- 1 user1 user1 666 May 6 16:56 file

Reading the line, we can decipher the ownership and permissions.

In particular, user user1 is the sole owner, who also has read (r) and write (w) access to the regular (first –) file. Additionally, the user’s private group, also called user1, and the global permissions are read-only.

In practice, deletion requires read, write, and execute permissions on the containing directory:

$ ls -l /dir
drwxrwxrwx 1 root root 4096 May 6 16:25 .
drwxr-xr-x 1 root root 4096 May 6 06:25 ..

Note that we added the -a flag to get the special . directory of /dir, which tells us its attributes.

Now, we know that user1 could have been the one who deleted the /dir/file. In the future, how do we make sure?
3. Auditing

The general idea of auditing is to help keep user actions in check. It provides a way to map activity to certain accounts, enabling administrators to trace:

    what action was performed
    which user acted
    which object or objects were involved
    the time at which an event happened

Combined with strong security concepts such as encryption-protected authentication and authorization, auditing can ensure almost complete accountability.

In this way, a trail of records exists, whereby events can be reconstructed. In fact, the mechanism is more or less identical in terms of data to the logs used to track databases such as mysql:

$ cat /var/lib/mysql/audit.log
```
[...]
<AUDIT_RECORD>
  <TIMESTAMP>2022-10-05T16:06:56 UTC</TIMESTAMP>
  <RECORD_ID>6_2022-10-05T16:03:33</RECORD_ID>
  <NAME>Query</NAME>
  <CONNECTION_ID>5</CONNECTION_ID>
  <STATUS>0</STATUS>
  <STATUS_CODE>0</STATUS_CODE>
  <USER>root[root] @ localhost [127.0.0.1]</USER>
  <OS_LOGIN/>
  <HOST>localhost</HOST>
  <IP>127.0.0.1</IP>
  <COMMAND_CLASS>drop_table</COMMAND_CLASS>
  <SQLTEXT>DROP TABLE IF EXISTS t</SQLTEXT>
 </AUDIT_RECORD>
 [...]
```

Of course, operating system auditing doesn’t directly allow recovery like some databases do – we need the data and means for that. In that way, audit data sits somewhere between a backup and simple history logs:
```
$ cat /home/user1/.mysql_history
create database baeldung
create user user1@localhost IDENTIFIED BY 'password'
grant select,insert,update,delete,create,drop,index,alter,create temporary tables,lock tables on baeldung.* to user1@localhost
flush privileges
exit
```
However, armed with such knowledge, we are still in a much better position than resorting to manual forensics. Let’s see how this works on the operating system level.
4. Linux Auditing with auditd

Under Linux, we can perform and automate auditing in many ways. In very simple cases, we can employ inotifywait and inotifywatch. However, the comprehensive auditd package can be a better choice.
4.1. Installation and Main Configuration

Since it’s not a part of all Linux distributions by default, we might need to install auditd on our own:

$ apt-get install auditd
[...]

Next, we establish the default configuration of the daemon in /etc/audit/auditd.conf:
```
$ cat /etc/audit/auditd.conf
#
# This file controls the configuration of the audit daemon
#

local_events = yes
write_logs = yes
log_file = /var/log/audit/audit.log
log_group = adm
log_format = ENRICHED
flush = INCREMENTAL_ASYNC
freq = 50
max_log_file = 8
num_logs = 5
priority_boost = 4
name_format = NONE
##name = mydomain
... long output omited
transport = TCP
krb5_principal = auditd
##krb5_key_file = /etc/audit/audit.key
distribute_network = no
q_depth = 400
overflow_action = SYSLOG
max_restarts = 10
plugin_dir = /etc/audit/plugins.d
```
Most of the critical settings in the file are self-explanatory and have sane defaults. For the rest, we can use a configuration reference.

Crucially, we should note down the path to the log_file: /var/log/audit/audit.log. Of course, write_logs has to be yes for that to matter.

For auditd to suit our needs, we also may need to set some rules, based on which auditing will be done.
4.2. Rule Structure

Basically, rules are triggers that govern the recording of audit events. Similar to firewalls, when an event matches a rule, it’s logged.

Rules are stored in the /etc/audit/audit.rules file:

$ cat /etc/audit/audit.rules
## This file is automatically generated from /etc/audit/rules.d
-D
-b 8192
-f 1
--backlog_wait_time 60000

However, this file is only the consolidated version of all .rules files in the /etc/audit/rules.d/ directory:

$ ls /etc/audit/rules.d/
audit.rules

Thus, to change or add rules properly, we should first modify or create files there.
4.3. Understanding Rules

Let’s first check the defaults:

$ cat /etc/audit/rules.d/audit.rules
## First rule - delete all
-D

## Increase the buffers to survive stress events.
## Make this bigger for busy systems
-b 8192

## This determine how long to wait in burst of events
--backlog_wait_time 60000

## Set failure mode to syslog
-f 1

For the most part, the options are explained in the comments. It’s worth noting that the buffer size is in entries, not in a multiple of bytes.

Following are all the options for a rule file row:

    # <comment>
    -w <path-to-file> -p <permissions> -k <keyname>
    -a <action>,<list> -S <system-call> -F <field=value> -k <keyname>
    –<flag> <value>

Note that the package is very strict about rule syntax. For instance, comments on the same line as rules are not tolerated. Also, repetition of rules is risky. Therefore, to avoid issues, the syntax should be followed strictly. With this in mind, we can continue.
4.4. Setting Rules

Now, let’s create a very simple rule file /etc/audit/rules.d/baeldung.rules:

## Enable ruleset
-e 1
## Limit the rate to 120 audit entries per second
-r 120

## Monitor /baeldung for rwxa events
-w /baeldung -p rwxa -k toplevel_baeldung
## Monitor /file for read events
-w /file     -p r    -k root_file
## Monitor for name change syscall
-S sethostname -a always,exit -k hostname_change

Here, -w /baeldung -p rwxa -k toplevel_baeldung monitors the /baeldung directory for any events involving a read (r), write (w), execute (x), or attribute change (a).

On the other hand, -a always,exit -S sethostname -k hostname_change monitors for a system call (-S with sethostname). The always action is needed to log an event, while exit decides when and how that happens.

Essentially, all rows of the rule files are passed to the userspace auditing control component auditctl. Thus, we can interpret any rules via the tool’s manual.
4.5. Starting the Daemon

Once done with the preliminary steps, we can load the configuration via augenrules:
```
$ augenrules --check
/sbin/augenrules: Rules have changed and should be updated
$ augenrules --load
No rules
enabled 1
failure 2
[...]
$ augenrules --check
/sbin/augenrules: No change
```
Here, the –check switch tests for any new rule additions, while –load regenerates all rules from /etc/audit/rules.d/.

Importantly, augenrules –check might show a false negative, claiming No change when there are issues with the syntax. We can diagnose any problems here by going through the rules and ensuring they’re correct. Further, we can confirm what’s in effect:
```
$ auditctl -l
-w /baeldung -p rwxa -k toplevel_baeldung
-w /file -p r -k root_file
-a always,exit -S sethostname -F key=hostname_change

The -l switch to auditctl lists all currently active rules.
```
Finally, we can run the daemon with auditd:

$ auditd

Usually, we can look for problems during launch with journalctl -u auditd.
4.6. Reading Logs

Let’s now check the log using the path we saw in the configuration above:

$ cat /var/log/audit/audit.log
type=DAEMON_START msg=audit(1644796660.200:666): op=start ver=3.0.7
  format=enriched kernel=4.9.0-8-amd64 auid=4294967295 pid=1666000 =0 ses=4294967295
  subj=unconfined  res=success AUID="unset" UID="root"
[...]
type=SERVICE_START msg=audit(1644796660.216:669): pid=1 uid=0 auid=4294967295
  ses=4294967295 subj==unconfined msg='unit=auditd comm="systemd"
  exe="/usr/lib/systemd/systemd" hostname=? addr=? terminal=? res=success'
  UID="root" AUID="unset"

Evidently, the service has started. Also, from the type=DAEMON_START line, we can see that it has PID 1666000.

Moreover, we can extract a timestamp from the msg section (1644796660.200), also part of other events. After it, separated by a colon, is the event identification number (666 and 669).

Now, we can browse the log manually or use the provided ausearch for filtered searches:

$ ausearch --event 666
----
time->Tue Feb 15 20:11:06 2022
type=DAEMON_START msg=audit(1644948666.200:666): op=start ver=3.0.7
  format=enriched kernel=4.9.0-8-amd64 auid=4294967295 pid=1666000 uid=0
  ses=4294967295 subj=unconfined  res=success AUID="unset" UID="root"

Notably, a big advantage to ausearch is the –interpret (-i) flag, which decodes data within messages since parts of them are hex-encoded:

$ ausearch --event 666 --interpret
----
time->Tue Feb 15 20:11:06 2022
type=DAEMON_START msg=audit(02/15/2022 20:11:06.200:666): op=start ver=3.0.7
  format=enriched kernel=4.9.0-8-amd64 auid=unset pid=1666000 uid=0 ses=unset
  subj=unconfined  res=success

Comparing the output, we see that the value of the auid parameter in the record was translated from a string of hex numbers to unset. Also, the date stamp is converted to a human-readable format.

In both examples above, we used an event number directly, but there are also many other criteria, e.g.:

    -m (–message) to query by message type
    -c (–comm) to query by command name
    -ui (–uid) to query by user ID

Additionally, we can format the output as raw, default, interpret, csv, and text. This is possible via the –format flag.
5. Generating Events and Checking Records with auditd

Finally, we can see auditd in action with some simple examples. Let’s explore reading and writing first and then move to deletion.
5.1. Reading and Writing

First, let’s write to /file:

$ echo Input. > /file

Next, we check the logs for any action with our file with the –file flag:

$ ausearch --file /file
<no matches>

Here, we see no matches because, as per our rule, we’re only auditing read events. With this in mind, let’s perform a simple read via cat:

$ cat /file
Input.
$ ausearch --file /file --interpret
----
type=PROCTITLE msg=audit(02/15/2022 20:12:22.240:11666) : proctitle=cat /file
type=PATH msg=audit(02/15/2022 20:12:22.240:11666) : item=0 name=/file inode=22
  dev=08:11 mode=file,644 ouid=root ogid=root rdev=00:00 nametype=NORMAL
  cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 cap_frootid=0
type=CWD msg=audit(02/15/2022 20:12:22.240:11666) : cwd=/
type=SYSCALL msg=audit(02/15/2022 20:12:22.240:11666) : arch=x86_64
  syscall=openat success=yes exit=3 a0=AT_FDCWD a1=0x7fffd21697d9 a2=O_RDONLY
  a3=0x0 items=1 ppid=1732318 pid=1733641 auid=user1 uid=user1 gid=user1
  euid=user1 suid=user1 fsuid=user1 egid=user1 sgid=user1 fsgid=user1
  tty=pts1 ses=3873 comm=cat exe=/usr/bin/cat subj==unconfined key=root_file

All of these lines also called records, are part of the same event, 11666. In the type=PATH line of that event, we can see details about the file itself, like inode number, device, mode, and others.

Moreover, the line starting with type=SYSCALL is our main interest, also identified by the key=root_file value of the rule. In fact, it contains the full username (uid=user1). When not interpreting the results, users are recorded by their numbers. In that case, we can get the username via id:

$ id -nu 1000
user1

The type=SYSCALL record also gives us the command (comm=cat, exe=/usr/bin/cat) used to access the file.
5.2. Deletion

Coming back to the previous example of file deletion, we can detect who deleted a file from a subdirectory of /baeldung. First, let’s create one with a single file in it:

$ mkdir --parents /baeldung/x/
$ echo Input. > /baeldung/x/file.ext

Next, we check the logs:
```
$ ausearch --file /baeldung --interpret
type=PROCTITLE msg=audit(02/15/2022 20:30:40.504:12666) : proctitle=mkdir --parents /baeldung/x/
type=PATH msg=audit(02/15/2022 20:30:40.504:12666) : item=4 name=(null) inode=1966583
  dev=08:11 mode=dir,755 ouid=root ogid=root rdev=00:00 nametype=CREATE cap_fp=none
  cap_fi=none cap_fe=0 cap_fver=0 cap_frootid=0
type=PATH msg=audit(02/15/2022 20:30:40.504:12666) : item=3 name=(null) inode=1966582
  dev=08:11 mode=dir,755 ouid=root ogid=root rdev=00:00 nametype=PARENT cap_fp=none
  cap_fi=none cap_fe=0 cap_fver=0 cap_frootid=0
type=PATH msg=audit(02/15/2022 20:30:40.504:12666) : item=2 name=(null) nametype=CREATE
  cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 cap_frootid=0
type=PATH msg=audit(02/15/2022 20:30:40.504:12666) : item=1 name=(null) inode=1966582
  dev=08:11 mode=dir,755 ouid=root ogid=root rdev=00:00 nametype=PARENT cap_fp=none
  cap_fi=none cap_fe=0 cap_fver=0 cap_frootid=0
type=PATH msg=audit(02/15/2022 20:30:40.504:12666) : item=0 name=/baeldung inode=1966582
  dev=08:11 mode=dir,755 ouid=root ogid=root rdev=00:00 nametype=PARENT cap_fp=none
  cap_fi=none cap_fe=0 cap_fver=0 cap_frootid=0
type=CWD msg=audit(02/15/2022 20:30:40.504:12666) : cwd=/baeldung
type=SYSCALL msg=audit(02/15/2022 20:30:40.504:12666) : arch=x86_64 syscall=mkdir
  success=yes exit=0 a0=0x7ffcf6eb17d8 a1=0777 a2=0x0 a3=0xfffffffffffffb8d items=5
  ppid=1732318 pid=1734036 auid=noot uid=root gid=root euid=root suid=root fsuid=root
  egid=root sgid=root fsgid=root tty=pts1 ses=3873 comm=mkdir exe=/usr/bin/mkdir
  subj==unconfined key=toplevel_baeldung
[...]
```
There are events for the creation and population of both the directory /baeldung/x and the file /baeldung/x/file.ext, along with the user responsible (root). Now, let’s change the whole directory’s permissions to allow any user to delete files:

$ ls -la /baeldung
total 12
drwxr-xr-x  3 root root 4096 Feb 18 00:06 .
drwxr-xr-x 29 root root 4096 Feb 18 00:01 ..
drwxr-xr-x  2 root root 4096 Feb 15 00:06 x
$ chmod --recursive 777 /baeldung
$ ls -la /baeldung/.
total 12
drwxrwxrwx  3 root root 4096 Feb 15 00:06 .
drwxr-xr-x 29 root root 4096 Feb 15 00:01 ..
drwxrwxrwx  2 root root 4096 Feb 15 00:06 x

Even these changes have associated records, as we can see via the –comm flag :

$ ausearch --file /baeldung --comm chmod --interpret
----
type=PROCTITLE msg=audit(02/15/2022 20:56:56.248:12696) : proctitle=chmod --recursive 777 /baeldung
type=PATH msg=audit(02/15/2022 20:56:56.248:12696) : item=0 name=/baeldung inode=1966582
  dev=08:11 mode=dir,755 ouid=root ogid=root rdev=00:00 nametype=NORMAL cap_fp=none
  cap_fi=none cap_fe=0 cap_fver=0 cap_frootid=0
type=CWD msg=audit(02/15/2022 20:56:56.248:12696) : cwd=/
type=SYSCALL msg=audit(02/15/2022 20:56:56.248:12696) : arch=x86_64 syscall=fchmodat
  success=yes exit=0 a0=AT_FDCWD a1=0x55b15f13e500 a2=0777 a3=0xfffffffffffffd2c
  items=1 ppid=1732318 pid=1734049 auid=noot uid=root gid=root euid=root suid=root
  fsuid=root egid=root sgid=root fsgid=root tty=pts1 ses=3873 comm=chmod exe=/usr/bin/chmod
  subj==unconfined key=toplevel_baeldung
----
type=PROCTITLE msg=audit(02/15/2022 20:56:56.248:12697) : proctitle=chmod --recursive 777 /baeldung
type=PATH msg=audit(02/15/2022 20:56:56.248:12697) : item=0 name=/baeldung inode=1966582
  dev=08:11 mode=dir,777 ouid=root ogid=root rdev=00:00 nametype=NORMAL cap_fp=none
  cap_fi=none cap_fe=0 cap_fver=0 cap_frootid=0
type=CWD msg=audit(02/15/2022 20:56:56.248:12697) : cwd=/
type=SYSCALL msg=audit(02/15/2022 20:56:56.248:12697) : arch=x86_64 syscall=openat
  success=yes exit=3 a0=AT_FDCWD a1=0x55b15f13e500
  a2=O_RDONLY|O_NOCTTY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC a3=0x0 items=1 ppid=1732318
  pid=1734049 auid=noot uid=root gid=root euid=root suid=root fsuid=root egid=root
  sgid=root fsgid=root tty=pts1 ses=3873 comm=chmod exe=/usr/bin/chmod subj==unconfined
  key=toplevel_baeldung

Finally, let’s delete file.ext as user1:

$ whoami
user1
$ rm --force /baeldung/x/file.ext

The event record is there with all data we need:

$ ausearch --file /baeldung/x/file.ext --comm rm --interpret
----
type=PROCTITLE msg=audit(02/15/2022 23:59:59.159:16660) : proctitle=rm --force /baeldung/x/file.ext
type=PATH msg=audit(02/15/2022 23:59:59.159:16660) : item=1 name=/baeldung/x/file.ext
  inode=1966584 dev=08:11 mode=file,777 ouid=user1 ogid=user1 rdev=00:00 nametype=DELETE
  cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 cap_frootid=0
type=PATH msg=audit(02/15/2022 23:59:59.159:16660) : item=0 name=/baeldung/x/
  inode=1966583 dev=08:11 mode=dir,777 ouid=user1 ogid=user1 rdev=00:00
  nametype=PARENT cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 cap_frootid=0
type=CWD msg=audit(02/15/2022 23:59:59.159:16660) : cwd=/
type=SYSCALL msg=audit(02/15/2022 23:59:59.159:16660) : arch=x86_64 syscall=unlinkat
  success=yes exit=0 a0=AT_FDCWD a1=0x56227e23e4d0 a2=0x0 a3=0xfffffffffffffbca items=2
  ppid=1732318 pid=1734073 auid=noot uid=user1 gid=user1 euid=user1 suid=user1 fsuid=user1
 egid=user1 sgid=user1 fsgid=user1 tty=pts1 ses=3873 comm=rm exe=/usr/bin/rm
  subj==unconfined key=toplevel_baeldung

Note that the audit entry also has data for the directory since we changed its contents.

Now, we have proof of all events which led to the removal of any data within a given directory. Let’s make it indisputable.
6. Security and Consolidation

Protecting any kind of log is important, but audit information is sensitive by its nature. Because of this, let’s ensure only root has access to the audit log:

$ ls -la /var/log/audit/audit.log
-rw-r----- 1 root root 66600 May 16 12:15 /var/log/audit/audit.log

Importantly, this may become even more critical when storing information from multiple nodes. The scenario can come up since the auditd package enables us to configure a server as a consolidation node for events from other machines.

Of course, tightening security on a central node in every aspect is vital. This includes areas like SSH access and firewalling.
7. Summary

In this article, we looked at the comprehensive auditd package in Linux. Specifically, we explored installing, configuring, and using the daemon to monitor file access.

In conclusion, with auditd, Linux provides an all-around option for auditing, monitoring, and collecting information on file and operating system events.


    Terms of Service Privacy Policy Company Info Contact 

