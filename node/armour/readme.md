

##
#
https://security.padok.fr/en/blog/security-docker-apparmor
#
##


29 May 2023

More and more applications now run in containers that are lightweight and easily scalable. However, since they provide less isolation than virtual machines, they pose new security challenges. AppArmor offer tools to tackle these challenges and interfaces with Docker containers to provide more isolation and security.
SOMMAIRE
AppArmor
What is AppArmor?
Understand AppArmor profiles
AppArmor modes
Interface AppArmor with Docker containers
How to use AppArmor with Docker?
Tutorial
AppArmor in Kubernetes
Conclusion
AppArmor
What is AppArmor?
AppArmor, like SELinux, is a Linux module for hardening kernel security. It implements Mandatory Access Control (MAC) on Linux that traditionally relies on Discretionary Access Control (DAC). In MAC, unlike DAC, users cannot set rights on resources because they are defined according to policies managed by security administrators. AppArmor enforces a policy following a name-based access control to limit the files and Linux capabilities programs can use.

AppArmor is simpler to configure and maintain than SELinux. But it provides fewer features for hardening kernel security. In addition, this module controls access based on paths of program files, contrary to SELinux which uses labels (thus requires a file system that supports them).

AppArmor is shipped with every Debian-based Linux distribution. You can check that this module is loaded with the command:

$ aa-status
apparmor module is loaded.
 

Understand AppArmor profiles
This section gives a quick overview of what a profile is and how it is structured.

With AppArmor, applications can only access resources for which they have explicit permission. It relies on profiles to configure application rights that can grant or deny access to files and capabilities.

Example of profile:

include <tunables/home>

# profile name
/usr/bin/myapp {
    # ---- 1: include -------
    include <file>
    include "my/sub/rule"

    # ---- 2: capability ----
    capability setuid,
    capability setgid,

    # ---- 3: network -------
    network inet dgram,
    network inet stream,

    # ---- 4: rlimit --------
    rlimit stack >= 5K,

    # ---- 5: file ----------
    @{HOME}/myfile rw,
    @{HOME}/app    ix,
}
A profile consists of a name, which is generally a path to the program it applies to, and a set of rules (inside braces). There are 5 main types of rules:

include: this keyword allows to include rules from other files.
capability: grants access to Linux capabilities (here the application can change process UIDs and GIDs).
network: grants access to the network based on the address type and family (here the use of IPv4 TCP and IPv4 UPD is allowed).
rlimit: restricts the resources the process can use (here its stack size is limited to 5KB).
file: sets rights on files (here the application can read and write to ~/myfile and it can execute ~/app which will then inherit this profile).
The syntax and details of available rules are described in the AppArmor man pages.

Once created, a profile can be loaded into the kernel using apparmor_parser.

AppArmor modes
Each profile can be either in enforce mode or complain mode.

In enforce mode, accesses not authorized by the profile rules are blocked and rule violations are reported (with syslog or auditd). To set a profile in enforcement mode (default behavior), use the command aa-enforce.
In complain mode, policy violation attempts are not blocked, they only are reported. This mode is useful to test profiles before enforcing them. To set a profile in complain mode, use the command aa-complain.
There is a third mode, the audit mode, which can be used in addition to the other two. It is similar to complain mode, except all accesses (successes and failures) are logged. To set a profile in audit mode, use the command aa-audit.

All loaded profiles can be listed along with their mode with the following command:

$ aa-status
apparmor module is loaded.
54 profiles are loaded.
50 profiles are in enforce mode.
[...]
4 profiles are in complain mode.
[...]
2 processes have profiles defined.
2 processes are in enforce mode.
[...]
0 processes are in complain mode.
0 processes are unconfined but have a profile defined.
 

Interface AppArmor with Docker containers
How to use AppArmor with Docker?
On systems hardened with AppArmor, Docker can enforce AppArmor profiles on containers. By default, it automatically generates and applies a profile for containers named docker-default that is created in tmpfs and then loaded in the kernel. However, this behavior can be overridden by specifying a custom profile (already loaded in the kernel) with the flag --security-opt in the docker run command:

$ docker run --security-opt apparmor=<profile> <image>
⚠️The default profile is very permissive, if you want to harden the security of your application you most likely want to override it.

Profiles are applied on containers and not on the Docker Engine daemon. If you want to use a profile on the daemon, you can generate and load one by using AppArmor directly. A profile is available in the Docker Engine source repository for the daemon but it is currently not installed with Docker, it has to be loaded manually.

Tutorial
This section is a small tutorial presenting how to create profiles for containers with bane and how to apply them. It will go through the generation of a profile for a Node.js application.


Install AppArmor and bane
Make sure the AppArmor module is installed on your kernel with the command aa-status. If not, see distribution-specific instructions on how to install it:

It is shipped by default on all Debian-based Linux distributions.
Follow the wiki instructions to install it on Archlinux / Manjaro
To install bane, follow the instructions given on the release page of the tool depending on your OS and your computer architecture.


Generate an AppArmor profile for a docker container with bane
bane is a profile generator for docker containers. It simplifies the writing of profiles for docker containers. To start, we will create a very restricted profile preventing writing, network access, and use of any Linux capabilities. Then, to understand the rights our application requires, we will put this profile in audit and complain modes.

bane generates AppArmor profiles from .toml configuration files. Let's create a file named nodejs.toml with the following configuration:

# name of the profile, auto prefix with "docker-"
# so the final name will be "docker-nodejs"
Name = "nodejs"

[Filesystem]
# read only paths for the container
ReadOnlyPaths = [
	"/bin/**",
	"/boot/**",
	"/dev/**",
	"/etc/**",
	"/home/**",
	"/lib/**",
	"/lib64/**",
	"/media/**",
	"/mnt/**",
	"/opt/**",
	"/proc/**",
	"/root/**",
	"/sbin/**",
	"/srv/**",
	"/tmp/**",
	"/sys/**",
	"/usr/**",
]

[Network]
# deny raw sockets
Raw = false
# deny packet sockets which allow to manage raw packets
# at the device driver level
Packet = false
Protocols = [
	"tcp",
]
Now that we have a configuration file, we can generate our AppArmor profile:

$ sudo bane nodejs.toml
The generated profile is located in the file /etc/apparmor.d/containers/docker-nodejs. You should have the following profile:

#include <tunables/global>


profile docker-nodejs flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>

  network inet tcp,

  deny network raw,

  deny network packet,

  file,
  umount,

  deny /bin/** wl,
  deny /boot/** wl,
  deny /dev/** wl,
  deny /etc/** wl,
  deny /home/** wl,
  deny /lib/** wl,
  deny /lib64/** wl,
  deny /media/** wl,
  deny /mnt/** wl,
  deny /opt/** wl,
  deny /proc/** wl,
  deny /root/** wl,
  deny /sbin/** wl,
  deny /srv/** wl,
  deny /tmp/** wl,
  deny /sys/** wl,
  deny /usr/** wl,

  deny @{PROC}/* w,   # deny write for all files directly in /proc (not in a subdir)
  deny @{PROC}/{[^1-9],[^1-9][^0-9],[^1-9s][^0-9y][^0-9s],[^1-9][^0-9][^0-9][^0-9]*}/** w,
  deny @{PROC}/sys/[^k]** w,  # deny /proc/sys except /proc/sys/k* (effectively /proc/sys/kernel)
  deny @{PROC}/sys/kernel/{?,??,[^s][^h][^m]**} w,  # deny everything except shm* in /proc/sys/kernel/
  deny @{PROC}/sysrq-trigger rwklx,
  deny @{PROC}/mem rwklx,
  deny @{PROC}/kmem rwklx,
  deny @{PROC}/kcore rwklx,
  deny mount,
  deny /sys/[^f]*/** wklx,
  deny /sys/f[^s]*/** wklx,
  deny /sys/fs/[^c]*/** wklx,
  deny /sys/fs/c[^g]*/** wklx,
  deny /sys/fs/cg[^r]*/** wklx,
  deny /sys/firmware/efi/efivars/** rwklx,
  deny /sys/kernel/security/** rwklx,
}
Set the docker-nodejs profile to complain + audit modes
For that, edit the content of the file /etc/apparmor.d/containers/docker-nodejs which is the profile bane generated and replace the line:

profile docker-nodejs flags=(attach_disconnected,mediate_deleted)
with:

profile docker-nodejs flags=(audit,complain,attach_disconnected,mediate_deleted)
The flags we added tell AppArmor to load our profile in audit and complain modes.

In order to make the resulting configuration less permissive, we will remove all executing rights. To do that, replace the line:

file,
with:

/** rwmlk,
bane automatically loads profiles in AppArmor, but since we modified the docker-nodejs profile, we need to reload it with the command:

$ sudo apparmor_parser -r /etc/apparmor.d/containers/docker-nodejs
 

Start our container with the docker-nodejs AppArmor profile
Let's run a small Node.js application that runs a web server responding to requests with their content:

profile docker-nodejs flags=(audit,complain,attach_disconnected,mediate_deleted)
To access the server, we can use curl from the command line:

$ curl http://localhost:8000/test
{"code":"success","meta":{"total":0,"count":0},"payload":[]}%
 

Analyze the audit logs to understand which resources our web server needs to access
Now we will analyze logs produced by AppArmor to understand how our profile works. Shut down the docker container we just launch and open the AppArmor log file in /var/log/kern.log (or /var/log/audit/audit.log if you have auditd installed) with:

$ sudo tail -f /var/log/kern.log
Let's start our container again:

$ docker run --rm --security-opt apparmor=docker-nodejs -p 8000:8000 clementde/tutorial-docker-apparmor:v0.1.0
And run a curl command to request the web server:

$ curl http://localhost:8000/test
We can now analyze the logs to understand what our container needs to operate:

apparmor="AUDIT" operation="open" profil="docker-nodejs" name="/etc/ld.so.cache" pid=57949 comm="docker-entrypoi" requested_mask="r" fsuid=0 ouid=0
apparmor="AUDIT" operation="getattr" profil="docker-nodejs" name="/etc/ld.so.cache" pid=57949 comm="docker-entrypoi" requested_mask="r" fsuid=0 ouid=0
apparmor="AUDIT" operation="open" profil="docker-nodejs" name="/lib/x86_64-linux-gnu/libc-2.24.so" pid=57949 comm="docker-entrypoi" requested_mask="r" fsuid=0 ouid=0
apparmor="AUDIT" operation="getattr" profil="docker-nodejs" name="/lib/x86_64-linux-gnu/libc-2.24.so" pid=57949 comm="docker-entrypoi" requested_mask="r" fsuid=0 ouid=0
apparmor="AUDIT" operation="file_mmap" profil="docker-nodejs" name="/lib/x86_64-linux-gnu/libc-2.24.so" pid=57949 comm="docker-entrypoi" requested_mask="r" fsuid=0 ouid=0
apparmor="AUDIT" operation="open" profil="docker-nodejs" name="/usr/local/bin/docker-entrypoint.sh" pid=57949 comm="docker-entrypoi" requested_mask="r" fsuid=0 ouid=0
apparmor="AUDIT" operation="getattr" profil="docker-nodejs" name="/usr/local/bin/node" pid=57983 comm="docker-entrypoi" requested_mask="r" fsuid=0 ouid=0
apparmor="ALLOWED" operation="exec" profil="docker-nodejs" name="/usr/local/bin/node" pid=57949 comm="docker-entrypoi" requested_mask="x" denied_mask="x" fsuid=0 ouid=0 target="docker-nodejs//null-/usr/local/bin/node"
apparmor="ALLOWED" operation="file_mmap" profil="docker-nodejs//null-/usr/local/bin/node" name="/usr/local/bin/node" pid=57949 comm="node" requested_mask="rm" denied_mask="rm" fsuid=0 ouid=0
apparmor="ALLOWED" operation="file_mmap" profil="docker-nodejs//null-/usr/local/bin/node" name="/lib/x86_64-linux-gnu/ld-2.24.so" pid=57949 comm="node" requested_mask="rm" denied_mask="rm" fsuid=0 ouid=0
To understand the logs we got, note that:

All lines with apparmor="AUDIT" tell us which authorized resources our container accessed.
All lines with apparmor="ALLOWED" gives us the resources forbidden by our profile that our container accessed.
So to make our profile work, we need to give execute access to /usr/local/bin/node. To do that, we can add the following line to our profile in /etc/apparmor.d/containers/docker-nodejs:

/usr/local/bin/node ix,
We can now reload our profile with:

$ sudo apparmor_parser -r /etc/apparmor.d/containers/docker-nodejs
Let's give it a new try to see if everything works as expected. When we restart the container and make a curl request, new ALLOWED operations are potentially logged:

apparmor="ALLOWED" operation="accept" profil="docker-nodejs" pid=59178 comm="node" lport=8000 family="inet6" sock_type="stream" protocol=6 requested_mask="accept" denied_mask="accept"
apparmor="ALLOWED" operation="file_perm" profil="docker-nodejs" pid=59178 comm="node" laddr=::ffff:172.17.0.2 lport=8000 faddr=::ffff:172.17.0.1 fport=43368 family="inet6" sock_type="stream" protocol=6 requested_mask="receive" denied_mask="receive"
apparmor="ALLOWED" operation="file_perm" profil="docker-nodejs" pid=59178 comm="node" laddr=::ffff:172.17.0.2 lport=8000 faddr=::ffff:172.17.0.1 fport=43368 family="inet6" sock_type="stream" protocol=6 requested_mask="receive" denied_mask="receive"
apparmor="ALLOWED" operation="recvmsg" profil="docker-nodejs" pid=59178 comm="node" laddr=::ffff:172.17.0.2 lport=8000 faddr=::ffff:172.17.0.1 fport=43368 family="inet6" sock_type="stream" protocol=6 requested_mask="receive" denied_mask="receive"
apparmor="ALLOWED" operation="file_perm" profil="docker-nodejs" pid=59178 comm="node" laddr=::ffff:172.17.0.2 lport=8000 faddr=::ffff:172.17.0.1 fport=43368 family="inet6" sock_type="stream" protocol=6 requested_mask="send" denied_mask="send"
apparmor="ALLOWED" operation="file_perm" profil="docker-nodejs" pid=59178 comm="node" laddr=::ffff:172.17.0.2 lport=8000 faddr=::ffff:172.17.0.1 fport=43368 family="inet6" sock_type="stream" protocol=6 requested_mask="send" denied_mask="send"
Our container tries to communicate with IPv6, so we need to allow it in our profile by adding the line:

network inet6 tcp,
 

Set the profile to enforce mode
No more ALLOW operations are logged after reloading the profile and restarting our container. We can put it in enforce mode by removing the flags we added previously. Replace the line:

profile docker-nodejs flags=(audit,complain,attach_disconnected,mediate_deleted)
with:

profile docker-nodejs flags=(attach_disconnected,mediate_deleted)
When we reload the profile and restart the docker container, everything works as expected!

We can now check that our profile is well enforced. For that, we can open a shell inside our container and try to run commands:

$ docker exec -it $(docker ps -q) sh
# ls
sh: 1: ls: Permission denied
# whoami
sh: 2: whoami: Permission denied
Note that the profile is enforced only inside the container, which is why we can still open a shell with docker exec.

AppArmor in Kubernetes
Kubernetes allows you to load AppArmor profiles on containers. You can specify a profile to run a Pod container with, by adding an annotation to the Pod's metadata:

container.apparmor.security.beta.kubernetes.io/<container_name>: <profile_ref>
However, for the profile to be applied, the Pod must run on a node that supports AppArmor and that already has the right profile loaded in the kernel. To set up your profile on your nodes, you can either use a DaemonSet, a node initialization script, or SSH on your nodes to add it manually.

The documentation provides a great article on how to use AppArmor along with Kubernetes.


Conclusion
With AppArmor, you can strongly confine your Docker applications to greatly limit the impact of a potential compromise. Writing profiles may seem tedious, but with a little practice, you can easily write simple profiles that secure your containers and kubernetes applications.
