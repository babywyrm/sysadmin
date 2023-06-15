Linux Privilege Escalation – Exploiting Capabilities
June 13, 2021 | by Stefano Lanaro | Leave a comment
Introduction
Capabilities in Linux are special attributes that can be allocated to processes, binaries, services and users and they can allow them specific privileges that are normally reserved for root-level actions, such as being able to intercept network traffic or mount/unmount file systems. If misconfigured, these could allow an attacker to elevate their privileges to root.

Capabilities List
Below is a handy list of capabilities that are available on Linux, and a brief description:

Capability	Description
CAP_AUDIT_CONTROL	Allow to enable/disable kernel auditing
CAP_AUDIT_WRITE	Helps to write records to kernel auditing log
CAP_BLOCK_SUSPEND	This feature can block system suspends
CAP_CHOWN	Allow user to make arbitrary change to files UIDs and GIDs (full filesystem access)
CAP_DAC_OVERRIDE	This helps to bypass file read, write and execute permission checks (full filesystem access)
CAP_DAC_READ_SEARCH	This only bypass file and directory read/execute permission checks
CAP_FOWNER	This enables to bypass permission checks on operations that normally require the filesystem UID of the process to match the UID of the file
CAP_KILL	Allow the sending of signals to processes belonging to others
CAP_SETGID	Allow changing of the UID (set UID of root in you process)
CAP_SETPCAP	Helps to transferring and removal of current set to any PID
CAP_IPC_LOCK	This helps to lock memory
CAP_MAC_ADMIN	Allow MAC configuration or state changes
CAP_NET_RAW	Use RAW and PACKET sockets (sniff traffic)
CAP_NET_BIND_SERVICE	SERVICE Bind a socket to internet domain privileged ports
CAP_SYS_CHROOT	Ability to call chroot()
CAP_SYS_ADMIN	Mount/Unmount filesystems
CAP_SYS_PTRACE	Debug processes (inject shellcodes)
CAP_SYS_MODULE	Insert kernel modules
CAP_FSETID	Do not clear set-user-ID and set-group-ID mode bits when a file is modified
CAP_LINUX_IMMUTABLE	Set the FS_APPEND_FL and FS_IMMUTABLE_FL inode flags (see ioctl_iflags(2))
CAP_NET_BROADCAST	Make socket broadcasts, and listen to multicasts
CAP_NET_ADMIN	Perform various network-related operations such as interface configuration, administration of IP firewall, modify routing tables etc.
CAP_IPC_OWNER	Bypass permission checks for operations on System V IPC objects
CAP_SYS_RAWIO	Perform I/O port operations (iopl(2) and ioperm(2))
CAP_SYS_PACCT	Enables or disables process accounting
CAP_SYS_BOOT	call reboots the system, or enables/disables the reboot keystroke
CAP_SYS_NICE	Lower the process nice value (nice(2), setpriority(2)) and change the nice value for arbitrary processes; set scheduling policies, CPU affinity, I/O scheduling and priority for processes, allow to migrate processes to arbitrary nodes
CAP_SYS_RESOURCE	Use reserved space on ext2 filesystems, make ioctl(2) calls, override resource disk quote limits, maximum number of consoles and maximum number of keymaps, /proc/sys/fs/pipe-size-max limit, /proc/sys/fs/mqueue/queues_max, /proc/sys/fs/mqueue/msg_max, and /proc/sys/fs/mqueue/msgsize_max limits allow more than 64hz interrupts from the real-time clock, and more
CAP_SYS_TIME	Set system clock (settimeofday(2), stime(2), adjtimex(2)); set real-time (hardware) clock
CAP_SYS_TTY_CONFIG	employ various privileged ioctl(2) operations on virtual terminals
CAP_MKNOD	Create special files using mknod(2)
CAP_LEASE	Establish leases on arbitrary files (see fcntl(2))
CAP_SETFCAP	Set arbitrary capabilities on a file
CAP_MAC_OVERRIDE	Override Mandatory Access Control (MAC). Implemented for the Smack LSM.
CAP_SYSLOG	Perform privileged syslog(2) operations
CAP_WAKE_ALARM	Trigger something that will wake up the system (set CLOCK_REALTIME_ALARM and CLOCK_BOOTTIME_ALARM timers)
CAP_AUDIT_READ	Allow reading the audit log via a multicast netlink socket
CAP_PERFMON	Employ various performance-monitoring mechanisms
CAP_BPF	Employ privileged BPF operations; see bpf(2) and bpf-helpers(7)
CAP_CHECKPOINT_RESTORE	Update /proc/sys/kernel/ns_last_pid (see pid_namespaces(7)), employ the set_tid feature of clone3(2) and read the contents of the symbolic links for other processes
The following capabilities are particularly dangerous and should be investigated further if found enabled on a system:

CAP_CHOWN
CAP_DAC_OVERRIDE
CAP_DAC_READ_SEARCH
CAP_SETUID
CAP_SETGID
CAP_NET_RAW
CAP_SYS_ADMIN
CAP_SYS_PTRACE
CAP_SYS_MODULE
CAP_FORMER
CAP_SETFCAP
Identifying Misconfigured Vulnerabilities
The following command can be used to identify binaries that have capabilities allocated to them:

getcap -r / 2>/dev/null

Whereas the following command can be used to check whether a running process has capabilities assigned:

cat /proc/[process ID]/status | grep Cap
Capabilities assigned to users are stored in the /etc/security/capability.conf configuration file:


Additionally, systemd offers directives for configuring capabilities on service units, through the “AmbientCapabilities” variable:


The easiest way to identify misconfigured capabilities is to use enumeration scripts such as LinPEAS:


Once the capabilities have been assigned, a great resource to find out if they can be vulnerable (if assigned to variables) is through GTFOBins, as for each applicable binary it has a handy “Capabilities” section which shows how certain capabilities can be exploited to elevate privileges. This HackTricks page is also great. Alternatively, googling for the capability and the object it is assigned to normally does the trick.

Exploiting Misconfigured Vulnerabilities
Based on the output from the commands used above, the /usr/bin/python3.8 binary has the cap_setuid capabilities assigned, which allows to set the effective user ID of a process when running its binary i.e. executing binaries as root.

Aaccording to GTFOBins, it can be easily exploited with the following command, which simply executes /bin/sh with the SUID bit set:

/usr/bin/python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'

Executing the command while logged in as a non-root user:


As shown above, this has allowed to escalate privileges to root, many different capabilities can be exploited to read/write to files, intercept network traffic, mount/unmount file systems and more, which can potentially lead to escalation of privileges.

Conclusion
Capabilities can certainly be a very powerful tool for system administrators to be able to do their job and work around some of the restrictions of the Linux operating system, however, they should be carefully set as if misconfigured they could lead to a full system compromise.
