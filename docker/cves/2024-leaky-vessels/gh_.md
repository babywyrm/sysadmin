several container breakouts due to internally leaked fds

##
#
https://github.com/opencontainers/runc/security/advisories/GHSA-xr7r-f8xq-vfvv
#
##

High	cyphar published GHSA-xr7r-f8xq-vfvv on Jan 31
Package
 github.com/opencontainers/runc (
Go
)
Affected versions
>=v1.0.0-rc93,<=1.1.11
Patched versions
1.1.12
Description
Impact
In runc 1.1.11 and earlier, due to an internal file descriptor leak, an attacker could cause a newly-spawned container process (from runc exec) to have a working directory in the host filesystem namespace, allowing for a container escape by giving access to the host filesystem ("attack 2"). The same attack could be used by a malicious image to allow a container process to gain access to the host filesystem through runc run ("attack 1"). Variants of attacks 1 and 2 could be also be used to overwrite semi-arbitrary host binaries, allowing for complete container escapes ("attack 3a" and "attack 3b").

Strictly speaking, while attack 3a is the most severe from a CVSS perspective, attacks 2 and 3b are arguably more dangerous in practice because they allow for a breakout from inside a container as opposed to requiring a user execute a malicious image. The reason attacks 1 and 3a are scored higher is because being able to socially engineer users is treated as a given for UI:R vectors, despite attacks 2 and 3b requiring far more minimal user interaction (just reasonable runc exec operations on a container the attacker has access to). In any case, all four attacks can lead to full control of the host system.

Attack 1: process.cwd "mis-configuration"
In runc 1.1.11 and earlier, several file descriptors were inadvertently leaked internally within runc into runc init, including a handle to the host's /sys/fs/cgroup (this leak was added in v1.0.0-rc93). If the container was configured to have process.cwd set to /proc/self/fd/7/ (the actual fd can change depending on file opening order in runc), the resulting pid1 process will have a working directory in the host mount namespace and thus the spawned process can access the entire host filesystem. This alone is not an exploit against runc, however a malicious image could make any innocuous-looking non-/ path a symlink to /proc/self/fd/7/ and thus trick a user into starting a container whose binary has access to the host filesystem.

Furthermore, prior to runc 1.1.12, runc also did not verify that the final working directory was inside the container's mount namespace after calling chdir(2) (as we have already joined the container namespace, it was incorrectly assumed there would be no way to chdir outside the container after pivot_root(2)).

The CVSS score for this attack is CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N (8.2, high severity).

Note that this attack requires a privileged user to be tricked into running a malicious container image. It should be noted that when using higher-level runtimes (such as Docker or Kubernetes), this exploit can be considered critical as it can be done remotely by anyone with the rights to start a container image (and can be exploited from within Dockerfiles using ONBUILD in the case of Docker).

Attack 2: runc exec container breakout
(This is a modification of attack 1, constructed to allow for a process inside a container to break out.)

The same fd leak and lack of verification of the working directory in attack 1 also apply to runc exec. If a malicious process inside the container knows that some administrative process will call runc exec with the --cwd argument and a given path, in most cases they can replace that path with a symlink to /proc/self/fd/7/. Once the container process has executed the container binary, PR_SET_DUMPABLE protections no longer apply and the attacker can open /proc/$exec_pid/cwd to get access to the host filesystem.

runc exec defaults to a cwd of / (which cannot be replaced with a symlink), so this attack depends on the attacker getting a user (or some administrative process) to use --cwd and figuring out what path the target working directory is. Note that if the target working directory is a parent of the program binary being executed, the attacker might be unable to replace the path with a symlink (the execve will fail in most cases, unless the host filesystem layout specifically matches the container layout in specific ways and the attacker knows which binary the runc exec is executing).

The CVSS score for this attack is CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:C/C:H/I:H/A:N (7.2, high severity).

Attacks 3a and 3b: process.args host binary overwrite attack
(These are modifications of attacks 1 and 2, constructed to overwrite a host binary by using execve to bring a magic-link reference into the container.)

Attacks 1 and 2 can be adapted to overwrite a host binary by using a path like /proc/self/fd/7/../../../bin/bash as the process.args binary argument, causing a host binary to be executed by a container process. The /proc/$pid/exe handle can then be used to overwrite the host binary, as seen in CVE-2019-5736 (note that the same #! trick can be used to avoid detection as an attacker). As the overwritten binary could be something like /bin/bash, as soon as a privileged user executes the target binary on the host, the attacker can pivot to gain full access to the host.

For the purposes of CVSS scoring:

Attack 3a is attack 1 but adapted to overwrite a host binary, where a malicious image is set up to execute /proc/self/fd/7/../../../bin/bash and run a shell script that overwrites /proc/self/exe, overwriting the host copy of /bin/bash. The CVSS score for this attack is CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H (8.6, high severity).
Attack 3b is attack 2 but adapted to overwrite a host binary, where the malicious container process overwrites all of the possible runc exec target binaries inside the container (such as /bin/bash) such that a host target binary is executed and then the container process opens /proc/$pid/exe to get access to the host binary and overwrite it. The CVSS score for this attack is CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H (8.2, high severity).
As mentioned in attack 1, while 3b is scored lower it is more dangerous in practice as it doesn't require a user to run a malicious image.

Patches
runc 1.1.12 has been released, and includes patches for this issue. Note that there are four separate fixes applied:

Checking that the working directory is actually inside the container by checking whether os.Getwd returns ENOENT (Linux provides a way of detecting if cwd is outside the current namespace root). This explicitly blocks runc from executing a container process when inside a non-container path and thus eliminates attacks 1 and 2 even in the case of fd leaks.
Close all internal runc file descriptors in the final stage of runc init, right before execve. This ensures that internal file descriptors cannot be used as an argument to execve and thus eliminates attacks 3a and 3b, even in the case of fd leaks. This requires hooking into some Go runtime internals to make sure we don't close critical Go internal file descriptors.
Fixing the specific fd leaks that made these bug exploitable (mark /sys/fs/cgroup as O_CLOEXEC and backport a fix for some *os.File leaks).
In order to protect against future runc init file descriptor leaks, mark all non-stdio files as O_CLOEXEC before executing runc init.
Other Runtimes
We have discovered that several other container runtimes are either potentially vulnerable to similar attacks, or do not have sufficient protection against attacks of this nature. We recommend other container runtime authors look at our patches and make sure they at least add a getcwd() != ENOENT check as well as consider whether close_range(3, UINT_MAX, CLOSE_RANGE_CLOEXEC) before executing their equivalent of runc init is appropriate.

crun 1.12 does not leak any useful file descriptors into the runc init-equivalent process (so this attack is not exploitable as far as we can tell), but no care is taken to make sure all non-stdio files are O_CLOEXEC and there is no check after chdir(2) to ensure the working directory is inside the container. If a file descriptor happened to be leaked in the future, this could be exploitable. In addition, any file descriptors passed to crun are not closed until the container process is executed, meaning that easily-overlooked programming errors by users of crun can lead to these attacks becoming exploitable.
youki 0.3.1 does not leak any useful file descriptors into the runc init-equivalent process (so this attack is not exploitable as far as we can tell) however this appears to be pure luck. youki does leak a directory file descriptor from the host mount namespace, but it just so happens that the directory is the rootfs of the container (which then gets pivot_root'd into and so ends up as a in-root path thanks to chroot_fs_refs). In addition, no care is taken to make sure all non-stdio files are O_CLOEXEC and there is no check after chdir(2) to ensure the working directory is inside the container. If a file descriptor happened to be leaked in the future, this could be exploitable. In addition, any file descriptors passed to youki are not closed until the container process is executed, meaning that easily-overlooked programming errors by users of youki can lead to these attacks becoming exploitable.
LXC 5.0.3 does not appear to leak any useful file descriptors, and they have comments noting the importance of not leaking file descriptors in lxc-attach. However, they don't seem to have any proactive protection against file descriptor leaks at the point of chdir such as using close_range(...) (they do have RAII-like __do_fclose closers but those don't necessarily stop all leaks in this context) nor do they have any check after chdir(2) to ensure the working directory is inside the container. Unfortunately it seems they cannot use CLOSE_RANGE_CLOEXEC because they don't need to re-exec themselves.
Workarounds
For attacks 1 and 2, only permit containers (and runc exec) to use a process.cwd of /. It is not possible for / to be replaced with a symlink (the path is resolved from within the container's mount namespace, and you cannot change the root of a mount namespace or an fs root to a symlink).

For attacks 1 and 3a, only permit users to run trusted images.

For attack 3b, there is no practical workaround other than never using runc exec because any binary you try to execute with runc exec could end up being a malicious binary target.

See Also
https://www.cve.org/CVERecord?id=CVE-2024-21626
https://github.com/opencontainers/runc/releases/tag/v1.1.12
The runc 1.1.12 merge commit a9833ff, which contains the following security patches:
506552a
0994249
fbe3eed
284ba30
b6633f4
683ad2f
e9665f4
Credits
Thanks to Rory McNamara from Snyk for discovering and disclosing the original vulnerability (attack 1) to Docker, @lifubang from acmcoder for discovering how to adapt the attack to overwrite host binaries (attack 3a), and Aleksa Sarai from SUSE for discovering how to adapt the attacks to work as container breakouts using runc exec (attacks 2 and 3b).
