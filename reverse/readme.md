
https://www.puckiestyle.nl/upgrade-shell-to-fully-interactive-tty-shell/

Often when we get a shell by exploiting vulnerabilities, the shell that we getting is a dumb terminal or not and interactive shell. This means that you cannot ctrl+c when accidentally run command such as ping where you need to terminate the process. If you do ctrl+c this not only kills the ping process, but also your shell.

To overcome this, I made a guide here where you can follow to convert your non-interactive shell to fully interactive shell.

Step 1
Get victim shell connection from your exploit either reverse or bind shell.

Step 2
On victim shell, upgrade the shell to tty shell. The most common is you can use python to spawn tty shell by using the pty built-in library. Make sure to spawn /bin/bash not /bin/sh. Read more here to see other methods of upgrading shell to tty shell.

$ python -c 'import pty;pty.spawn("/bin/bash")'
Step 3
Export some vars to the victim shell session. The best is to check your local terminal $TERM vars so that it same on the target terminal session.

echo $TERM
xterm-256color
Export that value on the target shell session.

export TERM=xterm-256color
export SHELL=/bin/bash
Step 4
On your local terminal, check for terminal rows and columns.

stty size
24 103
what you need to take note here is the current terminal rows and columns which is for me rows 24 and columns 103. You might be different.

On the victim shell, fork the shell to background by pressing ctrl+z and you’ll bring back to your local terminal.

^Z
[1]+  Stopped        nc -lvp 9091
Execute the following command to set the terminal to echo the input characters so that it catch by the victim terminal session. Follow with the command fg to bring back the victim shell to foreground.

stty raw -echo;fg
After that, your cursor might be somewhere on the middle of the terminal, type reset to reset the victim terminal session.

stty raw -echo;fg
nc -lvp 9091
                reset
Your victim terminal is now interactive, but it is not done yet. You need to specify the “new” terminal with rows and columns to make it display properly.

stty rows 24 columns 103
Now you’re happy with the fully interactive shell on victim.

If you do not have Python on the box

export TERM=xterm
SHELL=/bin/bash script -q /dev/null

scripts -qc /bin/bash /dev/null
