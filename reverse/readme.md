

```Reverse Engineering with Rizin
Last modified: 2023-07-30

Malware
Reverse Engineering
Rizin is a reverse engineering framework forked from Radare2.

Using Cutter
Cutter is a GUI tool for reverse engineering powered by Rizin.
It can also have a decompiler, so it’s recommended to use it first.

cutter <file>
Copied!
To use the Ghidra decompiler, install the package.

sudo apt install rizin-plugin-ghidra
# or
sudo apt install rz-ghidra
Copied!

Start Debugging
rizin ./example

# Debug mode
rizin -d ./example
# Write mode
rizin -w ./example
Copied!

Analyze
Analyze the program after starting the debugger.

# Analyze all calls
> aaa

# Analyze function
> af 
# List all functions
> afl
> afl | grep main
# Show address of current function
> afo
Copied!

Print Usage
# Print usage
> ?

# Add "?" suffix to print the usage of the specific command.
> i?
> p?
Copied!

Visual Mode
You can enter visual mode for more intuitive operation.

> v

# Visual Debugger Mode
> Vpp
Copied!
Below is a list of basic commands:

# Toggle print mode
p
# or
P

# Step
s

# Toggle cursor mode
c

# Exit
q

# Enable regular rizin commands
:
Copied!

Debug
# Step
> ds
# Step 3 times
> ds 3
# Step back
> dsb

# Setup a breakpoint
> db @ 0x8048920
# Remove a breakpoint
> db @ -0x8048920
# Remove all breakpoints
> db-*
# List all breakpoints
> dbl

# Continue to execute the program until we hit the breakpoint
> dc
# Continue until syscall
> dcs

# Read all registers values
> dr
> dr=
# Read given register value
> dr eip
> dr rip
# Set a register value
> dr eax=24
# Show register references
> drr
Copied!

Seek
# Print current address
> s

# Seek to given function
> s main
> s sym.main

# Seek to given address
> s 0x1360
> s 0x0x00001360

# Seek to register address
> s esp
> s esp+0x40
> s rsp
> s rsp+0x40

# Seek 8 positions
> sd 8

# Show the seek history
> sh
# Undoing
> shu
# Redoing
> shr
Copied!

Print
# Disassemble at current address
> pd
# Disassemble 10 instructions at current address
> pd 10
# Disassemble all possible opcodes at current address
> pda
# Disassemble all possible opcodes 10 instructions at current address
> pda 10
# Disassemble at the given function
> pd @ main
> pd 20 @ main

# Disassemble a function at current address
> pdf
# Disassemble at given address
> pdf @ 0x401005
# Disassemble the main function
> pdf @ main

# Print string
> ps @ 0x2100
# Print zero-terminated string
> psz @0x2100

# Show 200 hex bytes
> px 200
# Show hex bytes at given register
> px @ eip
> px @ esp
Copied!
To decompile functions, we need to Ghidra decompiler so first we need to install the ghidra plugin.

sudo apt install rizin-plugin-ghidra
Copied!
Then below are commands for decompiling.

# Decompile the "main" function
> pdg @ main
Copied!

Write
We need to add '-w' option when the debugger starts.

# Write string
> w Hello World\n @ 0x2100

# Write opcodes at given address
> wa 'mov eax, 1' @ 0x2100
> wa 'mov byte [rbp-0x1], 0x61' @ 0x2100
Copied!

Expressions
> ?vi 0x000011a4
4516

> ?vi 1+2
3
Copied!

Information about Binary File
# Information about the binary file
> i

# All summary
> ia

# Show main address
> iM

# Symbols
is

# List strings
> iz
# List strings in whole binary
> izz
Copied!

Reopen Current File
# Reopen current file in debug mode
> ood
```

##
##
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
