# Linux Shell Script Cheat Sheet

####
####
####


-   [Prerequisites](#prerequisites)

    -   [Useful vagrant commands](#useful-vagrant-commands)

-   [Shell script](#shell-script)

    -   [Commands](#commands)
    -   [Permission](#permission)
    -   [echo](#echo)
    -   [Special Variables](#special-variables)
    -   [Constants](#constants)
    -   [If Statement](#if-statement)
    -   [Case Statement](#case-statement)
    -   [Exit Status](#exit-status)
    -   [File Descriptors](#file-descriptors)

        -   [Standard Input](#standard-input)
        -   [Standard Output](#standard-output)
        -   [Standard Error](#standard-error)

    -   [Logger](#logger)
    -   [Checksum](#checksum)
    -   [Random](#random)
    -   [Head](#head)
    -   [Stream manipulation](#stream-manipulation)
    -   [Fold](#fold)
    -   [Path](#path)
        -   [Locate](#locate)
    -   [Create your very own command](#create-your-very-own-command)
    -   [Input arguments](#input-arguments)
    -   [Input options](#input-options)
    -   [Loop](#Loop)
    -   [Function](#function)
    -   [getopts](#getopts)
    -   [optind](#optind)
    -   [Math](#math)
        -   [bc](#bc)
        -   [awk](#awk)
    -   [Useful Tricks](#useful-tricks)
        -   [Search for keywords](#search-for-keywords)
        -   [Run the final command](#run-the-final-command)
    -   [Use Cases](#use-cases)

        -   [Check if I am root](#check-if-i-am-root)
        -   [Create a new user](#create-a-new-user)
        -   [Password Generator](#password-generator)
        -   [Create local users with random passwords](#create-local-users-with-random-passwords)
        -   [Create local users with random passwords and keep STDOUT and STDERR to a log file](#create-local-users-with-random-passwords-and-keep-stdout-and-stderr-to-a-log-file)

    -   [Reference](#reference)

## Prerequisites

1. Install virtualBox and [vagrant](https://www.vagrantup.com/) to automate the process of creating a virtual machine.
2. Take a look at [vagrant cloud](https://app.vagrantup.com/boxes/search) to see what public vagrant boxes are available
3. (Optional) Customise Your terminal and vim

-   Zoom the font size of your terminal:
    Terminal -> Preferences -> Switch to `text` tab -> Font
-   Set terminal colour in ~/.bash_profile:

```
# Global terminal colours
export CLICOLOR=1
export LSCOLORS=GxFxCxDxBxegedabagacedH
```

-   Show git branch on terminal in ~/.bash_profile:

```
# Git branch in prompt.
parse_git_branch() {
  git branch 2> /dev/null | sed -e '/^[^*]/d' -e 's/* \(.*\)/ (\1)/'
}
export PS1="\u@\h \W\[\033[31m\]\$(parse_git_branch)\[\033[00m\] $ "
```

-   Set vim colour in ~/.vimrc:

```
syntax on

colorscheme desert
```

-   Display line numbers in vim:

Vim any file

```shell
$vim ANY_FILE
```

Type `:set nu` and enter

4. Useful shortcuts

    - terminal
        - Search command history: `ctrl` + `R`, next: `R`
    - vim
        - Jump to line 14: `:14`
        - Scroll to top: `gg` or `:1`
        - Reach the end of a file: `shift` + `g`
        - Search: `/` or `?`

### Useful vagrant commands

-   Download a box(OS image) and store it to your local storage , e.g.

```shell
$vagrant box add username/os_name
```

-   Initialise a vagrant project and import the box into VirtualBox:

```shell
$vagrant init username/os_name
$vagrant up
```

[Exercise](https://www.udemy.com/course/linux-shell-scripting-projects/learn/lecture/7980558#overview)

-   You can create a box with your very own Vagrantfile, which contains a serial of steps of creating a machine. (Think of it a script defines commands of VirtualBox to create a virtual machine)
-   [Vagrant file example](https://github.com/Catherine22/Linux-tutorial/Vagrantfile)

-   Once you have the machine created, what you do the most might be to start the machine and SSH into the machine.

1. Run the box (with the username test1 for example)

```shell
$vagrant up test1
```

2. SSH into the machine

```shell
$vagrant ssh test1
```

And you will see something like this `[vagrant@testbox01 ~]$`.

## Shell script

### Commands

1. Put shebang in the first line

```shell
#!/bin/bash
```

When you write shebang, i.e. "#!", it specifies which interpreter this script is going to use.

2. To see what a command actually is, check its type at first.

Example 1, a program

```shell
$type -a whoami
```

And you will get `whoami is /usr/bin/whoami`. It is a program, so we can open its manual by typing `man`

```shell
$man whoami
```

Example 2, a shell keyword

```shell
$type -a if
```

It turns out `if is a shell keyword`. So now you can learn the keyword by typing `help`

```shell
$help if
```

Example 3, a shell builtin

```shell
$type -a test
```

It turns out:

```
test is a shell builtin
test is /usr/bin/test
```

Show the manual by typing `help`, you can also add `| less` to get it more readable.

```shell
$help test | less
```

3. To know what command we are using, for example, if I type `$head`, where is this `head` from

```shell
$which head
```

And you will see `/usr/bin/head`

4. Another example is `userdel`, if you run

```shell
$type -a userdel
```

then you get

```shell
userdel is /usr/sbin/userdel
userdel is /sbin/userdel
userdel is /usr/sbin/userdel
```

You can use `which` command to check waht `userdel` you are using right now.

### Permission

1. Check access permission at first

```shell
$ls -l
```

And you will see the permission

```shell
-rw-r--r-- 1 vagrant vagrant   32 Dec  3 08:19 test1_echo.sh
```

Ignore the first `-`, we have three characters a group, the first `rw-` is the permission of the owner of the file means the readable, writeable but non-executable. The next set `r--` represents the permission of the group of the file, the last `r--` represents the permission that everyone else in this system granted.

2. Execute the file and you will get _Permission denied_ error
3. Grant the permission to execute the file

```shell
$chmod 755 test1_echo.sh
```

> r=4, w=2, x=1
> To calculate the number of `chmod`, for example, I need `rwxr-xr-x`, the number will be (4+2+1) (4+1) (4+1) = 755. That's how 755 comes from.

Type `ls -l` again, and you'll see:

```shell
-rwxr-xr-x 1 vagrant vagrant   32 Dec  3 08:19 test1_echo.sh
```

4. Execute the script

```shell
$./test1_echo.sh
```

> .: this directory
> /: separate the file and `.`
> ..: parent directory

You can simply run the file by `./test1_echo.sh`, or you can even go from parent directory like `../localusers/test1_echo.sh`

#### Shell builtin

To see if a command is a shell builtin, type

```shell
$type [COMMAND]
```

For example, you can try `$help echo`, and you will get `echo is a shell builtin`

You can get documentation of any shell builtin by typing

```shell
$help [SHELL_BUILTIN]
```

To show in another page

```shell
$help [SHELL_BUILTIN]|less
```

E.g. `$help echo`

### echo

To print something such as variables on the terminal.

```bash
#!/bin/bash

# Print 'Hello world'
echo 'Hello World'

# Assign a value to a variable (NO BLANKS before the value)
NAME='Catherine'

# Print the variable (You MUST use double quotes)
echo "$NAME"

# Print a sentence contained a variable
echo "Hello, there! I'm $NAME."

# Combine variables
LINE1='England is barely big enough to contain her. '
LINE2='She will travel Paris, Italy, the Pyrenees. She was mentioning Russia.'

echo "${LINE1}${LINE2}"

# Reassignment
LINE1='Will she be staying long? '
LINE2='Oh, I doubt it.'

echo "${LINE1}${LINE2}"
```

```
┌──────┐
│ echo │
├──────┴─────────────────────────────────────────────────────────────────┐
│1. No blanks                                                            │
│2. Single quotes for value, double quotes for variable                  │
└────────────────────────────────────────────────────────────────────────┘
```

### Special Variables

Here are the list of special variables this tutorial mentioned:

-   `${UID}`
-   `${EUID}`
-   `${0}`
-   `${?}`
-   `${RANDOM}`
-   `${PATH}`

To see more bash variables, type `man bash`

1. UID/EUID

```shell
$echo "Your UID is ${UID} and EUID is ${EUID}"
```

2. id(uid, gid and group)

```shell
$id
```

You will see `uid=1000(vagrant) gid=1000(vagrant) groups=1000(vagrant)` in Vagrant machine, and you will see more information on Mac by the way ([link](https://apple.stackexchange.com/questions/113822/what-are-com-apple-access-ssh-and-com-apple-access-screensharing-can-i-dele)).

To print one piece of information e.g. name of gid, type:

```shell
$id -g -n
```

These options can be merged. E.g. `$id -gn`

> They're different when a program is running set-uid. Effective UID is the user you changed to, UID is the original user. (Which means **UID IS READ ONLY**)

3. username

```shell
USERNAME=$(id -un) # or `id -un` or $(whoami) or `whoami`
echo "Your username: ${USERNAME}"
```

4. Check if it is root

```shell
if [[ "${UID}" -eq 0 ]]
then
  echo 'You are root'
else
  echo 'You are not root'
fi
```

5. Root user
   Two ways to become a root user:
    - Run this code snippet with `sudo`, and you will get 'You are root' result.
    - Or you can switch to root user by typing `su` at first.

When you are not root, your might see `[vagrant@testbox01 localusers]$`, once you become the root user, it shows `[root@testbox01 localusers]#`

6. Display what user typed on the command line. E.g. in test.sh

```shell
#!/bin/bash

echo "You executed this command: ${0}"
```

and you run `./test.sh`, you will see `./test.sh`, but if you run this file by typing `/vagrant/localusers/test.sh`, it will print `/vagrant/localusers/test.sh`

```
┌───────────┐
│ Variables │
├───────────┴────────────────────────────────────────────────────────────┐
│1. Define a code snippet with $(YOUR_COMMAND) or  `YOUR_COMMAND`        │
│2. Single quotes for value, double quotes for variable                  │
└────────────────────────────────────────────────────────────────────────┘
```

### Constants

```shell
readonly PI='3.14'
echo "${PI}"
```

### If Statement

Rule 1

```shell
if [[ xxx -eq xxx ]]
then
    # do something
fi;
```

E.g.

Write in one single line and separate each command by `;`

```shell
$if [[ 'a' -eq 'a' ]]; then echo 'same'; fi;
```

To be readable, you can truncate commands by pressing `shift` + `enter`. No `;` anymore.

```shell
$if [[ 'a' -eq 'a' ]]
>  then echo 'same'
>fi
```

> `-eg` or `=`: equal  
> `-ne` or `!=`: not equal
> `-lt`: less than, which comes with a number.
> `-gt`: great than, which comes with a number.

```
┌────┐
│ If │
├────┴───────────────────────────────────────────────────────────────────┐
│ if [[ condition1 ]]                                                    │
│ then                                                                   │
│    // do something                                                     │
│ elif [[ condition2 ]]                                                  │
│ then                                                                   │
│    // do something                                                     │
│ else                                                                   │
│    // do something                                                     │
│ fi                                                                     │
└────────────────────────────────────────────────────────────────────────┘
```

### Case Statement

You may have code snippet like this:

```shell
#!/bin/bash

if [[ "${1}" = '-attack' ]] || [[ "${1}" = '--a' ]]
then
  echo 'slashing...'
elif [[ "${1}" = '-move' ]] || [[ "${1}" = '--m' ]]
then
  echo 'teleporting...'
elif [[ "${1}" = '-bombardment' ]] || [[ "${1}" = '--b' ]]
then
  echo 'letting out an arcane torrent...'
elif [[ "${1}" = '-provoke' ]] || [[ "${1}" = '--p' ]] || [[ "${1}" = '-shout' ]] || [[ "${1}" = '--s' ]]
then
  echo 'transforming your skin to diamond...'
else
  echo 'No idea' >&2 # STDERR
  exit 1 # fail
fi
```

And you type:

```shell
$./test.sh --p
# transforming your skin to diamond...

$./test.sh -sneak
# no idea
$ echo $?
# 1 (from exit status)
```

You can update your to `case` version

```shell
#!/bin/bash

case "${1}" in
  -attack|--a)
    echo 'slashing...'
    ;;
  -move|--m)
    echo 'teleporting...'
    ;;
  -bombardment|--b)
    echo 'letting out an arcane torrent...'
    ;;
  -provoke|--p|-shout|--s)
    echo 'transforming your skin to diamond...'
    ;;
  *)
    echo 'No idea' >&2 # STDERR
    exit 1 # fail
    ;;
esac
```

With [OPTIND](#optind), you can easily handle invalid arguments.

```
┌──────┐
│ case │
├──────┴─────────────────────────────────────────────────────────────────┐
│ case condition in                                                      │
│   variable1)                                                           │
│     // do something                                                    │
|    ;;                                                                  │
│   variable2)                                                           │
│     // do something                                                    │
|    ;;                                                                  │
│   *)                                                                   │
│    // do something                                                     │
|    ;;                                                                  │
│ esac                                                                   │
│                                                                        │
│ Argument validation: OPTIND                                            │
└────────────────────────────────────────────────────────────────────────┘
```

### Exit status

To check if your command works properly, you don't need to see the STDOUT or STDERR, you should check the exit status.

```shell
# 0: success; non-zero: error
$echo ${?}
```

#### Principle of status code

-   0: success
-   Not 0: fail

1. Check existed exit status, take `useradd` for example

```shell
$man useradd
```

2. Search the keyword "exit" by typing `/exit`, `n` for next and `N` for previous

3. You will find

> EXIT VALUES
>
> The useradd command exits with the following values:
>
> 0 success
>
> 1 can't update password file
>
> 2 invalid command syntax
>
> ...

#### Get the exit status of the previous command

1. Verify the command we've just typed (in shall script)

```shell
USERNAME=$(id -un)

# Test if the command worked (check the exit status of the previous command, i.e. 'id -un' in this case
if [[ "${?}" -ne 0 ]]
then
  echo "The id command did not work successfully."
  exit 2
fi

echo "Username: ${USERNAME}"
```

2. Verify the command we've just typed (in bash)

```shell
$id -un
```

Then you get "vagrant"

```shell
$echo "${?}"
```

And you get 0

Now if I run a false command like

```shell
$id -abc
```

You get the error:

```
id: invalid option -- 'b'
Try 'id --help' for more information.
```

Get the exit status, and this time, it will be 1

```shell
$echo "${?}"
```

```
┌─────────────┐
│ Exit status │
├─────────────┴──────────────────────────────────────────────────────────┐
│ > status code                                                          │
│   0: success                                                           │
│   others: fail                                                         │
│                                                                        │
│ > At the end of your shell script, add:                                │
│   exit 0                                                               │
└────────────────────────────────────────────────────────────────────────┘
```

### File Descriptors

A file descriptor is simply a number that represents a open file.

By default, every new process starts with 3 open file descriptors:

-   FD 0: STDIN
-   FD 1: STDOUT
-   FD 2: STDERR

By default, a STDIN comes from your keyboard, and STDOUT and STDERR are displayed on the screen. None of them are files. In fact, Linux represents practically everything as a file.

#### Standard Input

Aka. STDIN

-   Read the input with comments

```shell
$read -p 'type something: ' WORDS
type something: Hello
$echo "${WORDS}"
Hello
```

-   Read one line of STDIN

```shell
# Create a file at first
FILE="tmp"
echo "hello" > ${FILE}

# Read the first line of the tmp file
read LINE_1 < ${FILE}
echo "Line 1: ${LINE_1}"
```

-   Read implicitly or explicitly

```shell
# Read files in an implicit way (using default file descriptor (0))
$read x < /etc/centos-release
$echo "${x}"

# Read files in an explicit way (NOTICE, no space between 0 and <)
$read x 0< /etc/centos-release
$echo "${x}"
```

#### Standard Output

Aka. STDOUT

Formula: `STATEMENT1 TYPE> STATEMENT2`
Formula: `STATEMENT1 TYPE>> STATEMENT2`

> STATEMENT1: a statement that will through info  
> TYPE: STDOUT is `1>` or `>`; STDERR is `2>`; Both is `&>`; Convert STDOUT to STDERR by using `1>&2`, the converse is `2>&1`  
> `>` vs. `>>`: `>` is to overwrite whereas `>>` is to append to the next line.  
> STATEMENT2: Somewhere to keep outputs or `cat` statement to show on screen.

-   Write the output to a file.

```shell
FILE="tmp"
head -n3 /etc/passwd > ${FILE}
```

You will get `tmp` file filled in

```
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
```

-   Append string to next line.

```shell
echo $(date | sha256sum | head -c10) >> ${FILE}
echo "end" >> ${FILE}
```

The tmp file will be written

```
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
84ba4cc4cf
end
```

-   Write implicitly or explicitly

```shell
# Write files in an implicit way (using default file descriptor (1))
$echo "${UID}" > uid
$cat uid

# Read files in an explicit way (NOTICE, no space between 1 and >)
$echo "${UID}" 1> uid
$cat uid
```

#### Standard Error

To check if your command works properly, you don't need to see the STDOUT or STDERR, you should check the exit status.

```shell
# 0: success; non-zero: error
$echo ${?}
```

-   Prerequisites

Here is a head command, it prints the first line of designated files

```shell
$head -n1 /etc/passwd /etc/hosts
```

It will print:

```
==> /etc/passwd <==
root:x:0:0:root:/root:/bin/bash

==> /etc/hosts <==
127.0.0.1	testbox01	testbox01
```

Now, to make this command malfunction, we add an fake file.

```shell
$head -n1 /etc/passwd /etc/hosts fakefile
```

The first two files still work properly, but it shows an error message underneath.

```
==> /etc/passwd <==
root:x:0:0:root:/root:/bin/bash

==> /etc/hosts <==
127.0.0.1	testbox01	testbox01
head: cannot open ‘fakefile’ for reading: No such file or directory
```

If we write the outputs into a file, this error message will not be written.

```shell
$head -n1 /etc/passwd /etc/hosts fakefile > head.out
$cat head.out
```

It will print:

```
==> /etc/passwd <==
root:x:0:0:root:/root:/bin/bash

==> /etc/hosts <==
127.0.0.1	testbox01	testbox01
```

-   STDERR

But if we specify its file descriptor to 2 (STDERR)

```shell
$head -n1 /etc/passwd /etc/hosts fakefile 2> head.err
$cat head.err
```

It will print:

```
head: cannot open ‘fakefile’ for reading: No such file or directory
```

We can merge make this operation a bit fancy. I.e. using STDOUT and STDERR in one command:

```shell
$head -n1 /etc/passwd /etc/hosts fakefile > head.out 2> head.err
```

Or you can append error messages by using `2>>`

Another common feature is to merge STDOUT and STDERR together:

```shell
$head -n1 /etc/passwd /etc/hosts fakefile > head.both 2>&1
```

which is equivalent to the shorter statement below:

```shell
$head -n1 /etc/passwd /etc/hosts fakefile &> head.both
```

Run `cat -n` to print it with number of lines.

```shell
$cat -n head.both
```

It will print:

```
     1	==> /etc/passwd <==
     2	root:x:0:0:root:/root:/bin/bash
     3
     4	==> /etc/hosts <==
     5	127.0.0.1	testbox01	testbox01
     6	head: cannot open ‘fakefile’ for reading: No such file or directory
```

In pine, STDERR cannot be passed directly, you have convert it to STDOUT at first. Both STDOUT and STDERR go through the pine. E.g.

```shell
$head -n1 /etc/passwd /etc/hosts fakefile 2>&1 | cat
```

It is equivalent to another statement

```shell
$head -n1 /etc/passwd /etc/hosts fakefile |& cat
```

Formula: `STATEMENT1 TYPE> STATEMENT2`
Formula: `STATEMENT1 TYPE>> STATEMENT2`

> STATEMENT1: a statement that will through info  
> TYPE: STDOUT is `1>` or `>`; STDERR is `2>`; Both is `&>`; Convert STDOUT to STDERR by using `1>&2`, the converse is `2>&1`  
> `>` vs. `>>`: `>` is to overwrite whereas `>>` is to append to the next line.  
> STATEMENT2: Somewhere to keep outputs or `cat` statement to show on screen.

```
┌─────────────────────────────────┐
│ Standard Input / Output / Error │
├─────────────────────────────────┴──────────────────────────────────────┐
│ > 0: STDIN                                                             │
│   1: STDOUT                                                            │
│   2: STDERR                                                            │
│                                                                        │
│ > STDIN:                                                               │
│   $read x 0< /etc/centos-release                                       │
│   = $read x < /etc/centos-release                                      │
├────────────────────────────────────────────────────────────────────────┤
│ > Formula: `STATEMENT1 TYPE> STATEMENT2`                               │
│   > STATEMENT1: a statement that will through info                     │
│   > TYPE: STDOUT is `1>` or `>`; STDERR is `2>`; Both is `&>`;         │
│     Convert STDOUT to STDERR by using `1>&2`, the converse is `2>&1`   │
│   > `>` vs. `>>`: `>` is to overwrite whereas `>>` is to append to the │
│      next line.                                                        │
│   > STATEMENT2: Somewhere to keep outputs or `cat` statement to show   │
│     on screen.                                                         │
│                                                                        │
│ > STDOUT:                                                              │
│   > No STDERR                                                          │
│     $head -n1 /etc/passwd /etc/hosts fakefile > head.both              │
│     = $head -n1 /etc/passwd /etc/hosts fakefile 1> head.both           │
│   > Combine STDERR                                                     │
│     $head -n1 /etc/passwd /etc/hosts fakefile &> head.both             │
│   > Send STDOUT to STDERR                                              │
│     $echo 'error' 1>&2 | cat -n                                        │
│     = $echo 'error' >&2 | cat -n                                       │
│   > Hide STDOUT                                                        │
│     $head -n1 /etc/passwd /etc/hosts fakefile 1> /dev/null             │
│     = $head -n1 /etc/passwd /etc/hosts fakefile > /dev/null            │
│                                                                        │
│ > STDERR:                                                              │
│   > STDERR Only                                                        │
│     $head -n1 /etc/passwd /etc/hosts fakefile 2> head.err              │
│   > Send STDERR to STDOUT (In pine, STDERR cannot be passed directly)  │
│     $head -n1 /etc/passwd /etc/hosts fakefile 2>&1 | cat               │
│     = $head -n1 /etc/passwd /etc/hosts fakefile |& cat                 │
│   > Hide STDERR                                                        │
│     $head -n1 /etc/passwd /etc/hosts fakefile 2> /dev/null             │
│   > Hide STDOUT and STDERR                                             │
│     $head -n1 /etc/passwd /etc/hosts fakefile &> /dev/null             │
└────────────────────────────────────────────────────────────────────────┘
```

### Logger

Log something

```shell
$logger 'hello from vagrant user'
```

Print all logs

```shell
$sudo tail /var/log/messages
```

You will see messages below:

```
Mar 28 21:58:01 testbox01 vagrant: hello from vagrant user
```

You can tag on your messages by using `-t`

```shell
$logger -t Doris "Dinner's ready"
```

Again, this time you will see

```shell
Mar 28 21:59:09 testbox01 Doris: Dinner's ready
```

### Checksum

List all available checksum methods

```shell
$ls -l /usr/bin/*sum

# -rwxr-xr-x 1 root root 33152 Aug 20 02:25 /usr/bin/cksum
# -rwxr-xr-x 1 root root 41504 Aug 20 02:25 /usr/bin/md5sum
# -rwxr-xr-x 1 root root 37448 Aug 20 02:25 /usr/bin/sha1sum
# -rwxr-xr-x 1 root root 41608 Aug 20 02:25 /usr/bin/sha224sum
# -rwxr-xr-x 1 root root 41608 Aug 20 02:25 /usr/bin/sha256sum
# -rwxr-xr-x 1 root root 41624 Aug 20 02:25 /usr/bin/sha384sum
# -rwxr-xr-x 1 root root 41624 Aug 20 02:25 /usr/bin/sha512sum
# -rwxr-xr-x 1 root root 37432 Aug 20 02:25 /usr/bin/sum
```

> -b, --binary
>
> read in binary mode
>
> -c, --check
>
> read SHA256 sums from the FILEs and check them
>
> --tag create a BSD-style checksum
>
> -t, --text
>
> read in text mode (default)
>
> Note: There is no difference between binary and text mode option on GNU system.

Get the sha256sum of a file

```shell
$sha256sum YOUR_FILE
```

### Random

Generate random numbers

```shell
echo ${RANDOM}

# 3054
```

To dive into the random method, go to the [Password Generator](#password-generator) section

### Head

1. Print the first line of a file

```shell
# 1st line
$head -n1 FILE_NAME

# the first two lines
$head -n2 FILE_NAME
```

2. Print the first character of a file

```shell
# 1st character
$head -c1 FILE_NAME

# the first three characters
$head -c3 FILE_NAME
```

3. Print the first 5 characters of inputs

```shell
$echo 12345678 | head -c5
```

4. Another feature of `head` command is to read multiple files. E.g.

```shell
$head -n1 /etc/passwd /etc/hosts
```

And you will get:

```
==> /etc/passwd <==
root:x:0:0:root:/root:/bin/bash

==> /etc/hosts <==
127.0.0.1	testbox01	testbox01
```

### Stream manipulation

With `|`, you can manipulate the input stream.

E.g. Print the first 5 characters of inputs

```shell
# You will get 12345
$echo 12345678 | head -c5
```

And you can keep modify the inputs with multiple `|`

E.g. Print the first 8 characters of the sha256 checksum of the timestamp

```shell
$date +%s | sha256sum | head -c8
```

### fold

wrap each input line to fit in specified width

> -b, --bytes
>
> count bytes rather than columns
>
> -c, --characters
>
> count characters rather than columns
>
> -s, --spaces
>
> break at spaces
>
> -w, --width=WIDTH
>
> use WIDTH columns instead of 80

For example

```shell
S='!@#$%^&*()_-+='
echo "${S}" | fold -b1
```

You will get these characters printed on a single line one by one

```
!
@
#
$
%
^
&
*
(
)
_
-
+
=
```

A further use case of `fold` is to generate a random string. The `shuf` method works on shuffling lines of text, you cannot shuffle a string directly, you must fold it at first.

```shell
echo "${S}" | fold -c1 | shuf
```

```
#
+
=
-
@
(
$
!
*
_
^
&
%
)
```

And you can print each line of the character by using `head`

### Path

E.g. I have a file in /vagrant/localusers/test_path.sh

1. `basename`: Get the file name (removed the directory)

```shell
$basename /vagrant/localusers/test_path.sh
```

It returns `test_path.sh`

2. `dirname`: Get the path of a file (except the file itself)

```shell
$dirname /vagrant/localusers/test_path.sh
```

It returns `/vagrant/localusers`

#### Locate

To find a command which is not in your path, you need `locate`, `install` and `configure`.  
`locate` searches an index created by the `updatedb` command, which is typically scheduled to run once a day. Therefore, `locate` command does not have up-to-the-minute information.

1. Locate `userdel` (You may be able to see more results by running `locate` with `sudo`)

```shell
$locate userdel
```

then you would get

```shell
/usr/sbin/luserdel
/usr/sbin/userdel
/usr/share/bash-completion/completions/userdel
/usr/share/man/de/man8/userdel.8.gz
/usr/share/man/fr/man8/userdel.8.gz
/usr/share/man/it/man8/userdel.8.gz
/usr/share/man/ja/man8/userdel.8.gz
/usr/share/man/man1/luserdel.1.gz
/usr/share/man/man8/userdel.8.gz
/usr/share/man/pl/man8/userdel.8.gz
/usr/share/man/ru/man8/userdel.8.gz
/usr/share/man/sv/man8/userdel.8.gz
/usr/share/man/tr/man8/userdel.8.gz
/usr/share/man/zh_CN/man8/userdel.8.gz
/usr/share/man/zh_TW/man8/userdel.8.gz
```

2. Create your own userdel

```shell
$touch userdel
```

If you run `locate userdel`, you won't see the `userdel` you placed.

3. Scan the whole file directory to update the DB

```shell
$sudo updatedb
```

4. Locate `userdel` again, and this time, you will get the latest results.

```shell
$locate userdel
```

5. To narrow down the search results, you could user `| grep xxx` to print results with keywords `xxx`

```shell
$locate userdel | grep bin
```

### Create your very own command

To see where a command from, you can type `which`. E.g.

```shell
$which head
```

Then you will see `/usr/bin/head`

1. To create my own `head` shell script

```shell
$vim user/local/bin/head
```

And fill in something like

```shell
#!/bin/bash

echo 'Hello from my head'
```

2. Escalate the privilege

```shell
$sudo chmod 755 /usr/local/bin/head
```

3. Check if your head command is changed

```shell
$which head
```

And you will see `/usr/local/bin/head`. Besides, you can list all matches by typing `$which -a head`.

4. Run the `head` command

```shell
$head # Hello from my head
```

5. You can still run the previous head by assigning the full path. E.g.

```shell
$/usr/bin/head -n1 /etc/passwd
```

6. Remove the `head` and stop using this user-defined shell script.

```shell
$sudo rm /usr/local/bin/head
```

7. Run `head` to see if it works properly. If not, run

```shell
# This command is to forget all remembered locations
$hash -r
```

### Input arguments

See how many arguments user inputs

```shell
NUMBERS_OF_PARAMS="${#}"

echo "You supplied ${NUMBERS_OF_PARAMS} argument(s) on the command line"
```

The simplest way to get input arguments is `"${1}"`.

E.g. in test.sh, you type `$./test.sh A B C D E`

```shell
echo "Parameter 1: ${1}"
echo "Parameter 2: ${2}"
echo "Parameter 3: ${3}"
```

You will get

```
Parameter 1: A
Parameter 2: B
Parameter 3: C
```

You will lose rest of the arguments. In order to get all arguments, you need a for-loop or while-loop.

### Input options

Three ways to handle user inputs:

1. `read`: Pause the process and ask for inputs
2. input arguments: User types arguments while executing the shell script
3. input options: User types arguments while executing the shell script

The difference between input arguments and input options is the syntax user inputs. E.g.

A command with arguments will be like `./test.sh arg1 arg2`  
On the other hands, a comment with options will be like `./test.sh -v -i`

### Loop

#### For-loop

Get all arguments

```shell
for ARGUMENT in "${@}"
do
  echo "${ARGUMENT}"
done
```

If you want to gather all input characters including whitespace as one argument, you can do

```shell
for ARGUMENT in "${*}"
do
  echo "${ARGUMENT}"
done
```

#### While-loop

`while` + `shift`

1. Create a script test.sh

```shell
while [[ "${#}" -gt 0 ]]
do
  echo "Number of parameters: ${#}"
  echo "Param 1: ${1}"
  echo "Param 2: ${2}"
  echo "Param 3: ${3}"
  echo
  shift
done
```

> `-gt`: great then

2. Run `./test.sh A B C`, and then you will get

```
Number of parameters: 3
Param 1: A
Param 2: B
Param 3: C

Number of parameters: 2
Param 1: B
Param 2: C
Param 3:

Number of parameters: 1
Param 1: C
Param 2:
Param 3:
```

```
┌─────────────┬──────────────┐
│   for-loop  │  while-loop  │
├─────────────┴──────────────┴───────────────────────────────────────────┐
│ > for-loop # print 1-5                                                 │
│   for e in {1..5}                                                      │
│   do                                                                   │
│     echo "${e}"                                                        │
│   done                                                                 │
│                                                                        │
│ > for-loop # print 1, 3, 5, 7, 9                                       │
│   for e in {1..9..2}                                                   │
│   do                                                                   │
│     echo "${e}"                                                        │
│   done                                                                 │
│                                                                        │
│ > for-loop # Loop an array                                             │
│   CARS=('sedan' 'suv' 'hatchback')                                     │
│   for e in ${CARS[*]}                                                  │
│   do                                                                   │
│     echo "${e}"                                                        │
│   done                                                                 │
├────────────────────────────────────────────────────────────────────────┤
│ > while-loop                                                           │
│   while [[ CONDITION ]]                                                │
│   do                                                                   │
│     # do something                                                     │
│   done                                                                 │
└────────────────────────────────────────────────────────────────────────┘
```

### Function

Functions need to be defined before they are used.

-   Two ways to define a function without arguments

```shell
#!/bin/bash

f1() {
    echo 'running f1()'
}

function f2 {
    echo 'running f2()'
}

f1
f2
```

-   Functions with arguments

```shell
f3() {
    # The `local` command can only be used inside of a function
    local ARGS="${@}"
    echo "${ARGS} from f3()"
}

f3 'a' 'b'
```

-   Using global variable to control the flow of a function

```shell
# This is how shell script define a constant
readonly VERBOSE='true'
log() {
    if [[ "${VERBOSE}" = 'true' ]]
    then
        # The `local` command can only be used inside of a function
        local MESSAGES="${@}"
        echo "${MESSAGES} from log()"
    fi
    # To see your log, run: sudo tail /var/log/messages
    logger -t my_app "${MESSAGES}"
}

log 'exception: 404 not found'
```

### getopts

`getopts` parses command line arguments.

Demo: [password_generator.sh]

### optind

The variable `optind` is the index of the next element to be processed in argv.

Demo: [password_generator.sh]

### Math

To calculate a number and assign it as a variable, you will need:

```shell
$NUM=$(( 6 / 4 ))
```

If you print it, you will get 1, and which is not correct

```shell
$echo ${NUM}
```

If you need to calculate, you will need to install another program such as `bc`

```shell
$sudo yum install -y bc
```

```shell
$bc -h
```

Update a number in another statement.

```shell
$NUM='2'
$(( NUM++ ))
$echo ${NUM} # NUM = 3
$NUM=$(( NUM +=5 ))
$echo ${NUM} # NUM = 8
```

#### let

```shell
$let NUM='2 + 3'
$echo ${NUM} # NUM = 5
```

```shell
$let NUM++ # NUM = 6
```

#### expr

```shell
$expr 6 / 4 # 1
```

```shell
$NUM=$(expr 1 + 1) # NUM = 2
```

#### bc

Allow floating calculation in bc, you will need to add `-l`

```shell
$bc -l
```

-   bc reads standard input, and to calculate floating numbers, you will need `-l` option

```shell
$echo '6 / 4' | bc -l
```

#### awk

Another way to calculate floating numbers

```shell
$awk "BEGIN {print 6/4}"
```

### Useful Tricks

#### Search for keywords

```shell
$YOUR_COMMAND | grep KEYWORDS
```

E.g. To `locate` all password files (including root) placed in **system** directory

```shell
$sudo locate password | grep system
```

#### Run the final command

```shell
$!!
```

Or with `sudo`

```shell
$sudo !!
```

### Use Cases

#### Check if I am root

```shell
if [[ "${UID}" -eq 0 ]]
then
  echo 'You are root'
else
  echo 'You are not root'
fi
```

#### Create a new user

-   create a new user

```shell
$sudo useradd -c leonardo-da-vinci -m da-vinci
```

> -c, --comment COMMENT
>
> Any text string. It is generally a short description of the login, and is currently used as the field for the user's full name.

> -m, --create-home
>
> Create the user's home directory if it does not exist. The files and directories contained in the skeleton directory (which can be defined with the -k option)
> will be copied to the home directory.
>
> By default, if this option is not specified and CREATE_HOME is not enabled, no home directories are created.
>
> The directory where the user's home directory is created must exist and have proper SELinux context and permissions. Otherwise the user's home directory cannot be created or accessed.

-   Set the password

Using `echo`

```shell
$sudo echo 123456 | passwd  --stdin da-vinci
```

Or using STDIN

```shell
# Create a password file
echo "123456" > secret
passwd --stdin da-vinci < secret
```

-   Expire a password for an account. The user will be forced to change the password during the next login attempt.

```shell
$sudo passwd -e da-vinci
```

-   Switch to da-vinci, the user we just created

```shell
$su - da-vinci
```

-   Logout

```shell
$exit
```

The script to create a user: [add_local_user.sh]

### Password Generator

-   Rule of thumb: [pwd_generator_guideline.sh]
-   Demo: [password_generator.sh]

### Create local users with random passwords

-   The script allow you to:

    1. Create local user
    2. Generate a random password for local user
    3. Return exit status and log
    4. Print username(s) and password(s) on console

-   Demo: [add_local_users.sh]

```shell
$./add_local_users.sh Kent David Emma
```

### Create local users with random passwords and keep STDOUT and STDERR to a log file

-   The script allow you to:

    1. Create local user
    2. Generate a random password for local user
    3. Return exit status (0: Success; 1: failure + STDERR)
    4. Keep log to a `log.txt` file
    5. Hide STDOUT of statements, and keep STDERR to the log file
    6. Print username(s) and password(s) on console

-   Demo: [add_local_users_prod.sh]

```shell
$./add_local_users_prod.sh Kent David Emma
```

### Back up files

-   Back up `/etc/passwd` file
-   Define a function to create a backup for files.
-   Log message by using system logger
-   Notice, files in `/var/tmp/` deleted every 10 days whereas files in `/var/` deleted every 30 days.

```shell
#!/bin/bash

readonly VERBOSE='true'
log() {
    if [[ "${VERBOSE}" = 'true' ]]
    then
        # The `local` command can only be used inside of a function
        local MESSAGES="${@}"
        echo "${MESSAGES} from log()"
    fi
    # To see your log, run: sudo tail /var/log/messages
    logger -t my_app "${MESSAGES}"
}

backup_file() {
    local FILE="${1}"

    if [[ -f "${FILE}" ]]
    then
        local BACKUP="/var/tmp/$(basename ${FILE}).$(date +%F-%N)"
        log "Backing up ${FILE} to ${BACKUP}."

        # The exit status of the function will be the exit status of the cp -p command
        cp -p ${FILE} ${BACKUP}
    else
        # The file doesn't exist, return a non-zero status
        return 1
    fi
}

backup_file '/etc/passwd'

if [[ "${?}" -eq '0' ]]
then
    log 'File backup succeeded'
else
    log 'File backup failed'
    exit 1
fi

# It will print on terminal: Backing up /etc/passwd to /var/tmp/passwd.2020-03-29-279478030. from log()
# You can see the log by running: sudo tail /var/tmp/messages
# Your backup will be in /var/tmp/passwd.2020-03-29-279478030
```

> The difference between `cp` and `cp -p`, for example:  
> If you type `ls -l /etc/passwd`, you will see  
> `-rw-r--r-- 1 root root 1184 Feb 23 00:43 /etc/passwd`  
> Copy the passwd file and paste it into /tmp/ folder  
> `cp /etc/passwd /var/tmp/`  
> The date of your passwd file will be when you paste it into.  
> `-rw-r--r-- 1 vagrant vagrant 1184 Apr 2 01:23 passwd`  
> Therefore, to fix this issue, you need to add `-p` to make sure the date of your copy will be exactly the same.
> `cp -p /etc/passwd /var/tmp/`  
> `-rw-r--r-- 1 vagrant vagrant 1184 Feb 23 00:43 passwd`

## Reference

[Linux Shell Scripting: A Project-Based Approach to Learning]

[add_local_user.sh]: add_local_user.sh
[add_local_users.sh]: add_local_users.sh
[pwd_generator_guideline.sh]: pwd_generator_guideline.sh
[password_generator.sh]: password_generator.sh
[add_local_users_prod.sh]: add_local_users_prod.sh
[linux shell scripting: a project-based approach to learning]: https://www.udemy.com/course/linux-shell-scripting-projects/
