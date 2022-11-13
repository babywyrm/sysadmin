`Note: These notes are for my personal reference!`

# 𝐁𝐚𝐬𝐡 𝐒𝐜𝐫𝐢𝐩𝐭𝐢𝐧𝐠 𝐂𝐡𝐞𝐚𝐭𝐬𝐡𝐞𝐞𝐭

## 𝐁𝐚𝐬𝐢𝐜𝐬

- Telling interpreter that the file is bash file

```
!#/bin/bash
```

- Make the file executable
```
$ chmod +x script.sh
```

## 𝐂𝐨𝐦𝐦𝐞𝐧𝐭𝐬

```
# this is a single line comment 
```
```
# Multi line comment

# - Method I
<<COMMENTS
  This 
  is a 
  multiline
  comment
COMMENTS

```
```

# - Method II
:'
 This 
  is a 
  multiline
  comment
'

```

## 𝐕𝐚𝐫𝐢𝐚𝐛𝐥𝐞𝐬

- Syntax: `variable_name=variable_value`
- `Note: There should not be any white spaces on either side of the =`
- `Single quotes (') helps to treat every character as it is`
- `Double quotes (") helps to do the substitution`

---

System Defined Variables | Meaning
--- | ---
`BASH` | represents the Shell Name.
`BASH_VERSION` | specifies the shell version which the Bash holds.
`COLUMNS` | specify the no. of columns for our screen
`HOME` | specifies the home directory for the user
`LOGNAME` | specifies the logging user name.
`OSTYPE` | tells the type of OS.
`PWD` | represents the current working directory.
`USERNAME` | specifies the name of currently logged in user.

```
                                                                                      
#!/bin/bash

echo $BASH
echo $BASH_VERSION
echo $COLUMNS
echo $HOME
echo $LOGNAME
echo $OSTYPE
echo $PWD
echo $USERNAME
                                                                                       
```

---

## 𝐑𝐞𝐚𝐝𝐢𝐧𝐠 𝐈𝐧𝐩𝐮𝐭

- Syntax: `read [flag] varname`
  - `-s` : for silent mode
  - `-p` : for prompt mode
  - `-a` : for arrays

```
┌──(shreyas㉿kali)-[~/practise/bash_scripting]
└─$ cat read.sh  
#!/bin/bash

echo "firstname: "
read firstname
echo "lastname: "
read lastname

echo "Hello Mr. $firstname $lastname"

┌──(shreyas㉿kali)-[~/practise/bash_scripting]
└─$ ./read.sh  
firstname: 
shreyas
lastname: 
chavhan
Hello Mr. shreyas chavhan

```


```
┌──(shreyas㉿kali)-[~/practise/bash_scripting]
└─$ vim read_prompt.sh
                                                                                       
┌──(shreyas㉿kali)-[~/practise/bash_scripting]
└─$ chmod +x read_prompt.sh 
                                                                                       
┌──(shreyas㉿kali)-[~/practise/bash_scripting]
└─$ cat read_prompt.sh     
#!/bin/bash

read -p "Your Name: " name

echo "Hello Mr. $name"
                                                                                       
┌──(shreyas㉿kali)-[~/practise/bash_scripting]
└─$ ./read_prompt.sh 
Your Name: Shreyas
Hello Mr. Shreyas
                          
```
```
┌──(shreyas㉿kali)-[~/practise/bash_scripting]
└─$ vim read_silent.sh
                                                                                       
┌──(shreyas㉿kali)-[~/practise/bash_scripting]
└─$ ./read_silent.sh  
Your Password 
Your Password is mypassword, it's secret - don't tell anyone!
                                                                                       
┌──(shreyas㉿kali)-[~/practise/bash_scripting]
└─$ cat read_silent.sh 
#!/bin/bash


read -sp "Your Password " password

echo ""
echo "Your Password is $password, it's secret - don't tell anyone!"

```

- Multi-line input

```
while read -r line; do
   printf '%s\n' "$line"
done
```

---


## 𝐁𝐚𝐬𝐡 𝐢𝐟-𝐞𝐥𝐢𝐟-𝐞𝐥𝐬𝐞


- Syntax
```
if [condition]; then
  <blah blah>
elif [condition]; then
  <blah blah>
else
  <blah blah>
fi

```


- `||` : OR
- `&&` : AND

```
if [] || []; then
  <blah blah>
elif [] && []; then
  <blah blah>
else
  <blah blah>
fi
```

Operators | Description
--- | ---
`! EXPRESSION` | To check if `EXPRESSION` is false.
`-n STRING` | To check if the length of `STRING` is greater than zero.
`-z STRING` | To check if the length of `STRING` is zero (i.e., it is empty)
`STRING1 == STRING2` | To check if `STRING1` is equal to `STRING2`.
`STRING1 != STRING2` | To check if `STRING1` is not equal to `STRING2`.
`INTEGER1 -eq INTEGER2` | To check if `INTEGER1` is numerically equal to `INTEGER2`.
`INTEGER1 -gt INTEGER2` | To check if `INTEGER1` is numerically greater than `INTEGER2`.
`INTEGER1 -lt INTEGER2` | To check if `INTEGER1` is numerically less than `INTEGER2`.
`-d FILE` | To check if `FILE` exists and it is a directory.
`-e FILE` | To check if `FILE` exists.
`-r FILE` | To check if `FILE` exists and the read permission is granted.
`-s FILE` | To check if `FILE` exists and its size is greater than zero (which means that it is not empty).
`-w FILE` | To check if `FILE` exists and the write permission is granted.
`x FILE` | To check if `FILE` exists and the execute permission is granted.

---

## 𝐁𝐚𝐬𝐡 𝐂𝐚𝐬𝐞𝐬

- Syntax:
```
#!/bin/bash  
  
echo "Which Operating System are you using?"  
echo "Windows, Android, Chrome, Linux, Others?"  
read -p "Type your OS Name:" OS  
  
case $OS in  
    Windows|windows)  
        echo "That's common. You should try something new."  
        echo  
        ;;  
    Android|android)  
        echo "This is my favorite. It has lots of applications."  
        echo  
        ;;  
    Chrome|chrome)  
        echo "Cool!!! It's for pro users. Amazing Choice."  
        echo  
        ;;  
    Linux|linux)  
        echo "You might be serious about security!!"  
        echo  
        ;;  
    *)  
        echo "Sounds interesting. I will try that."  
        echo  
        ;;  
esac  
```

---

## 𝐁𝐚𝐬𝐡 𝐟𝐨𝐫 𝐋𝐨𝐨𝐩

- C++ like for loop

```
for ((i = 0 ; i < 100 ; i++)); do
  echo $i
done
```

- To read a range
```
for num in {1..10}  
  do  
  echo $num  
done  
```

- a range with increment

```
for num in {1..10..1}  
  do  
  echo $num  
done  
```

- a range with decrement

```
for num in {10..0..1}  
  do  
  echo $num  
done  
```

- Array variables

```
array=(  "element1" "element 2" .  .  "elementN" )  
  
for i in "${arr[@]}"  
  do  
  echo $i  
done  
```

- white spaces in String as word separators

```
#!/bin/bash  
  
for word in $str;  
do  
  <Statements>  
done  
```

- Each line in string as a word

```
#!/bin/bash  
  
for word in "$str";  
  do  
  <Statements>  
done  
```

- Infinite loop

```
i=1;  
for (( ; ; ))  
  do  
  sleep 1s  
  echo "Current Number: $((i++))"  
done  
```
---

## 𝐁𝐚𝐬𝐡 𝐰𝐡𝐢𝐥𝐞 𝐥𝐨𝐨𝐩

- C++ Style while loop
```
i=1  
while((i <= 10))  
  do  
  echo $i  
  let i++  
done  
```



## 𝐂𝐮𝐭 𝐂𝐡𝐞𝐚𝐭𝐬𝐡𝐞𝐞𝐭

Command | Explanation
:-:|---
`cut -c 3` | display `3rd character` from each line of text
`cut -c 2,7` | display the `2nd and 7th character` from each line of text
`cut -c 2-7` | display a range of characters starting at the `2nd position` of a string and ending at the `7th position`(both positions included)
`cut -c -4` | display the `first four` characters from each line of text
`cut -d $'\t' -f -3` | display `first three` fields of a `tab delimited` file
`cut -c 13-` | display the characters from `13th` position to the `end`
`cut -d ' ' -f 4` | display `4th word` with space `' '` as a delimiter
`cut -d ' ' -f -3` | display `first three words` with space `' '` used as a delimiter
`cut -d $'\t' -f 2-` | given a `tab` delimited file, display the fields from `second fields to last field`


## 𝐎𝐭𝐡𝐞𝐫 𝐍𝐨𝐭𝐞𝐬

- Chop off the arithmetic operations to decimal points: `bc <<< "scale=3; $expression"` 
- Round of the arithmetic operation result: `printf %.3f $(echo $expression | bc -l)`

- Performing Arithmatic Operations (add, subtract, multiply divide) on two variables: `$((EXPR))`
```
read -s X;
read -s Y;

echo $(($X + $Y));
echo $(($X - $Y));
echo $(($X * $Y));
echo $(($X / $Y));
```

- `head` :  output the first part of files

```
head -n <number of lines>       # display first n lines from a text file
head -c <number of characters>  # display first n characters from a text file
```

- `tail` : output the last part of files
```
tail -n <number of lines>      # display last n lines from a text file
tail -c <number of characters> # display last n characters from a text file
```

- Reading a file line by line

```
while read -r line; do <command> "$line" done < filename
```
---
> Done

##
#
#
##


# Notes on `bash`

This is just a random collection of commands which I have found useful in Bash. This Gist is expected to grow over time (until I have mastered the whole of Bash). Another useful resource is this [list of Unix commands on Wikipedia](https://en.wikipedia.org/wiki/List_of_Unix_commands#List). Hyperlinked bash commands in general lead to relevant Man (manual) pages.

## Contents

- [Notes on `bash`](#notes-on-bash)
  - [Contents](#contents)
  - [Get the current date and time and generate timestamped filenames with `date`](#get-the-current-date-and-time-and-generate-timestamped-filenames-with-date)
  - [Display date and time in `bash` history using `HISTTIMEFORMAT`](#display-date-and-time-in-bash-history-using-histtimeformat)
  - [Calculate running times of commands using `time`](#calculate-running-times-of-commands-using-time)
  - [Run script in the current shell environment using `source`](#run-script-in-the-current-shell-environment-using-source)
  - [Updating and upgrading packages using `apt update` and `apt upgrade`](#updating-and-upgrading-packages-using-apt-update-and-apt-upgrade)
  - [Seeing available disk space (using `df`) and disk usage (using `du`)](#seeing-available-disk-space-using-df-and-disk-usage-using-du)
  - [View the return code of the most recent command using `$?`](#view-the-return-code-of-the-most-recent-command-using-)
  - [Use stdout from one command as a command-line argument in another using `$()` notation](#use-stdout-from-one-command-as-a-command-line-argument-in-another-using--notation)
  - [Serial communication using `minicom`](#serial-communication-using-minicom)
  - [Change users using `su`](#change-users-using-su)
  - [Finding access permissions using `stat`](#finding-access-permissions-using-stat)
  - [Changing access permissions using `chmod`](#changing-access-permissions-using-chmod)
  - [Change ownership of a file using `chown`](#change-ownership-of-a-file-using-chown)
  - [Recursively find word counts of all files with a particular file ending](#recursively-find-word-counts-of-all-files-with-a-particular-file-ending)
  - [View all of the most recent bash commands using `history`](#view-all-of-the-most-recent-bash-commands-using-history)
  - [View the full path to a file using `realpath`](#view-the-full-path-to-a-file-using-realpath)
  - [Fixing `$'\r': command not found` error when running a bash script in WSL using `dos2unix`](#fixing-r-command-not-found-error-when-running-a-bash-script-in-wsl-using-dos2unix)
  - [Extract (unzip) a `.tar.gz` file using `tar -xvzf`](#extract-unzip-a-targz-file-using-tar--xvzf)
  - [Compress (zip) a file or directory using `tar -czvf`](#compress-zip-a-file-or-directory-using-tar--czvf)
  - [Viewing available memory and swap files using `free`](#viewing-available-memory-and-swap-files-using-free)
  - [View running processes using `ps aux`](#view-running-processes-using-ps-aux)
  - [Useful `grep` commands](#useful-grep-commands)
  - [Useful `gcc` flags (including profiling with `gprof`)](#useful-gcc-flags-including-profiling-with-gprof)
  - [Counting the number of lines in a file using `wc`](#counting-the-number-of-lines-in-a-file-using-wc)
  - [Viewing the first/last `n` lines of a file using `head`/`tail`](#viewing-the-firstlast-n-lines-of-a-file-using-headtail)
  - [Changing the bash prompt](#changing-the-bash-prompt)
  - [`apt-get update` vs `apt-get upgrade`](#apt-get-update-vs-apt-get-upgrade)
  - [Checking the version of an installed `apt` package using `apt list`](#checking-the-version-of-an-installed-apt-package-using-apt-list)
  - [Clear the console window using `clear`](#clear-the-console-window-using-clear)
  - [Iterating through files which match a file pattern](#iterating-through-files-which-match-a-file-pattern)
  - [Recursively `git add`-ing files (including files hidden by `.gitignore`)](#recursively-git-add-ing-files-including-files-hidden-by-gitignore)
  - [`git`-moving files in a loop](#git-moving-files-in-a-loop)
  - [Iteratively and recursively `git`-moving files one directory up](#iteratively-and-recursively-git-moving-files-one-directory-up)
  - [Search for files anywhere using `find`](#search-for-files-anywhere-using-find)
  - [Connect to a WiFi network from the command line using `nmcli`](#connect-to-a-wifi-network-from-the-command-line-using-nmcli)
  - [View the hostname and IP address using `hostname`](#view-the-hostname-and-ip-address-using-hostname)
  - [Viewing the properties of a file using `file`](#viewing-the-properties-of-a-file-using-file)
  - [Viewing and editing the system path](#viewing-and-editing-the-system-path)
  - [Viewing the Linux distribution details using `lsb_release`](#viewing-the-linux-distribution-details-using-lsb_release)
  - [WSL](#wsl)
  - [Connecting to a serial device using WSL](#connecting-to-a-serial-device-using-wsl)
  - [View filesize using `ls -l`](#view-filesize-using-ls--l)
  - [Reboot/restart machine using `reboot`](#rebootrestart-machine-using-reboot)
  - [Shutdown machine](#shutdown-machine)
  - [Add user to group](#add-user-to-group)
  - [Check if user is part of a group](#check-if-user-is-part-of-a-group)
  - [View directory contents in a single column](#view-directory-contents-in-a-single-column)
  - [Storing `git` credentials](#storing-git-credentials)
  - [Automatically providing password to `sudo`](#automatically-providing-password-to-sudo)
  - [Sort `$PATH` and remove duplicates](#sort-path-and-remove-duplicates)
  - [Download VSCode](#download-vscode)
  - [Get the absolute path to the current `bash` script and its directory using `$BASH_SOURCE`](#get-the-absolute-path-to-the-current-bash-script-and-its-directory-using-bash_source)
  - [`ssh`](#ssh)
    - [Passwordless `ssh` terminals](#passwordless-ssh-terminals)
    - [Scripting individual `ssh` commands](#scripting-individual-ssh-commands)
    - [Displaying graphical user interfaces over `ssh` using Xming](#displaying-graphical-user-interfaces-over-ssh-using-xming)
    - [Jump over intermediate `ssh` connections using `ProxyJump`](#jump-over-intermediate-ssh-connections-using-proxyjump)
  - [Synchronise remote files and directories with `rsync`](#synchronise-remote-files-and-directories-with-rsync)
  - [Create an `alias`](#create-an-alias)
  - [Create a symbolic link using `ln -s`](#create-a-symbolic-link-using-ln--s)
  - [Find CPU details (including model name) using `lscpu`](#find-cpu-details-including-model-name-using-lscpu)

## Get the current date and time and generate timestamped filenames with `date`

The command `date` can be used to print the current date and time on the command line, or to get a string variable containing the current date and time which can be used in future commands, for example:

```
$ date
Fri Feb 11 14:53:37 GMT 2022
$ echo $(date) > ~/temp.txt
$ cat ~/temp.txt
Fri Feb 11 14:53:39 GMT 2022
```

It can also be used to generate a timestamped filename on the command line, for example:

```
$ mkdir ./temp && cd ./temp
$ ls
$ echo "Hello, world!" > "Info $(date '+%Y-%m-%d %H-%M-%S').txt"
$ ls
'Info 2022-09-06 13-35-13.txt'
```

## Display date and time in `bash` history using `HISTTIMEFORMAT`

Using the command `history 10` will display the last 10 `bash` commands that were used, but not when they were used (date and time). To include this information in the bash history in the current bash terminal, use the command `export HISTTIMEFORMAT="| %Y-%m-%d %T | "`. Note that using the command `history 10` will now display the date and time of commands that were used both before and after setting `HISTTIMEFORMAT`. To make this behaviour persist in future bash terminals, use the following commands ([source](https://stackoverflow.com/a/41975189/8477566)):

```
echo 'export HISTTIMEFORMAT="| %Y-%m-%d %T | "' >> ~/.bash_profile
source ~/.bash_profile
```

Example:

```
$ history 5
   94  | 2022-05-17 15:48:24 | ls /
   95  | 2022-05-17 15:48:28 | df -h
   96  | 2022-05-17 15:48:33 | cd ~
   97  | 2022-05-17 15:48:36 | ps
   98  | 2022-05-17 15:48:40 | history 5
```

## Calculate running times of commands using `time`

Prepend a `bash` command with `time` to print the running time of that command, EG `time ls /`. Note that arguments to the command being timed don't need to be placed in quotation marks (as is the case with running commands over `ssh`). `time` displays 3 statistics, which are described below ([source](https://stackoverflow.com/a/556411/8477566)):

- `real`: wall clock time, from start to finish of the command being run, including time that the process spends being blocked
- `user`: amount of CPU time spent in user-mode code (outside the kernel), NOT including time that the process spends being blocked, summed over all CPU cores
- `sys`: amount of CPU time spent in the kernel within the process (IE CPU time spent in system calls within the kernel, as opposed to library code, which is still running in user-space), NOT including time that the process spends being blocked, summed over all CPU cores

Note that `time` can be used to time multiple sequential commands, including commands which are themselves being timed using `time`, by placing those commands in brackets. For example:

```
$ time (time ps && time ls /etc/cron.daily)
  PID TTY          TIME CMD
 1035 tty1     00:00:00 bash
 1156 tty1     00:00:00 bash
 1157 tty1     00:00:00 ps

real    0m0.024s
user    0m0.000s
sys     0m0.016s
apport  apt-compat  bsdmainutils  dpkg  logrotate  man-db  mdadm  mlocate  passwd  popularity-contest  ubuntu-advantage-tools  update-notifier-common

real    0m0.026s
user    0m0.000s
sys     0m0.016s

real    0m0.052s
user    0m0.000s
sys     0m0.031s
```

## Run script in the current shell environment using `source`

Given a script called `./script`, running the command `source script` will run `script` in the current shell environment. This means that any environment variables etc set in `script` will persist in the current shell. This is different from running `./script` or `bash script` or `bash ./script`, which will execute the commands in `script` in a new shell environment, so any changes to the shell environment made by `script` will not persist in the current shell (EG if `script` changes an environment variable or sets a new one, the value of that environment variable will not persist once `script` has finished running).

This can be useful EG if making a change to `~/.bashrc` (`bashrc` stands for "Bash Run Commands", which are run every time a bash shell is started) using `nano`, and wanting to apply those changes to the current shell without closing it and starting a new one:

```
$ nano ~/.bashrc
$ # <Make changes to the shell in the nano text editor>
$ source ~/.bashrc
```

## Updating and upgrading packages using `apt update` and `apt upgrade`

To update `apt` package lists, use the command `sudo apt update`. This command doesn't modify, upgrade or install any new or existing packages, but should be run before upgrading or installing any new or existing packages, to make sure that the most recent versions of those packages are used.

To upgrade all existing packages to their most recent versions, use the command `sudo apt upgrade`. This should be called before installing any new packages using `sudo apt install package-name`, to avoid any dependency issues.

These commands are often used one after the other, before installing a new package, as follows:

```
sudo apt update
sudo apt upgrade
```

## Seeing available disk space (using `df`) and disk usage (using `du`)

To see how much disk space is available, use the command `df`. To view the output in a human-readable format which chooses appropriate memory units for each file system (GB, MB, etc.), use the `-h` flag:

```
df -h
```

To see the size of a file or directory, use the `du` command (`du` stands for disk usage) (again, use the `-h` flag for human-readable format). This program can accept multiple files and/or directories in a single command:

```
du -h file1 [file2 dir1 dir2 etc]
```

If a directory is given to `du`, `du` will recursively search through the directory and print the size of all files in the directory. To only print the total size of the directory, use the `-s` flag (short for `--summarize`).

`du` can also accept wildcards. For example, to print the sizes of all files and directories in the user's home directory (printing the size of directories, but not the files and subdirectories within), use the following command:

```
du -sh ~/*
```

Note that this is different to `du -sh ~` or `du -sh ~/`, which would only print the size of the home directory.

To print the sizes of all directories in the root directory (note that this command runs surprisngly quickly compared to searching through the filesystem on Windows):

```
sudo du -sh /*
```

To sort the output from `du`, pipe the input into `sort`, and [as described here](https://serverfault.com/a/156648/620693), if using the `-h` flag for `du`, then also provide the `-h` flag to `sort`, so that `sort` will sort according to human-readable file-sizes, as shown below:

```
du -sh /path/to/dir/* | sort -h
```

To view the `N` biggest file-sizes, pipe the output from the previous command into `tail`, for example:

```
du -sh /path/to/dir/* | sort -h | tail -n10
```

## View the return code of the most recent command using `$?`

View the return code of the most recent command run in the current `bash` process using the following command:

```
echo $?
```

It is also possible to use `$?` as a regular `bash` variable, EG it can be compared in logical conditions.

## Use stdout from one command as a command-line argument in another using `$()` notation

The stdout from one command can be used as a command-line argument in another using `$()` notation, as shown in the following examples:

```
$ echo $(ls -p)
gui_testing_data/ gui_test.py package.json package-lock.json README.md requirements.txt src/
$ wc -l $(ls -p | grep -v "/")
    39 gui_test.py
    24 package.json
  9671 package-lock.json
     9 README.md
     0 requirements.txt
  9743 total
```

The next example automatically finds the name of the serial device to use with `minicom`:

```
$ minicom --device $(ls -d /dev/serial/by-id/*) --baudrate 115200
```

(Note that the `-p` flag in `ls -p` is used "to append / indicator to directories", so that this can be piped into the `grep -v "/"` which removes all directories from the list, and the `-d` flag is used along with the `*` wildcard to print the full path to the serial device, instead of the relative path to `/dev/serial/by-id/`)

## Serial communication using `minicom`

To install `minicom`:

```
sudo apt-get update
sudo apt install minicom
```

To use `minicom` with a device whose name is `$DEVICE_NAME` in the `/dev/` folder and with a baud-rate of `$BAUD_RATE`:

```
minicom --device /dev/$DEVICE_NAME --baudrate $BAUD_RATE
```

## Change users using `su`

To change to the root user, use the command `sudo su`. This can alleviate some permission problems that are not solved even by using the `sudo` command. To return to the previous user, either use the command `sudo <username>`, or just use the command `exit`, EG:

```
$ tail -n1 /etc/iproute2/rt_tables
103 vlan3
$ sudo echo "105 vlan5" >> /etc/iproute2/rt_tables
bash: /etc/iproute2/rt_tables: Permission denied
$ sudo su
root# echo "105 vlan5" >> /etc/iproute2/rt_tables
root# exit
exit
$ tail -n1 /etc/iproute2/rt_tables
105 vlan5
```

## Finding access permissions using `stat`

Use the `stat` command to find the status of a file, including its access permissions, EG:

```
$ stat /etc/iproute2/rt_tables
  File: /etc/iproute2/rt_tables
  Size: 87              Blocks: 0          IO Block: 512    regular file
Device: 2h/2d   Inode: 1125899908643251  Links: 1
Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)
Access: 2019-05-21 15:43:05.544609577 +0100
Modify: 2018-01-29 16:08:52.000000000 +0000
Change: 2020-02-06 15:48:13.093754700 +0000
 Birth: -
```

For the permissions (next to `access`):
- As described in [Unix file types on Wikipedia](https://en.wikipedia.org/wiki/Unix_file_types):
  - The first character describes the file type
- As described in the [`chmod` man page](https://ss64.com/bash/chmod.html):
  - The next three characters (characters 2-4) describe read/write/execute permissions for the user who owns the file
  - The next three characters (characters 5-7) describe read/write/execute permissions for other users in the file's group
  - The next three characters (characters 8-10) describe read/write/execute permissions for other users NOT in the file's group

Therefore, `-rw-r--r--` says that this is a regular file, which is readable and writeable for the user who owns the file, and readable for everyone else.

## Changing access permissions using `chmod`

Use `chmod` ("change mode") to change the access permissions of a file or folder. As described in the [`chmod` man page](https://ss64.com/bash/chmod.html), the access permissions can be specified using letters (as described above in "Finding access permissions using `stat`") or in octal.

Alternatively, `chmod` can be used in symbolic mode, EG:
- `chmod u+x file` to make a file executable by the user/owner
- `chmod a+r file` to allow read permission to everyone
- `chmod a-x file` to deny execute permission to everyone
- `chmod go+rw file` to make a file readable and writable by the group and others

The examples above are taken from the [`chmod` man page](https://ss64.com/bash/chmod.html).

To make a file executable for all users, use the command `chmod +x /path/to/file`.

## Change ownership of a file using `chown`

Change the ownership of a file or directory using `chown`. If changing ownership of a directory, use the `-R` flag to also recursively change ownership of all subdirectories within that directory ([source](https://unix.stackexchange.com/a/119836/421710)). Example:

```
$ sudo chown username:groupname filename
$ sudo chown -R username:groupname dirname
$ sudo chown -R jake:jake dirname
```

## Recursively find word counts of all files with a particular file ending

The following command can be used to recursively find line counts of all files with a particular file ending (in this case `.py` for Python), excluding all files in the `venv` directory (or more specifically, any files containing the substring `venv` in their path). This is achieved by using a `$` character in the regular expression to match a line-ending, and using `\` to escape the `.` character. The sum of the line counts for all matching words is displaying at the bottom:

```
find |  grep "\.py$" | grep -v venv | xargs wc -l
```

TODO: turn this into a slightly more sophisticated Python scripy that accepts command line arguments specifying what filename ending to look for, and specifically ignoring directories containg the excluded words, and not filenames as well

## View all of the most recent bash commands using `history`

The `history` command prints out all of the previously recorded bash commands ([source](https://askubuntu.com/a/359125/1078405)). To view the most recent bash commands, the output from `history` can be piped into `tail`. For example, to print the 20 most recent bash commands:

```
history | tail -n20
```

To search for a specific command, the output from `history` can be piped into `grep`, EG:

```
$ history | grep realpath
  493  realpath ~
  505  history | grep realpath
```

## View the full path to a file using `realpath`

To view the full path to a file, use the `realpath` command, EG:

```
$ realpath ~
/home/jol
```

## Fixing `$'\r': command not found` error when running a bash script in WSL using `dos2unix`

As described [here](https://askubuntu.com/a/1046371/1078405), this is because of a carriage return used in DOS-style line endings. The problem can be solved as follows:

```
sudo apt-get update
sudo apt-get install dos2unix
dos2unix name_of_shell_script.sh
./name_of_shell_script.sh
```

## Extract (unzip) a `.tar.gz` file using `tar -xvzf`

A `.tar.gz` file can be unzipped easily in `bash` on Linux or in WSL.

To extract a file or direcrory ([source](https://askubuntu.com/a/25348/1078405)):

```bash
tar -xvzf compressed_file_name.tar.gz
```

To extract into a particular directory:

```bash
tar -xvzf compressed_file_name.tar.gz -C output_dir_name
```

Description of flags:

> - `x`: tar can collect files or extract them. x does the latter.
> - `v`: makes tar talk a lot. Verbose output shows you all the files being extracted.
> - `z`: tells tar to decompress the archive using gzip
> - `f`: this must be the last flag of the command, and the tar file must be immediately after. It tells tar the name and path of the compressed file.
> - `C`: means change to the directory specified by the following argument (NB this directory must already exist, if it doesn't then first create it using `mkdir`)

## Compress (zip) a file or directory using `tar -czvf`

A `.tar.gz` file can be created easily in `bash` on Linux or in WSL.

To zip up a file ([source](https://www.howtogeek.com/248780/how-to-compress-and-extract-files-using-the-tar-command-on-linux/)):

```
tar -czvf name-of-archive.tar.gz /path/to/directory-or-file
```

> Here’s what those switches actually mean:
>
> - `c`: Create an archive.
> - `z`: Compress the archive with gzip.
> - `v`: Display progress in the terminal while creating the archive, also known as "verbose" mode. The v is always optional in these commands, but it’s helpful.
> - `f`: Allows you to specify the filename of the archive.


## Viewing available memory and swap files using `free`

The `free` command can be used to view available RAM, RAM usage, and available/used memory in swap files. More information about how to create a swap file can be found in [this tutorial](https://linuxize.com/post/create-a-linux-swap-file/). The `-h` flag can be used with the `free` command to produce a more human-readable output:

```
$ free -h
              total        used        free      shared  buff/cache   available
Mem:            15G        8.8G        6.8G         17M        223M        6.9G
Swap:           29G         56M         29G
```

## View running processes using `ps aux`

`ps` and `top` are two commands which can be used to view running processes, their CPU usage, process ID, etc. They differ mainly in that "`top` is mostly used interactively", while "`ps` is designed for non-interactive use (scripts, extracting some information with shell pipelines etc.)", as described [in this Stack Overflow answer](https://unix.stackexchange.com/a/62186/421710) (see [here](https://superuser.com/questions/451344/difference-between-ps-output-and-top-output) for more differences).

One thing to notice in `top` is that some processes are suffixed by `d` to denote that they are daemon processes ([as described here](https://unix.stackexchange.com/a/72590)), and some processes are prefixe by `k` to denote that they are kernel threads ([as described here](https://superuser.com/a/1087716/1098000)).

When using `ps`, the following flags are useful, as described [here](https://unix.stackexchange.com/a/106848/421710):

- `a` - show processes for all users
- `u` - display the process's user/owner
- `x` - also show processes not attached to a terminal

It is often useful to pipe the output from `ps` into `grep` to narrow down the list of processes to those of interest, for example:

```
ps aux | grep -i cron
```

## Useful `grep` commands

`grep` stands for **G**lobal (-ly search for a) **R**egular **E**xpression (and) **P**rint (the results). It is especially useful for filtering the outputs of other command-line tools or files. Here are some useful features of `grep` (`TODO`: make this into a separate Gist?):

- The `-v` ("in**v**ert") flag can be used print only the lines which **don't** contain the specified string (this is the opposite of the normal behaviour of grep, which prints out lines which do contain the specified string). This can be useful when piping together `grep` commands, to include some search queries and exclude others, EG in the command `sudo find / | grep tensorrt | grep -v cpp`

  - Hint: put the inverted expression before the non-inverted expression to get the results of the non-inverted expression highlighted in the bash terminal output, if this feature is available and preferred

- The `-i` flag can be used for case-**i**nsensitive pattern-matching, IE `grep -i foo` will match `foo`, `FOO`, `fOo`, etc.

- `grep` can be used to search for strings within a file, using the syntax `grep <pattern> <file>` ([source](https://stackoverflow.com/a/48492465/8477566))

- The outputs from grep can be used as the input to a program which doesn't usually accept inputs from `stdin` using the `xargs` command, EG `find | grep svn | xargs rm -rfv` will recursively delete all files and folders in the current directory that contain the string `svn` (good riddance!) (the `-v` flag will also cause `rm` to be verbose about every file and folder which it deletes)

- ...

## Useful `gcc` flags (including profiling with `gprof`)

Flag | Meaning
--- | ---
`-H` | "Print the full path of include files in a format which shows which header includes which" (note that the header file paths are printed to `stderr`) ([source](https://stackoverflow.com/a/18593344/8477566))
`-M` | "Output a rule suitable for `make` describing the dependencies of the main source file. The preprocessor outputs one make rule containing the object file name for that source file, a colon, and the names of all the included files" (the dependencies include both the header files and source files) ([source 1](https://gcc.gnu.org/onlinedocs/gcc/Preprocessor-Options.html#Preprocessor-Options), [source 2](https://stackoverflow.com/a/42513/8477566))
`-MM` | "Like `-M` but do not mention header files that are found in system header directories" ([source](https://gcc.gnu.org/onlinedocs/gcc/Preprocessor-Options.html#Preprocessor-Options))
`-fsanitize=address -fsanitize=undefined -fsanitize=float-divide-by-zero -fno-sanitize-recover` | "Enable AddressSanitizer, a fast memory error detector", and other useful Program Instrumentation Options ([source 1](https://gcc.gnu.org/onlinedocs/gcc/Instrumentation-Options.html)) ([source 2](https://man7.org/linux/man-pages/man1/gcc.1.html)). Note that it is necessary "to add `-fsanitize=address` to compiler flags (both `CFLAGS` and `CXXFLAGS`) and linker flags (`LDFLAGS`)" ([source](https://stackoverflow.com/a/40215639/8477566))
`-pg` | "From the man page of `gcc`": "Generate extra code to write profile information suitable for the analysis program `gprof`. You must use this option when compiling the source files you want data about, **and you must also use it when linking**." After compiling and linking using the `-pg` flags, execute the program, EG `./name_of_exe`, which should produce a file called `gmon.out`, and then use `gprof` to generate formatted profiling information as follows: `gprof name_of_exe gmon.out > analysis.txt` ([source](https://www.thegeekstuff.com/2012/08/gprof-tutorial/))
` -Xlinker -Map=output.map ` | Use these flags while linking to generate a map file called `output.map`, describing the data and instruction memory usage in the executable ([source](https://stackoverflow.com/a/38961713/8477566))

## Counting the number of lines in a file using `wc`

Use the program `wc` (which is a mandatory UNIX command, and stands for "word count") can be used to count the number of words, lines, characters, or bytes in a file. To count the number of lines in a file, use the `-l` flag, for example in the file `/etc/dhcp/dhclient.conf`:

```
wc -l /etc/dhcp/dhclient.conf
```

`wc` can also accept a list of files as separate arguments (separated by spaces).

As described on [the Wikipedia page for `wc`](https://en.wikipedia.org/wiki/Wc_(Unix)#Usage), the `-l`flag prints the line count, the `-c` flag prints the byte count, the `-m` flag prints the character count, the `-L` flag prints the length of the longest line (GNU extension), and the `-w` flag prints the word count. Example:

```
$ wc -l /etc/dhcp/dhclient.conf
54 /etc/dhcp/dhclient.conf
$ wc -w /etc/dhcp/dhclient.conf
207 /etc/dhcp/dhclient.conf
$ wc -c /etc/dhcp/dhclient.conf
1735 /etc/dhcp/dhclient.conf
$ wc -m /etc/dhcp/dhclient.conf
1735 /etc/dhcp/dhclient.conf
```

The `wc -l` command is useful for counting the number of lines in a file before printing the first or last N lines of the file using the `head` or `tail` commands (see below), where N ≤ the number of lines in the file.

## Viewing the first/last `n` lines of a file using `head`/`tail`

To view the first n lines of a text file, use the `head` command with the `-n` flag, EG:

```
$ head -n5 /etc/dhcp/dhclient.conf
# Configuration file for /sbin/dhclient.
#
# This is a sample configuration file for dhclient. See dhclient.conf's
#       man page for more information about the syntax of this file
#       and a more comprehensive list of the parameters understood by
```

Similarly, use the `tail` command to view the last n lines of a text file.

## Changing the bash prompt

The bash prompt can be changed by simply setting a new value to the `PS1` variable; here is an example using WSL:

```
PS C:\Users\Jake\Documents> bash
jake@Jakes-laptop:/mnt/c/Users/Jake/Documents$ PS1="$ "
$ echo test
test
$ date
Fri Apr 24 18:17:17 BST 2020
$
```

In order to change the prompt back to its previous value, store the value in a different variable before changing it:

```
PS C:\Users\Jake\Documents> bash
jake@Jakes-laptop:/mnt/c/Users/Jake/Documents$ DEFAULT=$PS1
jake@Jakes-laptop:/mnt/c/Users/Jake/Documents$ PS1="$ "
$ date
Fri Apr 24 18:25:49 BST 2020
$ PS1=$DEFAULT
jake@Jakes-laptop:/mnt/c/Users/Jake/Documents$
```

## `apt-get update` vs `apt-get upgrade`

Regarding the difference between these commonly used commands, as described in [this Stack Overflow answer](https://askubuntu.com/a/222352/1078405):

> - `apt-get update` downloads the *package lists* from the repositories and "updates" them to get information on the newest versions of packages and their dependencies, for all repositories and PPAs (doesn't actually install new versions of software)
> - `apt-get upgrade` will fetch new versions of packages existing on the machine if APT knows about these new versions by way of `apt-get update`
> - `apt-get dist-upgrade` will do the same job which is done by `apt-get upgrade`, plus it will also intelligently handle the dependencies, so it might remove obsolete packages or add new ones
>
> You can combine commands with `&&` as follows:

```
sudo apt-get update && sudo apt-get dist-upgrade
```

As described in [this Stack Overflow answer](https://askubuntu.com/a/226213/1078405), as to why you would ever want to use `apt-get upgrade` instead of `apt-get dist-upgrade`:

> Using upgrade keeps to the rule: under no circumstances are currently installed packages removed, or packages not already installed retrieved and installed. If that's important to you, use `apt-get upgrade`. If you want things to "just work", you probably want `apt-get dist-upgrade` to ensure dependencies are resolved

In summary, `apt-get upgrade` is likely to be safer if it works, but if not, `apt-get dist-upgrade` is more likely to work.

## Checking the version of an installed `apt` package using `apt list`

To view the version of a installed package which is available through `apt` (Advanced Package Tool), use the command `apt list <package-name>` for a concise description, or `apt show <package-name>` for a more verbose output. (A similar command, `apt policy <package-name>` is also available, although currently I'm not sure what the difference is between `apt show` and `apt policy` is).

To view a list of all installed packages, use the command

```
apt list --installed
```

This list can be very large, so it might be sensible to redirect the output into a text file. To do this and then display the first 100 lines of the text file:

```
apt list --installed > aptlistinstalled.txt && head -n100 aptlistinstalled.txt
```

To achieve the same thing but without saving to a text file:

```
apt list --installed | head -n100
```

To list all installed packages which contain the string "`cuda`":

```
apt list --installed | grep cuda
```

## Clear the console window using `clear`

The console window can be cleared using the command `clear`.

## Iterating through files which match a file pattern

It is possible to iterate through files which match a file pattern by using a `for`/`in`/`do`/`done` loop, using the `*` syntax as a wildcard character for string comparisons, and using the `$` syntax to access the loop-variable ([source](https://stackoverflow.com/a/2305537/8477566)). For example, the following loop will print out all the files whose names start with `cnn_mnist_`:

```
for FILE in cnn_mnist_*; do echo $FILE; done
```

## Recursively `git add`-ing files (including files hidden by `.gitignore`)

To recursively add all files in the current directory and all its subdirectories, use the following command (the `-f` flag instructs `git` to add files even if they included in `.gitignore`, which is useful EG for committing specific images):

```
git add ** -f
```

## `git`-moving files in a loop

The example above about "iterating through files which match a file pattern" can be modified to `git`-move all the files that start with `cnn_mnist_` into a subfolder called `cnn_mnist`. The `-n` flag tells `git` to do a "dry-run" (showing what will happen/checking validity of the command without actually executing the command); remove the `-n` flag to to actually perform the `git mv` command:

```
for FILE in cnn_mnist_*; do git mv -n $FILE cnn_mnist/$FILE; done
```

The following will do the above, but removing the `cnn_mnist_` from the start of each string using a bash parameter expansion:

```
for FILE in cnn_mnist_*; do NEW_FILE=${FILE//cnn_mnist_/}; git mv -n $FILE cnn_mnist/$NEW_FILE; done
```

## Iteratively and recursively `git`-moving files one directory up

Following the examples above, to recursively `git`-move all files and folders in the current directory up by one directory (the `-n` flag is included here again to perform a dry run; remove the `-n` flag to perform an actual `git`-move command):

```
for FILE in ./*; do git mv -n $FILE ../$FILE; done
```

Note that `git` will recursively move the contents of any subdirectories by default.

## Search for files anywhere using `find`

To search for a file `file_to_search_for` in the directory `path/to/search`, use the [`find`](https://linux.die.net/man/1/find) command, EG:

```
sudo find path/to/search -name file_to_search_for
```

Note that the `find` command will automatically search recursively through subdirectories; sudo must be used to allow access to restricted directories. Patterns can be used, EG to search for any filename ending or file extension, but it may be necessary to put the `names` argument in single-quotes, to prevent a wildcard expansion to be applied before the program is called, as described in [this Stack Overflow answer](https://stackoverflow.com/a/6495536/8477566):

```
sudo find path/to/search -name 'file_to_search_for*'
```

Similarly, to check for Python scripts or shared object files:

```
sudo find path/to/search -name '*.py'
sudo find path/to/search -name '*.so'
```

To search the entire filesystem, replace `path/to/search` with `/`; this can be useful to check if a library is installed anywhere on the system, and return the location of that library, in case it is not on the system path (if it is on the system path, it can be found with [`which`](https://linux.die.net/man/1/which)).

Note that an alternative to using the `-name` flag is to pipe the output from `find` into `grep`, EG:

```
sudo find / | grep nvcc
```

Unlike using `-name`, `grep` will match the search query anywhere in the filename or directory (instead of an exact filename), without further modifications.

To only return paths to files from `find` and not include paths to directories, use the `-type f` option, EG:

```
sudo find / -type f | grep nvcc | grep -v docker  | wc -l
```

If no args are passed to `find` then it will recursively search through the current directory and print out the names of all files and subdirectories, EG `find | grep svn`.

## Connect to a WiFi network from the command line using `nmcli`

As described in Part 3 of [this Stack Overflow answer](https://askubuntu.com/a/16588/1078405), a WiFi network can be easily connected to from the command line using the `nmcli` command:

```
nmcli device wifi connect ESSID_NAME password ESSID_PASSWORD
```

To simply view a list of available WiFi networks:

```
nmcli device wifi
```

To view a list of *all* available internet connections (ethernet, wifi, etc):

```
nmcli device
```

Note that when running `nmcli` commands, `device`, `dev`, and `d` are all synonymous, and can be used interchangeably.

## View the hostname and IP address using `hostname`

To view the hostname, use the following command:

```
hostname
```

An alternative command is:

```
echo $HOSTNAME
```

To view the IP address, use the following command (see [this Stack Overflow answer](https://stackoverflow.com/a/13322549/8477566) for details):

```
hostname -I
```

## Viewing the properties of a file using `file`

The `file` command can be used to view the properties of a file, EG whether a shared library is 32-bit or 64-bit, and which platform it was compiled for:

```
$ file lib.c
lib.c: ASCII text, with CRLF line terminators
$ file lib.dll
lib.dll: PE32 executable (DLL) (console) Intel 80386, for MS Windows
$ file lib64.dll
lib64.dll: PE32+ executable (DLL) (console) x86-64, for MS Windows
```

## Viewing and editing the system path

To view the system path (directories in which executables can be run from any other directory without need to specify the path to the executable):

```bash
echo $PATH
```

This will print every directory on the system path, separated by a colon. To print each directory on a new line, there are multiple options; one option is to use a global (`g`) regular-expression substitution (`s`) using the Unix program [`sed`](https://en.wikipedia.org/wiki/Sed) (short for Stream EDitor) as follows, where `:` is the regular expression to be matched, and `\n` is what it is to be replaced with:

```bash
echo $PATH | sed 's/:/\n/g'
```

Another option is to use a [shell parameter expansion](https://stackoverflow.com/questions/13210880/replace-one-substring-for-another-string-in-shell-script/13210909):

```bash
echo -e "${PATH//:/'\n'}"
```

To add a new directory to the path ([source](https://unix.stackexchange.com/questions/26047/how-to-correctly-add-a-path-to-path)):

```bash
PATH=$PATH:~/new/dir
```

## Viewing the Linux distribution details using `lsb_release`

The command `lsb_release` is used to view details about the current Linux distribution under the Linux Standard Base (LSB), and optionally any LSB modules that the system supports. Using this command with flags `lsb_release -irc` will show the distributer ID of the Linux distribution which is running, the release number of the distribution, and the code name of the distribution, EG:

```
$ lsb_release -irc
Distributor ID: Ubuntu
Release:        18.04
Codename:       bionic
```

## WSL

WSL is the Windows Subsytem for Linux, which "[allows Linux binaries to run in Windows unmodified](https://www.petri.com/bash-out-of-beta-in-windows-10)", by adding a compatability layer which presumably allows Windows to interpret Linux binary [Executable Formats and Application Binary Interfaces](https://stackoverflow.com/questions/2059605/why-an-executable-program-for-a-specific-cpu-does-not-work-on-linux-and-windows).

To open a Windows path in WSL, open a Windows command prompt (Powershell or CMD) in that location, and run `bash` (with no arguments).

## Connecting to a serial device using WSL

To connect to a serial device using WSL (see above), the COM port for the serial device must be found in Windows Device Manager. Say the device is connected to COM3, it can be connected to from WSL with a baud rate of 115200 using the following command ([source 1](https://docs.microsoft.com/en-gb/archive/blogs/wsl/serial-support-on-the-windows-subsystem-for-linux), [source 2](https://www.scivision.dev/usb-tty-windows-subsystem-for-linux/)):

```bash
sudo chmod 666 /dev/ttyS3 && stty -F /dev/ttyS3 115200 && sudo screen /dev/ttyS3 115200
```

## View filesize using `ls -l`

The command `ls` will list files and subdirectories in the directory that is specified as an argument (with no argument, the current directory is used by default). The `-l` flag is used to specify a long-list format, which gives extra data such as permissions, file-size in bytes, time of last edit, and more. The option `--block-size MB` can be used with the `-l` flag to specify file-sizes in megabytes. In this case, a single filename can be used as the main argument to `ls`, in which case only the details for the specified file will be listed. In summary, the syntax for viewing the size of a file in megabytes is:

```
ls -l --block-size MB path/to/file
```

## Reboot/restart machine using `reboot`

A machine can be rebooted from terminal using `reboot`:

```
sudo reboot
```


## [Shutdown](https://youtu.be/MQOG5BkY2Bc) machine

A machine can be shut down from terminal using [`shutdown`](https://youtu.be/MQOG5BkY2Bc):

```
sudo shutdown now
```

This is useful for example for a [Coral Dev Board](https://coral.ai/products/dev-board/); as stated at the bottom of the [getting started guide](https://coral.ai/docs/dev-board/get-started/), the power cable should not be removed from the Dev Board while the device is still on, because this risks corrupting the system image if any write-operations are in progress. The Dev Board can be safely shutdown by calling in terminal `sudo shutdown now`; when the red LED on the Dev Board turns off, the power cable can be unplugged.

## Add user to group

To add a user to a group (which may be necessary for obtaining permissions to complete other tasks), use [`usermod`](https://linux.die.net/man/8/usermod):

```
sudo usermod -aG groupname username
```

## Check if user is part of a group

To see the groups of which a user is a member of, use the [`id`](http://man7.org/linux/man-pages/man1/id.1.html) command:
```
id -nG username
```

To see if the user is a member of a particular group, pipe the output from the `id` command into `grep` followed by the name of the relevant group; if the user is a member of this group, then a line of text from the output of `id` containing the name of that group will be printed; otherwise nothing will be printed. NB this can be used as an `if` condition, EG ([source](https://stackoverflow.com/questions/18431285/check-if-a-user-is-in-a-group)):

```bash
if id -nG "$USER" | grep -qw "$GROUP"; then echo $USER belongs to $GROUP; fi
```

NB the `q` and `w` flags are being used to make `grep` quiet, and only match whole words.

## View directory contents in a single column

To view directory contents in a single column (as opposed to the default table view of `ls`), using the `-1` flag (as in numerical one, not a letter L or I):

```
ls -1
```

## Storing `git` credentials

As stated in [this StackOverflow answer](https://stackoverflow.com/a/52298381/8477566) to the question entitled [Visual Studio Code always asking for git credentials](https://stackoverflow.com/q/34400272/8477566), a simple but non-ideal solution to the problem is to use the following command:

```
git config --global credential.helper store
```

Note that this method is unsafe, because the credentials are stored in plain text in the file `~/.git-credentials`, and these credentials can become compromised if the system becomes hacked. Another solution, as stated in [this answer](https://stackoverflow.com/a/34627954/8477566), is to use the `git` credential helper to store the credentials in memory with a timeout (default is 15 minutes), EG:

```
git config --global credential.helper 'cache --timeout=3600'
# Set the cache to timeout after 1 hour (setting is in seconds)
```

Yet another solution, as stated in [this answer to a post on Reddit](https://www.reddit.com/r/vscode/comments/832xbj/how_to_stop_the_git_login_popup_in_vscode/dvf94cb?utm_source=share&utm_medium=web2x&context=3), is to use "Git Credential Manager Core (GCM Core)", as described in [these instructions](https://docs.github.com/en/get-started/getting-started-with-git/caching-your-github-credentials-in-git).

[This StackOverflow answer](https://stackoverflow.com/a/15382950/8477566) provides instructrions for how to unset the `git` credentials, using the following command:

```
git config --global --unset credential.helper
```

Note that the command `rm ~/.git-credentials` should also be used after the above command in order to delete the saved credentials.

This answer also states that:

> You may also need to do `git config --system --unset credential.helper` if this has been set in the system configuration file (for example, Git for Windows 2).

## Automatically providing password to `sudo`

As stated in [this StackOverflow answer](https://superuser.com/a/67766/1098000), `sudo` can be used with the `-S` switch, which causes `sudo` to read the password from `stdin`:

```
echo <password> | sudo -S <command>
```

## Sort `$PATH` and remove duplicates

These Python commands can be used on Linux to organise `$PATH` into alphabetical order and remove duplicates, and print the result to `stdout`:

```python
import os

path_list = os.getenv("PATH").split(":")
no_final_slash = lambda s: s[:-1] if (s[-1] == "/") else s
unique_path_set = set(no_final_slash(os.path.abspath(p)) for p in path_list)
sorted_unique_path_list = sorted(unique_path_set, key=lambda s: s.lower())

print("*** Separated by newlines ***")
print("\n".join(sorted_unique_path_list))
print("*** Separated by colons ***")
print(":".join(sorted_unique_path_list))
```

## Download VSCode

[Source](https://code.visualstudio.com/docs/setup/linux)

```
sudo apt update
sudo apt upgrade
sudo snap install --classic code # or code-insiders
```

## Get the absolute path to the current `bash` script and its directory using `$BASH_SOURCE`

Use the variable `$BASH_SOURCE` to get the path to the current `bash` script. Use this with `realpath` and `dirname` to get the absolute path of the script, and its parent directory. For example:

```bash
X1=$BASH_SOURCE
X2=$(realpath $BASH_SOURCE)
X3=$(dirname $(realpath $BASH_SOURCE))
echo $X1
echo $X2
echo $X3
```

## `ssh`

To open a terminal session on a remote Linux device on a local network, use the following command on the host device:

```
ssh username@hostname
```

After using this command, `ssh` should ask for the password for the specified user on the remote device.

If `stdout` is not being flushed over `ssh`, this problem can be fixed by passing the `-t` command to `ssh`, EG `ssh -t username@hostname` ([source](https://serverfault.com/a/437739/620693))

### Passwordless `ssh` terminals

To configure `ssh` to not request a password when connecting, use the following commands on the local device, replacing `$(UNIQUE_ID)` with a string which is unique to `username@hostname` (the password for `ssh-keygen` can be left blank, whereas the correct password for `username@hostname` needs to be entered when running `ssh-copy-id`):

```
ssh-keygen  -f ~/.ssh/id_rsa_$(UNIQUE_ID)
ssh-copy-id -i ~/.ssh/id_rsa_$(UNIQUE_ID) username@hostname
```

Now `username@hostname` can be connected to over `ssh` without needing to enter a password, using the command `ssh -i ~/.ssh/id_rsa_$(UNIQUE_ID) username@hostname`. To automate this further such that the path to the SSH key doesn't need to be entered when using `ssh`, edit `~/.ssh/config` using the following command:

```
nano ~/.ssh/config
```

Enter the following configuration, replacing `$(SHORT_NAME_FOR_REMOTE_USER)` with a short name which is unique to `username@hostname`:

```
Host $(SHORT_NAME_FOR_REMOTE_USER)
   User username
   Hostname hostname
   IdentityFile ~/.ssh/id_rsa_$(UNIQUE_ID)
```

Save and exit `nano`. `username@hostname` can now be connected to over `ssh` using the following command, without being asked for a password ([source](https://stackoverflow.com/a/41135590/8477566)):

```
ssh $(SHORT_NAME_FOR_REMOTE_USER)
```

This should also allow `rsync` to run without requesting a password, again by replacing `username@hostname` with `$(SHORT_NAME_FOR_REMOTE_USER)`.

If the above steps don't work and `ssh` still asks for a password, the following tips may be useful:
- Make sure that the `~` and `~/.ssh` directories and the `~/.ssh/authorized_keys` file on the remote machine have the correct permissions ([source 1](https://superuser.com/a/925859/1098000)) ([source 2](https://serverfault.com/a/271054/620693)) ([source 3](https://askubuntu.com/a/90465/1078405)):
  - `~` should not be writable by others. Check with `stat ~` and fix with `chmod go-w ~`
  - `~/.ssh` should have `700` permissions. Check with `stat ~/.ssh` and fix with `chmod 700 ~/.ssh`
  - `~/.ssh/authorized_keys` should have `644` permissions. Check with `stat ~/.ssh/authorized_keys` and fix with `chmod 644 ~/.ssh/authorized_keys`
- If the permissions were wrong and have been changed and passwordless `ssh` still doesn't work, consider restarting the `ssh` service with `service ssh restart` ([source](https://superuser.com/a/925859/1098000))
- Make sure that the line `PubkeyAuthentication yes` is present in `/etc/ssh/sshd_config` on the remote device, and not commented out with a `#` (as in `#PubkeyAuthentication yes`) ([source](https://superuser.com/a/904667/1098000)).
- Call `ssh-copy-id` with the `-f` flag on the local device
- Consider checking the permissions of the `id_rsa` files on the local machine ([source 1](https://serverfault.com/a/434498/620693)) ([source 2](https://unix.stackexchange.com/a/36687/421710))

### Scripting individual `ssh` commands

To run individual commands on a remote device over `ssh` without opening up an interactive terminal, use the following syntax (the quotation marks can be ommitted if there are no space characters between the quotation marks):

```
ssh username@hostname "command_name arg1 arg2 arg3"
```

It may be found that commands in `~/.bashrc` on the remote device are not run when using the above syntax to run single commands over `ssh` on the remote device, which might be a problem EG if `~/.bashrc` adds certain directories to `$PATH` which are needed by the commands which are being run over `ssh`. This might be because the following lines are present at the start of `~/.bashrc` on the remote device:

```
# ~/.bashrc: executed by bash(1) for non-login shells.
# see /usr/share/doc/bash/examples/startup-files (in the package bash-doc)
# for examples

# If not running interactively, don't do anything
case $- in
    *i*) ;;
      *) return;;
esac
```

These lines cause `~/.bashrc` to exit if it's not being run interactively, which is the case when running single commands over `ssh`. To solve this problem, either put whichever commands that need to be run non-interactively in `~/.bashrc` before the line `case $- in`, or comment out the lines from `case $- in` to `esac` (inclusive) on the remote device ([source](https://serverfault.com/a/1062611/620693)).

### Displaying graphical user interfaces over `ssh` using Xming

From WSL on a Windows PC, it is possible to display graphical user interfaces which are running on a remote Linux device using X11 forwarding. To do so:

- Install Xming on the Windows machine from [here](https://sourceforge.net/projects/xming/)
- Make sure Xming is running on the Windows machine (there should be an icon for Xming in the icon tray in the Windows taskbar when Xming is running)
- Use the `-X` flag when connecting over `ssh`, EG `ssh -X username@hostname`
- Test that X11 forwarding is running succesfully by entering the command `xclock` in the `ssh` terminal, which should cause a clock face to appear on the Windows machine
- If this doesn't work, it may be necessary to use the command `export DISPLAY=localhost:0.0` in WSL, and/or to add this command to the bottom of `~/.bashrc` (EG using the command `echo "export DISPLAY=localhost:0.0" >> ~/.bashrc`) and restart the WSL terminal
- If an error message is displayed from the remote machine saying `connect localhost port 6000: Connection refused`, then make sure that Xming is running on the local machine

### Jump over intermediate `ssh` connections using `ProxyJump`

- Sometimes it is desirable to connect to `username@hostname` over `ssh`, but to do so it is necessary to first connect to `username_proxy@hostname_proxy` over `ssh`, and from `username_proxy@hostname_proxy` connect to `username@hostname` over `ssh`
- This can be automated by adding entries into `~/.ssh/config` (see section "[Passwordless `ssh` terminals and commands](#passwordless-ssh-terminals)" above) for `username@hostname` and `username_proxy@hostname_proxy` with aliases `shortname` and `shortname_proxy`, and under the configuration for `shortname`, add the line `ProxyJump shortname_proxy` (following the indentation of the lines above)
- Now, when using the command `ssh shortname`, `ssh` will automatically connect to `shortname_proxy` first, and from `shortname_proxy` connect to `shortname` over `ssh`
- Note that if using `ssh-keygen` and `ssh-copy-id` to log into `username@hostname` without a password (described above), then an entry for `username@hostname` should first be added to `~/.ssh/config` on the local machine (including the `ProxyJump` entry described above), then `ssh-keygen` and `ssh-copy-id` should be used on the local machine (not from `username_proxy@hostname_proxy`) to enable passwordless access to `username@hostname` directly from the local machine

## Synchronise remote files and directories with `rsync`

To synchronise a local directory with a remote directory, use the following command:

```
rsync -Chavz /path/to/local/dir username@hostname:~/path/to/remote
```

Description of flags:

Flag | Meaning
--- | ---
`-C` | Automatically ignore common temporary files, version control files, etc
`-h` | Use human-readable file sizes (EG `65.49K bytes` instead of `65,422 bytes`)
`-a` | Sync recursively and preserves symbolic links, special and device files, modification times, groups, owners, and permissions
`-v` | Verbose output is printed to `stdout`
`-z` | Compress files (EG text files) to reduce network transfer

([source 1](https://www.digitalocean.com/community/tutorials/how-to-use-rsync-to-sync-local-and-remote-directories)) ([source 2](https://linux.die.net/man/1/rsync))

- To configure `rsync` to not request a password when synchronising directories, follow the instructions in the previous section "[Passwordless `ssh` terminals and commands](#passwordless-ssh-terminals)".
- `rsync` can be used with the `--delete` option to delete extra files in the remote directory that are not present in the local directory ([source](https://askubuntu.com/a/665918/1078405)).
- To ignore certain files (EG hidden files, `.pyc` files), use the `--exclude=$PATTERN` flag
  - Multiple `--exclude` flags can be included in the same command, EG `rsync -Chavz . hostname:~/target_dir --exclude=".*" --exclude="*.pyc"`
- To copy the contents of the *current directory on the local machine to* a subdirectory of the home directory called `target_dir` on the remote machine, use the command `rsync -Chavz . hostname:~/target_dir` (note *no* `/` character after `target_dir`)
- To copy the contents of a subdirectory of the home directory on the remote machine called `target_dir` *to the current directory on the local machine*, use the command `rsync -Chavz hostname:~/target_dir/ .` (note that there *is* a `/` character after `target_dir`)

## Create an `alias`

Use `alias` to create an alias, EG `alias gcc-7=gcc`. This means that every time `bash` tries to use the command `gcc-7`, instead it will replace `gcc-7` with `gcc` (but the rest of the command will remain unchanged). This might be useful EG if a shell script assumes that `gcc-7` is installed, and keeps trying to call this version specifically with the command `gcc-7`, but instead a later version of `gcc` is installed that works equally well. Instead of installing an earlier version of `gcc`, using the command `alias gcc-7=gcc` will mean that every call to `gcc-7` is replaced with an equivalent call to `gcc`. This can be placed in `~/.bashrc` (short for `bash` Run Commands, which is run every time `bash` starts up) using the command `echo "alias gcc-7=gcc" >> ~/.bashrc`, and then either restarting the console, or running `source ~/.bashrc`.

```bash
echo "alias gcc-7=gcc" >> ~/.bashrc
```

## Create a symbolic link using `ln -s`

Use `ln` with the `-s` flag to create a symbolic link. This could be useful EG in the scenario described above in the context of `alias`, if `alias` is not working because the commands are not being run in `bash` (this might be the case in a `makefile` which uses `sh` instead of `bash`, see [here](https://unix.stackexchange.com/a/217245/421710)). Instead of using `alias gcc-7=gcc`, an alternative is to use `sudo ln -s /usr/bin/gcc /usr/bin/gcc-7`, which creates a symbolic link in `/usr/bin/` from `gcc-7` to `gcc`, which is more likely to be portable between different shells (not just `bash`).

```bash
sudo ln -s /usr/bin/gcc /usr/bin/gcc-7
```

## Find CPU details (including model name) using `lscpu`

Example:

```
$ lscpu
Architecture:        x86_64
CPU op-mode(s):      32-bit, 64-bit
Byte Order:          Little Endian
CPU(s):              8
On-line CPU(s) list: 0-7
Thread(s) per core:  2
Core(s) per socket:  4
Socket(s):           1
Vendor ID:           GenuineIntel
CPU family:          6
Model:               126
Model name:          Intel(R) Core(TM) i7-1065G7 CPU @ 1.30GHz
Stepping:            5
CPU MHz:             1498.000
CPU max MHz:         1498.0000
BogoMIPS:            2996.00
Virtualization:      VT-x
Hypervisor vendor:   Windows Subsystem for Linux
Virtualization type: container
Flags:               fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush dts acpi mmx fxsr sse sse2 ss ht tm pbe syscall nx pdpe1gb rdtscp lm pni pclmulqdq dtes64 monitor ds_cpl vmx est tm2 ssse3 fma cx16 xtpr pdcm pcid sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer aes xsave osxsave avx f16c rdrand lahf_lm abm 3dnowprefetch fsgsbase tsc_adjust bmi1 avx2 smep bmi2 erms invpcid avx512f avx512dq rdseed adx smap avx512ifma clflushopt intel_pt avx512cd sha_ni avx512bw avx512vl avx512vbmi umip pku avx512_vbmi2 gfni vaes vpclmulqdq avx512_vnni avx512_bitalg avx512_vpopcntdq rdpid ibrs ibpb stibp ssbd
```

##
##

###
### Conditionals
###
if [[ -d "${DIRECTORY}" ]]; then ... fi   # Returnes true if the directory exists
if [[ ! -d "${DIRECTORY}" ]]; then ... fi   # Returnes true if the directory does not exists
if [[ ! -e "${file}" ]]; then ... fi   # Returnes true if the file/directory does not exists
if [[ -z ${variable} ]]; then ... fi  #  Returns true if variable is not set. 
if [[ $? -ne 0 ]]; then .. fi # Returns true if the previous command has failed. 

# Create directory if not already exists:
[ -d foo ] || mkdir foo
mkdir -p foo

# Or a more sophisticated version:
if [[ ! -e $dir ]]; then
    mkdir $dir
elif [[ ! -d $dir ]]; then
    echo "$dir already exists but is not a directory" 1>&2
fi

# Arithmetic conditions:
if (( $var % 4 == 0 )); then echo "The number is dividable by four."; fi

# Chromosome names are usually read as jobindices. But it has to be fixed, as the 23rd chromosome is referred as X
if [[ $chr == 23 ]]; then chr="X"; fi;

# Checking if variable is an integer:
if [[ $window =~ ^-?[0-9]+$ ]]; then echo "Variable is integer!"; fi

###
### For/while loops
###
for cohort in `cat ${workingDir}/../../cohort.list.txt` ; do # looping through a list read from a file (words separated by whitespace)
for i in $(seq 1 12); do # looping though a list of numbers defined by a sequence
for i in {1..22}; do # looping though a list of numbers defined by a sequence

# Reading a file line by line:
while read p; do
     echo $p
done < file

# The same as above, but more intuitive:
cat file | while read line; do
     echo $line
done

# Looping through the indices of arrays:
for i in "${!foo[@]}"; do

# Loop control:
break # Breaks the execution of a loop (no more rounds).
continue # Continues to the next element of the loop

###
### Arrays
###
declare -a arrayname=(element1 element2 element3)
arrayname[0]
arrayname[1]
arrayname[2]
echo ${#arrayname[@]} #Number of elements in the array
echo ${#arrayname}  #Number of characters in the first element of the array
echo ${#arrayname[3]} # length of the element located at index 3
echo ${arrayname[@]:3:2} # Extracting certain elements of the array

# Splitting sting to get an array:
string="a;b;c;d;e"
array=(${string//;/ })

# Splitting a string and access the resulting array:
IN="cica;kutya;macska"
arrIN=(${IN//;/ })

# Using associative arrays in Bash:
declare -A aa # -A shows it will be an associative array

# assigning key/value pairs of an associative array:
aa[hello]=world
aa[ab]=cd
aa=([hello]=world [ab]=cd)

# Retrieving element of an associative array:
if [[ ${aa[hello]} ]]; then
     echo "equal"
fi
bb=${aa[hello]}

# Iterating over an associative array in bash
for i in "${!aa[@]}"; do
  echo "key  : $i"
  echo "value: ${aa[$i]}"
done

###
### Simple variables
###

# put command output into a variable:
var=$(ls -la)

# Exporting shell variable into awk:
var="Cica"

# Substituting string in variable:
mv ${i} ${i/cica/kutya}
cica="cirmos cica hajj, hova lett a vaj"
echo ${cica/ /_} # one replace
echo ${cica// /_} # Global replace

###
### Tips & tricks
###

# Finding lines in file, that do not contain the pattern
cat <file> | grep -v -E "pattern"

# Creating small text file with cat:
cat > new_file Do typing, and once you are ready hit ctrl-d

# Get the first 20k entries from a vcf file plus the header indicated by # tags:
zcat file.vcf.gz | perl -lane ‘if( $_ =~ /#/){print $_ } else {$a++; print $_; die if $a == 20000;}’ | bgzip > new.vcf.gz

# find only non unique lines in file:
cat <file>  | sort | uniq -d
# get the count of unique lines in file
cat <file> | sort | uniq -c 

# Get a sorted list of unique items in a list:
# Source: http://www.theunixschool.com/2012/08/linux-sort-command-examples.html
sort -u # The -u switch makes the output unique
sort -n # Numerical sort
sort -r <file> # Sort file in a reverse order, can be used with other commands.
sort <file1> <file2> # Sorting multiple files together
sort -nu <file1> <file2> # Sorting two files numerically, removing duplicates
sort -t"," file # Sorting by multiple fields, definition of the delimiter
sort -t"," -km,n # Sorting file by multiple columns, starting from column m to n
sort -t"," -k2,2 # Sorting file by second column
sort -t"," -k 

# Print out line only if the exported pattern is matched.
more file | awk -v ref="$var" 'match($0, ref) {print $0}'
awk -v ref1="$var1" -v ref2="$var2" # Exporting more variables into awk

# Get current date:
date "+%Y.%m.%d"

# if you want to echo tab separated characters in bash:
echo -e "cica\tkutyus"

# redirecting messages to stderr:
echo "This message will be printed to the standard error." 1>&2

# printing to stdout without tailing newline:
echo -n "Some text " 
echo "this text will be in the same line!"

# Using watch for commands with pipes:
watch -n 1 'bjobs | wc -l'
 
# if you want to print to the screen a table, and want to the columns to be aligned, then use:
column –t

# Piping arguments into a command:
echo "url" | xargs curl

# Creating archive with tar:
tar cf archive_name.tar dirname/
tar czf archive_name.tar.gz dirname/

# Moving files at the same time:
tar czvf archive_name.tar.gz dirname/ | xargs rm -fr

# Extracting a single file from a tar archive:
tar xvf test.tar -C anotherDirectory/ testfile1

# Get list of files of the archive:
tar tf test.tar 

# joining together gzipped files:
# -a # - keep unmatched rows from this file.
# -1 # - join the first file by this column.
# -e <str> - sting for missing values.
# -o order of output column.
join <(zcat file1.gz)  <(zcat file2.gz) -1 1 -2 1 -a1 -e "NA" -o '1.1 1.2 1.3 2.2'

# Some special joins:
paste -d" " <(zcat ${inputDir}/${legendFile} | cut -d" " -f1-4 | tail -n +2) <(zcat ${inputDir}/${hapFile}) | gzip > ${temp}/${outfile}
     # -d" " - We specify the the character we use to join the lines
     # <()  - Files are piped into the paste process
     # zcat File1.gz - The first file is gzipped, so as we join files, we have to unzip as well
     #  | cut -d" " -f1-4 - We define space as column separator, then we cut the first four columns
     #  | tail -n +2 - We get rid of the first row.

# Pattern for grep can be piped in:
cut -f2 /tmp/chr22_1_temp | grep -f - <(zcat /lustre/scratch113/projects/helic/Reference_panel/uk10k_legend_files/chr22.legend.gz)
     # We pipe into the second column of a file to grep as a serch pattern.
     # We search for these pattern in a file, which have to be zcat

# Grepping multiple patterns:
grep -E 'foo|bar' *.txt
egrep 'foo|bar' *txt # egrep is equal to grep -e

# Checking file size:
size=$(stat -c '%s' /uk10k_vs_helic/chr${chr}_chunk${chunk}_counts.csv )
if [ ! ${size} -ge 50 ]; then fi 

# shuffle lines in files:
cat file | shuf > file_shuffled

# chmod switches:
1 = ..x
2 = .w.
4 = r..
3 = .wx
5 = r.x
6 = rw.
7 = rwx

# Recursively change permission on folders:
chmod -R g+w folder
chmod -R o-x folder

# Killing process running in the background:
ps -aux | grep script_name

# Submitting mathematical expression into the Bash shell:
cica=1231422; kutya=2345
echo `expr ${cica} - ${kutya}`
echo $(( $cica - $kutya ))

# Keep stuff downloading:
wget -c --tries=0 --read-timeout=20 -o ${path_to_file}/filename ${URL}

# Modification of the files by a chain of commands in place:
cat file | awk '$4 > 12' | sponge file

# Substitute string in file using sed:
sed -i 's@{pattern1}@'"{pattern2}"'@'  <file>
sed -i -e  's/pattern1/pattern2/g' <file>
sed -f script.file.sed <targetfile>

# Compressing a whole folder using gzip:
tar -zcvf archive-name.tar.gz directory-name # Creating archive
tar -zxvf archive-name.tar.gz # Extracting archive

# Multiple echoes into the same line:
echo -n "cica"
echo "ful"

# Gemma does not read files where the phenotype is missing. The values in the 6th column cannot be -9
# So it has to be replaced:
awk '$6 = 1' ${path}/${prefix}.fam | sponge ${path}/${prefix}.fam

# Nice top and loop hack:
tmuxes=$(ps -e | grep tmux | cut -d" " -f1) # list of PIDs for all running tmux sessions.
top $(for id in $tmuxes ; do echo -p $id; done) # top only these PIDs. 

# Visualize hidden stuffs:
type ll # show the alias of the command ll
type mkcdir # echo the content of the mkcdir function

# Join two files by matching columns:
join -j1 -a 1 -e NA -o 1.1 1.2 2.1 <(sort -k1 file1 ) <(sort -k1 file2)
# -j join by this column, -o print these colums, -a print unpaired from this file. -e replace empty fields with this string.

# Very fast grep from files
LC_ALL=C grep pattern file

#

###
### awk
###

'BEGIN {total=0}{
        itemno=$1;
        book=$2;
        bookamount=$3*$4;
        total=total+bookamount;
        print itemno," ", book,"\t","$"bookamount;
} END { print "Total Amount = $"total }'

# awk special variables:
# NR - line number
# NF - number of fields
# IFS - input field separator
# OFS - output field separator
# $NF - last column
# $(NF - 1) - column second from the last
awk '{print $(NF -1), $NF }' # printing out the last two columns

###
### Farm stuffs:
###

# Killing all bsubbed jobs on farm:
bjobs | -d" " -f1 | sort -u | xargs -n1 bkill

# Accessing jobindex within script:
chr=$LSB_JOBINDEX

# More information on the available queues:
bqueues -l normal

# Submit script to bsub (also selecting queue):
bsub -G helic \
        -J "Hvs1kg_${chr}_${chunk}"  -M8000 -R'select[mem>8000] rusage[mem=8000]' \
        -e ${logdir}/Hvs1kg_${chr}_${chunk}.error \
        -o ${logdir}/Hvs1kg_${chr}_${chunk}.log \
        -q normal \
        perl ${outdir}/TestSNP.pl ${chr} ${chunk}

# Submitting job-array:
-J "Jobname_[1-22]" # the job will be submitted for all chromosomes
-e "Jobname_chr%I.errro" # Referring to jobindex

# Efficiently submitting jobs to the farm:
export LSB_DEFAULTGROUP=helic
for i in {1..22}; do echo tabix -f -p vcf chr$i.snps.vcf.gz; done | ~ag15/array 1g index

# Switching queues:
bswitch ${queue} ${job_ID}

# Compressing bjobs:
bjobs -A

###
### bash scripts
###

# importing command line parameter within a script:
trait=$1
chr=$2

# bash handling command line options:
OPTIND=1
while getopts "h?vf:" opt; do
    case "$opt" in
          ...
          ...
     esac
done

# Writing functions in bash:
function cica { echo "parameter passed to function: " $1 }
cica "pocok"

# Get the path of the script is located:
scriptDir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# using references in bash:
MANOLIS=/lustre/scratch115/realdata/mdt0/projects/t144_helic_15x/analysis/HA/VCFs/byChr/chrX.snps.splitindel.nostar.vcf.gz
file=MANOLIS
eval echo \$${file}

# parameter processing:
$0 - first positional parameter. Name of the script.
$1..$9 - argument list
${10}..${N} - argument list above 9
$* - all positional parameter except $0
$@ - all positional parameter except $0
$# - the number of positional parameters excluding $0

# Removing elements from the argument list:
shift

# vim commands:
:w filename - Current document will be saved as filename
:u - undo last command

# A small function to set up an ssh tunnel (for ipython notebooks)
function python_tunel { ssh -Y -Y -N -f -L localhost:${1}:localhost:${1} ds26@${2}; }

# PS1 stuffs:
\h - host name to the first dot
\H - full host name
\A - current time in hh:mm format
\u - user name
\w - full path of the current working directory
\W - basename of the current working directory
\# - command number of this command
\e[1;32m - color starts
\e[m - color ends
\e[1;31m- light red
\e[1;32m - light green
\e[1;34m - light blue

# Example PS1:
export PS1="\[\e[1;34m\]\A \u@\h\[\e[m\]:\[\e[1;32m\]\W$\[\e[m\] "

# Using a env to get bash or python location:
#!/usr/bin/env bash
#!/usr/bin/env python

# Piping output into an other command as a command line parameter:
cat signals.tsv | perl -lane 'if ($F[0] =~ /rs/){print $F[0]} else {printf "%s_%s/%s\n", $F[3],$F[4],$F[5]}' | xargs -n1 -I % /nfs/team144/ds26/FunctionalAnnotation/v2.2/VarAnnot_2.2.py -i %

# monitoring the progression of a command output. With pipes (surrounded by single quotes):
watch -n2 'bjobs | grep tabix' 

# Bash find command useful arguments:
find . -regex ''
find . -type d # Find directories
find . -type f # Find files.
find . -type f -name *.sh  # Find only files with sh extension.
find . -type f -newermt 2007-06-07 ! -newermt 2007-06-08 # finding files between specific dates
find . -type f -name *.sh -exec grep -n -H HELIC5102819 {} # findin files and execute command.
 
# password-less ssh login:
ssh-keygen # generating public/private keys on local host
ssh-copy-id -i ~/.ssh/id_rsa.pub remote-host # copy public key to remote host

# Important grep parameters:
grep -E  # Use extended regular expression.
grep -P  # Use Perl like regular expression.
grep -x  # Pattern match the whole line
grep -o  # Output matching string (potentially more words per line)
grep -v  # Reverse pattern
grep -w  # Match word
grep -c  # Count matches
grep -i  # Ignore case.
grep -f  # Pattern read from file
grep -H  # Always print file name in front of the line.
grep -m 1 # Stop after # matches.
grep -n  # Output line number in which the pattern was found.
grep -h  # Surprass file name from output.
grep -A 3 # print 3 lines after the match
grep -B 3 # print 3 lines before the match

# Lower/upper casing in bash:
echo "A string to change case" | tr "[:lower:]" "[:upper:]"
string="A string to change case"
echo ${string^^}
echo ${string,,}

# git commands:
git clone https://github.com/YOUR-USERNAME/YOUR-REPOSITORY # Cloning github repository

# Tabix parameters:

# From the absolute path of a file get file name and folder:
file=/nfs/team144/ds26/tools/rsID2ChrPos.pl
basename "${file}" # rsID2ChrPos.pl
dirname "${file}" # /nfs/team144/ds26/tools/

# Extracting specific file from tar achive:
tar -xf etc.tar etc/apt/sources.list

# Referencing variables:
dir=/lustre/scratch115/realdata/mdt0/projects
ref=dir
eval ls -al \$$ref

# Find all files in a folder owned by me and add write permission for the group:
find . -user ds26 | xargs -n1 -I % chmod g+w %

# Default variable value:
echo ${varName:-DefaultValue}

# Cases in bash:
case $var1 in 
    "cica" ) var2="cica" ;;
    "kutya" ) var2="kutya" ;;
    * ) var2="other";;
esac

# check if a string has a substring:
if [[ $string == *substring* ]]; then echo "Substring has been found!"; fi
if [[ $string =~ .*substring.* ]]; then echo "Substring has been found!"; fi

# Stream redirection:
>&2 # Stdout to stderr
2>&1 # Stderr to stdout

# Repeating a command until it returns successfully:
while [ $? -ne 0 ]; do !!; done

#

##
##

