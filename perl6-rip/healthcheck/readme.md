```
Hi:

    perl -e 'print "hello world!\n"'

A simple filter:

    perl -ne 'print if /REGEX/'

Filter out blank lines (in place):

    perl -i -ne'print if /\w/'

Search and replace (in place):

    perl -i -pe's/SEARCH/REPLACE/' 

Add first and penultimate columns:

    perl -lane 'print $F[0] + $F[-2]'

Just lines 15 to 17:

    perl -ne 'print if 15 .. 17' *.pod

In-place edit of *.c files changing all foo to bar:

    perl -p -i.bak -e 's/\bfoo\b/bar/g' *.c

Command-line that prints the first 50 lines (cheaply):

    perl -pe 'exit if $. > 50' f1 f2 f3 ...

Delete first 10 lines:

    perl -i.old -ne 'print unless 1 .. 10' foo.txt

Change all the isolated oldvar occurrences to newvar:

    perl -i.old -pe 's{\boldvar\b}{newvar}g' *.[chy]

Command-line that reverses the whole file by lines:

    perl -e 'print reverse <>' file1 file2 file3 ....

Find palindromes:

    perl -lne 'print if $_ eq reverse' /usr/dict/words

Command-line that reverse all the bytes in a file:

    perl -0777e 'print scalar reverse <>' f1 f2 f3 ...

Command-line that reverses the whole file by paragraphs:

    perl -00 -e 'print reverse <>' file1 file2 file3 ....

Increment all numbers found in these files:

    perl i.tiny -pe 's/(\d+)/ 1 + $1 /ge' file1 file2 ....

Command-line that shows each line with its characters backwards:

    perl -nle 'print scalar reverse $_' file1 file2 file3 ....

Delete all but lines between START and END:

    perl -i.old -ne 'print unless /^START$/ .. /^END$/' foo.txt

Binary edit (careful!):

    perl -i.bak -pe 's/Mozilla/Slopoke/g' /usr/local/bin/netscape

Duplicate words:

    perl -0777 -ne 'print "$.: doubled $_\n" while /\b(\w+)\b\s+\b\1\b/gi'

Print the last 50 lines (expensive!):

    perl -e '@lines = <>; print @lines[ $#lines .. $#lines-50' f1 f2 f3 ...

Move files < 1000 bytes to DIR:

    ls -l *xls | perl -na -F'/\s+/' -e 'print "$F[8]\n" if $F[4] < 1000' |
    xargs -J % mv % DIR

Print 1st, 2nd, and last columns (use -l for auto-line-end processing):

    perl -F"\t" -nlae'print join "\t", @F[0,1,-1]' 

Print columns 1-20:

    perl -F"\t" -nlae'print join "\t", @F[0..19]'

Print all filenames & their line #s w/ pattern:

    perl -ne'if (/PATTERN/) { print "$ARGV: $.\n" }; $. = 0 if eof'

Print file up to some pattern:

    perl -ne'if (/PATTERN/) { close ARGV } else { print }'

Inclusive of line w/ pattern:

    perl -pe'if (/PATTERN/) { close ARGV }'

Delete columns of file after column N+2:

    perl -i -F'\t' -nlae'print join "\t", @F[0..N]' 

Insert new column after column N:

    perl -i -F'\t' -nae'print join "\t", @F[0..N], "new", @F[N+1..$#F]'

Cut files in dir at pattern & omit blank lines:

    perl -i -ne 'if (/PATTERN/) { close ARGV } else { print unless /^$/ }'

Insert line numbers in a file:

    perl -i -ne 'printf "%04d %s", $., $_'

Insert text at line N:

    perl -i -pe 'print "text\n" if $. == N; $. = 0 if eof'

Print filenames of files containing pattern in first N lines:

    perl -n -e 'if (/PATTERN/) { print "$ARGV\n"; close ARGV }' 
            -e 'close $ARGV if $. = N'

Return part of select filenames:

    perl -ne '$ARGV =~ /^(.*)\.TXT$/; print "$&\n"; close ARGV'

Add columns M thru N and insert total:

    perl -F'\t' -nlae '$t=0; $t += $_ for @F[M..N]; print "$_\t$t" '

Replace pattern on first line of each file:

    perl -i -pe'
        $new = 1; 
        s/PATTERN/REPLACE/ if $new; 
        $new = eof(ARGV) ? 1 : 0'

Create two columns of random numbers:

    jot -r 100 | rs 50

Given a list of random numbers, ranging from 1 to 20, show the count
of those numbers >= 10 and those < 10:

    jot -r 20 1 20 | perl -ne 'print $_ >= 10 ? 1 : 0, "\n"' | sort | uniq -c

... or showing percentages:

    jot -r 20 1 20 
      | perl -ne 'print $_ >= 10 ? 1 : 0, "\n"' 
      | sort 
      | uniq -c 
      | cut -c 3-4 
      | perl -ne'chomp; $sum += $_; push @counts, $_; 
                END { print $_, " : ", $_ / $sum, "\n" for @counts }'

... or to show the percentage of nines in the list:

      | perl -ne 'print $_ == 9 ? 1 : 0, "\n"' 

Given a list of numbers, ranging from 0 to 20,000, show the distribtion (i.e., 
individual counts) of those numbers after each is rounded to the nearest 
$1,000 increment:

    jot -r 20 0 20000 
      | perl -pe'$_ = 1000 * int($_/1000)."\n"' 
      | sort -n 
      | uniq -c

... or showing percentages:

    jot -r 20 1000 20000 
      | perl -pe'$_ = 1000 * int($_/1000) . "\n"' 
      | sort -n
      | uniq -c 
      | perl -ne'($n,$num) = /(\d+)/g; $counts{$num} = $n; $sum += $n; 
                  END { print $_, 
                        " : ", 
                  $counts{$_} / $sum, "\n" 
                  for sort {$a<=>$b} keys %counts }'

... or to find the median (i.e., the middle number):

	    | perl -e'@lines = <>; print $lines[int($#lines/2)]'

... or to find the average:

    jot -r 20 0 20000 | perl -pe'$_=1000 * int($_/1000)."\n"'

```

------------------------------------------------------------------------------------------
#CLI shortcut keystrokes(linux&MAC)
Ctrl+L: Clear the screen. This is similar to running the “clear” command.
Ctrl+C: Interrupt (kill) the current foreground process running in in the terminal. This sends the SIGINT signal to the process
Ctrl+Z: Suspend the current foreground process running in bash. This sends the SIGTSTP signal to the process. To return the process to the foreground later, use the fg process_name command.
Ctrl+D: Close the bash shell.This is similar to running the exit command
Ctrl+L: Clear the screen. This is similar to running the “clear” command.

Ctrl+S: Stop all output to the screen. This is particularly useful when running commands with a lot of long, verbose output, but you don’t want to stop the command itself with Ctrl+C.
Ctrl+Q: Resume output to the screen after stopping it with Ctrl+S.

Ctrl+A or Home: Go to the beginning of the line.
Ctrl+E or End: Go to the end of the line.
Alt+B: Go left (back) one word.
Alt+F: Go right (forward) one word.

Ctrl + U to clear up to the beginning

Ctrl + U to recall a command by searching history
Up Arrow to recall the previous command from history
Down Arrow to go to next command in the command history

#multiple virtual consoles
CTRL + ALT + F1-F8
-------------------------------------------------------------------------------------------------------------------------------------------------
#An absolute path is a complete path to a resource, beginning at the filesystem's root
#The filesystem root is represented as a single forward slash: /

#Relative path
/home/damon #if you're already in your home directory
Music/Rock #the rest of the path relative to where you are now
-------------------------------------------------------------------------------------------------------------------------------------------------
#the tilde character "~" represents the current, logged-on user's home directory
$ cp /etc/ssh/sshd_config ~
$ cd ~
#The single dot represents the present working directory, or where you are right now.
$ sudo cp /etc/ssh/sshd_config .
#Double dots represent the parent directory, or the directory immediately above the current one in the filesystem
$ cd ..
-------------------------------------------------------------------------------------------------------------------------------------------------
$ bash --version
------------------------------------------------------------------------------------------
/etc #configuration files on the system
/etc/hosts #maps hostnames to IP addresses
/etc/skel #files copied to each user's home
/usr #user by user and supersuser accounts.Stores application programs
/usr/bin #executables used by users, in user's PATH statement
/usr/sbin #executables used by superusers
/usr/local #applications which are not part of linux
#applications installed after initial linux installation,in user's PATH statement
#administrative applications installed after initial linux installation
/usr/local/bin
/usr/doc #the default location for application documentation is in a directory named for the application
/var #stores log files, mails and other data
/var/spool #mail & printing files
/var/tmp #data that should persist across reboot

/var/log #log files
/var/log/anaconda.log - While installing Linux, all installation related messages are stored in this log file
/var/log/audit/ - This subdirectory contains logs information stored by the Linux audit daemon (auditd)
/var/log/auth.log - user logins,such as password prompts
/var/log/boot.log - Contains information that are logged when the system boots
/var/log/cron - Whenever cron daemon (or anacron) starts a cron job, it logs the information about the cron job in this file
/var/log/debug #debugging information from the Ubuntu system and applications
/var/log/daemon.log - display server, SSH sessions, printing services, bluetooth
/var/log/dmesg - Contains kernel ring buffer. This file is overwritten when the system is rebooted.
/var/log/faillog -failed user login attempts. ssh(used for remote login), su(to switch users), at, cron (both used for scheduling tasks) use PAM modules for authentication
/var/log/kern.log - Contains information logged by the kernel. Helpful to troubleshoot a custom-built kernel.
/var/log/lastlog #last logins
/var/log/messages #the main system log,the messages that are logged during system startup
/var/log/sa/ - Contains the daily sar files that are collected by the sysstat package.
/var/log/samba/ - Contains log information stored by samba, which is used to connect Windows to Linux.
/var/log/setroubleshoot/ - SELinux uses setroubleshootd (SE Trouble Shoot Daemon) to notify about issues in the security context of files and logs those information in this log file.
/var/log/secure #failed login attempts, failed SSH login attempts, successful SSH logins
/var/log/syslog
/var/log/user.log - Contains information about all user level logs.

/var/log/Xorg.x.log - Log messages from the X server to this file.
/var/log/Xorg.0.log
/var/log/yum.log - Contains information that are logged when a package is installed using yum

#binary log files,cannot be read with a normal text editor,special command-line tools are used to display the relevant information in human-readable format
/var/log/btmp - This file contains information about failed login attempts
/var/log/utmp - The utmp file allows one to discover information about who is currently using the system.
/var/log/wtmp - The wtmp file records all logins and logouts.

#This subdirectory contains additional logs from the mail server. 
#For example, sendmail stores the collected mail statistics in /var/log/mail/statistics file
/var/log/mail/ 
/var/log/maillog - Logs information from the mail server that is running on the system.
/var/log/mail.log - Logs information from the mail server that is running on the system.

#- Contains the apache web server access_log and error_log and related virtual hosts logs if set up to log here.
/var/log/httpd/ 
/var/log/apache2 
/var/log/apache2/error.log
/var/log/mysql.log

#All printer and printing related log messages
/var/log/cups 
/var/log/spooler 

/bin #binaries run during system startup
/sbin #administrative binaries run by superusers
/root #home for superuser
/home #user home dirs
/boot #files run by boot loader and kernel
/dev #peripheral access files
/proc #virtual dir contains system info
/tmp #stores temporary files
/etc/grub.conf or /boot/grub/grub.conf #customize the behavior and appearance of the boot menu
/dev/shm,/dev/shmfs #also known as tmpfs,df -h,file system which keeps all files in virtual memory,no files created on hard drive
/etc/passwd #UID/GID stored, UID/GUID zero(0) for root, all UID/GID <1000 privileged access, all other users UID/GID>1000

#list group members
/etc/group #secondary group memberships, 
awk -F':' '/sudo/{print $4}' /etc/group 
grep '^sudo' /etc/group
grep -w sudo /etc/group
------------------------------------------------------------------------------------------
#Bard

 The command [ -f /var/run/reboot-required ] && sudo reboot -f first checks if the file /var/run/reboot-required exists. If it does, the command then runs the sudo reboot -f command, which forcefully reboots the system.

The file /var/run/reboot-required is created by some Linux distributions when a system update requires a reboot. This is to ensure that the system is properly updated before it is restarted.

The sudo reboot -f command forcefully reboots the system, even if there are unsaved changes in open files. This is useful if the system is unresponsive or if you need to reboot it immediately.

Some of the best uses cases for the command [ -f /var/run/reboot-required ] && sudo reboot -f are:

    After a system update that requires a reboot.
    If the system is unresponsive.
    If you need to reboot the system immediately.

It is important to note that forcefully rebooting the system can sometimes cause data loss. Therefore, you should only use this command if you are sure that there are no unsaved changes in open files.
------------------------------------------------------------------------------------------
#ChatGPT

This command is used in a Linux shell environment and is composed of two parts connected by the && operator. The overall purpose of this command is to check if a specific file exists and, if it does, initiate a system reboot with administrative privileges. Let's break down each part of the command:

    [ -f /var/run/reboot-required ]: This is a conditional test using the [ (test) command. The -f flag checks if the specified file (/var/run/reboot-required) exists. This file is often used on Ubuntu-based systems to indicate that a system reboot is required due to software updates or configuration changes.

    &&: This is the logical "AND" operator. It's used to execute the command on the right only if the command on the left (the test in this case) evaluates as true or successful.

    sudo reboot -f: If the previous test [ -f /var/run/reboot-required ] is successful (meaning the file exists), this command is executed. The sudo command is used to execute the subsequent command with superuser (root) privileges. reboot is a command used to restart the system, and the -f flag forces an immediate reboot without further confirmation.

Best Use Cases:

    Automated Reboot after Updates: This command is commonly used in automated scripts or scheduled tasks, particularly after software updates have been applied to a Linux system. If the file /var/run/reboot-required exists, it suggests that important updates have been installed that require a system restart for them to take effect. By using this command, you can ensure that the system automatically reboots when necessary after updates.

    Post-Configuration Reboot: In situations where configuration changes are applied that necessitate a reboot, this command can be used to automatically restart the system. For example, if you've made changes that affect kernel modules or critical system services, an automated reboot might be necessary to apply those changes.

    Server Maintenance and Deployment Scripts: When performing maintenance tasks on servers or during deployment procedures, administrators might use this command to ensure that a system is properly restarted after specific actions are taken.

    Scripted System Checks: This command can be incorporated into system health-check scripts that are run periodically to ensure the system is in a proper state. If the script detects that a reboot is required, it can automatically initiate one.

It's important to exercise caution when using commands that trigger a system reboot, especially in automated scenarios. Rebooting a system without proper planning can lead to unexpected downtime and disruption of services. Always thoroughly test any scripts or commands in a controlled environment before deploying them in production systems.

------------------------------------------------------------------------------------------
"&&" 
#where the second command is executed only if the exit status of the preceding command is 0 (zero exit code)
#The right side of && is evaluated if the exit status of the left side is zero (i.e. true)

"||" 
#If the exit status of the first command is not 0 (non-zero exit code), then execute the second command
#The right side of || is evaluated if the left side exit status is non-zero (i.e. false)

#Opposite to &&, the statement after the || operator will only be executed if the exit status of the test command is false
[ -f /etc/resolv.conf ] && echo "$FILE exist." || echo "$FILE does not exist."

------------------------------------------------------------------------------------------
#Syntax for Command Substitution
#The old-style uses backticks (also called backquotes) to wrap the command being substituted
#The new style begins with a dollar sign and wraps the rest of the command in parenthesis
$ rpm -ql $(rpm -qa | grep httpd)

$(command)  #Command Substitution 
(list) #Group commands in a subshell: ( )
{ list; } #Group commands in the current shell: { }
[[ expression ]]  #Test - return the binary result of an expression: [[ ]]

command substitution; output from pwd works as the argument for echo command
$ echo `pwd`

Command Substitution
# `backquotes` also known as `backticks`
KERNEL_VERSION=`uname -r`
#(parentheses)
KERNEL_VERSION=$( uname -r )
$ echo $KERNEL_VERSION
4.15.0-29-generic

 #Command substitution in Bash
 #execute a command and substitute it with its standard output,command executes within a subshell

$ var_date=$(date) && echo $var_date
$ due_date="01-01"
$ echo "Status as of $(date +%m-%d-%Y) : The delivery is due on ${due_date}-2022"

echo "${myvar:-bash}"    #check the variable, $myvar is set or unset. If $myvar is unset, then the string ‘bash’ will print
echo "${myvar:=bash}"	 #set the value, ‘bash’ to $myvar and print ‘bash’ to the terminal if $myvar is unset
echo "${myvar:+python}"  #print, ‘python’ to the terminal if $myvar is set before

$ mystr="Bangladesh"
$ echo "${mystr:0:6}" #six characters from $mystr starting from position 0 to 6
$ echo "${mystr:6}" #all characters from $mystr, starting from position 6 to the end	
$ echo "${#mystr}" #count and print the total number of characters of $mystr

The process substitution >(command) will be replaced by a file name.
------------------------------------------------------------------------------------------
{ Commands; } : Commands execute in current shell
( Commands ) : Commands will execute in a subshell

$ VAR="1"; { VAR="2"; echo "Inside group: VAR=$VAR"; }; echo "Outside: VAR=$VAR"
Inside group: VAR=2
Outside: VAR=2

#the variable is changed in a subshell. Therefore, the changes will not affect the outer shell
$ VAR="1"; ( VAR="2"; echo "Inside group: VAR=$VAR" ); echo "Outside: VAR=$VAR"
Inside group: VAR=2
Outside: VAR=1

$ pwd; { cd /etc; pwd; }; pwd #current shell
$ pwd; ( cd /etc; pwd ); pwd #subshell

------------------------------------------------------------------------------------------
#Placing a list of commands between curly braces causes the list to be executed in the current shell context. 
#No subshell is created.

$ { ls && v=3; } > tmp
$ echo "$v"
3

#pipe creates a new subshell
$ { ls a* && v=3; } | grep my
$ echo "$v" #does not print variable v



touch abc{1,2,3,4}
echo ${month[3]}
echo {10..0}
mkdir /some/dir/{a,b,c,d}
mkdir -p -v /home/jon/tmp/{dir1,anotherdir,similardir} #Apply a command on files with different names

------------------------------------------------------------------------------------------
#Parameter Expansion
#specify a variable within {} to protect it against expansion. 
#useful when the characters immediately following it can be interpreted as part of the variable name.
$ price=5
$ echo "${price}USD"
------------------------------------------------------------------------------------------
# avoid dot slash "./" when running executable scripts, binary file

#OPTION 1
export PATH=$PATH:/path/to/directory

#OPTION 2
ln -s /path_to_script/myscript /usr/bin/myscript 

#OPTION 3
bash -c /Users/you/myscript.sh

#OPTION 4 , add the line below into  "~/.bashrc." 
export PATH=/path_to_folder_containing_executable/:$PATH
------------------------------------------------------------------------------------------
    #Hosts File
    Windows 10 - "C:\Windows\System32\drivers\etc\hosts"
    Linux - "/etc/hosts"
    Mac OS X - "/private/etc/hosts"
-------------------------------------------------------------------------------------------------------------------- 
 #Reading file content from command line
 $ while read line; do echo $line; done < company.txt
--------------------------------------------------------------------------------------------------------------------
mount -t tmpfs tmpfs /mnt/tmp #in-memory filesystem,tmpfs is a temporary filesystem that only exists in RAM
--------------------------------------------------------------------------------------------------------------------
#which is an external binary, located at /usr/bin/which which steps through the $PATH environment variable and checks for the existence of a file
which modprobe
#command is built in to shell, with the -v option how shell invokes the command specified as its option
command -v modprobe
--------------------------------------------------------------------------------------------------------------------
#ls -ai command
 
$ ls ..  # double dot(..) represents the parent directory
$ sudo rm ..
rm: cannot remove '..': Is a directory
$ sudo rm -rf ..
rm: refusing to remove '.' or '..' directory: skipping '..'

$ ls .  #single dot(.) represents the current directory
$ sudo rm .
rm: cannot remove '.': Is a directory
$ sudo rm -rf .
rm: refusing to remove '.' or '..' directory: skipping '.'
--------------------------------------------------------------------------------------------------------------------
#list all failed SSH logins
grep "Failed password" /var/log/auth.log
egrep "Failed|Failure" /var/log/auth.log
cat /var/log/auth.log | grep "Failed password"
grep "Failed password" /var/log/auth.log | awk '{print $11}' | uniq -c | sort -nr # the number of failed attempts of each IP address,
--------------------------------------------------------------------------------------------------------------------
tar -czf - ./Documents/ | (pv -p --timer --rate --bytes > backup.tgz) #Monitor tar progress
pv -p history.log | wc #Count number of lines, words, bytes
pv -p /etc/hosts | wc
pv history.log | zip>$HOME/Documents/history.zip #history.log  and show progress
pv origin-cdn.cyberciti.org_access.log > /tmp/origin-cdn-access.log #copy a file and show progress
pv origin-cdn.cyberciti.org_access.log > /dev/null #show progress
pv -cN rawlogfile origin-cdn.cyberciti.org_access.log | gzip | pv -cN gziplogfile > access.log.gz #see progress of both pipes

(pv -n backup.tar.gz | tar xzf - -C path/to/data ) 2>&1 | dialog --gauge "Running tar, please wait..." 10 70 0 #extract tar ball and show progress using the dialog command
tar -czf - ./Documents/ | (pv -n > backup.tgz) 2>&1 | dialog --gauge "Progress" 10 70

nc -l -v -w 30 -p 2000 > /tmp/data.bin #create a network port 2000
nc -l -v -w 30 -p 2000 > /tmp/data.bin #Open another terminal
--------------------------------------------------------------------------------------------------------------------
timeout 10s tail -f /var/log/pacman.log #terminate after 10 seconds
timeout 3.2s dmesg -w #display all messages from the kernel ring buffer, only 3.2 seconds
timeout 3m ping 127.0.0.1 #ping command after 3 minutes
timeout 2d ping 127.0.0.1 #ping command after 2 days
timeout --foreground 2m test.sh #By default runs in background, run it foreground

timeout -k 20 10 tail -f /var/log/pacman.log #if the command is still running even after the time out, send a kill signal
timeout -s 9 3s ping 127.0.0.1 #use 9 as SIGKILL
kill -l #list all acceptable signal
timeout -k 5s 3m sh test.sh #let the script run for 3 minutes, if it does not exit, kill after 5 seconds
--------------------------------------------------------------------------------------------------------------------
/home/user01/test.file can also be denoted by ~/test.file #The tilde (~) is a Linux "shortcut" to denote a user's home directory.
cd ~ #change into user's home directory
--------------------------------------------------------------------------------------------------------------------
w #show who is logged on and what they are doing.
w user #print info for a specific user
w -i #display IP address instead of hostname for from field.
w -o #print blank space for idle times less than one minute
--------------------------------------------------------------------------------------------------------------------
# stops after 50secs, stdout seen
skaffold dev & sleep 50s; kill $!
--------------------------------------------------------------------------------------------------------------------
$ ssh root@192.168.1.1 'bash -s' < script.sh #Execute the local script.sh on the remote server ssh
$ ssh root@192.168.1.1 'uptime; df -h'
$ ssh root@192.168.1.1 'free -m | cat /proc/loadavg'

$ ssh root@192.168.1.1 << EOF
uname -a
lscpu  | grep "^CPU(s)"
grep -i memtotal /proc/meminfo
EOF
--------------------------------------------------------------------------------------------------------------------
#setting system locale to en_US.utf8
localectl set-locale LC_CTYPE=en_US.utf8
localectl status
----------------------------------------------------------------------------------------------------
ip -o -4 addr list enp0s8 | awk '{print $4}' | cut -d/ -f1 # print IP with a given interface
ip -o -6 addr list enp0s8 | awk '{print $4}' | cut -d/ -f1
ifconfig | awk '/192.168.18.84/ {print $1}' RS="\n\n" # print interface with a given IP
----------------------------------------------------------------------------------------------------
#-n     do not output the trailing newline
echo -n $PASSWORD | faas-cli login --username admin --password-stdin
----------------------------------------------------------------------------------------------------
cat verifyURL.sh
#!/bin/bash

url="https://gist.github.com/githubfoam/d313d580a92d84123b841ebbd4f255a6"

if wget $url >/dev/null 2>&1 ; then
        echo "Url : $url ...is online"
else
        echo "Url : $url ...is not online"
fi

#if link exists
#--head avoid downloading the file contents
#--fail make the exit status nonzero on a failed request
#--silent avoid status or errors 
url="https://www.katacoda.com/courses/kubernetes/launch-single-node-cluster"
if curl --output /dev/null --silent --head --fail "$url"; then
  echo "URL exists: $url"
else
  echo "URL does not exist: $url"
fi

time curl -I http://mydomain.com | grep HTTP # get the header for the page, and time the process
curl -I "www.google.com" 2>&1 | awk '/HTTP\// {print $2}' # see only the HTTP status code
curl -I "https://www.google.com" 2>&1 | grep -w "200\|301" # see if a given website is up or down
curl -w "\n" http://localhost:8080/hello # avoid your terminal printing a '%' or put both result and next command prompt on the same line
lynx -head -dump http://www.google.com #Check Whether a Website is up or down
lynx -head -dump http://www.google.com 2>&1 | awk '/HTTP\// {print $2}' # see only the HTTP status code

#SSL certificate problem 
curl -kfsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
curl https://curl.se/ca/cacert.pem -o /etc/pki/ca-trust/source/anchors/curl-cacert-updated.pem && update-ca-trust
wget --no-check-certificate http://curl.haxx.se/ca/cacert.pem
----------------------------------------------------------------------------------------------------
$ time ./a.out
<output from code>

real    0m5.279s #real is the wall-clock time,Elapsed real time, real time, wall-clock time, or wall time is the actual time taken from the start of a computer program to the end. In other words, it is the difference between the time at which a task finishes and the time at which the task started. 
user    0m1.915s #user is the time spent executing the user’s program,
sys     0m0.006s #sys is the time spent on system tasks required by the program
 ----------------------------------------------------------------------------------------------------
 #linux benchmark
 sysbench --test=cpu run
  sysbench --test=cpu help
 sysbench --test=cpu --cpu-max-prime=20000 run
 sysbench --test=memory run
 sysbench --test=memory help
 sysbench --test=fileio help
 sysbench --test=fileio --file-test-mode=seqwr run
 sysbench --test=fileio --file-total-size=100G cleanup
  ----------------------------------------------------------------------------------------------------
 # generate load
$ yes > /dev/null &

# maximum number of processes available to a single user.
$ ulimit -u
# The limit is set with the -S option
$ ulimit -S -u 500

#inspect the load figures on the server before and after the stress test
uptime
sudo stress --cpu 100 --timeout 300
uptime

$ sudo (yum/apt-get) install stress
## Stress using CPU-bound task
stress -c 4
## Stress using IO-bound task 
stress -i 2
#  a load average of four is imposed on the system by specifying two CPU-bound processes, one I/O-bound process, and one memory allocator process
stress -c 2 -i 1 -m 1 --vm-bytes 128M -t 10s

$ sudo apt-get install stress-ng
 stress-ng --cpu 4 --io 4 --vm 1 --vm-bytes 1G --timeout 60s --metrics-brief
stress-ng --hdd 5 --hdd-ops 100000
stress --cpu 4 --io 3 --vm 2 --vm-bytes 256M --timeout 35s

# The restriction can be made permanent by configuring the nproc value
/etc/security/limits.conf
# initiate a fork bomb
":(){ :|:& };:"
# run ./$0& twice
#!/bin/sh
./$0&
./$0&
----------------------------------------------------------------------------------------------------
# Listing all currently known events:
perf list
# CPU counter statistics for the specified command:
perf stat command
# CPU counter statistics for the specified PID, until Ctrl-C:
perf stat -p PID
# Sample on-CPU functions for the specified command, at 99 Hertz:
perf record -F 99 command
# Trace all block device (disk I/O) requests with stack traces, until Ctrl-C:
perf record -e block:block_rq_insert -ag
# Add a tracepoint for the kernel tcp_sendmsg() function entry ("--add" is optional):
perf probe --add tcp_sendmsg
# Trace system calls by process, showing a summary refreshing every 2 seconds:
perf top -e raw_syscalls:sys_enter -ns comm
# Show perf.data with a column for sample count:
perf report -n

 ----------------------------------------------------------------------------------------------------
#ls command
ltrace -c ls
ltrace -p <PID>
ltrace -l /lib/libselinux.so.1 id -Z #execute the id -Z command and show the calls made to the libselinux.so module
ltrace -o foobar.log ./foobar #edirect output of ltrace to a file
ltrace -e malloc ./foobar #filter and display only calls to a certain library function

#ls command
strace ls
strace -v #-v verbose option that can provide additional information on each system call
strace -s 80 -f ./program	#print the first 80 characters of every string
strace -i ls # print instruction pointer at the time of system call
strace -r ls # display a relative timestamp upon entry to each system call
strace -t ls #each line in strace output to start with clock time
strace -T ls #show time spent in system calls
strace -c ls #print a summary
strace -p 3569 #If a process is already running, you can trace it by simply passing its PID
strace -p `pidof rsyslogd`
strace -p $(pgrep rsyslogd) #monitor process without knowing its PID, but name
#if there are multiple processes to be traced at once (e.g. all instances of an running apache httpd)
strace $( pgrep httpd | sed 's/^/-p/' ) 
strace -c -p 3569 Summary of Linux Process
strace -c ls Counting number of sys calls
strace -o output.txt ls
strace -e trace=network -o OUTFILE php -q test2.php # write the output of strace to a file or redirect the output
strace -e trace=network php -q test2.php 2> test2debug #redirect the output
strace -e trace=open,stat,read,write ls
strace -e trace=mprotect,brk ifconfig eth0 # trace mprotect or brk system calls
strace -e trace=network ifconfig eth0 #Trace all the network related system calls
strace -e trace=network #Monitoring the network
strace -e trace=memory Monitoring memory calls
strace -e open ls  display only a specific system call, use the strace -e option
strace -f -eopen /usr/sbin/sshd 2>&1 | grep ssh	shows the three config files that OpenSSH’s sshd reads as it starts,strace sends its output to STDERR by default
strace -e trace=file -p 1234 #See all file activity,Monitoring file activity
strace -e trace=desc -p 1234
strace -P /etc/cups -p 2261 #track specific paths, use 1 or more times the -P parameter, following by the path
strace -f -o strace_acroread.txt acroread #follow system calls if a process fork
strace -q -e trace=process df -h trace all system calls involving process management.
strace -q  -e trace=file df -h trace all system calls that take a filename as an argument
strace -f -e execve ./script.sh #check what commands are exactly being executed by a script by using strace
strace -f -e execve bash x.sh

$ strace e execve bash -c true
$ strace -ve execve bash -c true
$ strace -e execve bash -c /bin/true

$ strace -o OUT -ff -e execve bash -c "/bin/true ; /bin/false"
$ grep execve OUT*
OUT.29328:execve("/usr/bin/bash", ["bash", "-c", "/bin/true"], 0x7ffc75ace798 /* 25 vars */) = 0
OUT.29328:execve("/bin/true", ["/bin/true"], 0x55bf673522c0 /* 25 vars */) = 0
OUT.29336:execve("/usr/bin/bash", ["bash", "-c", "/bin/true ; /bin/false"], 0x7ffe1b316638 /* 25 vars */) = 0
OUT.29337:execve("/bin/true", ["/bin/true"], 0x55aba17c92c0 /* 25 vars */) = 0
OUT.29338:execve("/bin/false", ["/bin/false"], 0x55aba17c92c0 /* 25 vars */) = 0

# Under Linux, fork is a special case of the more general clone system call, which you observed in the strace log.
#The child runs a part of the shell script. The child process is called a subshell.
strace -f -o bash-mystery-1.strace bash -c 'v=15; (echo $v)'
strace -f -o bash-mystery-2.strace bash -c 'v=15; bash x.sh'
man 2 clone #create a child process
grep clone bash-mystery-2.strace # filter child process

strace -e open,read,write cat /etc/HOSTNAME
strace -e open,read,write cat /etc/HOSTNAME > /dev/null
strace -e file cat /etc/HOSTNAME

#Execute Strace on a Running Linux Process Using Option -p
ps -C firefox-bin #PID 126
sudo strace -p 126 -o firefox_trace.txt #display the following error when your user id does not match the user id of the given process.
pidof sshd #PID 126
strace -p 126

#sleep.sh, endless loop
#! /bin/bash
while :
do
 sleep 10 &
 echo "Sleeping for 4 seconds.."
 sleep 4
done

$ sh sleep.sh & # run in the background
$ pstree -p #see sleep.sh child/parent processes
$ pgrep sleep | sed 's/^/-p/'
$ pidof sleep
$  sudo strace -c -fp PID # attach to parent process of the sleep.sh
$ strace -c -fp $( pgrep sleep | sed 's/^/-p/' ) # another terminal, monitor multipe=le child processes of sleep.sh
$ strace $( pgrep sleep | sed 's/^/-p/' ) # another terminal, monitor multipe=le child processes of sleep.sh

man 3 stat #access the documentation. stat is the system call that gets a file's status
man 2 execve

$ grep openat trace.log
----------------------------------------------------------------------------------------------------
PATH=/data/myscripts:$PATH #add directory /data/myscripts to the beginning of the $PATH environment variable
PATH=$PATH:/data/myscripts #add that directory to the end of the path

echo 'export PATH=$PATH:/new/directory' >> ~/.zshrc
source ~/.zshr
----------------------------------------------------------------------------------------------------
echo "$(pwd)"
#interpret backslash escapes 
echo -e "Tecmint \nis \na \ncommunity \nof \nLinux \nNerds" 
echo -e "Tecmint \bis \ba \bcommunity \bof \bLinux \bNerds" 
echo -e "Tecmint \tis \ta \tcommunity \tof \tLinux \tNerds" 
echo -e "\vTecmint \vis \va \vcommunity \vof \vLinux \vNerds" 
echo -e "\n\vTecmint \n\vis \n\va \n\vcommunity \n\vof \n\vLinux \n\vNerds" 

echo -e "Geeks \bfor \bGeeks"  -e here enables the interpretation of backslash escapes,\b : it removes all the spaces in between the text
echo -e "Geeks \cfor Geeks" \c : suppress trailing new line with backspace interpretor ‘-e‘ to continue without emitting new line.
 echo -e "Geeks \nfor \nGeeks"  \n : this option creates new line from where it is used.
 echo -e "Geeks \tfor \tGeeks" \t : this option is used to create horizontal tab spaces.
 echo -e "Geeks \vfor \vGeeks \v : this option is used to create vertical tab spaces.
 echo -e "# SNMP version 2c community\nrocommunity monsvronly 192.168.58.8" >> /etc/snmp/snmpd.conf
 echo * #print all files/folders, similar to ls command 
----------------------------------------------------------------------------------------------------
#sh calls the program sh as interpreter and the -c flag means execute the following command as interpreted by this program
#sh -c spawns a non-login, non-interactive session of sh (dash in Ubuntu). 

$ sudo sh -c "echo 0" #In Ubuntu, sh is usually symlinked to /bin/dash, meaning that if you execute a command with sh -c the dash shell will be used to execute the command instead of bash
$ readlink -e $(which sh)
/usr/bin/dash
sudo sh -c 'ls -hal /root/ > /root/test.out' #The redirection of the output is performed by sudo.
sudo sh -c "echo foo > ~root/out.txt"
sudo echo "foo" | sudo dd of=/root/test2.out
sudo su -c 'echo "foo" > ~root/test4.out'
sudo su -c 'echo "foobarr" | tee  ~root/test5.out'
sudo su -c 'echo "append foobarr " | tee  -a ~root/test5.out'
sudo ls /root/out.txt

$ sudo bash -c "echo 0"
$ readlink -e $(which bash)
/usr/bin/bash

#the features that are specific to interactive shells only (by default), e.g. history expansion, source-ing of ~/.bashrc and /etc/bash.bashrc etc will not be available in this session as it is non-interactive
#simulate an interactive sessions behavior (almost), by using the -i option
sh -ic 'ls -hal /root/ > /root/test.out'
#the features that are specific to login shells only (by default) e.g. source-ing of ~/.profile (given ~/.bash_profile and ~/.bash_login do not exist) and /etc/profile will not be done as the shell is a non-login shell
#simulate login-shells behavior using the -l option
sh -lc 'ls -hal /root/ > /root/test.out'
#simulate both login and interactive sessions
sh -lic 'ls -hal /root/ > /root/test.out'
----------------------------------------------------------------------------------------------------
brew install <formula> #install a package (or Formula in Homebrew vocabulary) 
brew uninstall <formula>
brew upgrade <formula>
brew update
brew list --versions
brew search <formula>
brew info <formula>
brew cleanup --dry-run #see what formulas Homebrew would delete without actually deleting

#Homebrew-Cask extends Homebrew and allows you to install large binary files via a command-line tool
brew tap caskroom/cask #make Cask available by adding it as a tap

#https://brew.sh/
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install.sh)" #Install Homebrew
----------------------------------------------------------------------------------------------------
bash -c "$(curl -sL https://raw.githubusercontent.com/ilikenwf/apt-fast/master/quick-install.sh)" #remote script install
curl https://raw.githubusercontent.com/golang/dep/v0.5.1/install.sh | sh #remote script install
----------------------------------------------------------------------------------------------------

ln -s $PWD/istioctl /usr/local/bin/istioctl #create symbolic link
----------------------------------------------------------------------------------------------------
hwclock --utc --systohc # set the hardware clock to match system (software) clock on a Linux-only computer, The --utc option tells it to use UTC, which is appropriate for a Linux-only system, --systohc sets the hardware clock based on the current value of the software clock
----------------------------------------------------------------------------------------------------
logger shutting down to add network card #create a log file entry noting that you’re manually shutting down the system to add a new network card prior to using shutdown, The logger utility can be used to create a one-time log fle entry that you specify
----------------------------------------------------------------------------------------------------
rsyslogd -v #Check if rsyslog is installed
rsyslogd -f /etc/rsyslog.conf -N1 #Check Rsyslog Configuration for Errors

semanage port -l| grep syslog #view the current SELinux ports settings for rsyslog
semanage port -a -t syslogd_port_t -p udp 541 #add a UDP port 541 to SELinux

#Verifying the Configuration

#On the client server
logger "Test message from the system `hostname`" 
nc -u 192.168.59.12 514 #verify connectivity to remote rsyslog server TCP port 50514
telnet 192.168.59.12 50514 #verify connectivity to remote rsyslog server TCP port 50514

#On the Centralized rsyslog server
tail /var/log/messages  
tail –f /var/log/messages
netstat –pnltu # Confirm That the Syslog Server Is Listening on Port 514
ss -tunlp | grep 514
ss -4altunp | grep 514
ss -tulnp | grep "rsyslog"
nc -ulp 514 #cannot telnet to UDP port 514, use netcat 


#add the necessary UDP and/or TCP firewall rules to allow incoming syslog traffic
# systemctl restart rsyslog
# firewall-cmd --add-port=514/udp --permanent
# firewall-cmd --add-port=514/tcp --permanent
# firewall-cmd --reload
----------------------------------------------------------------------------------------------------
username must contain fewer than 32 characters and start with a letter
may consist of letters, numbers, and certain symbols
----------------------------------------------------------------------------------------------------
Deleting a group does not delete all the accounts associated with the group
Groups may have passwords, these are not account login passwords
----------------------------------------------------------------------------------------------------
/etc/modprobe.d #all the modules and other files, except for the optional configuration files
stat /lib/modules/`uname -r` #modprobe searches the module directory
more /proc/modules #a text list of the modules that the system has loaded

lsmod #list of currently loaded device drivers
lsmod | wc -l #total loaded Linux kernel modules
lsmod | grep nvidia #see if Linux kernel drivers (modules) named nvidia loaded or not
lsmod | egrep -i 'nvidia|e1000e|kvm_intel' #Search for multiple Linux device driver modules

modinfo e1000 # information about specific driver
----------------------------------------------------------------------------------------------------
#KVM

$ egrep -c '(vmx|svm)' /proc/cpuinfo | echo "virtualization is  supported" | echo "virtualization is not supported"
$ egrep -c '(vmx|svm)' /proc/cpuinfo && echo "virtualization is  supported" || echo "virtualization is not supported"
grep -i vmx /proc/cpuinfo #check if the CPU supports virtualization
lsmod | grep kvm #check  if the kvm kernel module is loaded

$ grep -c ^processor /proc/cpuinfo #check that your server has (at least) 8 CPU cores

To run KVM, you need a processor that supports hardware virtualization. 
Intel and AMD both have developed extensions for their processors, deemed respectively Intel VT-x (code name Vanderpool) and AMD-V (code name Pacifica)
#If 0 it means that your CPU doesn't support hardware virtualization.
#If 1 or more it does - but you still need to make sure that virtualization is enabled in the BIOS. 
$egrep -c '(vmx|svm)' /proc/cpuinfo  
$egrep -q 'vmx|svm' /proc/cpuinfo && echo yes || echo no #To use VM drivers, verify that your system has virtualization support enabled
#If the above command outputs “no”
#If you are running within a VM, your hypervisor does not allow nested virtualization. You will need to use the None (bare-metal) driver
#If you are running on a physical machine, ensure that your BIOS has hardware virtualization enabled
$cat /sys/hypervisor/properties/capabilities #if it is enabled or not from xen

$kvm-ok #If you see You can still run virtual machines, but it'll be much slower without the KVM extensions
INFO: Your CPU does not support KVM extensions
KVM acceleration can NOT be used

$egrep -c ' lm ' /proc/cpuinfo #If 0 is printed, it means that your CPU is not 64-bit. If 1 or higher it is 64-bit
$ uname -m
x86_64

#By default dhcpd based network bridge configured by libvirtd
$ brctl show
$ virsh net-list 

#All VMs (guest machine) only have network access to other VMs on the same server.
#A private network 192.168.122.0/24 created
$ virsh net-dumpxml default

virt-install --name=linuxconfig-vm \
--vcpus=1 \
--memory=2048 \
--cdrom=/media/sanchez/KARNAK/linux_distributions/CentOS-Stream-8-x86_64-20210617-dvd1.iso \
--disk size=5 \
--os-variant=centos-stream8
----------------------------------------------------------------------------------------------------

wc -mlw file1.txt file2.txt #Count words, characters, and lines in multiple files 	
ls -l *.pdf | wc -l #Count a Certain Type of Files in a Directory
wc -m yourTextFile # count the total number of characters	
wc -w yourTextFile #count the number of words
$ wc -c file1.txt #the number of characters in a file
$ wc -l file1.txt #the number of lines in a file
$ head -5 .bash_history | wc -w # the number of words in the first 5 lines of the file

# filecount=$(ls | wc -l)
# echo $filecount
----------------------------------------------------------------------------------------------------
# terminal1
$ ls > pipe2
$ mkfifo pipe5 -m700
$ ls -l > pipe5
$ rm pipe5
$rm dir1 #remove a non-empty directory

# terminal2
$ ls -lart pipe2 # list hidden files in the current directory
prw-rw-r-- 1 vagrant vagrant 0 Feb 25 15:33 pipe2
$ ls -lart pipe5
prwx------ 1 vagrant vagrant 0 Feb 25 20:52 pipe5
$ cat < pipe5
total 15828
prw-rw-r-- 1 vagrant vagrant        0 Feb 25 15:33 pipe2
prw-rw-r-- 1 vagrant vagrant        0 Feb 25 20:51 pipe4
prwx------ 1 vagrant vagrant        0 Feb 25 20:52 pipe5
-rw-rw-r-- 1 vagrant vagrant 16207833 Jan 22 22:02 terraform_0.12.20_linux_amd64.zip
----------------------------------------------------------------------------------------------------
pushd #stores a directory path in the directory stack,adds directory paths onto a directory stack (history), allows you to navigate back to any directory in history
pushd +2 #use the directory index in the form pushd +# or pushd -# to add directories to the stack and move into
popd #removes the top directory path from the same stack
popd +1 #remove a directory from the directory stack inded use popd +# or popd -#
dirs #display directories in the directory stack (or history)
dirs -v

pushd $(pwd) && cd /opt
popd

----------------------------------------------------------------------------------------------------
#from windows to linux copy problem fix
$ make
Makefile:21: *** missing separator.  Stop.
$ perl -pi -e 's/^  */\t/' Makefile

# unix/windows file editing
"/bin/bash^M: bad interpreter: No such file or directory"
fix:  sed -i -e 's/\r$//' build_all.sh

----------------------------------------------------------------------------------------------------
# ls do not provide creation time but change time
$ type ll
ll is aliased to `ls -alF'

# -a option shows all hidden files and directories (Those who start with .")
#the -F classify the results in files and folders,makes it more visual when a lot of files and directories with different extensions exist
ls -alF

ls -i About-TecMint #inode

The Bash shell feature that is used for matching or expanding specific types of patterns is called globbing
$ ls -l ????.txt #files whose names are four characters long
$ ls -l foot????.doc # files whose names are 8 characters long, first 4 characters are f, o, o and t and extension is doc
$ ls -l best.??? #all files with the name ‘test’ having any extension of three characters long


$ ls –lt #lists files in long listing format, and sorts files based on modification time, newest first
$ ls –lth
$ ls –ltr #list down files /folders sorted with modified time, -r reverse order
$ ls -ltr | grep "`date | awk '{print $2" "$3}'`" #todays date
$ ls -ltr | grep "$(date +"%b %e")"
$ ls -ltr | grep "Feb 18" #current date "Mar 22" # list files on specific dates
$ ls -ltr | awk '$6 == "Feb" && $7 >=15 && $7 <= 31 {print $6,$7,$8,$9}' # list files after Feb 15t
$ ls -ltr . | awk '$6 == "Feb" && $7 >=15 && $7 <= 31 {print $6,$7,$8,$9}' # list files after Feb 15t on specific directory

$ ls -lrt /var/log | awk '{ total += $5 }; END { print total }' # sum of file sizes

$ ls -FaGl /var/log/apt | printf "%'d\n" $(awk '{SUM+=$4}END{print SUM}') #total size 
$ ls -FaGl /var/log/apt | sudo tee /dev/stderr | printf "%'d\n" $(awk '{SUM+=$4}END{print SUM}') #list directory contents and total size 
$ ls -laUR /var/log/apt | grep -e "^\-" | tr -s " " | cut -d " " -f5 | awk '{sum+=$1} END {print sum}' #only sum up file sizes not the directory itself

# total size, sum of files listed
$ sumcol()
> {
>     awk "{sum+=\$$1} END {print sum}"
> }
$ ls -lrt /var/log/apt/ | sumcol 5

$ ls -l | grep 'Mar 22 12:27' | tr -s ' ' | cut -d ' ' -f9 | xargs rm -rf #delete files on specific date

#Listing of files in directory based on last modification time of file’s status information, or the 'ctime'
#list that file first whose any status information like: owner, group, permissions, size etc has been recently changed.
$ ls –lct #List Files Based on Last Modification Time 
$ ls –ltu #Listing of files in directory based on last access time, i.e. based on time the file was last accessed, not modified.

#Sorting Ouptut of ls -l based on Date
#based on 6th field month wise, then based on 7th field which is date, numerically
ls -l | sort -k6M -k7n 
ls -l | head -n 10 | sort -k6
ls -l | head -n 10| sort -k6M -k7n #based on 6th field month wise, then based on 7th field which is date

ls -lt --time=birth #sorted by creation/birth date time
ls -l --time=creation #sorted by creation/birth date time

$ ls -l *.pl #all files of ‘pl’ extension

$ ls -l [p-s]* #all files and folders whose name contains p or q or r or s
$ ls -l [1-5]* #all files and folders whose name starts with any digit from 1 to 5

$ ls -l {?????.sh,*st.txt} #files whose names are 5 characters long and the extension is ‘sh’ or the last two characters of the files are ‘st’ and the extension is ‘txt’
$ rm {*.doc,*.docx} #delete all files whose extensions are ‘doc’ or ‘docx’

$ ls a*+(.bash|.sh) #filenames which are starting with character ‘a’ and has the extension ‘bash’ or ‘sh’

ls -alt #list files in last modifed date order use the -t flag which is for 'time last modified'.
ls -altr #list files in last modifed date order use the -t flag which is for 'time last modified', reverse order
----------------------------------------------------------------------------------------------------
echo test > >(cat) #the output of echo would be redirected to the file that serves as the input to cat, and cat would produce the contents of that file on standard output

echo foo | cat -n
echo foo > >(cat -n) # emulate pipe above

The process substitution >(command) will be replaced by a file name. 
This file name corresponds to a file that is connected to the standard input of the "command" inside the substitution

$ cat .profile | while read line; do ((counter1++)); done
$ echo $counter1
$ while read line; do ((count++)); done < <(cat ~/.profile)
$ echo $count
101
----------------------------------------------------------------------------------------------------
#Network Troubleshooting 
Step 1: Check if your interface is configured
$ ifconfig

sudo resolvconf -u

Step 2: Setting up your interface
check if the drivers are loaded
$ dmesg | grep -3 -i eth
configure the interface
ifconfig eth0 128.42.14.176 netmask 255.255.255.0 up
Assign a Broadcast to Network Interface
ifconfig eth0 netmask 255.255.255.224
If the loopback interface is not up
ifconfig lo up
now be able to ping your own machine
$ ping -c 3 127.0.0.1

Step 3: Check if you can ping the gateway
ping the DNS server

Step 6: Setting up routing
# route add -net <naddr> netmask <maddr> eth0
# route add default gw <gaddr> eth0
setup the loopback route if it's missing
# route add -host 127.0.0.1 lo

#Adding and removing routes
ip ro add 10.0.0.0/16 via 192.0.2.253 
ip ro del 10.0.0.0/16 via 192.0.2.253
ip ro
ip -6 ro #IPv6
ip route get 8.8.8.8 | sed -n '/src/{s/.*src *\([^ ]*\).*/\1/p;q}' # IP reaching the public internet, multiple IPs interfaces
ip ro get $dst_ip from $src_ip #Check routing path
ip ro get 192.0.0.0

$ ip route show
default via 10.0.2.2 dev eth0 proto dhcp metric 100
10.0.2.0/24 dev eth0 proto kernel scope link src 10.0.2.15 metric 100
192.168.18.0/24 dev eth1 proto kernel scope link src 192.168.18.9 metric 101

traffic to anywhere else should be forwarded through eth0 to the gateway at 10.0.2.2
traffic to 10.0.2.2 (the gateway to the public Internet) should be forwarded directly to its destination through eth0
traffic to anywhere within 192.168.18.0/24 (the local area network) should be forwarded directly to its destination through eth1

$ ip route get to 192.168.18.12 from 192.168.18.9 iif eth1
$ ip route get to 192.168.18.9  from 192.168.18.12 iif eth1

$ route -n
route add dest_ip_address gateway_address #Add a route to a destination through a gateway
route add subnet_ip_address/24 gateway_address #Add a route to a /24 subnet through a gateway
route -t add dest_ip_address/24 gateway_address #Run in test mode (does not do anything, just print)
route flush #Remove all routes
route delete dest_ip_address/24 #Delete a specific route

Step 7: Name resolution
3 files: /etc/host.conf, /etc/hosts, /etc/resolv.conf

/etc/host.conf:
order hosts,bind
multi on

/etc/hosts:
127.0.0.1      localhost loopback
<IPaddr>        this.host.name

/etc/resolv.conf:
domain yourdept.yourcompany.com
search yourdept.yourcompany.com yourcompany.com
nameserver <domainaddr>

----------------------------------------------------------------------------------------------------
# ping a host
ping 192.168.0.2
#show routing table without resolving domain names
netstat -nr
netstat -r -n # The flag U indicates that route is up and G indicates that it is gateway 
netstat -alun | grep 161
# show informations about errors/collisions
netstat -ni  
# show statistics about your network card
netstat -i -I em0  
netstat -a
netstat -at
netstat -s
netstat -au
netstat -l
netstat -lu
netstat -lt
netstat -tulpn  	
netstat -plan
netstat -plan | grep ":80"
netstat -lntp | grep ':8080.*java' > /dev/null && command
netstat -pan -A inet,inet6 | grep -v ESTABLISHED #determine which ports are listening for connections from the network
netstat -tlnw #Use the -l option of the netstat command to display only listening server sockets:
netstat -plnS #Scan for Open SCTP Ports
netstat -nl -A inet,inet6 | grep 2500 #Scan for Open SCTP Ports
netstat -pant | grep -Ei 'apache|:80|:443'
netstat -tunlp | grep ":80 "
List all TCP sockets and related PIDs
netstat -antp
netstat -anp
List all UDP sockets and related PIDs
netstat -anup
# find out on which port a program is running
netstat -ap | grep ssh
#If there is an IP address instead, then the port is open only on that specific interface
#For listening ports, if the source address is 0.0.0.0, it is listening on all available interfaces
#The Recv-Q and Send-Q fields show the number of bytes pending acknowledgment in either direction
#the PID/Program name field shows the process ID and the name of the process responsible for the listening port or connection
netstat -anptu 
#number of established connection
netstat -an|grep ESTABLISHED|awk '{print $5}'|awk -F: '{print $1}'|sort|uniq -c|awk '{ printf("%s\t%s\t",$2,$1); for (i = 0; i < $1; i++) {printf("*")}; print ""}'

#see that the Nessus server is up and running
netstat -n | grep tcp
netstat -tap | grep LISTEN
netstat -pltn | grep 8834
----------------------------------------------------------------------------------------------------
#ss is the socket statistics command that replaces netstat
ss -tr #netstat -t
ss -ntr #see port numbers
ss -an |grep LISTEN #netstat -an |grep LISTEN
ss -an | grep 2500 #show SCTP open ports
ss -tlw # list open ports in the listening state
ss -plno -A tcp,udp,sctp #The UNCONN state shows the ports in UDP listening mode
----------------------------------------------------------------------------------------------------

# find route to example.com
traceroute www.example.com
#find route to example.com using tcptraceroute (which uses tcp to discover path)
tcpdraceroute www.example.com
# The maximum number of hops can be adjusted with the -m flag.
traceroute -m 255 obiwan.scrye.net
# adjust the size of the packet that is sent to each hop by giving the integer after the hostname
traceroute google.com 70

Specify Gateway
sudo traceroute  -g 10.0.2.2 yahoo.com
traceroute -g 192.5.146.4 -g 10.3.0.5 35.0.0.0
#shows the path of a packet that goes from istanbul to sanfrancisco through the hosts cairo and paris
#The -I option makes traceroute send ICMP ECHO probes to the host sanfrancisco
#The -i options sets the source address to the IP address configured on the interface qe0
traceroute -g cairo -g paris -i qe0 -q 1 -I sanfrancisco 
ip r / ip route #gateway / router
ip r | grep default #default gateway
route -n # The flag U indicates that route is up and G indicates that it is gateway
route -nee
netstat -r -n # The flag U indicates that route is up and G indicates that it is gateway 
routel #list routes
routel | grep default #default gateway


Specify Source Interface
sudo traceroute  -i eth0 yahoo.com
Autonomous Systems
traceroute  -A  yahoo.com

tracepath yahoo.com
tracepath -n yahoo.com
tracepath -b yahoo.com
sets the initial packet length
tracepath -l 28 yahoo.com
set maximum hops (or maximum TTLs) to max_hops
tracepath -m 5 yahoo.com
set the initial destination port to use
tracepath -p 8081  yahoo.com

hostname -f #show fully qualified domain name (FQDN)
hostname #shortname
hostname -I #the primary/first IP address
hostname -I | awk '{print $1}' # get primary/first IP IP address of server
hostname -I | awk '{print $2}' # get second IP IP address of server

real-time view of the current state of your system
$ htop

$ timedatectl
$ timedatectl list-timezones
$ sudo timedatectl set-timezone 'Africa/Lubumbashi'

# Enable NTP synchronization
timedatectl set-ntp true
timedatectl status

# show connected sockets
sockstat -c 
# show listening sockets and processes
sockstat -l

# show arp table
arp -a #Show current arp tabl
arp -na 
ip neighbour #Show neighbors (ARP table)
arp -d 192.168.0.2 # delete a record from arp table
sudo arp -a -d #Clear the entire cach
arp -s 192.168.0.2  00:10:b5:99:bf:c4 #add a static record in arp table
# listen on em0 network interface and sniff packets that pass via em0
$ sudo arp -i eth0


find out reachability of an IP on the local Ethernet with arping i.e send ARP request 192.168.1.1:
$ sudo arping -I eth0 -c 3 192.168.18.12
$ sudo arping -I eth1 -c 3 192.168.18.12
Find duplicate IP
$ sudo arping -D -I eth1 -c 3 192.168.18.12

ping -I eth0 8.8.8.8 #ping 8.8.8.8 using eth0 as a source interface 
ping google.com
ping -6 hostname/IPv6 #request IPv6 or IPv4 address
ping -4 hostname/IPv4
#The default interval between each ping request is set to one second. You can increase or decrease that time using the –i switch
#decrease the ping interval, use values lower than 1
ping -i 0.5 google.com 
ping -s 1000 google.com #use -s to increase the packet size from the default value of 56 (84) bytes.
ping -f hostname-IP #use ping flood to test your network performance under heavy load
ping -c 2 google.com #Limit Number of Ping Packets
ping -w 25 google.com #stop printing ping results after 25 seconds
ping -c 10 -q google.com #The letter “q” in this command stands for “quiet” output.
ping -D google.com #Add Timestamp Before Each Line in ping Output

$ file *
20:30:               empty
file1:               ASCII text
file2:               ASCII text
$ file raw_file.txt #if a text file contains ASCII or Unicode
$ file -b symbolic_test1.txt
symbolic link to test1.txt
-----------------------------------------------------------------------------------------------------
# parse html with curl
curl -s https://miloserdov.org/ | grep -E -o '<h3 class=ftitle>.*</h3>' | sed 's/<h3 class=ftitle>//' | sed 's/<\/h3>//'
curl http://test.com | sed -rn 's@(^.*<dd>)(.*)(</dd>)@\2@p'

cat - > file.html << EOF
<div class="tracklistInfo">
<p class="artist">Diplo - Justin Bieber - Skrillex</p>
<p>Where Are U Now</p>
</div><div class="tracklistInfo">
<p class="artist">toto</p>
<p>tata</p>
</div>
EOF
cat file.html | tr -d '\n'  | sed -e "s/<\/div>/<\/div>\n/g" | sed -n 's/^.*class="artist">\([^<]*\)<\/p> *<p>\([^<]*\)<.*$/artist : \1\ntitle : \2\n/p'
cat file.html | grep -A2 -E -m 1 '<div class="tracklistInfo">'
cat file.html | grep -A2 -E -m 1 '<div class="tracklistInfo">' | tail -n1
cat file.html | grep -A2 -E -m 1 '<div class="tracklistInfo">' |  tail -n2 | head -n1
cat file.html | grep -A2 -E -m 1 '<div class="tracklistInfo">' |  tail -n2 | head -n1 | sed 's/<[^>]*>//g'
-----------------------------------------------------------------------------------------------------
Check what ethernet devices exist currently
# ls -al /sys/class/net
# ls -Rl
list hidden files and the contents of all subdirectories
ls -aR /home/username
# ls -pu
see eth* devices
# ls -al /sys/class/net
Get the PCI address of the NIC
# lspci | grep Mellanox
# lspci | grep Eth 

iw distinguishes between wireless LAN hardware devices (the physical layer, referred to as phy) and the network interface configured to use that hardware (e.g. wlan0, 
similar to an Ethernet eth0 interface). To see the list of devices, and interfaces for each device
#iw dev

**MAC_ADDRESS	08:00:27:e3:b0:01
$ ip link show eth1
3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP mode DEFAULT group default qlen 1000
    link/ether 08:00:27:e3:b0:01 brd ff:ff:ff:ff:ff:ff
$ ip addr show eth1
3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 08:00:27:e3:b0:01 brd ff:ff:ff:ff:ff:ff
    inet 192.168.1.253/24 brd 192.168.1.255 scope global noprefixroute eth1
       valid_lft forever preferred_lft forever
    inet6 fe80::a00:27ff:fee3:b001/64 scope link
       valid_lft forever preferred_lft forever
       
 #temporarily set the IP address
 ifconfig eth0 192.168.8.185
 ifconfig eth0 192.168.8.185 netmask 255.255.255.0 up
 #temporarily change the MAC address
 ifconfig eth0 down hw ether AA:BB:CC:DD:EE:FF && ifconfig eth0 up
 ifconfig  eth0 netmask 255.255.255.0
 ifconfig  eth0 broadcast 192.168.70.255

ip addr show -> List IP address of the server
ip addr show eth0
ip addr | grep inet6 #check that your server supports IPV6
ip addr show eth1 | grep "inet "
ip addr add 10.132.1.1/24 dev eth1 ->  Add a new IP4 address
ip addr show eth1 -> confrm that the new address is available on the interface

ip link set eth2 down -> bring an interface down  
ip link set eth2 up

ip -s link->view basic network statistics on all interfaces
ip -s link ls eth0 ->see the statistics for the eth0 interface
ip -s -s link ls eth0 ->see additional info

ss -t ->show established TCP connections
ss -u ->show established UDP connections
ss -A tcp 
ss -x 
ss -ltn ->see which ports are listening for connections
ss -nt
ss -ltn
ss -ua
ss -a -A udp
ss -lun ->udp
ss -s->prints out the statistics

#Install sysstat package
# /etc/default/sysstat ENABLED="true"
#sudo service sysstat restar
vmstat 1 99999 ->the system statistics every second, for the number of times specifed (99999 in this instance)
vmstat –a 1 99 ->show memory usage information
vmstat -a -S M 1 9 -> reformat in Mega Bytes
vmstat 1 99999 ->gather information for disks and other block devices
vmstat -d -w
iostat 1 9 ->CPU information and disk information for all devices
iostat -d -p sda 1 9-> show information for device sda with disk statistics
sar -u 1 30 -> display CPU statistics every second for 30 seconds 
sar -r 1 30  -> display memoru statistics every second for 30 seconds 
sar -b 1 30  -> display block device statistics every second for 30 seconds 

#=====================================================================

# curl the binay version info from latest download and later wget the file with
$curl -s https://api.github.com/repos/prometheus/prometheus/releases/latest \
| grep browser_download_url \
| grep linux-amd64 \
| cut -d '"' -f 4 \
| wget -qi -
$ ls
prometheus-2.37.0.linux-amd64.tar.gz
$tar xvf prometheus*.tar.gz
$cd prometheus*/


#specify directory and rename the file
wget --output-document="/home/my_new_file_name" http://someurl
#add the appropriate BeeGFS repositories
wget -o /etc/yum.repos.d/beegfs-rhel7.repo http://www.beegfs.com/release/beegfs_2015.03/dists/beegfs-rhel7.repo
wget -q https://www.virtualbox.org/download/oracle_vbox.asc -O- |  apt-key add -

wget example.com/big.file.iso  #start download and stop download ctrl+c key pair
wget -c example.com/big.file.iso  #resume download 

wget ‐‐continue example.com/big.file.iso #Resume an interrupted download previously started by wget itself
wget ‐‐continue ‐‐timestamping wordpress.org/latest.zip #Download a file but only if the version on server is newer than your local copy
wget ‐‐page-requisites ‐‐span-hosts ‐‐convert-links ‐‐adjust-extension http://example.com/dir/file #Download a web page with all assets - like stylesheets and inline images - that are required to properly display the web page offline.
wget -q  http://somesite.com/TheFile.jpeg #-q: Turn off wget's output
wget http://example.com/images/{1..20}.jpg # Download a list of sequentially numbered files from a server
wget -m -r -linf -k -p -q -E -e robots=off http://127.0.0.1 # Download a complete website
wget ‐‐mirror ‐‐domains=abc.com,files.abc.com,docs.abc.com ‐‐accept=pdf http://abc.com/ #Download the PDF documents from a website through recursion but stay within specific domains.
wget ‐‐execute robots=off ‐‐recursive ‐‐no-parent ‐‐continue ‐‐no-clobber http://example.com/ #Download an entire website including all the linked pages and files
wget ‐‐level=1 ‐‐recursive ‐‐no-parent ‐‐accept mp3,MP3 http://example.com/mp3/ #Download all the MP3 files from a sub-directory
wget --recursive --no-clobber --page-requisites --html-extension --convert-links --restrict-file-names=windows --domains some-site.com --no-parent www.some-site.com #Download Entire Website
wget ‐‐recursive ‐‐no-clobber ‐‐no-parent ‐‐exclude-directories /forums,/support http://example.com #Download all files from a website but exclude a few directories
wget --reject=png www.some-site.com #Reject file types while downloading
wget -r -A .pdf http://some-site.com/ #Download all PDF files from a website
wget -r -H --convert-links --level=NUMBER --user-agent=AGENT URL #Download With Wget Recursively,declare a user agent such as Mozilla (wget –user-agent=AGENT)
wget -e https_proxy=xx.xx.xx.xx:8080 https://example.com/  #use proxy server with wget

wget -S --spider http://www.uniqlo.com/ #Only Header Information

##if link exists
url="https://www.katacoda.com/courses/kubernetes/launch-single-node-cluster"
if wget --spider "$url" 2>/dev/null; then #2> /dev/null silences wget's stderr output
  echo "URL exists: $url"
else
  echo echo "URL does not exist: $url"
fi

#connect to a remote server,start download on the remote server,disconnect from the remote server,let it run on the background
$ nohup wget -q url &  

wget -i file.txt #Read download URLs from a file,useful in a shell script.

#one liner if condition
wget --spider http://192.168.50.15/${distribution}_${codename}_oscap_report.html 2>/dev/null && echo "link exists" || echo "link does not exist"

wget --spider -S "www.magesh.co.in" 2>&1 | awk '/HTTP\// {print $2}' #see only the HTTP status code
wget --spider -o wget.log -e robots=off --wait 1 -r -p http://www.mysite.com/ #crawl a website and generate a log file of any broken links

wget --spider https://example.com/filename.zip 2>&1 | grep Length #file download size without downloading the actual file
wget ‐‐spider ‐‐server-response http://example.com/file.iso #Find the size of a file without downloading it (look for ContentLength in the response, the size is in bytes)

wget ‐‐output-document - ‐‐quiet google.com/humans.txt #Download a file and display the content on the screen without saving it locally
wget ‐‐server-response ‐‐spider http://www.labnol.org/ #the last modified date of a web page (check the LastModified tag in the HTTP header)
wget ‐‐output-file=logfile.txt ‐‐recursive ‐‐spider http://example.com #Check the links on your website to ensure that they are working. The spider option will not save the pages locally.
wget ‐‐limit-rate=20k ‐‐wait=60 ‐‐random-wait ‐‐mirror example.com # limited the download bandwidth rate to 20 KB/s and the wget utility will wait anywhere between 30s and 90 seconds before retrieving the next resource.
wget -O index.html  --certificate=OK.crt --private-key=OK.key https://example.com/ #Client SSL Certificate
wget -q -O - --header="Content-Type:application/json" --post-file=foo.json http://127.0.0.1 # POST a JSON file and redirect output to stdout
wget -O wget.zip http://ftp.gnu.org/gnu/wget/wget-1.15.tar.gz #Download file with different name
wget -o download.log http://ftp.gnu.org/gnu/wget/wget-1.15.tar.gz #redirect the wget command logs to a log file using ‘-o‘ switch.
wget ‐‐output-document=filename.html example.com #Download a file but save it locally under a different name
wget ‐‐directory-prefix=folder/subfolder example.com #Download a file and save it in a specific folder
wget -r -l inf -A .png,.jpg,.jpeg,.gif -nd https://jekyllrb.com # Download all images of a website
wget -r --level=1 -H --timeout=1 -nd -N -np --accept=mp3 -e robots=off -i musicblogs.txt #take a text file of your favourite music blogs and download any new MP3 files
wget --ftp-user=User --ftp-password=Mir URL # FTP download
wget http://ftp.gnu.org/gnu/wget/wget-1.15.tar.gz ftp://ftp.gnu.org/gnu/wget/wget-1.14.tar.gz.sig #Download multiple file with http and ftp protocol
wget -i /wget/urls.txt #Read URL’s from a file
wget -Q10m -i download-list.txt #Setting Download Quota
wget -c http://ftp.gnu.org/gnu/wget/wget-1.15.tar.gz #Resume download
wget -b /wget/log.txt http://ftp.gnu.org/gnu/wget/wget-1.15.tar.gz #Download files in background
wget -b -c --tries=NUMBER URL #number of tries (wget –tries=NUMBER), continue partial download (wget -c)
wget -b --limit-rate=SPEED -np -N -m -nd --accept=mp3 --wait=SECONDS http://www.uniqlo.com/ #no parent to ensure you only download a sub-directory (wget -np),update only changed files (wget -N), mirror a site (wget -m), ensure no new directories are created (wget -nd), accept only certain extensions (wget –accept=LIST) 
wget -c --limit-rate=100k  /wget/log.txt http://ftp.gnu.org/gnu/wget/wget-1.15.tar.gz #Limit download speed
wget --http-user=username --http-password=password http://some-network.net/some-file.txt #Options –http-user=username, –http-password=password
wget --ftp-user=username --ftp-password=password ftp://some-network.net/some-file.txt #–ftp-user=username, –ftp-password=password
wget --tries=75 http://ftp.gnu.org/gnu/wget/wget-1.15.tar.gz #Increase Retry Attempts.
wget ‐‐refer=http://google.com ‐‐user-agent="Mozilla/5.0 Firefox/4.0.1" http://nytimes.com #Wget can be used for downloading content from sites that are behind a login screen or ones that check for the HTTP referer and the User-Agent strings of the bot to prevent screen scraping.
wget ‐‐cookies=on ‐‐save-cookies cookies.txt ‐‐keep-session-cookies ‐‐post-data 'user=labnol&password=123' http://example.com/login.php_ _wget ‐‐cookies=on ‐‐load-cookies cookies.txt ‐‐keep-session-cookies http://example.com/paywall #Fetch pages that are behind a login page. You need to replace user and password with the actual form fields while the URL should point to the Form Submit (action) page.
wget ‐‐span-hosts ‐‐level=inf ‐‐recursive dmoz.org #
wget -r --level=inf -p -k -E --span-hosts --domains=domainA,domainB http://www.domainA #download an entire site (domain A) when its resources are on another domain, (domain B)
wget --page-requisites --convert-links --adjust-extension --span-hosts --domains domainA,domainB domainA #
wget --recursive --level=inf --page-requisites --convert-links --html-extension -rH -DdomainA,domainB domainA #
wget --recursive --level=inf --page-requisites --convert-links --adjust-extension --span-hosts --domains=domainA,domainB domainA #

#=====================================================================
sudo permission denied
The redirection to a file is handled by bash. It does therefore not inherit permissions granted by sudo.
"sudo tee" for writing to a file as root.

lsblk -f -> when used with the -f option, it prints file system type on partitions 
sudo file -sL /dev/sdb1 -> file system type on partitions
lsblk -f
lsblk -l
lsblk --scsi
lsblk -o name,type,fstype,label,partlabel,model,mountpoint,size
lsblk --json | jq -c '.blockdevices[]|[.name,.size]'

#/etc/fstab explained, Each field can be separated by another either by spaces or tabs

First field – The block device,reference a block device is by using its LABEL or UUID (Universal Unique IDentifier)
$ lsblk -d -fs /dev/sdb1 # get UUID

Second field – The mountpoint
Third field – The filesystem type
Fourth field – Mount options, use the default set of mount options we specify default as a value
Fifth field – Should the filesystem be dumped?, either 0 or 1,used by the dump backup program (if installed)

Sixth field – Fsck order;fsck utility, should check filesystems on boot;
value of 1 must always be used for the root filesystem
if not  root filesystem,for all the others, value of  2
If not provided it defaults to 0


# generate traces of the i/o traffic on block devices 
"sudo blktrace -d /dev/sda -o - | blkparse -i -"


#writing ISO usb bootable
sudo umount /dev/sdX
sudo dd if=/path/to/ubuntu.iso of=/dev/sdX bs=4M && sync
sdx-> lslbk command
sync-> sync bit is important as dd can return before the write operation finishes.

# mount all file systems on /etc/fstab
mount -a
mount -fav
cat /proc/mounts
# format linux swap partition
mkswap
--------------------------------------------------------------------------------------------------------------------
#search man pages

man -k . #List all available man pages on the system and provide a short description
man -f virt-manager # Keyword must be the exact name of a man page
man -K date -> display a list of all manual pages containing the keyword "date"
man -wK word ->list out all manual files with some word.
man -wK --regex "ipv4.*listen"
man --regex ".*network$" 

#search through all man pages on a system for the specified keyword and output the location of any man pages that contain that keyword
man -S 1 --regex "^virsh" 

man yum | less +/"install @" #search "install @" pattern in man yum page
man -P 'less -p install ' yum #search "install" pattern in man yum page
--------------------------------------------------------------------------------------------------------------------
# Clone / Compile specific kernel
sudo git clone git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git linux -> latest stable kernel to "linux" directory
git tag -l | grep v4.9.1 -> find specific kernel version
git checkout -b kernel490 v4.9.1 -> switch to kernel with custom name "kernel490"


#tail -f vs less +F
#tail -f only reads the end of the file
#tail -f doesn't keep the whole file in memory.
tail -f /var/log/syslog
#less +F reads the whole file
#less +F impractical for very large files.
#less +F can highlight, search, navigate through file
#hit Ctrl-c to go to “normal” less mode (as if you had opened the file without the +F flag)
#the search with /foo,next or previous occurrence with n or N, up and down with j and k,, create marks with m
#hit F to go back to watching mode
less +F /var/log/syslog

less -n +F #read only the end of the file

tail -100f /var/log/messages | grep -V ACPI | grep -i ata #real-time monitoring,tailing 100 lines from the end
tail -f /var/log/nginx/access.log /var/log/nginx/access.log #watching multiple files

#top 10 internet protocol addresses hitting a webserver from the access log
cat /var/log/nginx/access.log | cut -f 1 -d ' ' | sort | uniq -c | sort -hr | head -n 10

multitail /var/log/auth.log /var/log/kern.log #shows the contents of log files horizontally
multitail -s 2 /var/log/auth.log /var/log/kern.log #view the contents of log files vertically in two columns
multitail -s 2 /var/log/syslog, /var/log/kern.log, /var/log/daemon.log and var/log/messages
multitail -s 2 -ci green /var/log/auth.log -ci blue /var/log/kern.log
lnav /var/log/syslog /var/log/messages
lnav a.zip b.zip
--------------------------------------------------------------------------------------------------------------------
#crontab
Display scheduled jobs for the specified user
crontab -l -u vagrant
crontab -l
# Display Cron Table
ls -la /etc/cron*

sudo crontab -u user -e #
crontab -e #when running as a non-root user
sudo crontab -e #the root user's crontab


#If the /etc/cron.allow file exists, then users must be listed in it in order to be allowed to run the crontab command
#If the /etc/cron.allow file does not exist but the /etc/cron.deny file does, 
#then users must not be listed in the /etc/cron.deny file in order to run crontab
#If the /etc/cron.allow file exists, then users must be listed in it in order to be allowed to run the crontab command
/etc/cron.deny # If a blank cron.deny file has been created, cron only available to root or users in cron.allow. 

# Delete All Cron Jobs
crontab -r
crontab -r -i #the command prompt  to confirm
# All scripts in each directory are run as root
#Cron jobs may not run with the environment, in particular the PATH, that you expect. Try using full paths to files and programs
#The "%" character is used as newline delimiter in cron commands. If you need to pass that character into a script, you need to escape it as "\%".
#anacron uses the run‑parts command and /etc/cron.hourly, /etc/cron.weekly, and /etc/cron.monthly directories.
#anacron itself is invoked from the /etc/crontab file
#user crontabs
/etc/cron.hourly/, /etc/cron.daily/, /etc/cron.weekly/, and /etc/cron.monthly/
ls -la /etc/cron.daily/ #View daily cron jobs

crontab -l > backup_cron.txt #Backup All Cron Jobs

/etc/crontab #not recommended that you add anything,this could cause a problem if the /etc/crontab file is affected by updates
/etc/cron.d #not be affected by updates, several people might look after a server, then the directory /etc/cron.d is probably the best place to install crontabs
/etc/cron.d #These files also have username fields

#the files inside /etc/cron.d
chown root:root /etc/cron.d/*
chmod go-wx /etc/cron.d/*
chmod -x /etc/cron.d/*

$ cat /etc/cron.allow
barak
$ sudo systemctl restart cron
$ cat /etc/cron.d/barak_job
*/1 * * * * barak echo "Nightly Backup Successful: $(date) " > /tmp/test1_job.log
*/1 * * * * /usr/bin/free -m | awk '{ if($1 == "Mem:" ) print $3}' | awk '{ if ( $1 > 140 ) print $0; else print "less" }' >> /tmp/memo.log

#troubleshooting cron
$ cat /etc/cron.d/barak_job
*/1 * * * * barak echo "Nightly Backup Successful: $(date) " &> /tmp/test1_job.log #redirect stdout and stderr to a file.
*/1 * * * * barak echo "Nightly Backup Successful: $(date) " > /tmp/test1_job.log2 2>&1 #redirect stdout and stderr to a file.

#php specific
php /bla/bla/something.php >> /var/logs/somelog-for-stdout.log
#the only difference from the syntax of the user crontabs is that the line specifies the user to run the job as
00 01 * * * rusty /home/rusty/rusty-list-files.sh #run Rusty's command script as user rusty from his home directory.

/usr/bin/php /home/username/public_html/cron.php #Execute PHP script:
mysqldump -u root -pPASSWORD database > /root/db.sql #MySQL dump:
/usr/bin/wget --spider "http://www.domain.com/cron.php"  #Access URL:

$ cat /etc/cron.allow
barak
$ sudo systemctl restart cron/crond
$ cat /etc/cron.d/barak_job
*/1 * * * * barak echo "Nightly Backup Successful: $(date)" >> /tmp/mybackup.log
$ crontab -u barak -l
#*/1 * * * * barak echo "Nightly Backup Successful: $(date) runs" >> /tmp/barak_job.log
$ sudo tail -f /var/log/syslog | grep --color=auto CRON

crontab -e
@hourly echo "Nightly Backup Successful: $(date)" >> /tmp/mybackup.log

#"-u borg" is used take the identity of the borg user
# cat /etc/cron.daily/borgbackup_check 
#!/bin/bash
sudo -u borg borg check /borgbackup >> /var/log/borgbackup.log

#once every 5 minutes
cat | sudo tee /etc/cron.d/cron-mrtg << EOF
*/5 * * * * env LANG=C /usr/bin/mrtg /etc/mrtg.cfg
EOF
#verify
cat /etc/cron.d/cron-mrtg
crontab -l 

cat | sudo tee /etc/cron.d/sysinfo << EOF
#once every 5 minutes
*/5 * * * * /bin/bash /home/vagrant/sysinfo_func.sh
EOF
#verify
cat /etc/cron.d/cron-mrtg

* * * * * /bin/date >> /tmp/cron_output #This will append the current date to a log file every minute.
* * * * * /usr/bin/php /var/www/domain.com/backup.php > /dev/null 2>&1 #run a script but keep it running in the background
at specific time
00 15 * * 4 sh /root/test.sh
35 21 * * 7 /bin/date >> /tmp/cron_output
every 5 minutes
*/5 * * * *  mycommand
an hourly cron job but run at minute 15 instead (i.e. 00:15, 01:15, 02:15 etc.):
15 * * * * [command]
once a day, at 2:30am:
30 2 * * * [command]
once a month, on the second day of the month at midnight (i.e. January 2nd 12:00am, February 2nd 12:00am etc.):
0 0 2 * * [command]
on Mondays, every hour (i.e. 24 times in one day, but only on Mondays):
0 * * * 1 [command]
three times every hour, at minutes 0, 10 and 20:
0,10,20 * * * * [command]
# Stop download Mon-Fri, 6am
0 6 * * 1,2,3,4,5 root          virsh shutdown download
*/5 * * * * /path/to/some-script.sh #every 5 minutes
@reboot /scripts/script.sh #tasks to execute on system reboot
@hourly /scripts/script.sh #execute on an hourly.
0 * * * */scripts/script.sh #execute on an hourly.
@daily /scripts/script.sh # execute on a daily basis.
0 2 * * * /scripts/script.sh # executes the task in the second minute of every day.#
@weekly /bin/script.sh #execute on a weekly basis
0 0 4 * sun /bin/script.sh #execute on a weekly basis
@monthly /scripts/script.sh #execute on a monthly basis
0 0 1 * * /scripts/script.sh #execution of a task in the first minute of the month
@yearly /scripts/script.sh #schedule tasks on a yearly basis.
@yearly /scripts/script.sh #executes the task in the fifth minute of every year.
* * * * *  sleep 15; /scripts/script.sh #schedule a cron to execute after every 15 Seconds
0 4,17 * * mon,tue /scripts/script.sh #execute twice on Monday and Tuesday
0 17 * * mon,wed  /script/script.sh #run each Monday and Wednesday at 5 PM
0 7,17 * * * /scripts/script.sh #execute at 7 AM and 5 PM daily
0 5 * * mon  /scripts/script.sh #execute the task on every Monday at 5 AM
0 */6 * * * /scripts/script.sh #run a script for 6 hours interval
0 8-10 * * * /scripts/script.sh # run every hour between 08-10AM
0 2 * * sat  [ $(date +%d) -le 06 ] && /script/script.sh #execute on first Saturday of every month
0   12  1-7 *   *   [ "$(date '+\%a')" = "Mon" ] && echo "It's Monday" #on the first Monday of every month
* * * feb,jun,sep *  /script/script.sh #run tasks in Feb, June and September months
--------------------------------------------------------------------------------------------------------------------
tail -n 1 /usr/share/dict/words #limit the number of lines to show
tail -c 24 /usr/share/dict/words #limit the number of bytes to show
tail /usr/share/dict/words /usr/share/dict/french #show the last ten lines of multiple files
tail -n 5 file_1 file_2
tail -n +N <filename>   #the lines starting from line number N
tailf -F /var/log/syslog #monitoring the log file even at its rotation
tail -q /usr/share/dict/words /usr/share/dict/french #suppress the header line pass the -q option
ls -t /etc | tail -n 5  #show the five files or folders modified the longest time ago

#brctl show -> Bridge connections
--------------------------------------------------------------------------------------------------------------------
#LVM
pvdisplay
pvck
pvs
lvscan
lvdisplay
lvmdiskscan
vgchange
vgscan -a y
e4defrag -cv /path/to/myfiles (defrag folder )


$ sudo pvcreate /dev/sdb
$ sudo pvs
  PV         VG       Fmt  Attr PSize   PFree
  /dev/sda2  centos   lvm2 a--  <63.00g 4.00m
  /dev/sdb   vg_iscsi lvm2 a--  <30.00g    0
$ sudo pvdisplay
  --- Physical volume ---
  PV Name               /dev/sdb
  VG Name               vg_iscsi
  PV Size               30.00 GiB / not usable 4.00 MiB
  Allocatable           yes (but full)
  PE Size               4.00 MiB
  Total PE              7679
  Free PE               0
  Allocated PE          7679
  PV UUID               hG93NW-gvRB-njUP-pgj8-omRF-YzFe-rTMWOz

  --- Physical volume ---
  PV Name               /dev/sda2
  VG Name               centos
  PV Size               <63.00 GiB / not usable 3.00 MiB
  Allocatable           yes
  PE Size               4.00 MiB
  Total PE              16127
  Free PE               1
  Allocated PE          16126
  PV UUID               rFHI2D-fvZw-Mf2P-gKTC-ZTwt-vdiY-TEQc14
  
$ sudo vgcreate vg_iscsi /dev/sdb
$ sudo vgdisplay
  --- Volume group ---
  VG Name               vg_iscsi
  System ID
  Format                lvm2
  Metadata Areas        1
  Metadata Sequence No  2
  VG Access             read/write
  VG Status             resizable
  MAX LV                0
  Cur LV                1
  Open LV               0
  Max PV                0
  Cur PV                1
  Act PV                1
  VG Size               <30.00 GiB
  PE Size               4.00 MiB
  Total PE              7679
  Alloc PE / Size       7679 / <30.00 GiB
  Free  PE / Size       0 / 0
  VG UUID               j63noX-S9I0-5Gp0-3FPg-IZ23-oZNK-6qpb7X
$ sudo lvcreate -l 100%FREE -n lv_iscsi vg_iscsi
[vagrant@vg-suricata-30 ~]$ sudo lvscan
  ACTIVE            '/dev/vg_iscsi/lv_iscsi' [<30.00 GiB] inherit
  ACTIVE            '/dev/centos/swap' [2.00 GiB] inherit
  ACTIVE            '/dev/centos/home' [<20.01 GiB] inherit
  ACTIVE            '/dev/centos/root' [40.98 GiB] inherit
$ sudo lvdisplay
  --- Logical volume ---
  LV Path                /dev/vg_iscsi/lv_iscsi
  LV Name                lv_iscsi
  VG Name                vg_iscsi
  LV UUID                exEdIG-s2bK-vFEa-fD3X-dplu-q2W3-1rTXsE
  LV Write Access        read/write
  LV Creation host, time vg-suricata-30, 2019-12-18 12:35:56 +0000
  LV Status              available
  # open                 0
  LV Size                <30.00 GiB
  Current LE             7679
  Segments               1
  Allocation             inherit
  Read ahead sectors     auto
  - currently set to     8192
  Block device           253:3  

 $ sudo vgremove vg_iscsi
 $ sudo pvremove /dev/sdb
--------------------------------------------------------------------------------------------------------------------
#troubleshooting prometheus

#Shutting down Prometheus
lsof -n -i4TCP:9090 #find a process (Prometheus) listening on port 9090 
pgrep -f prometheus
curl -X POST :9090/-/quit
curl -X POST http://localhost:9090/-/quit #  (when the --web.enable-lifecycle flag is enabled)

#Prometheus Reload 
curl -i -XPOST localhost:9090/-/reload 
killall -HUP prometheus

./promtool check config prometheus.yml #check if prometheus.yml is valid

journalctl --boot | grep prometheus

#reload Prometheus config file
kill -HUP 9783
--------------------------------------------------------------------------------------------------------------------

#list open files
lsof
#list open files owned by user1
lsof -u user1
#list open file via tcp
lsof -i TCP:1-1024
lsof -i TCP:80
PID 27808
lsof -Pan -p 27808 -i
lsof -p 2


# troubleshooting #1
find all the opened files and processes along with the one who opened them
# lsof –p PID
Count number of files & processes
# lsof -p 4271 | wc -l
Check the currently opened log file
lsof –p | grep log
Find out port number used by daemon
# lsof -i -P |grep 4271

# find out what running processes are associated with each open port on Linux
netstat -nlp|grep 9000
sudo ss -lptn 'sport = :80'
sudo netstat -nlp | grep :80
sudo lsof -n -i :80 | grep LISTEN
fuser 3306/tcp
fuser 80/tcp
ss -tanp | grep 6379
fuser -v -n tcp 22
sudo netstat -ltnp | grep -w ':80'
netstat -tulpn | grep :80
netstat -tulpn
ls -l /proc/1138/exe 
sudo ss -tulpn
sudo ss -tulpn | grep :3306
fuser 7000/tcp
ls -l /proc/3813/exe 
man transmission
whatis transmission
# find out current working directory of a process pid 3813
ls -l /proc/3813/cwd
pwdx 3813
# Find Out Owner Of a Process on Linux
cat /proc/3813/environ
grep --color -w -a USER /proc/3813/environ
lsof -i :80 | grep LISTEN
# The file /etc/services is used to map port numbers and protocols to service names
grep port /etc/services
grep 443 /etc/services

#Start a Linux Process or Command in Background
$ tar -czf home.tar.gz .
$ tar -tvf home.tar.gz # list the contents of a .tar file
$ bg
$ jobs
OR
$ tar -czf home.tar.gz . &
$ jobs
#Keep Linux Processes Running After Exiting Terminal
$ sudo rsync Templates/* /var/www/html/files/ &
$ jobs
$ disown  -h  %1
$ jobs
OR
$ nohup tar -czf iso.tar.gz Templates/* &
$ jobs
#Detach a Linux Processes From Controlling Terminal
firefox </dev/null &>/dev/null &

count & # count command running on the background
jobs
fg
bg
fg %#    #Replace the # with serial number of the job,bring any job in the foreground 
fg %2 #bring job 2 into the foreground
jobs -l
count 2> /dev/null &

$ tail -f temp.log  #Placing a Foreground Job into the Background,suspend the job with a Ctrl-Z,
^Z[1]+ Stopped tail -f temp.log  
$ bg # bg to place the suspended job in the background
$ jobs # list the jobs in the background


$ jobs -l # list job in the background, process id 105231
[1]+ 105231 Running 
$ fg 1 # bring job #1 in the foreground from the background, process id 105231
sudo rsync 

$ fg 1 #type ctrl+z to send the job #1 to the background, process id 105231
sudo rsync 
^Z
[1]+  Stopped 

$ jobs -l # list the job #1 in the background which is stopped, process id 105231
[1]+ 105231 Stopped 

$ bg 1 # run the job 1 in the background again, process id 105231
[1]+ sudo rsync 

$ jobs -l # list the job #1 in the background, process id 105231
[1]+ 105231 Running
-----------------------------------------------------------------------------------------------------
2 is the file descriptor of stderr
the integer file descriptors associated with the streams stdin, stdout, and stderr are 0, 1, and 2, respectively.

a number 0 = standard out (i.e. STDIN)
a number 1 = standard out (i.e. STDOUT)
a number 2 = standard error (i.e. STDERR)
if a number isn't explicitly given, then number 1 is assumed by the shell (bash)

">" send to as a whole completed file, overwriting target if exists

"echo test > file.txt"  is equivalent to "echo test 1> file.txt"
echo test 2> file.txt #redirect stderr to file.txt

"/dev/null" is the null device it takes any input you want and throws it away. 
It can be used to suppress any output

"2>/dev/null"
Redirect STDERR to /dev/null (nothing shows up on console)
The general form of this one is "M>/dev/null", where "M" is a file descriptor number. 
This will redirect the file descriptor, "M", to "/dev/null".

">&" is the syntax to redirect a stream to another file descriptor

"echo test 1>&2"   equivalent to "echo test >&2"


"2>&1"
The general form of this one is "M>&N", where "M" & "N" are file descriptor numbers. 
It combines the output of file descriptors "M" and "N" into a single stream.
"&" indicates that what follows and precedes is a file descriptor, and not a filename.

"2>&-"
closing a file descriptor used with redirection
The general form of this one is "M>&-", where "M" is a file descriptor number. 
This will close output for whichever file descriptor is referenced, i.e. "M"

"|&"
Redirect STDERR and STDOUT to STDIN
This is just an abbreviation for "2>&1 |"

"&>/dev/null"
Redirect both STDERR & STDOUT to /dev/null (nothing shows up on console)
This is just an abbreviation for >/dev/null 2>&1. 
It redirects file descriptor 2 (STDERR) and descriptor 1 (STDOUT) to /dev/null

">/dev/null"
Redirect STDOUT to /dev/null (only STDERR shows on console)
This is just an abbreviation for 1>/dev/null. 
It redirects file descriptor 1 (STDOUT) to /dev/null.

"command > /dev/null 2>&1 &"     #Run command in the background, discard stdout and stderr
"command >> /path/to/log 2>&1 &" #Run command and append stdout and stderr to a log file


./command >/dev/null 2>&1 #Hide standard and error outputs

Hide standard output
./command >/dev/null
sends 2 (stderr) into 1 (stdout), and sends stdout to file.log
command > file.log 2>&1 
Hide standard and error outputs and release terminal (run the command in background)
./command >/dev/null 2>&1 &
prevent standard output and error output, redirecting them both to /dev/null
script > /dev/null 2>&1

-----------------------------------------------------------------------------------------------------
#Identify processes using files, directories, or sockets.Who is Using a File or Directory
$ fuser  .
$ fuser -v ./
Check Processes Using TCP/UDP Sockets
fuser -v -n tcp 5000
the processes that are using my 'home' directory
$ fuser ~
$ fuser ~ -v
check for the root directory
$ fuser /
$ fuser / -v
$ fuser -v /home/ismail
$ fuser -v -m /home/ismail/.bashrc
$ fuser -v -n tcp 8080
$ fuser -v -n udp 53
kill this TCP listener, you can use option -k
$ fuser -i -k 8080/tcp
shows all processes at the (local) TELNET port
$ fuser telnet/tcp
list signals
$ fuser -l
STOP a process
$ fuser -i -k STOP [FILE/DIRECTORY]
kills all processes accessing the file system /home 
$ fuser -km /home


$ who #logged-in users,List Connected Users
#all the currently logged in users, the time of login and their host machine's IP address.
#review the contents of the /var/log/utmp file
$ who -H 
$ who -r
run-level 5  2018-07-14 17:16
$ runlevel ->‘N’ indicates that the runlevel has not been changed since the system was booted. And, "number" is the current runlevel 
The last run level, and the current run level.
$ runlevel

md5sum ubuntu-6.10-desktop-i386.iso
sha256sum ubuntu-9.10-dvd-i386.iso
echo "$(cat kubectl.sha256)  kubectl" | sha256sum --check # Validate the kubectl binary against the checksum file
sha1sum filename #view the SHA-1 of a file
sha1sum -c DNi70074.bio.sha1 #read SHA1 sums from the FILEs and check
sha1sum --check --ignore-missing DNi70074.bio.sha1 # Do not fail or report status for missing files

$ wget https://github.com/coreruleset/coreruleset/archive/refs/tags/v3.3.2.zip
$ echo -n '88f336ba32a89922cade11a4b8e986f2e46a97cf v3.3.2.zip' | sha1sum -c -
v3.3.2.zip: OK
$ sha1sum v3.3.2.zip
88f336ba32a89922cade11a4b8e986f2e46a97cf  v3.3.2.zip

#watch is used to run any designated command at regular intervals. 
watch -n 5 "ls -l | wc l"

--------------------------------------------------------------------------------------------------------------------
# detect driver hardware problems
dmesg | more
The output of dmesg is maintained in the log file
/var/log/dmesg
cat /var/log/dmesg | less
data from /dev/kmsg
use syslog
# dmesg -S
# limit the output to only error and warnings
dmesg --level=err,warn
# dmesg produce timestamps 
dmesg --level=err -T
dmesg -T | grep -i eth0
dmesg --level=err,warn -T | grep -i eth0
# limit dmesg's output only to userspace messages
dmesg -u
# timestmaps along with decode facility and levels in dmesg command output
dmesg -Tx
Supported log levels (priorities):
   emerg - system is unusable
   alert - action must be taken immediately
    crit - critical conditions
     err - error conditions
    warn - warning conditions
  notice - normal but significant condition
    info - informational
   debug - debug-level messages
dmesg -TL -f kern
dmesg -TL -f daemon
Supported log facilities:
    kern - kernel messages
    user - random user-level messages
    mail - mail system
  daemon - system daemons
    auth - security/authorization messages
  syslog - messages generated internally by syslogd
     lpr - line printer subsystem
    news - network news subsystem
# verify vt-d is ON
"dmesg | grep Virtualization"
# dmesg | grep -i memory
# dmesg | grep -i dma
# dmesg | grep -i usb
# dmesg | grep -E "memory|dma|usb|tty" 
# dmesg | grep -E "sda|dma"
Clear dmesg logs
# dmesg -C
# dmesg -c
Display colored messages
# dmesg -L
Monitor real time dmesg logs
# dmesg --follow
# dmesg -Tx --follow
# watch "dmesg | tail 7-20"
Display raw message buffer
# dmesg -r
#virtual machine check
$ dmesg |grep -i hypervisor
--------------------------------------------------------------------------------------------------------------------
$ dmidecode -s system-manufacturer
--------------------------------------------------------------------------------------------------------------------

#32x 64x query
uname –m
arch
#linux version
lsb_release -a
cat /etc/issue
cat /etc/os-release
cat /etc/lsb-release
cat /etc/*-release
cat /proc/version
hostnamectl set-hostname server1
hostnamectl set-hostname --pretty "Web dev test environment"
hostnamectl set-hostname --static webdev-test-env
$ hostname --ip-address
$ hostname --all-ip-addresses

dnsdomainname -f



#create file w multiple lines
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
  


sudo ls -hal /tmp/ | sudo tee /tmp/test.out > /dev/null #The redirect to /dev/null is needed to stop tee from outputting to the screen
sudo ls -hal /tmp/ | sudo bash -c "cat >> /tmp/test.out"  #To append instead of overwriting the output file METHOD1
sudo ls -hal /tmp/ | sudo tee /tmp/test.out  #To append instead of overwriting the output file METHOD2
sudo ls -hal /tmp/ | sudo tee --append /tmp/test.out #To append instead of overwriting the output file METHOD2


# append text with non-root user
echo "deb http://research.cs.wisc.edu/htcondor/ubuntu/8.8/bionic bionic contrib" |sudo tee -a /etc/apt/sources.list

#do not see the contents of the website (may receive an access denied or ‘bad bot’ message)
curl -A 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.140 Safari/537.36' URL
curl --compressed URL
curl URL | iconv -f windows-1251 -t UTF-8 #convert from the windows-1251 encoding to the UTF-8 encoding
curl -u username:password URL #websites require a username and password to view their content,specify other authentication methods using --ntlm | --digest
#showing only headers, HTML code not displayed
curl -s -I -A 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.140 Safari/537.36' https://www.acrylicwifi.com/AcrylicWifi/UpdateCheckerFree.php?download | grep -i '^location'
curl -s -v http://www.paterva.com/web7/downloadPaths41.php -d 'fileType=exe&os=Windows' 2>&1 | grep -i 'Location:'

#save cookies,data transfer using the POST method, the --data option is used
curl --cookie-jar cookies.txt http://forum.ru-board.com/misc.cgi --data 'action=dologin&inmembername=f123gh4t6&inpassword=111222333&ref=http%3A%2F%2Fforum.ru-board.com%2Fmisc.cgi%3Faction%3Dlogout'
#get information from a page that only registered users have access to, specify the path to the file with previously saved cookies
curl -b cookies.txt 'http://forum.ru-board.com/topic.cgi?forum=35&topic=80699&start=3040' | iconv -f windows-1251 -t UTF-8

#extracting entire archive
curl -L -o ds.tar.gz https://downloads.dockerslim.com/releases/1.37.3/dist_linux.tar.gz
tar -xvf ds.tar.gz -C /usr/local/bin

#uncompress the tar.gz file into a specific folder. 
tar -xzvf your_file.tar.gz -C /path/to/destination/folder


tar xvzf tkn_0.10.0_Darwin_x86_64.tar.gz -C /usr/local/bin tkn
tar xjvf backup.tbz
tar -zxvf backup.tar.gz
tar -xf file_name.tar.gz --directory /target/directory

#ssh and tar to make secure backups. Make a backup via encrypted file transfer
tar --create --directory /home/joe/tmp/ --file - *| \
ssh raspberrypi "tar --directory /home/joe \
--verbose --list --file -"

wget --no-check-certificate https://www.cacti.net/downloads/cacti-latest.tar.gz
tar -zxvf cacti-latest.tar.gz
mv cacti-1* /opt/cacti
(OR tar -xf cacti-latest.tar.gz --directory /opt/cacti)

tar -zxvf /tmp/onos-1.12.0.tar.gz  --strip-components 1 --directory /opt --one-top-level=onos
tar xvf mysql-5.7.23-linux-glibc2.12-x86_64.tar.gz --one-top-level=mysql57 --strip-components 1
tar zxvf ugly_name.tgz --one-top-level=pretty_name
#extract .xz file
unxz tor-browser-linux32-5.5.4_en-US.tar.xz
tar xvf tor-browser-linux32-5.5.4_en-US.tar
#extract .bz2 file
bzip2 -dk FileZilla_3.29.0_x86_64-linux-gnu.tar.bz2 
tar xvf FileZilla_3.29.0_x86_64-linux-gnu.tar
#extract .zip file
unzip terraform_0.11.7_linux_amd64.zip -d terraform
#extract .rar file
unrar e extract.rar r
# create user home directory backup 
tar cvf filename.tar /home/vagrant/
# show which files were changed
tar dvf filename.tar
# update the changed files
tar uvf filename.tar 
# make smaller backup 
gzip filename.tar


#format a USB storage device with FAT32 file system
mkfs –t vfat <USB-device-mount-point>
# mount -o loop,offset=$((10860003 * 512)) disk.img /mnt
#find out the USB device mount point
fdisk -l
#unmount the drive,you can’t format a mounted drive.
sudo umount /dev/sdb1
sudo mkfs.vfat /dev/sdb1
sudo mkfs.ntfs /dev/sdb1
mkfs.ext4 <USB-device-mount-point>
mkfs.ntfs <USB-device-mount-point>
#Set label name to USB drives
sudo mkfs.vfat /dev/sdb1 -n sk

==========================================================================================================
#Create a New Sudo User(CentOS)
adduser username
passwd username
usermod -aG wheel username #add user to the wheel group.By default, on CentOS, members of the wheel group have sudo privileges
su - username # switch to the new user account

#verify if user is sudoer
sudo -l -U userjohndoe  #list user's privileges or check a specific command
sudo --validate / sudo -v #update the user's cached credentials, authenticating the user if necessary
sudo --list #print the list of allowed and forbidden commands for the user who is executing the sudo command
groups #verify if user is sudoer, member of wheel group
sudo whoami # returns root

----------------------------------------------------------------------------------------------------
#Create a New Sudo User (ubuntu)
sudo adduser barak #create new user
sudo adduser barak sudo #Add the user to sudo group 
usermod -aG sudo barak #Add the user to sudo group 

id barak  #verify sudo group
groups newuser #verify sudo group

su - barak #Verify Sudo Access
$ ls /root
ls: cannot open directory '/root': Permission denied
sudo ls /root
----------------------------------------------------------------------------------------------------
echo $HOME $USER
sudo bash -c 'echo $HOME $USER'
sudo -H bash -c 'echo $HOME $USER'
----------------------------------------------------------------------------------------------------
cmd:
sudo sh -c "go build ."

problem:
bash: line 1: go: command not found

fix:
# indicates that the go command is not in the system's PATH when running the command with sudo. 
#This is because sudo does not preserve the user's environment variables, including the PATH variable.

sudo env "PATH=$PATH" sh -c "go build ."
----------------------------------------------------------------------------------------------------
When you use the "su otheruser" command without the hyphen (-), you switch to the specified user's account, 
but you inherit the current environment variables and working directory of the original user. 
This can lead to potential issues if you need the new user's environment to be set up completely.

Example Use Cases:

If you only need to quickly execute a single command as "otheruser" 
but do not require the environment to be exactly the same, 
you might use "su otheruser" to avoid the overhead of starting a new shell session.

┌──(vagrant㉿vg-kali-02)-[~]
└─$ su barak
Password:
┌──(barak㉿vg-kali-02)-[/home/vagrant]
└─$ echo $HOME
/home/barak

┌──(barak㉿vg-kali-02)-[/home/vagrant]
└─$ pwd
/home/vagrant

┌──(barak㉿vg-kali-02)-[/home/vagrant]
└─$ exit
exit

┌──(vagrant㉿vg-kali-02)-[~]
└─$
----------------------------------------------------------------------------------------------------
When you use the "su - otheruser" command with the hyphen (-), you not only switch to the specified user's account 
but also start a new shell session with the target user's environment variables and home directory. 
This ensures a clean environment as if you had logged in directly as that user.

In general, you should use su - otheruser if you need to change the shell environment. 
This is especially important if you are going to be running commands that require specific permissions or settings that are not available in the default shell environmen

Example Use Cases:

Suppose you are the "originaluser" and you want to run a script that requires specific environment variables 
and settings of "otheruser." In this case, you would use "su - otheruser" to ensure the script runs with the correct environment.

┌──(vagrant㉿vg-kali-02)-[~]
└─$ su - barak
Password:
┌──(barak㉿vg-kali-02)-[~]
└─$ echo $HOME
/home/barak

┌──(barak㉿vg-kali-02)-[~]
└─$ pwd
/home/barak

┌──(barak㉿vg-kali-02)-[~]
└─$ exit
logout

┌──(vagrant㉿vg-kali-02)-[~]
└─$
----------------------------------------------------------------------------------------------------
#-H flag makes sudo assume root's home directory as HOME instead of the current user's home directory
sudo -H 
#sudo user
echo "stack ALL=(ALL) NOPASSWD: ALL" |sudo tee -a /etc/sudoers

#allow a user aaron to run all commands using sudo without a password, open the sudoers file
$ sudo visudo
aaron ALL=(ALL) NOPASSWD: ALL 

%sys ALL=(ALL) NOPASSWD: ALL #all member of the sys group will run all commands using sudo without a password
alf ALL=(ALL) NOPASSWD: ALL #permit a user to run a given command (/bin/kill) using sudo without a password
%sys ALL=(ALL) NOPASSWD: /bin/kill, /bin/rm #the sys group to run the commands: /bin/kill, /bin/rm using sudo without a password

#su vs sudo
#"sudo" asks for your password,"su" asks for the password for the user whom you are switching to
#sudo lets you issue commands as another user without changing your identity,entry in /etc/sudoers to execute these restricted permissions
#without entering the root password
#su keeps the environment of the old/original user even after the switch to root 
#creates a new environment (as dictated by the ~/.bashrc of the root user), 
#similar to the case when you explicitly log in as root user from the log-in screen.
"su -"  
"su -l" #pass more arguments

"su -c" #su [target-user] -c [command-to-run]  a command that you want to run after switching to the target user.
su -c '/home/annie/annie-script.sh' annie #While logged in as user dave, run the annie-script.sh as user annie
su -c 'echo I am $(whoami)' #Without specifying a target user,switch into root

#The password prompt is not preferable, during scripting
#disable the password prompt when user dave is executing scripts as user annie.dave uses su without having to input annie‘s password.
#/etc/pam.d/su,add the following lines right after the line "auth sufficient pam_rootok.so" 
auth  [success=ignore default=1] pam_succeed_if.so user = annie #rule checks if the target user is annie
auth  sufficient                 pam_succeed_if.so use_uid user = dave #rule to check if the current user is dave
su -c /home/annie/annie-script.sh annie #run by dave

auth       sufficient pam_rootok.so
auth       [success=ignore default=1] pam_succeed_if.so user = otheruser
auth       sufficient   pam_succeed_if.so use_uid user ingroup somegroup

#/etc/sudoers
echo 'dave ALL=(annie) /home/annie/annie-script.sh' | EDITOR='tee -a' visudo #The rule grants dave the permission to execute the script annie-script.sh as user annie on any hosts
sudo -u annie /home/annie/annie-script.sh #while logged in as dave
sudo -u root /home/annie/annie-script.sh #Sorry, user dave is not allowed to execute '/home/annie/annie-script.sh' as root
"sudo -s" or "sudo -i" #mimic "su" or "su -l"
"sudo -s or sudo -i" #temporarily become a user with root privileges

#/etc/sudoers
echo 'dave ALL=(ALL) /home/annie/annie-script.sh' | EDITOR='tee -a' #The rule grants dave to execute the script annie-script.sh as any users
sudo -u root /home/annie/annie-script.sh #while logged in as dave

#The password prompt is not preferable, during scripting
#/etc/sudoers
dave ALL=(ALL) NOPASSWD: /home/annie/annie-script.sh' | EDITOR='tee -a'

# switching to root using sudo -i (or sudo su) cancels auditing/logging
# when a sudo command is executed, the original username and the command are logged
"sudo su"
"sudo -i"
su is equivalent to sudo -i
gives you the root environment, i.e. your ~/.bashrc is ignored.
simulates a login into the root account
Your working directory will be /root
will read root's .profile


"sudo -s" 
gives you the user's environment, so your ~/.bashrc is respected.
launches a shell as root
doesn't change your working directory

"sudo bash" #runs bash as a super user
sudo -E #The -E (preserve environment) option indicates to the security policy that the user wishes to preserve their existing environment variables. 
==========================================================================================================
mount -l
lshw -short
sudo lshw -class disk
sudo lshw -short -class disk
lshw -class processor
file -Ls
dmesg
denyhosts
vmstat
w
uptime
ps
free
iostat
pmap
paste
uname
sudo
mkdir
chown
ptree
pkill

killall
kill -KILL PID
kill –TERM [PID] #means terminate.the default signal sent by kill,equivalent to kill <PID>

kill –HUP [PID] #reset or restart the process
all signals
$ kill -l
stop and restart process
$ kill -1 13980
1 SIGHUP
9 SIGKILL stop process without letting gracefully
15 SIGTERM stop process
------------------------------------------------------------------------------------------------------------------
$ touch mylog
$ ls -lai mylog
3145761 -rw-rw-r-- 1 vagrant vagrant 0 Mar 27 21:01 mylog
update the access time of existing file
$ touch -c mylog
Change file access time - 'a' of existing file
$ touch -a mylog
Change the modified time '-m' of existing file
$ touch -m mylog
$ touch -am mylog
Set a specific access/modify time instead of current time, specify the datetime in format [[CC]YY]MMDDhhmm[.ss]
$ touch -c -t 201603051015 mylog
$ touch -c -d '5 Jan 2009' mylog
$ touch -c -d '20:30' myfile
Use the timestamp of another file as reference
$ touch myfile -r mylog
use the timestamps of 'apl' for 'apl.c'
$ touch apl.c -r apl
$ ls -lai mylog
3145761 -rw-rw-r-- 1 vagrant vagrant 0 Mar 27 21:06 mylog

$ stat mylog
  File: 'mylog'
  Size: 0               Blocks: 0          IO Block: 4096   regular empty file
Device: fc00h/64512d    Inode: 3145761     Links: 1
Access: (0664/-rw-rw-r--)  Uid: ( 1000/ vagrant)   Gid: ( 1000/ vagrant)
Access: 2019-03-27 21:07:54.953000000 +0000
Modify: 2019-03-27 21:07:54.953000000 +0000
Change: 2019-03-27 21:07:54.953000000 +0000
 Birth: -
force touch to not create any new file
$ touch -c newfile
$ ls -l newfile
ls: cannot access 'newfile': No such file or directory
$ stat newfile
stat: cannot stat 'newfile': No such file or directory

------------------------------------------------------------------------------------------------------------------
# create symbolic link
ln -s test1.txt symbolic_test1.txt
stat symbolic_test1.txt
touch -c -d '5 Jun 2001' -h symbolic_test1.txt
stat symbolic_test1.txt
# detect symbolic link
touch a.xt
ln -s a.txt b.txt
stat b.txt
file b.txt

ln -s source.file softlink.file 
ls -lia #does not share the same inode number and permissions of original file
rm source.file
stat softlink.file #No such file or directory

# create hard link
ln source.file hardlink.file
ls -lia #shares the same inodes number and permissions of original file
rm source.file
stat hardlink.file
echo "hola el mundo" >>source.file #change the content of either of the files, the change will be reflected
cat hardlink.file 
cat source.file 

lscpiu
stat file.txt
#standard output activities for each available processor
mpstat
mpstat -P ALL 2 2
----------------------------------------------------------------------------------------------------
df –h # view the amount of free disk space
df -HT #Display File System Type
df -hT /home
df -t ext3 #display a certain file system type use the ‘-t‘ option
df -x ext3 #Exclude Certain File System Type
df -k #usage in 1024-byte blocks, use the option ‘-k‘
df -m # MB (MegaByte)
df -i # view number of inodes in the system
df -kl # get a detail description on disk space usage

---------------------------------------------------------------------------------------------------
du -sh /* # list directory sizes under root / disk
du -sh /* | sort -h
du -m /some/path | sort -nr | head -n 20 #sorted list containing the 20 biggest dirs
for each in $(ls) ; do du -hs "$each" ; done
du --threshold=1M -h | sort -h #includes hidden dot folders (folders which start with .).
du -h | sort -h 3

du -bch #-b gives you the file size instead of disk usage, and -c gives a total at the end
du -ch | tail -1
du -sh /some/dir #the summary of a grand total disk usage size of an directory use the option “-s” 
du -sh /var/* |grep G
du -ah /home/tecmint # displays the disk usage of all the files and directories
du -kh /home/tecmint #the disk usage of a directory tree with its subtress in Kilobyte blocks. Use the “-k” (displays size in 1024 bytes units).
du -kh /home/tecmint #Megabytes (MB)
du -ch /home/tecmint #The “-c” flag provides a grand total usage disk space at the last line
du -ah --exclude="*.txt" /home/tecmint
du -ha --time /home/tecmint #the disk usage based on modification of time, use the flag “–time”

#The problem with du is that it adds up the size of the directory nodes as well,not to sum up only the file sizes.
# total size of files in a directory
du -h -c directory #listing path 
du -h -c directory|tail -1 #only total size 
$ du -sh /var/log/apt #only total size and listing 

#du prints actual disk usage rounded up to a multiple of (usually) 4 KB instead of logical file size
$ for i in {0..9}; do echo -n $i > $i.txt; done #create files 
$ ls *.txt
0.txt  1.txt  2.txt  3.txt  4.txt  5.txt  6.txt  7.txt  8.txt  9.txt
$ du -ch *.txt | tail -1
40K     total
$ ls -FaGl *.txt | printf "%'d\n" $(awk '{SUM+=$4}END{print SUM}')
10

du /var/* -shc --exclude=lib #--exclude to exclude any directory
du /var/ -h --exclude=lib --max-depth=1 #first-level sub-directories in the /var/ directory. 
 
$ du -ch /var/log/apt | tail -1 | cut -f 1
$ du -ac --bytes /var/log/apt
$ du -ac --bytes /var/log/apt | grep "log$" | awk '{ print; total += $1 }; END { print "total lobsters: ", total, " Bytes" }'
$ du -ac --bytes /var/log/apt | grep "log$" | awk '{ print; total += $1 }; END { print "total lobsters: ", total/1024, " KB" }'
$ du -ac --bytes /var/log/apt | grep "log$" | awk '{ print; total += $1 }; END { print "total lobsters: " total/1024/1024 " MB" }'
$ du /var/log/apt/*.log | awk '{ print; total += $1 }; END { print "total size: ",total }'
----------------------------------------------------------------------------------------------------
$ dir /var/log/apt #list directory contents
$ dir /var/log/apt | tee >( awk '{ total += $4 }; END { print total }' ) #list directory contents and total size 
$ dir /var/log/apt | awk '{ print; total += $4 }; END { print "total size: ",total }' #total size 

----------------------------------------------------------------------------------------------------
#List all running processes containing the string stuff
cat /proc/cpuinfo
grep "physical id" /proc/cpuinfo | wc -l
cat /proc/meminfo
grep MemTotal /proc/meminfo | awk '{FS=":"}{print $2 }' | awk '{print $1/1024/1024}' 
cat /proc/zoneinfo
cat /proc/mounts
cat /etc/issue

# missing files
$ sudo ls -lai /lost+found/
# errors about a corrupt superblock on the drive
$ e2fsck -b 8193

$list files sorted by size
ls –lSr
ls -il 
#get pid of my_app
my_app & $! 

pidof lighttpd -> Find PID of A Program/Command
pidof -s php5-cgi
pidof -x fetch-data -> Get pids of scripts
pidof -o 4242 lighttpd ->  ignore or omit processes,useful to ignore calling shell or shell script or specific pid.
------------------------------------------------------------------------------------------
# history,The ! prefix is used to access previous commands.
    !$ - last argument from previous command(last command)
    !:1 # last command's 1st argument
    !:2 # last command's 2nd argument
    !:1-2 # last command's 1st and 2nd argument
    !^ - first argument (after the program/built-in/script) from previous command
    !* - all arguments from previous command
    
    
    !! - previous command (often pronounced "bang bang")
    !n - command number n from history
    !pattern - most recent command matching pattern
    !!:s/find/replace - last command, substitute find with replace
    !3:2 #take the second argument from the third command in the history
    !-5:3 #take the third argument from the fifth last command in the history,Using a minus sign to traverse from the last command of the history

    
$ echo 'one' 'two'
one two
$ !$
'two'
$ !^
'one'
$ !*
'one' 'two'
$ !!
echo 'one' 'two'
one two

$ ls /tmp && cd !*
------------------------------------------------------------------------------------------
$ curl -kL http://localhost/banana
#curl -IL http://localhost
HTTP/1.1 200 OK
Server: nginx/1.10.2

curl -Is http://www.google.com | head -n 1 #check whether a web site is up, and what status message the web server is showing
curl -sSf http://example.org > /dev/null
curl -XGET 'localhost:9200/?pretty'

curl -X PUT "http://127.0.0.1:9200/mytest_index" #sending data with POST and PUT requests
curl -d "param1=value1&param2=value2" -X POST http://localhost:3000/data
curl -d "param1=value1&param2=value2" -H "Content-Type: application/x-www-form-urlencoded" -X POST http://localhost:3000/data
curl -d "@data.txt" -X POST http://localhost:3000/data
curl -d '{"key1":"value1", "key2":"value2"}' -H "Content-Type: application/json" -X POST http://localhost:3000/data
curl -d "@data.json" -X POST http://localhost:3000/data

# check if apache is running
curl -sf http://webserver/check_url
# process was holding a particular port open
ss -tp state listening sport = :80 | grep httpd
# check a particular process id
lsof -p 1036 -P | grep 'TCP \*:80'
$ echo "The process id is" $$
$ echo "The process id is" $$$$
# check what process is listening
$ sudo fuser -n tcp 22
22/tcp:               1088 14324 14354

echo $SHELL -> determine current shell type
cat /proc/cpuinfo | grep 'vmx\|svm' ->  VT-x/AMD-v virtualization is enabled in BIOS 

# troubleshooting nginx
journalctl -u nginx.service
tail -n 50 /var/log/nginx/error.log
tail -n 50 //var/log/nginx/access.log
nginx -t
sudo ss -tulpn # Verify that port 80 or 443 
curl -I http://10.21.136.13
curl http://10.21.136.13
dig +short localhost @8.8.8.8
   ------------------------------------------------------------------------------------------------
   #/etc/systemd/journald.conf
   #SystemMaxUse=100M 
   cat /etc/systemd/journald.conf | grep SystemMaxUse
   journalctl --vacuum-size=100M
   
   sudo usermod -a -G systemd-journal $USER # add the current user to the systemd-journal group
   
   # process the data further with text processing tools like grep, awk, or sed, or redirect the output to a file
   journalctl --no-pager #print its output directly to the standard output instead of using a pager by including the --no-pager flag
   
   journalctl -o json -n 10 --no-pager #change the format to format like JSON
   journalctl -o json-pretty -n 10 --no-pager
   
    cp /etc/systemd/journald.conf{,.orig}
    cp a.txt{,.$(date +%Y%m%d-%H%M)} #clone with date info
    
   sudo mkdir -p /var/log/journal
   ls -l /var/log/journal/3a0d751560f045428773cbf4c1769a5c/
   sudo cp /etc/systemd/journald.conf{,.orig}
   sed -i 's/#Storage.*/Storage=persistent/' /etc/systemd/journald.conf # set "Storage" type to "persistent
   sudo vi /etc/systemd/journald.conf
   Storage=persistent
   systemctl restart systemd-journald.service
   journalctl --flush # move the journal log files from /run/log/journal to /var/log/journal
   #The options prefixed with "Runtime" apply to the journal files when stored on a volatile in-memory file system, 
   #more specifically /run/log/journal
   
   
   journalctl --vacuum-files=2 # have 10 archived journal files and want to reduce these down to 2
   journalctl --verify
   
   journalctl | head -1 #What time range do I have logs for?
   journalctl -F _SYSTEMD_UNIT #What systemd services do I have logs for?  
   journalctl -F _COMM 
   journalctl -F _EXE 
   journalctl -F _CMDLINE
   #What users do the services that logged something run as (swap _UID/-u with _GID/-g for groups)?
   journalctl -F _UID | xargs -n1 id -nu 
   journalctl -F _UID | xargs -n1 id -ng
   
   #provide test input for journalctl
   logger -p err 'something erronous happened'
   systemd-cat -p info echo 'something informational happened'
   
   #What selector fields are there? Show up to 8 values each
   for f in $(sudo journalctl --fields); do 
   echo ===========$f; 
   sudo journalctl -F $f; 
   done | grep -A8 ========
  
   
   #remove all entries
   journalctl --rotate
   journalctl --vacuum-time=1s
   journalctl -m --vacuum-time=1s #-m flag, it merges all journals and then clean them up
   #remove all entries
   find /var/log/journal -name "*.journal" | xargs sudo rm
   systemctl restart systemd-journald
   #remove all entries
   rm -rf /run/log/journal/*

   journalctl --rotate --vacuum-size=500M #rotate journal files and remove archived journal files until the disk space they use is under 500M
   
   
   #Rotating is a way of marking the current active log files as an archive and create a fresh logfile from this moment
   # The flush switch asks the journal daemon to flush any log data stored 
   #in /run/log/journal/ into /var/log/journal/, if persistent storage is enabled.
   #Manual delete,removes all archived journal log files until the last second,clears everything
   journalctl --flush --rotate #applies to only archived log files only, not on active journal files
   journalctl --vacuum-time=1s
   #Manual delete,clears all archived journal log files and retains the last 400MB files
   journalctl --flush --rotate
   journalctl --vacuum-size=400M
   #Manual delete,only the last 2 journal files are kept and everything else is removed
   journalctl --flush --rotate
   journalctl --vacuum-files=2
   
   journalctl -b ->all of the journal entries that have been collected since the most recent reboot
   journalctl --list-boots #list of boot numbers, their IDs, and the timestamps of the first and last message pertaining to the boot
   journalctl --boot=ID _SYSTEMD_UNIT=foo
   journalctl -b -1 -> see the journal from the previous boot,use boot number to pick specific boot	
   journalctl -k -b -1  -> Shows kernel logs for the current boot.
   
   $ journalctl --list-boots #list boot id
   -1 340f8a96d40749f8b2530cc76810d62d Tue 2022-01-18 14:33:46 +03—Tue 2022-01-18 15:14:42 +03
    0 75c35ddeb4274787ad78d1092bf9743a Tue 2022-01-18 23:08:10 +03—Wed 2022-01-19 09:25:35 +03
   $ journalctl -b 75c35ddeb4274787ad78d1092bf9743a #use boot id
   
   journalctl --since "2015-01-10 17:15:00"
   journalctl -S "2020-91-12 07:00:00"
   journalctl -S -1d #The “d” stands for “day”, and the “-1” means one day in the past
   journalctl -S -1h
   journalctl --since "2015-06-26 23:15:00" --until "2015-06-26 23:20:00"
   journalctl -S "2020-91-12 07:00:00" -U "2020-91-12 07:15:00"
   journalctl --since yesterday
   journalctl -S yesterday
   journalctl --since yesterday --until now
   journalctl --since today
   journalctl -S -2d -U today #everything from two days ago up until the start of today
   journalctl --since 09:00 --until "1 hour ago"
   journalctl --since '1h ago' --until '10 min ago'
   
   #syslog log levels i.e. "emerg" (0), "alert" (1), "crit" (2), "err" (3), "warning" (4), "notice" (5), "info" (6), "debug" (7)
   journalctl -p 0
   journalctl -p 0..2 # logs for a range between emerg(0) and critical(2)
   journalctl -f -p warning    # show me warnings
   journalctl -p err           # show all errors 
   
   journalctl -xp info
   journalctl -xu sshd
   journalctl -fxu httpd.service
   journalctl -fxu sshd.service -p debug
   journalctl -fx
   journalctl -xn
   
   journalctl /dev/sda ->  displays logs related to the /dev/sda file system.
   journalctl /sbin/sshd #logs from the sshd binary
   journalctl -n20 _EXE=/usr/sbin/sshd
   journalctl /usr/bin/bash
   
   journalctl -u nginx.service -> see all of the logs from an Nginx unit on our system
   journalctl -u nginx.service --since today
   journalctl -b -u docker -o json
   journalctl -u docker.service --since "2016-10-13 22:00"
   journalctl _SYSTEMD_UNIT=sshd.service
   journalctl -u sshd.service
   journalctl -u sshd.service -x #logs with more details
   journalctl _PID=8088
   journalctl -b _SYSTEMD_UNIT=foo _PID=number #logs for systemd-units that match foo and the PID number
   #all messages from the foo service process with the PID plus all messages from the foo1 service
   journalctl -b _SYSTEMD_UNIT=foo _PID=number + _SYSTEMD_UNIT=foo1 
   journalctl -b _SYSTEMD_UNIT=foo _SYSTEMD_UNIT=foo1 #shows logs matching a systemd-unit foo or a systemd-unit foo1
   
   #Filter logs based on user
   id -u www-data 
   33   
   journalctl _UID=33 --since today   
   
   journalctl -k ->Kernel messages, those usually found in dmesg output
   journalctl _TRANSPORT=kernel
   
   journalctl -n 20 ->see with a number after the -n
   journalctl -n 10 -o short-full #Changing the Display Format
   journalctl -n 10 -o verbose
   journalctl -n 10 -o json
   journalctl -n 10 -o json-pretty
   journalctl -n 10 -o cat #see the log entry messages, without time stamps or other metadata
   
   journalctl --disk-usage #using persistent storage then the below output shows the amount of disk used
   #removes archived journal files until the disk space they use falls below the specified size 
   #(specified with the usual "K", "M", "G", "T" suffixes),
   journalctl --vacuum-size=1G
   journalctl --vacuum-time=1weeks #clear all messages older than one week
   journalctl --vacuum-time=2d #Retain only the past two days
   
   journalctl -f -> continuously prints log messages, similar to tail -f  
   journalctl -u mysql.service -f
   journalctl -f -e -p err docker --since today # -e implies -n1000
   
   #who ran sudo in the past week, what commandline, what PWD and user?
   journalctl  --since '1 week ago' _COMM=sudo -o json \
     | jq -r '(.__REALTIME_TIMESTAMP|tonumber|(./1e6)|todate) + "\t" + ._CMDLINE + "\t" + .MESSAGE' \
     | column -ts $'\t'
   #How many ssh auth errors today?   
   journalctl -o cat -p err -u ssh --since today | wc -l
   #filter specific error
   journalctl -o cat -p err | grep "tx hang"
   #executables have been logging errors at a loglevel lower than error in the past month?
   journalctl --since -1month -p 7..4 -o json | jq -r 'select (.MESSAGE | contains("error")) | ._EXE'  | sort -u
   #show error logs for a particular version of a service
   journactl -p err /opt/fooservice/9e76/bin/fooservice
   #Filter by start and end dates and particular PIDs
   journalctl _SYSTEMD_UNIT=docker --since '2018–11–01 14:00' --until '2018–11–13 14:00' _PID=123 _PID=456
   ------------------------------------------------------------------------------------------------
   Job for autofs.service failed because a configured resource limit was exceeded. See "systemctl status autofs.service" and "journalctl -xe" for details.
   systemctl start autofs 
   systemctl is-active autofs
   systemctl is-active autofs >/dev/null 2>&1 && echo YES || echo NO
   
   ps -aux | grep -i autofs | grep -v grep #grep command was shown in the output, remove this distraction is to add another pipe to grep -v grep
   
   kill -9 `ps -ef | grep '[k]eyword' | awk '{print $2}'` # get the pid from ps command
   ps -aux | grep dockerd | grep -v grep | awk '{print $2}'  # get the pid from ps command

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
$ ps aux | grep root #list services running as root
ps aux | grep 3813
ps -eo pid,user,group,args,etime,lstart | grep '[3]813'
ps aux | grep '[1]616'
ps -eo pid,user,group,args,etime,lstart | grep '[1]616'
ps aux | grep stuff
The init process, with process ID 1, which does nothing but wait around for its child processes to die. 
Usually started for /etc/inittab
$ ps -ef| grep init
# see the name of the process
$ sudo ps 1088 14324 14354
# CPU time, page faults of child processes
ps -Sla
$ ps -lu vagrant
memory information long format
$ ps -lma
signal format
$ ps -sx
controlling terminal
$ ps --tty 1 -s
#print a process tree
ps -ejH
ps axjf

list of command line arguments
pstree -a
show PIDS for each process name
pstree -p
sort processes with the same ancestor by PID instead of by name,numeric sort
pstree -n
pstree -np
find out the owner of a process in parenthesis
pstree -u
pstree -u vagrant
pstree -unp vagrant
highlight the current process and its ancestors
pstree -h
highlight the specified process
pstree -H 60093

find ID of a process owned by a specific user
$ pgrep -u vagrant sshd
$ pgrep -u vagrant -d:
list process names
$ pgrep -u vagrant -l
$ pgrep -u vagrant -a
count of matching processes
$ pgrep -c -u vagrant

top -> Checking the Priority of Running Processes
ps -o pid,comm,nice -p 594 -> Checking the Priority of Running Processes
ps -o pid,comm,nice,pri -p $(pidof snmpd)
ps -fl -C "perl test.pl" -> The “NI” column in the ps command output indicates the current nice value (i.e priority) of a process.
ps -p 2053 -o comm=

#NI – is the nice value, which is a user-space concept
#PRI – is the process’s actual priority, as seen by the Linux kernel
ps -o ni $(pidof snmpd)

#Total number of priorities = 140
#Real time priority range(PR or PRI):  0 to 99 
#User space priority range: 100 to 139
ps -o ni,pri $(pidof snmpd)

#PR = 20 + NI
#PR = 20 + (-20 to + 19)
#PR = (20 + -20)  to (20 + 19)
#PR = 0 to 39  (100 to 139 user space priority range)
ps -o pid,comm,nice,pri -p $(pidof snmpd)

cat /proc/$(pidof snmpd)/stat | awk '{print "priority " $18 " nice " $19}'
ps u $(pgrep snmpd) #ps with headers

#The NI column shows the scheduling priority or niceness of each process
#ranges from -20 to 19, with -20 being the most favorable or highest priority for scheduling
#19 being the least favorable or lowest priority
ps -e -o uid,pid,ppid,pri,ni,cmd |  { head -5 ; grep snmpd; } #ps with headers

# priority levels between -20 and 19
nice -10 perl test.pl -> test.pl is launched with a nice value of 10 when the process is started
nice --10 perl test.pl -> Launch a Program with High Priority
nice #Checking default niceness,the default is 0 

# 0 for none, 1 for real-time, 2 for best-exertion, 3 for inactive
ionice -c 3 -p 1 #PID as 1 to be an idle I/O process
ionice -c 2 bash #run ‘bash’  as a best-effort program
ionice -p 3467 #examine the class and priority used by PID 3467
ionice -c 1 -n 3 -p 3467 
#set the I/O scheduling class to Idle,takes longer,no longer performance degradation
# for pid in $(pidof rsync); do ionice -c 3 -p $pid; done
----------------------------------------------------------------------------------------------------- 
renice -n -19 -p 3534 -> Change the Priority of a Running Process
#adding more virtual runtime to the process
#The OS thinks that the process has taken more virtual runtime time than other processes in the run queue.
#in the next cycle, the CPU gives less time to the process
#The process finishes late as it’s getting less time “on CPU”
renice +10 PID
#The OS thinks that the process hasn’t got enough “on CPU” time than other processes in the run queue
#in the next cycle, the CPU gives more “on CPU” time to that process as compared to other processes in the run queue.
renice -10 PID
/etc/security/limits.conf -> set the default nice value of a particular user or group
$ pidof rsync
$ renice +10 2395
2395 (process ID) old priority 0, new priority 10
----------------------------------------------------------------------------------------------------- 
#Process affinity is the scheduler property that helps to bind or unbind the process so that the process will run only with the allotted CPU
#Processor affinity, or CPU pinning or “cache affinity”, enables the binding and unbinding of a process or a thread to a central processing unit (CPU) or a range of CPUs

#According to the taskset command man pages, value f means "any CPU."
$ pidof rsync
$ taskset -p 2395 #use the PID to get CPU affinity, returns the current CPU affinity in a hexadecimal bit mask format
pid 2395's current affinity mask: f
$ taskset -cp 2395 #get the CPU range of a process
pid 2395's current affinity list: 0-3

$ taskset -c 0 vlc #start the VLC program on CPU core ID 0
taskset 0xa gedit #launch gedit with CPU affinity 0xa.

#If the server gets a reboot or the process is restarted, the PID changes
taskset -p 0x11 9030 #assign a process to cores 0 and 4
taskset -cp 0,4 9030 #assign a process to cores 0 and 4
taskset -cp 1 9030 # bound the process 9030 to run only on CPU 1, configuration is not permanent
----------------------------------------------------------------------------------------------------- 

gpg --verify gnupg-2.2.3.tar.bz2.sig gnupg-2.2.3.tar.bz2 -> check the signature of the file gnupg-2.2.3.tar.bz2
----------------------------------------------------------------------------------------------------- 
systemd-analyze #the actual boot time of the machine
systemd-analyze blame #see how long every program and service takes to start up
systemd-analyze critical-chain # print out the results in a chain of events style
systemd-analyze critical-chain ntp.service networking.service
systemd-analyze plot > boot_analysis.svg
xviewer boot_analysis.svg  
systemd-analyze time -H tecmint@192.168.56.5 #view information from a remote host over ssh
systemd-analyze blame -H tecmint@192.168.56.5

systemd-cgtop #top control groups by their resource usage such as tasks, CPU, Memory, Input, and Output
----------------------------------------------------------------------------------------------------- 
PARSING JSON FILE

sudo apt-get install -y jq
curl -s 'https://api.github.com/users/lambda' | jq -r '.name'
 
grep -w \"key_name\" /vagrant/test.json |tail -1 | cut -d\" -f4
grep -w \"author\" /vagrant/test.json |tail -1 | cut -d\" -f4

$ FOOBAZ="tester"
$ jq -n --arg foobaz "$FOOBAZ" '{"foobaz":$foobaz}' > test1.json
$ cat test1.json

export $(jq -r '@sh "FOO=\(.foo) BAZ=\(.baz)"') #fill environment variables from JSON object keys (e.g. $FOO from jq query ".foo")
echo '{ "foo": 123, "bar": 456 }' | jq '.foo' #print out the foo property
apod_url=$(curl -s https://api.nasa.gov/planetary/apod?api_key=DEMO_KEY | jq -r '.hdurl') #get the URL of the current Astronomy Picture of the Day (APOD)
echo '{ "Version Number": "1.2.3" }' | jq '."Version Number"' #if a property has a spaces or weird characters
echo '[1,2,3]' | jq '.[]' #how iteration works
echo '[ {"id": 1}, {"id": 2} ]' | jq '.[].id' #access a property on each item
echo '{ "a": 1, "b": 2 }' | jq '.[]' #the value of each key/value pair
----------------------------------------------------------------------------------------------------
bootstrap.sh

parted /dev/sdb mklabel msdos
parted /dev/sdb mkpart primary 512 100%
mkfs.xfs /dev/sdb1
mkdir /mnt/disk

mount /mnt/disk
# Format the /dev/sdb partition with XFS filesystem and with a GPT partition table
sudo parted -s /dev/sdb mklabel gpt mkpart primary xfs
sudo mkfs.xfs /dev/sdb -f
sudo blkid -o value -s TYPE /dev/sdb
# list disk UUIDs
ls -l /dev/disk/by-id
$ fdisk -v
$ sudo fdisk -l
$ sudo fdisk -l /dev/sda1
-----------------------------------------------------------------------------------------------------
cut -c3    -> print the character from each 3rd line as a new line of output.
cut -c2,7 -> Display the 2nd and 7th character from each line of text
cut -c-4  -> Display the first four characters from each line of text
cut -c13-  -> Print the characters from thirteenth position to the end.
cut -d' ' -f4  -> Given a sentence, identify and display its fourth word. Assume that the space (' ') is the only delimiter between words.
cut -d' ' -f1-3  -> Given a sentence, identify and display its first three words. Assume that the space (' ') is the only delimiter between words.

cut -f 1-3  -> Given a tab delimited file with several columns (tsv format) print the first three fields.
cut  -f2-  -> Given a tab delimited file with several columns (tsv format) print the fields from second fields to last field.
-----------------------------------------------------------------------------------------------------
uniq -ci -> count the number of times each line repeats itself (only consider consecutive repetions).compare consecutive lines in a case insensitive manner
uniq -u  -> display only those lines which are not followed or preceded by identical replications

Given a text file, count the number of times each line repeats itself (only consider consecutive repetions). 
Display the count and the line, separated by a space. 
uniq -ci | cut -c7-
----------------------------------------------------------------------------------------------------- 
head -v -n 3 file1 # list the names of the files before outputting their content to the terminal
head -n2 -q file1 file2 #Use the -n option to print the first n lines from a file
head -n 20 -> Display the first lines of an input file.
head -n-2 example.txt # skips the last 2 lines and prints the remaining lines.
head -n10 filename | tail -5 #prints the lines between numbers 5 and 10
head -c5 example.txt #prints the first 5 bytes from the file.
head -c-7 example.txt #skip printing last 7 bytes.
head -c20 -> Display the first characters of an input file.
head -n 22 | tail -n +12 -> Display the lines (from line number 12 to 22, both inclusive) of a given text file
# print the lines between 5 and 10, both inclusive
cat filename | head | tail -6
-----------------------------------------------------------------------------------------------------
tail -n 20 | tail -n +12 -> Display the last lines of an input file.
tail -c 20 -> Display the last characters of an input file
-----------------------------------------------------------------------------------------------------
echo BigcapsSmallCaps | tr [:lower:] [:upper:] # convert string into lower case, capital case etc
tr '()' '[]' -> In a given fragment of text, replace all parentheses with box brackets 
tr -d [:lower:] -> In a given fragment of text, delete all the lowercase characters
tr -d "[:space:]" < raw_file.txt #remove all whitespace characters from the file
echo -e "   \t  A   \tB\tC   \t  " | tr -d "[:blank:]" #deletes any space or tabulation character
tr -s  ' ' -> In a given fragment of text, replace all sequences of multiple spaces with just one space
distribution=$(lsb_release --id | cut -f2 | tr [:upper:] [:lower:]) #all big caps to small caps
-----------------------------------------------------------------------------------------------------
sort -> Given a text file, order the lines in lexicographical order.
sort -r -> Given a text file, order the lines in reverse lexicographical order
sort -n -> the lines reordered in numerically ascending order
sort -nr  -> The text file, with lines re-ordered in descending order (numerically). 

given a file of text,in TSV (tab-separated) format.Rearrange the rows of the table in descending order of the values
sort -t$'\t' -rnk2
given a file of tab separated weather data (TSV). There is no header column in this data file.Sort the data in ascending order
sort -nk2 -t$'\t'
given a file of pipe-delimited weather data (TSV). There is no header column in this data file.
sort -nrk2 -t$'|'

-----------------------------------------------------------------------------------------------------
paste -s ->  Given a CSV file where each row contains the name of a city and its state separated by a comma.replace the newlines in the file with tabs
paste - - - ->  given a CSV file where each row contains the name of a city and its state separated by a comma, restructure the file in such a way, that three consecutive rows are folded into one, and separated by tab.
paste -s -d ";"  ->  given a CSV file where each row contains the name of a city and its state separated by a comma.replace the newlines in the file with semicolon
paste - - - -d ";" ->  given a CSV file where each row contains the name of a city and its state separated by a comma. restructure the file so that three consecutive rows are folded into one line and are separated by semicolons
-----------------------------------------------------------------------------------------------------
#Detect exploitation attempts of the vulnerability in uncompressed files in the Linux logs directory /var/log and all its subdirectories
egrep -I -i -r '\$(\{|%7B)jndi:(ldap[s]?|rmi|dns|nis|iiop|corba|nds|http):/[^\n]+' /var/log
find /var/log/ -type f -exec sh -c "cat {} | sed -e 's/\${lower://'g | tr -d '}' | egrep -I -i 'jndi:(ldap[s]?|rmi|dns|nis|iiop|corba|nds|http):'" \;
find /var/log/ -name '*.gz' -type f -exec sh -c "zcat {} | sed -e 's/\${lower://'g | tr -d '}' | egrep -i 'jndi:(ldap[s]?|rmi|dns|nis|iiop|corba|nds|http):'" \;
#searches for exploitation attempts in compressed files in folder /var/log and all sub folders
find /var/log -name \*.gz -print0 | xargs -0 zgrep -E -i '\$(\{|%7B)jndi:(ldap[s]?|rmi|dns|nis|iiop|corba|nds|http):/[^\n]+'

#files starting at the current directory (.) and that up to a maximum of 1 level of subdirectories
find . -maxdepth 2 -type f -name file.txt | xargs -I{} cat {} > ./total_file.txt

#Get total size of a list of files
perl -le 'map { $sum += -s } @ARGV; print $sum' -- *.pdf #Size of all non-hidden PDF files in current directory.

#list files between 1st Dec 2021 and 1st Jan 2022 and total size of each file
find . -type f -newermt 2012-01-01 ! -newermt 2022-01-01 -exec du -sh {} \;
find . -type f -newermt 2012-01-01 ! -newermt 2022-01-01 -exec ls -lt {} \; | sort -k6M -k7n #sorting month & date based
find . -name 'flibble*' -ctime +90 -exec du -sh {} \;

find . -type f -mmin -5 -print0 | xargs -0 /bin/ls -ltr #which files was modified in last 5 minutes
find . -type f -mmin -5 -exec ls -ltr {} +
find . -mmin -5 -exec ls -ltrd {} + #not limiting to files

#list files between 1st Dec 2021 and 1st Jan 2022 and grand total size of each found files, not sum of total sizes
"find . -name "*.tar" -type f -newermt 2012-01-01 ! -newermt 2022-01-01 -exec du -sch {} +"
find . "*.tar" -type f -newermt 2012-01-01 ! -newermt 2022-01-01 -exec du -sch {} + | tail -1 #only total
find . -name "*.tar" -type f -newermt 2012-01-01 ! -newermt 2022-01-01 -exec du -sch {} + | tail -1 | awk '{print $1}'

$ find . -size +2G #search for all files greater than 2 Gigabytes
$ find . -size -10k #search for all files with less than 10 Kilobytes
$ find . -size +10M -size -20M #search for files greater than 10MB but smaller than 20MB
$ sudo find /var -size +5M -exec ls -sh {} + #search for files in /etc directory which are greater than 5MB and print file size
$ find . -type f -exec ls -s {} + | sort -n -r | head -3 #Find first 3 largest files located in a in a current directory recursively
$ find /etc/ -type f -exec ls -s {} + | sort -n | head -3 #Find first 3 smallest files located in a in a current directory recursively
$ find . -type f -size 0b # search for empty files
$ find . -type f -empty # search for empty files

$ sudo find /var/log -name \*.log -size +1M -exec ls -lrt {} \; # find files larger than 1M,`M'    for Megabytes (units of 1048576 bytes)
$ sudo find /var/log -name \*.log -size +1M -exec ls -lrt {} \; | wc -l #get count
$ sudo find /var/log -name \*.log -size +1M -exec ls -lrt {} \; | awk '{ total += $5 }; END { print total }' # get total size, column 5(size) of ls command, 

#total size of all found files
$ sudo find /var/log -name \*.log -size +1M -exec ls -l {} \; | awk '{ sum += $5} END  \
{hum[1024^3]="Gb"; hum[1024^2]="Mb"; hum[1024]="Kb"; for (x=1024^3; x>=1024; x/=1024) { if (sum>=x) { printf "%.2f %s\n",sum/x,hum[x]; break; } } if (sum<1024) print "1kb"; }'


$ find /var/log/apt -type f -name "*.dat" -size +100M #list files larger than 100M

$ find /var/log/apt -iname *.log -print0 | xargs -r0 du -csh | tail -n 1; # -iname case insensitive
$ find /var/log/apt -iname *.log -exec ls -lh {} \;

$ find /var/log/apt -name *.log -size +10c -print0 | du -c --files0-from=- | awk 'END{print $1}'
$ find /var/log/apt -name *.log -size +10c -print0 | du -ch --files0-from=- | awk 'END{print $1}'
$ find /var/log/apt -name *.log -size +10c -print0 | du -ch --files0-from=- --total -s|tail -1 #xargs pipe "|" calls du command many times
$ find /var/log/apt -name *.log -type f -exec ls -s \; | awk '{sum+=$1;} END {print sum/1000;}' #excludes all directories
du -ch /var/log/apt | tail -1 | cut -f 1

$ (find /var/log/apt -name *.log -size +10c -printf '%s+'; echo 0 ) | bc
$ ( find /var/log/apt -name *.log -size +10c -printf 's+=%s\n'; echo s ) | bc

$ find /var/log/apt -name *.log -size +10c -printf '%s\n' | jq -s add
$ find /var/log/apt -name *.log -size +10c -exec stat -c%s '{}' + | jq -s add

find . -name "*.tar" -type f -newermt 2012-01-01 ! -newermt 2022-01-01 -print0 | xargs -0 du -c --block-size=human-readable
find . -name 'flibble*' -ctime +90 -print0 > filenames && du -shc --files0-from=filenames
du -c `find . -name 'flibble*' -ctime +90` | tail -1
find . -name 'flibble*' -ctime +90 -printf "%s\n" |perl -lnE '$sum += $_} END {say $sum'
find . -name 'flibble*' -ctime +90 -printf "%s\t%p\n" |perl -apE '$sum += $F[0]} END {say $sum'
echo "$(( ($(find . -name 'flibble*' -ctime +90 -type f -printf '%k+' )0)/1024/1024 )) GB"

#-mtime +7 means older than 8 days (age rounded to integer number of days greater than 7). 
log_history=13 && find /opt/freeswitch/var/log/freeswitch -type f -mtime +$log_history -delete #Delete old/rotated log files
# if tomcat directory exists,delete logs
log_history=13 && [[ -d /var/log/tomcat7 ]] && find /var/log/tomcat7 -type f -mtime +$log_history -delete 
#Delete FreeSWITCH wav/opus recordings older than 13 days
history=13 && find /var/freeswitch/meetings/ -name "*.wav"  -mtime +$history -delete

# find all files, SUID bit enabled
find / -perm -4000 -exec ls -l {} \;
find /usr/bin/ -perm -4000 -exec ls -l {} \;
find /bin/ -perm -4000 -exec ls -l {} \;
find / -xdev -perm -4000 2>/dev/null

#-perm denotes that we will search for the permissions that follow:
#-u=s denotes that we will look for files which are owned by the root user
#-type states the type of file we are looking for
#f denotes a regular file, excluding directories and special files
find / -perm -u=s -type f 2>/dev/null


find / -uid 0 –perm -4000 -print #find all programs whose SetUID is set to run as root
find / -perm -2000 -exec ls -l {} \; # find all files, SGID bit enabled

find /lib/modules/`uname -r` -type f -name '*quota_v*.ko*'

#counts files recursively in all subfolders in the specified folder
find /data -type f | wc -l
#counts files in the current dir, not recursively
find /data -maxdepth 1 -type f | wc -l
#counts folders recursively in all subfolders in the specified folder
find /data -type d | wc -l

find -type f -exec md5sum -t {} \; | cut -d ' ' -f 1 | sort | md5sum #compute checksum

find . -type f -newermt 2012-02-01 ! -newermt 2022-01-01 #between 1st Dec 2021 and 1st Jan 2022
find . -type f -newermt 2012-02-01 ! -newermt 2022-01-01 -ls #list files between 1st Dec 2021 and 1st Jan 2022
find . -type f -newermt 2012-02-01 ! -newermt 2022-01-01 -exec echo {} \; #test before delete
find . -type f -newermt 2012-02-01 ! -newermt 2022-01-01 -exec rm -rf {} \; #delete between 1st Dec 2021 and 1st Jan 2022
find . -type f -newermt 2012-01-01 ! -newermt 2022-01-01 -exec ls -l {} \;

#never put the -delete action at the first position
#If the -delete action is at the first position, during its evaluation, it deletes the given directory and everything in it
#the -delete action implies the -depth option
#The -depth option asks the find command to search each directory’s contents before the directory itself. 
# -delete as the first option, it starts deletion from each directory tree’s very bottom
$ find test -delete -type d -name '.git' # the test directory has been deleted
$ ls test
ls: cannot access 'test': No such file or directory

#the -delete action cannot delete a non-empty directory recursively, can only delete files and empty directories

find test -depth -type d -name '.git' -exec rm -r '{}' \; #remove all .git directories 
find test -type d -name '.git' | xargs rm -r #remove all .git directories 
find ~/Downloads/ -empty -type d -delete #delete all empty directories
find /path/ -empty -type d | wc -l ## count empty dirs only ##
find /path/to/dir/ -type d -empty -print0 | xargs -0 -I {} /bin/rmdir "{}" #find and delete all empty directories
find /path/to/dir -type d -empty -print0 -exec rmdir -v "{}" \; #find and delete all empty directories,slow due to -exec
$ sudo find /var -type d -empty -mtime +50
$ sudo find /var -type d -empty -mtime +5 -exec sh -c 'du -sch' sh {} +

#-exec with an external command, it fills each found file in the ‘{}’ placeholder
find test -name 'whatever.txt' -exec rm {} \; #remove all whatever.txt files
find test -name 'whatever.txt' | xargs rm #remove all whatever.txt files
find ~/Downloads/ -empty -type -f -delete #delete all empty files
find /path/ -empty -type f | wc -l ## count empty files only ##

find /path/to/dir/ -type f -empty -print0 | xargs -0 -I {} /bin/rm "{}" #delete all empty files
find /path/to/dir/ -type f -empty -print0 -exec rm -v "{}" \; #delete all empty files,slow due to -exec

find / -name .DS_Store -delete #-delete will perform better because it doesn't have to spawn an external process for each and every matched file
find / -name ".DS_Store" -exec rm {} \; #recommended because -delete does not exist in all versions of find
find / -iname "*~"  -exec rm -i {} \; # gives an interactive delete
find / -name .DS_Store -exec rm {} + #The command termination + instead of \; highly optimizes the exec clause by not running the rm command for each and every .DS_Store present on the file system
find / -name .DS_Store -print0 | xargs -0 rm #avoiding the overhead of spawning an external process for each matched file

find . -type f -newermt 2012-01-01 ! -newermt 2022-01-01 -exec du -sh {} \;#list files between 1st Dec 2021 and 1st Jan 2022 and total size

#-delete does not delete empty directories
$ find /path/to/dir/ -type d -name ".TemporaryItems" -delete
find: cannot delete ‘./.TemporaryItems’: Directory not empty
$ find /path/to/dir/ -type d -name ".TemporaryItems" -exec rm -rv "{}" +

find /home -group ftpusers # list file owned by a user or group
find /data/project -group ftpusers -name "*.c" # list file owned by all *.c file belongs to a group called “ftpusers
find /data/project -group ftpusers -name "*.c" # list file owned by all *.c file belongs to a group called “ftpusers ,case insensitive
find $HOME -name "*.mp4" -group pedro -ls #list file in ls command format pass the -ls
find /var -user pedro
find /var/www -user pedro -name "*.pl" # find all *.pl (perl files) file belongs to a user
find / -type f -user bonnie -o -user clyde #find files by users bonnie and clyde
find / -type d -user vivek -o -user wendy #find dirs  by users bonnie and clyde

----------------------------------------------------------------------------------------------------
#delete multiple folders in a folder which have files in them

Run the following command to list the folders that will be affected by the deletion command
The output of the find command will display a list of folder names. Carefully review this list to make sure that it includes only the folders you intend to delete
find . -type d

Once you're satisfied with the list and have made any necessary modifications to exclude specific folders, you can run the original deletion command:
find . -type d -exec rm -r {} \;


Use the xargs command to pass the output of the find command to the rm command:
find . -type d | xargs rm -rf

find . -type d -exec rm -r {} \;
find .: Searches for files and directories in the current directory and its subdirectories.
-type d: Specifies that the search should only include directories (folders).
-exec rm -r {} \;: Executes the rm -r command on each found directory. The {} is a placeholder for the found directory name, and \; indicates the end of the -exec command.
Be cautious when using this command, as it will delete all directories, including their contents, within the specified directory.

find . -type d -exec rm -rf {} \;
use the -f option with rm to suppress confirmation prompts and force deletion. However, be cautious with the -f option, as it will delete without asking for confirmation.
----------------------------------------------------------------------------------------------------


find test -type d -name '.git' # list git directories
find . -type d -newermt 2012-02-01 ! -newermt 2022-01-01 -ls #list directories between 1st Dec 2021 and 1st Jan 2022
find . -type d -newermt 2012-03-22 ! -newermt 2022-03-24 -exec echo {} \; #test before delete
find . -type d -newermt 2012-02-01 ! -newermt 2022-01-01 -exec rm -rf {} \; #delete directories between 1st Dec 2021 and 1st Jan 2022

find /dir/ -type f -newerXY 'yyyy-mm-dd'
The letters X and Y can be any of the following letters:
    a – The access time of the file reference
    B – The birth time of the file reference
    c – The inode status change time of reference
    m – The modification time of the file reference
    t – reference is interpreted directly as a time

find . -type f -newerat 2017-09-25 ! -newerat 2017-09-26 #all files accessed on the 25/Sep/2017
find /home/you -iname "*.c" -atime 30 -type f  #all *.c file accessed exactly 30 days ago
find /home/you -iname "*.c" -atime -30 -type f #all *.c file accessed 30 days ago, not older than 30 days
find /home/you -iname "*.c" -atime -30 -type f -ls
find /home/you -iname "*.c" -atime +30 -type f #all *.c file accessed more than 30 days ago, older than 30 days
find /home/you -iname "*.c" -atime +30 -type f -ls
-----------------------------------------------------------------------------------------------------
#Users of the bash shell need to use an explicit path in order to run the external time command and 
#not the shell builtin variant.  On systemwhere time is installed in /usr/bin,
       
#Real is wall clock time - time from start to finish of the call. This is all elapsed time including 
#time slices used by other processes and time the process spends blocked (for example if it is waiting for I/O to complete).

#User is the amount of CPU time spent in user-mode code (outside the kernel) within the process. 
#This is only actual CPU time used in executing the process. Other processes and time the process 
#spends blocked do not count towards this figure.

#Sys is the amount of CPU time spent in the kernel within the process. This means executing CPU time 
#spent in system calls within the kernel, as opposed to library code, which is still running in user-space

$ /usr/bin/time -o out.txt sudo find /var/log -name '*log' -ctime +1 -exec du -sh {} \;
$ cat out.txt
0.01user 0.03system 0:00.06elapsed 76%CPU (0avgtext+0avgdata 8756maxresident)k
0inputs+0outputs (0major+2771minor)pagefaults 0swaps

#the -exec action runs the specified command on the selected files, but the command line is built by appending each selected file name at the end
$ /usr/bin/time -o outplus.txt sudo find /var/log -name '*log' -ctime +1 -exec du -sh {} +;
$ cat outplus.txt
0.00user 0.01system 0:00.02elapsed 73%CPU (0avgtext+0avgdata 8804maxresident)k
0inputs+0outputs (0major+1091minor)pagefaults 0swaps

$ /usr/bin/time -o out.txt sudo find /var/log -name '*log' -ctime +1 -exec du -sh {} \;
$ /usr/bin/time -f "\t%C [Command details],\t%K [Total memory usage],\t%k [Number of signals process received]" ping -c 2 howtoforge.com
-----------------------------------------------------------------------------------------------------
# displays without comments                                                    
egrep -v "^#|^$" /etc/zabbix/zabbix_server.conf
-----------------------------------------------------------------------------------------------------
#r = recursive i.e, search subdirectories within the current directory
#n = to print the line numbers to stdout
#i = case insensitive search
grep -rni "string" * 
grep -rni "apache /etc/cron.d"

#string search current and subfolders
$ grep -rl "900990" .
./.crs-setup.conf.swp
./crs/crs-setup.conf
./crs-setup.conf

# displays the comments
grep ^# /etc/resolv.conf

# displays without comments                                                    
grep ^[^#] /etc/resolv.confprint directory/file structure in the form of a tree
grep ^[^\;] /etc/resolv.conffind . | sed -e "s/[^-][^\/]*\// |/g" -e "s/|\([^ ]\)/|-\1/"
grep -v "^#" /etc/zabbix/zabbix_server.conf | grep -v "^$"sed '' quote.txt -> display the contents of the file

# search multiple strings, words
grep 'string1' filename | grep 'string2' #search two strings in one line 
grep -n 'string1' filename | grep 'string2' #search two strings in one line and print line numbers
grep 'string1.*string2\|string2.*string1' filename #search two strings in one line 
grep -n 'string1.*string2\|string2.*string1' filename #search two strings in one line and print line numbers
grep -E "string1(?.*)string2" file #search two strings in one line 
grep -nE "string1(?.*)string2" file #search two strings in one line and print line numbers

#Grep for Multiple Strings
grep 'wordA*'\''wordB' *.py ### Search all python files for 'wordA' or 'wordB'
grep 'word*' *.txt ### Search all text files
grep 'word1\|word2\|word3' /path/to/file
grep 'warning\|error\|critical' /var/log/messages
grep -e 'warning\|error\|critical' /var/log/messages
egrep -wi --color 'warning|error|critical' /var/log/messages #-i (ignore case)
egrep -wi --color 'foo|bar' /etc/*.conf
egrep -Rwi --color 'foo|bar' /etc/ #including sub-directories
egrep -w 'warning|error|critical' /var/log/messages
grep -w 'warning\|error\|critical' /var/log/messages

egrep -ne 'null|three' #search multiple string and output line numbers 

grep -o "0x[^']*" file.txt # matching text starting with "0x"
grep "zip$" #filters the lines that end in zip

grep -r --include "*.jar" JndiLookup.class / #Detect the presence of Log4j 

grep --color regex filename #Highlight
grep --color ksh /etc/shells
grep -o regex filename #Only The Matches, Not The Lines
egrep "v{2}" filename #Match a character “v” two times
egrep 'co{1,2}l' filename #match both “col” and “cool” words
egrep 'c{3,}' filename #match any row of at least three letters ‘c’
grep "[[:digit:]]\{2\}[ -]\?[[:digit:]]\{10\}" filename #match mobile number format 91-1234567890
egrep '[[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}\.[[:digit:]]{1,3}' file #match an IP address,All three dots need to be escaped

$ grep '^[P-R]' list.txt #lines from list.txt file that starts with P or Q or R
$ grep '[^A-C]' list.txt #lines from list.txt file that starts with A or B or C

$ grep [!P-R] list.txt #from list.txt file that starts with ‘P’ or Q or R
$ grep [!4-8] list.txt #lines from list.txt file that starts with any digit from 4 to 8.

$ grep a$ list.txt #lines from list.txt file that ends with ‘a’
$ grep 50$ list.txt #lines from list.txt file that end with the number 50

grep -i "boar" /etc/passwd #Perform a case-insensitive search for the word ‘bar’

grep "Gnome Display Manager" /etc/passwd #If the search string includes spaces, enclose it in single or double quotation marks

#the string “linux” will match only if it occurs at the very beginning of a line
grep '^linux' file.txt #The ^ (caret) symbol 
grep 'linux$' file.txt #lines end with linux string
grep '^linux$' file.txt #lines contain only linux string
grep '^\.[0-9]' filename #lines starting with a dot and digit
grep '^..$' filename #lines with  two characters

#The . (period) symbol is a meta-character that matches any single character
grep 'kan..roo' file.txt #match anything that begins with “kan” then has two characters and ends with the string “roo”
grep 'acce[np]t' file.txt #find the lines that contain “accept” or “accent”
grep 'co[^l]a' file.txt #match any combination of strings starting with “co” followed by any letter except “l” followed by “la”, such as “coca”, “cobalt” and so on
grep '^[A-Z]' file.txt #matches each line that starts with a capital letter

grep 's*right' #match “right”, “sright” “ssright” and so on
grep -E '^[A-Z].*[.,]$' file.txt #matches all lines that starts with capital letter and ends with either period or comma

grep 'b\?right' file.txt #match both “bright” and “right”. The ? character is escaped with a backslash because we’re using basic regular expressions
grep -E 'b?right' file.txt

grep -E 's+right' file.txt #match “sright” and “ssright”, but not “right”
grep -E '[[:digit:]]{3,9}' file.txt #matches all integers that have between 3 and 9 digits

grep 'word' filename
grep 'word' file1 file2 file3
grep -i "boar" /etc/passwd #Perform a case-insensitive search for the word ‘bar’

"grep -R 'httpd' ." #Look for all files in the current directory and in all of its subdirectories
# search for a keyword in text files within a folder and its subfolders. 
grep -r "keyword" /path/to/directory
grep -r "keyword" --include "*.txt" /path/to/directory # search for a keyword in a specific type of file
grep -r -i "keyword" /path/to/directory #case-sensitive when searching for keywords

grep -r "192.168.1.5" /etc/ #search recursively i.e. read all files under each directory for a string “192.168.1.5”
grep -c 'nixcraft' frontpage.md #display the total number of times that the string ‘nixcraft’ appears in a file named frontpage.md

#Grep NOT
#-v flag to print inverts the match; that is, it matches only those lines that do not contain the given word
grep -v -c -e "that" ->  find out how many lines that does not match the pattern
grep -v Sales employee.txt #all the lines except those that contains the keyword “Sales”

grep -w "the" -> Output only those lines that contain the word 'the'.
grep -iw "the" -> Output only those lines that contain the word 'the'. The search should NOT be case sensitive.
grep -viwe "that" -> Only display those lines that do NOT contain the word 'that'.
grep -Eiw "th(e|ose|en|at)" < /dev/stdin -> display all those lines which contain any of the following words "the,that,then,those" .The search should not be sensitive to case. Display only those lines of an input file, which contain the required words.  
grep '\([0-9]\) *\1' -> Given an input file, with N credit card numbers,grep out and output only those credit card numbers which have two or more consecutive occurences of the same digit (which may be separated by a space, if they are in different segments). Assume that the credit card numbers will have 4 space separated segments with 4 digits each

#top 10 IP addresses in the log file.
grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}" access.log | uniq -ci | sort -nr | head -n10

ifconfig -a | grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}" | awk 'ORS=NR%2?" , ":"\n"'
ip addr show eth1 | grep inet | awk '{ print $2; }' | sed 's/\/.*$//'
ifconfig -a | grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}"

#list process binary path and permissions
ps aux | awk '{print $11}' | xargs -r ls -la 2>/dev/null |awk '!x[$0]++'
ps -elf | grep autofs | grep -v grep  | awk '{print $4}' | xargs kill -9 

######group expressions,grep -E option is for extended regexp,three expressions are functionally equivalent
grep "\(grouping\)" file.txt #use parentheses without using extended regular expressions, escape with the backslash
grep -E "(grouping)" file.txt
egrep "(grouping)" file.txt

grep -E "(GPL|General Public License)" GPL-3 #find either GPL or General Public License in the text
grep -E "(copy)?right" GPL-3 #matches copyright and right by putting copy in an optional group
grep -E '(fear)?less' file.txt #matches both “fearless” and “less”. The ? quantifier makes the (fear) group optional
grep -E "free[^[:space:]]+" GPL-3 # matches the string free plus one or more characters that are not white space characters
grep -E "[AEIOUaeiou]{3}" GPL-3 #find all of the lines in the GPL-3 file that contain triple-vowels
grep -E "[[:alpha:]]{16,20}" GPL-3 #match any words that have between 16 and 20 characters

grep -e pattern1 -e pattern2 filename #Grep OR Using grep -e,
egrep 'Tech|Sales' employee.txt #Grep OR Using egrep
grep 'Tech\|Sales' employee.txt #Grep OR Using \|,grep either Tech or Sales from the employee.txt file
grep 'fatal\|error\|critical' /var/log/nginx/error.log
grep -E 'fatal|error|critical' /var/log/nginx/error.log # use the extended regular expression, then the operator | should not be escaped
grep -E 'Tech|Sales' employee.txt #Grep OR Using -E

#Grep AND
grep Manager employee.txt | grep Sales #all the lines that contain both “Manager” and “Sales” in the same line
grep -E 'Dev.*Tech' employee.txt #all the lines that contain both “Dev” and “Tech” in it (in the same order).
grep -E 'Manager.*Sales|Sales.*Manager' employee.txt #all the lines that contain both “Manager” and “Sales” in it (in any order)
-----------------------------------------------------------------------------------------------------
user@host: $ cat<<EOF > file.txt
$ > 1 line
$ > other line
$ > n line
$ > EOF
user@host:
-----------------------------------------------------------------------------------------------------
# append text
cat<<EOF | sudo tee -a ceph.conf
public network = 192.168.18.0/24
osd pool default size = 2
EOF
-----------------------------------------------------------------------------------------------------
sudo install consul /usr/bin/consul
(
cat <<-EOF
  [Unit]
  Description=consul agent
  Requires=network-online.target
	After=network-online.target
  [Service]
  Restart=on-failure
  ExecStart=/usr/bin/consul agent -dev
  ExecReload=/bin/kill -HUP $MAINPID
  [Install]
  WantedBy=multi-user.target
EOF
) | sudo tee /etc/systemd/system/consul.service
-----------------------------------------------------------------------------------------------------
cat <<EOT | sudo tee /lib/systemd/system/procenv.service
 [Unit]
 Description=Display systemd environment

 [Service]
 Type=oneshot
 ExecStart=/usr/bin/procenv --file=/tmp/procenv-systemd.log
 EOT
----------------------------------------------------------------------------------------------------- 
> outputs to a file
>> appends to a file
< reads input 
<<Here tells the shell that you are going to enter a multiline string until the "tag" Here. You can name this tag as you want, it's often EOF or STOP.
"EOF" is known as a "Here Tag"

The redirection operators "<<" and "<<-" both allow redirection of lines contained in a shell input file, 
known as a "here-document", to the input of a command.

The format of here-documents is:
          <<[-]word
                  here-document
          delimiter
	  
If the redirection operator is <<-, then all leading tab characters are stripped from input lines and the line containing delimiter. 
This allows here-documents within shell scripts to be indented in a natural fashion.
-----------------------------------------------------------------------------------------------------
# Assign multi-line string to a shell variable
# The $sql variable now holds the new-line characters
# verify with echo -e "$sql"
sql=$(cat <<EOF
SELECT foo, bar FROM db
WHERE foo='baz'
EOF
)
-----------------------------------------------------------------------------------------------------
#Pass multi-line string to a file in Bash
$ cat <<EOF > print.sh
#!/bin/bash
echo \$PWD
echo $PWD
EOF
-----------------------------------------------------------------------------------------------------
# Pass multi-line string to a pipe in Bash
$ cat <<EOF | grep 'b' | tee b.txt
foo
bar
baz
EOF
-----------------------------------------------------------------------------------------------------
$ sudo tee <<EOF /etc/somedir/foo.conf >/dev/null
# my config file
foo=bar
EOF
-----------------------------------------------------------------------------------------------------
echo -e "
Home Directory: $HOME \n
hello world 1 \n
hello world 2 \n
line n... \n
" > file.txt 
-----------------------------------------------------------------------------------------------------
echo write something to file.txt | cat > file.txt
cat >file.txt <<< Write something here

# see the line numbers
cat -n song.txt
#  shows at the end of line and also in space showing ‘$‘ if there is any gap between paragraphs
# useful to squeeze multiple lines in a single line.
cat -e test
# all output will be redirected in a newly created file
cat test test1 test2 > test3
#  Sorting Contents of Multiple Files in a Single File
cat test test1 test2 test3 | sort > test4
# Display Multiple Files at Once
cat test; cat test1; cat test2

# append your text to the end of the file
cat >> ~/.bashrc <<EOF
# my config file
foo=bar
EOF

cat > /sys/devices/system/cpu/cpu1/cpufreq/scaling_governor <<EOF
performance
EOF
-----------------------------------------------------------------------------------------------------
curl -sSL https://releases.hashicorp.com/nomad/${NOMAD_VERSION}/nomad_${NOMAD_VERSION}_linux_amd64.zip -o nomad.zip
	  https://releases.hashicorp.com/packer/${PACKER_VERSION}/packer_${PACKER_VERSION}_linux_amd64.zip	
curl -sSL https://releases.hashicorp.com/vagrant/${VAGRANT_VERSION}/vagrant_${VAGRANT_VERSION}_linux_amd64.zip -o vagrant.zip
curl -sSL https://releases.hashicorp.com/vagrant/2.2.2/vagrant_2.2.2_linux_amd64.zip -o vagrant.zip
unzip vagrant.zip

$ curl -L https://raw.githubusercontent.com/do-community/ansible-playbooks/master/docker/ubuntu1804.yml -o /vagrant/docker_ubuntu.yml

export VER="4.4.6"
"curl -SL https://github.com/NagiosEnterprises/nagioscore/releases/download/nagios-$VER/nagios-$VER.tar.gz | tar -xzf -"
cd nagios-$VER
------------------------------------------------------------------------------------------
tar -C /usr/local -xzf go1.19.linux-amd64.tar.gz # extract the archive into /usr/local, creating a fresh Go tree in /usr/local/go
------------------------------------------------------------------------------------------
split --bytes=2048m WinXP.img WinXP_img_
# four files (2GB each) appeared
WinXP_img_aa
WinXP_img_ab
WinXP_img_ac
WinXP_img_ad
cat WinXP_img_* > WinXP.img

# join smaller files into a larger one
cat partfilename* > outputfilename

video.avi.01
video.avi.02
video.avi.03
cat video.avi.* > video1.avi

$ cat file1
1. Asia:
2. Africa:
3. Europe:
4. North America:

tac tacexample.txt #print files in reverse
$ tac file1
4. North America:
3. Europe:
2. Africa:
1. Asia:

$ cat file2
1. India
2. Nigeria
3. The Netherlands
4. The US
$ join file1 file2
1. Asia: India
2. Africa: Nigeria
3. Europe: The Netherlands
4. North America: The US

join -1 1 -2 1 -e 'empty' /tmp/in /tmp/out | tr " " "\t" #join the two files,the first column in each file as index

# create a new file “new.txt” that is a concatenation of “file1.txt” and “file2.txt”
cat file1.txt file2.txt > new.txt
 
format text and convert it to a different width
$ fmt --width=20 test.txt
------------------------------------------------------------------------------------------
g++ -v
g++ temp.cpp
# run
./a.out
------------------------------------------------------------------------------------------
# Installing software from source
tar xvzf package.tar.gz
tar xvjf package.tar.bz2
cd package
./configure
make
make install
# Cleaning up
make clean
make uninstall

# "make clean" runs as expected even if you do have a file named clean.
#  There are two reasons to use a phony target: to avoid a conflict with a file of the same name, and to improve performance. 
.PHONY: clean
clean:
rm -rf *.o

# case1
$ cat make
hello : hello.o
        gcc -Wall hello.o -o hello
$ cat hello.c
#include<stdio.h>

int main(void)
{
            printf("\n Hello World!!!\n");
                return 0;
}
$ cp make mon-makefile
$ ls
hello.c  make  mon-makefile

make -C makefile-test1/ hello
make -f mon-makefile
make -s

# case2
$ cat file2.h
void add(int a, int b, void (*f)(int));
$ cat file2.c
#include<stdio.h>
#include"file2.h"

void add(int a, int b, void(*f)(int))
{
            int c  = a+b;
                f(c);
}
$ cat file1.c
#include<stdio.h>
#include"file2.h"

void callback (int result)
{
            printf("\n Result is : [%d] \n", result);
}

int main(void)
{
            int a=0,b=0;
                printf("\n Enter two numbers to add: ");
                    scanf("%d %d",&a, &b);
                        add(a,b,callback);
                            return 0;
}
$ cat makefile
file : file1.o file2.o
                gcc -Wall file2.o file1.o -o file

file1.o : file1.c file2.h
                gcc -c -Wall file1.c -o file1.o

file2.o : file2.c file2.h
                gcc -c -Wall file2.c -o file2.o
$ cp make mon-makefile
$ ls
file1.c  file2.c  file2.h  makefile  mon_makefile


------------------------------------------------------------------------------------------
# linux system management
top
sar
vmstat
iostat
free
ps
tcpdump
iptraf
nestat

# /Proc file system - Various Kernel Statistics
cat /proc/cpuinfo
cat /proc/meminfo
cat /proc/zoneinfo
cat /proc/mounts
------------------------- -----------------------------------------------------------------
$ uptime
#"system load averages" that show the running thread (task) demand on the system as an average number of running plus waiting threads.
#show three averages, for 1, 5, and 15 minutes
#If the averages are 0.0, system is idle
#If the 1 minute average is higher than the 5 or 15 minute averages, then load is increasing
#If the 1 minute average is lower than the 5 or 15 minute averages, then load is decreasing.

ps -eL h -o state | egrep "R|D" | wc -l #The instantaneous number of such tasks
#Linux load average,the instantaneous load of a system the number of tasks (processes and threads) that are willing to run at a given time t
#either in state R or D, either actually running or blocked on some resource (CPU, IO, ...) waiting for an opportunity to run
------------------------------------------------------------------------------------------
list user vagrant's full command line of processes
$ top -c -u vagrant
ignore idle processes
$ top -i -u vagrant
updated with 5 secs intervals, including child processes
$ top -u vagrant -c -d 5 -S
#determine which Plaso processes are running
top -p `ps -ef | grep log2timeline.py | grep python | awk '{ print $2 }' | tr '\n' ',' | sed 's/,$//'`

#interactive top command
#If you have a multi-core CPU, press "1" to change the display and see individual statistics for each CPU
#press “t” to swap the CPU displays to simple ASCII graphs that show the percentage of usage for each CPU
#Pressing “c” toggles the COMMAND column between displaying the process name and the full command line
#Press “u” to see the processes for a single user. You’ll be prompted for the name or UID
#Press I to see only active tasks.
#press “r” to change the nice value (priority) for a process
#Press “k” to kill a process. You’ll then be prompted for the process ID you want to kill
------------------------------------------------------------------------------------------
The load averages shown by these tools is read /proc/loadavg file
cat /proc/loadavg
 
------------------------------------------------------------------------------------------
# same inodes
ls -ldi /. /..
2 drwxr-xr-x 24 root root 4096 Feb 21 20:28 /.
2 drwxr-xr-x 24 root root 4096 Feb 21 20:28 /..

# different inodes
ls -ldi /home/vagrant/. /home/vagrant/..
3145730 drwxr-xr-x 7 vagrant vagrant 4096 Feb 22 10:14 /home/vagrant/.
3145729 drwxr-xr-x 3 root    root    4096 Aug 24 08:48 /home/vagrant/..
------------------------------------------------------------------------------------------
#ChatGPT

Both .bashrc and .profile files are used for setting environment variables and defining user-specific configurations on Linux, but they have some differences in their purpose and usage.

Here are some of the differences between .bashrc and .profile files:

    File Location: .bashrc is a Bash shell-specific initialization file that is located in the user's home directory. On the other hand, .profile is a generic shell initialization file that is also located in the user's home directory.

    Shell Usage: .bashrc is loaded for Bash shell instances only, while .profile is loaded for every shell instance (including Bash, Korn shell, Bourne shell, etc.) that is started.

    Invocation: .bashrc is invoked for non-login shells, while .profile is invoked for login shells.

    Content: .bashrc is typically used for setting Bash shell-specific configurations such as aliases, environment variables, and command prompt settings, while .profile is used for setting environment variables and other configurations that should be applied to all shells.

    Loading order: When a Bash shell instance is started, it first loads the /etc/profile file, which is a system-wide shell initialization file. After that, it loads the user's ~/.bash_profile or ~/.bash_login or ~/.profile file (in that order) if it exists. If none of these files exist, it loads the ~/.bashrc file.

In summary, .bashrc is used for Bash shell-specific configurations, while .profile is used for general shell configurations that should apply to all shells. .bashrc is loaded for non-login shells, while .profile is loaded for login shells.

------------------------------------------------------------------------------------------
# The user file-creation mode mask (umask)
/etc/profile 
~/.bashrc 
~/.bash_profile

# By default
0022 (022)
0002 (002)
files
666
directories
777

The default umask 002 used for normal user
directory permissions
775
file permissions
664

The default umask for the root user is 022
directory permissions
755
file permissions
644

base permissions
directory permissions
(rwxrwxrwx) 0777
file permissions
(rw-rw-rw)  0666 

# No other user can read or write your data
umask 077
# when you share data with other users in the same group
# Members of your group can create and modify data files
# those outside your group can read data file, but cannot modify it.
umask 022
# exclude users who are not group members
umask 007

# The octal umasks are calculated via the bitwise AND of the unary complement of the argument using bitwise NOT
                Octal value : Permission
                0 : read, write and execute
                1 : read and write
                2 : read and execute
                3 : read only
                4 : write and execute
                5 : write only
                6 : execute only
                7 : no permissions
------------------------------------------------------------------------------------------
# testing webpages

$ telnet control01 80 #test website availability and get the response code

GET /index.html HTTP/1.1
Host: control01

GET /index.html HTTP/1.1
Host: control01
If-modified-since: Sun, 24 Feb 2019 12:59:37 GMT

GET /telnet-send-get-head-http-request HTTP/1.1
HOST: control01

HEAD / HTTP/1.1
Host: control01
------------------------------------------------------------------------------------------
# delete files containing special chars

$ cat>>"-f"<<EOF
> test
> EOF

$ ls
-f  test  test2  videos

$ ls -li
total 260
3145770 -rw-rw-r-- 1 vagrant vagrant      5 Mar  5 17:02 -f

find / -name wget 2>/dev/null
find /home/vagrant -name file1
find /home/vagrant -user root
find /home/vagrant -group root
find . -inum 3145770 -delete
find . -inum 3145770 -exec rm -i {} \;
ls -il {file-name}
find . -inum [inode] -exec rm -i {} \;
------------------------------------------------------------------------------------------
# steganography, attaching a .rar file to a .jpg etc.
cat pic.jpg file.rar > result.jpg
------------------------------------------------------------------------------------------
# view used IRQs 
cat /proc/interrupts
#determine the IRQ number associated with the Ethernet driver
$ grep enp0s3 /proc/interrupts
 19:      24006   IO-APIC-fasteoi   enp0s3
$ grep eth0 /proc/interrupts
 19:      13247   IO-APIC  19-fasteoi   eth0
 
 # troubleshoot network card etc. hardware conflicts, what addresses are used or free, or move conflicting hardware to free resource
 # listing IRQs currently being used.not listed IRQs are considered free.used when devices alert CPU to take action
 cat /proc/interrupts
 # listing used DMA channel.when devicess access memory directly without going through CPU
 cat /proc/dma
 # listing I/O ports currently being used.any range not listed is free and can be used by other devices.
 # devices have unique I/O addresses
 cat /proc/ioports
  
 ------------------------------------------------------------------------------------------
# view default shell for each user
$ cat /etc/passwd
# There are seven fields in the /etc/passwd file
# username, UID, GID, comment, home directory, command
# add an asterisk at the beginning of the password field in the /etc/passwd file, that user will not be able to log in
/etc/passwd

/etc/adduser.conf #Set DHOME variable for new default home directory of users.
# useradd tecmint
# useradd -m tecmint #create user with default home dir
# passwd tecmint
create admin user
sudo useradd vagrant -s /bin/bash -g sudo -m
modify a existing user to admin user
sudo usermod -aG sudo vagrant # add user to a group, add vagrant to sudo group
create a user ‘anusha‘ with a home directory ‘/data/projects‘.
# useradd -d /data/projects anusha
create a user ‘navin‘ with custom userid ‘999‘.
# useradd -u 999 navin
add a user ‘tarunika‘ with a specific UID and GID
# useradd -u 1000 -g 500 tarunika
add a user ‘tecmint‘ into multiple groups like admins, webadmin and developer
# useradd -G admins,webadmin,developers tecmint
# id tarunika
uid=995(tarunika) gid=1001(vboxadd) groups=1001(vboxadd)
create a user ‘aparna‘ with account expiry date i.e. 27th April 2014 in YYYY-MM-DD 
useradd -e 2014-03-27 aparna
useradd -r -d /opt/gvm -c "GVM User" -s /bin/bash gvm #Create a system account,subordinate uid/gid feature is disabled,mail directory is not created

chage -l aparna #verify the age of account
chage -d 0 user #Minimum number of days between password change  
make  changes to "/etc/shadow" file as root user #Minimum number of days between password change 
chage -M 7 aparna # aparna account’s password must be changed at least once every seven days

sudo useradd test-user-0 && sudo passwd -d test-user-0 #create user without password
awk -F: '($2 == "") {print}' /etc/shadow # verify users without password
passwd -l test-user-0 #Lock all empty password account
cat /etc/passwd | cut -d : -f 1 | awk '{ system("sudo passwd -S " $0) }' #list locked users
sudo passwd -S -a | grep " L " | cut -d " " -f1 #list locked users, ubuntu
sudo passwd -S -a | cut -d " " -f1-2 | grep "L$" #list locked users, ubuntu
passwd -l user1 #lock the password
grep user1 /etc/shadow  #two exclamation mark (!!) before the encrypted password which means that the password has been locked
passwd -u user1 #unlock the password
passwd -S user1 #see the lock status of the user

#A user whose account has a "non-interactive shell" (/bin/false, /sbin/nologin) can't log in interactively 
#prevents SSH command execution if the user has SSH keys on the system
#users can't get a shell prompt to run commands
# users may be able to log in to do read/send email (via POP/IMAP & SMTP AUTH)
#/etc/security/access.conf
#service accounts often don't have a "proper" login shell, /usr/sbin/nologin as login shell (or  /bin/false)
#service accounts have user IDs in the low range, e.g. < 1000 or so. Except for UID 0
#service accounts are typically locked
#not possible to login (for traditional /etc/passwd and /etc/shadow)
#achieved by setting the password hash to arbitrary values such as * or x)

useradd testuser --shell=/sbin/nologin
usermod testuser -s /sbin/nologin 
usermod -s /sbin/nologin test4 #Disable User Account With nologin or false Shells
usermod testuser -s /bin/false #exit as soon as the user logs in, and return exit status 0 (false),do not receive any kind of message like they would with /sbin/nologin
adduser subversion --shell=/bin/false --no-create-home
# directed to the /sbin/nologin shell and receive the following message This account is currently not available.
usermod testuser -s /bin/bash #enable shell by setting a shell


#list non-interactive shell users, service accounts, aka technical accounts
$ awk -F: '{if( $7~"/sbin/nologin" || $7~"/bin/false") print "service account..:",$1,"shell..:" $7}' /etc/passwd

#The users that have nologin defined as their default shell often have higher privileges,unable to log in directly 
#limit the damage that a breach of system could suffer
/sbin/nologin #Limiting system's attack surface
/bin/false


set a account password expiry date i.e. 45 days on a user ‘tecmint’
# useradd -e 2014-04-27 -f 45 tecmint
insert that user’s full name, Manis Khurana
# useradd -c "Manis Khurana" mansi
add a user ‘tecmint‘ without login shell
# useradd -s /sbin/nologin tecmint
create a user ‘ravi‘ with home directory ‘/var/www/tecmint‘, default shell /bin/bash and adds extra information about user
# useradd -m -d /var/www/ravi -s /bin/bash -c "TecMint Owner" -U ravi
# useradd -m -d /var/www/tarunika -s /bin/zsh -c "TecMint Technical Writer" -u 1000 -g 1000 tarunika
disabling login shell to a user called ‘avishek‘
# useradd -m -d /var/www/avishek -s /usr/sbin/nologin -c "TecMint Sr. Technical Writer" -u 1019 avishek
useradd librenms -d /opt/librenms -M -r -s "$(which bash)"

tecmint:x:504:504:tecmint:/home/tecmint:/bin/bash
    Username: User login name used to login into system. It should be between 1 to 32 charcters long.
    Password: User password (or x character) stored in /etc/shadow file in encrypted format.
    User ID (UID): Every user must have a User ID (UID) User Identification Number. By default UID 0 is reserved for root user and UID’s ranging from 1-99 are reserved for other predefined accounts. Further UID’s ranging from 100-999 are reserved for system accounts and groups.
    Group ID (GID): The primary Group ID (GID) Group Identification Number stored in /etc/group file.
    User Info: This field is optional and allow you to define extra information about the user. For example, user full name. This field is filled by ‘finger’ command.
    Home Directory: The absolute location of user’s home directory.
    Shell: The absolute location of a user’s shell i.e. /bin/bash.

userdel member2 # deletes the account but leaves the user’s home directory intact
userdel -f member2 # the -f option forces account deletion and fle removal under some circumstances
userdel -r member2 # delete user account member2, the -r option to userdel causes it to delete the user’s home directory and mail spoo

#disable root user

sudo passwd -l root #lock the password for the root user
sudo usermod -L root #lock the password for the root user
sudo passwd -d root # remove the password of the account,can not unlock a locked account if it doesn't have any password

#Enable Root Login
sudo passwd root #set a new password for the account
sudo passwd -u root #unlock the root user,unlock the password
su root

usermod -L testuser # lock user account / disable user account
cat /etc/shadow | grep testuser # verify locked user account, exclamation mark "!"
sudo passwd -S testuser #verify locked user account
passwd --status testuser #verify locked user account
usermod -U member1 # unlock user account
passwd -u user1 #unlock the password

# configure user default shell
usermod -s /bin/bash member1
# add the user geek to the group sudo
usermod -a -G sudo geek 

useradd -ms /bin/bash newuser #creates a home directory for the user and ensures that bash is the default shell
useradd -rm -d /home/ubuntu -s /bin/bash -g root -G sudo -u 1001 ubuntu

------------------------------------------------------------------------------------------
#use useradd instead of its interactive wrapper adduser

# create new user, new group with the same name
sudo adduser sdn --system --group
make sure username is added to the group libvirtd
$ sudo adduser `id -un` libvirtd
$ sudo adduser  $(id -un) libvirtd


 ------------------------------------------------------------------------------------------
#edit the managers entry in /etc/group to make sally, tom, and dale  members of the group managers (GID 501),the
#order of users in the comma-separated user list is unimportant
managers:x:501:dale,sally,tom 

cat /etc/group
cat /etc/gshadow
cut -d: -f1 /etc/group | sort
$ groupadd admins #add new group
$ sudo groupdel sshusers
$ useradd -G admins member1
sudo usermod -aG docker ${USER} #Add current logged in user to the docker group.
sudo usermod -aG docker $(whoami) #Add current logged in user to the docker group.
gpasswd -a devops1 sudo #Adding user devops1 to group sudo
gpasswd -d devops1 sudo #Removing user devops1 from group sudo

#list groups on Linux,/etc/group file
$ getent group 
$ getent group sudo # sudo group has ID of 27 and has ubuntu,barak,packer as members
sudo:x:27:ubuntu,barak,packer
$ cat /etc/group | awk -F: '{print $1}'
$ cat /etc/group | cut -d: -f1


$ groups # list the groups for the current logged user
$ groups barak #get a list of groups a specific user is in

whoami
grep "^$(whoami):" /etc/subuid 
grep "^$(whoami):" /etc/subgid
id -u print only the effective user ID
id -Gn
id vagrant

# The newgrp command allows a user to override the current primary group.
# newgrp can be handy when you are working in a directory where all files must have the same group ownership
newgrp microk8s #When you run the command, the system places you in a new shell and changes the name of your real group to the group specified with the Group parameter
#If you’re listed as member of the group and the group has a password assigned, then you won’t be prompted
#If there is no group password set, and the user is not listed as a member of the group, the user will be denied access
#you are not a member of the developers group and not a root, then you’ll be prompted for a group password if your account doesn’t have a password assigned
#If you’re root, then no prompted is presented.	
newgrp developers 
newgrp - developers #log in to the group developers
sudo groupadd developers #create group developers
sudo usermod -a -G developers richard
sudo gpasswd developers

#system account vs user account
#System users will be created with no aging information in /etc/shadow
#numeric identifiers are chosen in the SYS_UID_MIN–SYS_UID_MAX range defined in /etc/login.defs
useradd --system appuser
chage -l appuser
useradd --system --shell=/usr/sbin/nologin <username> #create a system user (without home directory and login shell)
useradd -r subversion #-r, --system  create a system account
adduser -r -s /bin/nologin subversion #create system account -s /sbin/nologin to disable any login shell
adduser --system --no-create-home --group yourusername
adduser subversion --system --group
adduser -r -s /bin/nologin subversion

$ sudo groupadd --system --gid 1002 appuser
$ cat /etc/group | grep appuser
appuser:x:1002:
$  sudo useradd --no-log-init --system --uid 1001 --gid 1002 appuser
$ cat /etc/passwd | grep appuser
appuser:x:1001:1002::/home/appuser:/bin/sh

# list a group's members
$ sudo lid -g sales
$ cut -d: -f1,4 /etc/passwd | grep $(getent group sales | cut -d: -f3) | cut -d: -f1
id username
grep "docker" /etc/group
grep -i --color 'root' /etc/group
getent group -> List all groups
cat /etc/group -> List all groups
getent group vboxusers
groups -> View the Groups a User Account
groupmod -g 3000 foo -> assign a new GID to group called foo
------------------------------------------------------------------------------------------
The command you've provided is a Linux shell command that utilizes the cp command to copy files and directories. Let's break down the components of the command:

    cp: This is the command itself, which stands for "copy." It's used to copy files or directories from one location to another.

    -vrbi: These are options or flags that modify how the cp command behaves:

        -v: Stands for "verbose." When this option is used, the cp command will provide more detailed output, showing the names of files as they are copied.

        -r: Stands for "recursive." This option is used when copying directories. It tells the cp command to copy not only the specified directory but also its contents and subdirectories.

        -b: Stands for "backup." With this option, the cp command will create backup copies of files that already exist in the destination directory before overwriting them.

        -i: Stands for "interactive." When this option is used, the cp command will prompt you for confirmation before overwriting files in the destination directory. This is a safety measure to prevent accidental data loss.

    /etc/skel/.: This is the source directory or file. In this case, it's the .skel directory located in the /etc directory. The /etc/skel directory is often used as a template for creating user home directories.

    ~/: This is the destination directory. The tilde (~) is a shorthand notation for the user's home directory. So, this part of the command specifies that the copied content should be placed in the user's home directory.

The purpose of this command is to copy the contents of the /etc/skel directory (which often contains default settings and configurations for new user accounts) into the user's home directory. It uses various options like -v, -r, -b, and -i to control the copying process and handle situations where files already exist in the destination directory.

To automatically answer "yes" to the interactive prompts and proceed with copying without manual confirmation, you can use the yes command in combination with the cp command. The yes command repeatedly outputs the letter "y" (or any other specified character) in response to prompts. Here's an example of how you could use it:

sh

yes | cp -vrbi /etc/skel/. ~/

In this example, the yes command keeps providing "y" responses to the interactive prompts, effectively saying "yes" to each one. This allows the cp command to copy files without requiring manual confirmation.
------------------------------------------------------------------------------------------
 #Files in /etc/skel are copied from this directory to new users’ home directories by certain account-creation tools
 #The files should be in all new users’ home directories should reside in /etc/skel.
 “skeleton” directory is defined in /etc/default/useradd file.
 # ls -lart /etc/skel
 # ls -ldi /etc/skel
33554552 drwxr-xr-x. 2 root root 62 Mar 24  2018 /etc/skel
 ------------------------------------------------------------------------------------------
valid login shells
# cat /etc/shells #list all available shells
# chsh -l

chsh -s /bin/ksh #Regular user can change their shell to the ksh

$ ps -p $$
    PID TTY          TIME CMD
  56017 pts/0    00:00:00 bash
  
grep tecmint /etc/passwd #view default login shell
usermod --shell /bin/bash tecmint #change its login shell from /bin/sh to /bin/bash
grep tecmint /etc/passwd #verify /bin/bash


grep tecmint /etc/passwd #view default login shell
chsh --shell /bin/bash tecmint #change its login shell from /bin/sh to /bin/bash
grep tecmint /etc/passwd #verify /bin/bash

$ sudo chsh -s /bin/ksh UserName #The superuser (root) changes the login shell for any account
chsh -s /bin/ksh vagrant #set default login shell to /bin/ksh for vagrant user

#open the /etc/passwd file, change manually
vi /etc/passwd

chsh vagrant -s /bin/rbash #change user vagrant's shell
su - vagrant #login to activate shell

whereis ksh
grep --color ksh /etc/shells
cat /etc/shells
echo $SHELL

~ [23]$ ps -p $$
    PID TTY          TIME CMD
 193052 pts/1    00:00:00 ksh
 
~ [27]$ ps -hp $$ | awk '{print $5}'
-ksh

~ [28]$ echo $0
-ksh

~ [29]$ printf "%s\n" $0
-ksh

~ [30]$ readlink /proc/$$/exe
/usr/bin/ksh93

awk -F: '/vagrant/ { print $7}' /etc/passwd #list user's shell type
sudo ps -ef | egrep 'tty|pts' #Listing all shell types used by users
$ w -h | awk '{print $2}' | xargs -L1 pgrep -oat

verify user vagrant's bash
# cat /etc/passwd | grep vagrant
# echo $SHELL
 Reading Library editor
 $ cat /etc/inputrc
 keyboard bindings
 $ bind -v
 ------------------------------------------------------------------------------------------
  semicolon ";" multiple commands on the same line
  backaslash "\" run commands longer than one line
  press tab key or twice ESC key, command completion
  "./" run a command from pwd
 ------------------------------------------------------------------------------------------
 history file size setting
 $ cat /etc/profile
 $ echo $HISTSIZE
 $ echo $HISTFILE
 $ fc -l

 #Linux Command History with date and time, temporary
HISTTIMEFORMAT="%d/%m/%y %H:%M "
HISTTIMEFORMAT="%d/%m/%y %T "

export HISTSIZE=0 #Disable the usage of history using HISTSIZE
echo $HISTSIZE
echo $HISTFILE
export HISTCONTROL=ignoredups #Eliminate the continuous repeated entry from history using HISTCONTROL
export HISTIGNORE="pwd:ls:ls -ltr:" #Ignore specific commands from the history using HISTIGNORE
export HISTCONTROL=erasedups #Erase duplicates across the whole history using HISTCONTROL
export HISTCONTROL=ignorespace #Force history not to remember a particular command using HISTCONTROL
#  service httpd stop [Note that there is a space at the beginning of service,to ignore this command from history]

history -c #Clear all the previous history

# !ps #Execute previous command that starts with a specific word
# !4 #Execute a specific command from history
# !-1 #execute the second last command
# !! #run the last executed command, or press CTRL+P
# !dconf #re-run the last command with the keyword ‘dconf’ in it

#lastb #shows users that failed to login,review the /var/log/btmp file (containing failed login attempts)

#the login history of users
last logins
last -R #review the contents of the /var/log/wtmp binary file
last | grep sysadmin
last -f /var/log/btmp #Use the last command to view the btmp file
last mark #pass the user name 
last pts/0 #pass the tty
last mark root pts/0 #specify multiple usernames and ttys
last -p 2020-01-15 #find out who logged into the system on a specific date
last -s 2020-02-13 -u 2020-02-18 #the -s (--since) and -t (--until) option to tell last to display the lines since or until the specified time
last -F #y default, last doesn’t show the seconds and the year. Use the -F, --fulltimes option
last -25 #last 25 logins
last -i #IP address
last -d #DNS address
#the system last rebooted
last reboot
  ------------------------------------------------------------------------------------------
  echo $PATH
  view all the env variables
  $ export -p
  $ set
  Set an Environment Variable
  $ export MYAPP=1
  holds the list of all directories that are searched by the shell when you type a command name
  $PATH
   
  system-wide
  $ cat /etc/profile
  single user
  $ cat .bash_profile
  # add PATH
vi .bash_profile
export PATH=$PATH:$HOME/Downloads/terraform
system-wide prompt setting
$ cat /etc/bashrc
$ echo $PS1
------------------------------------------------------------------------------------------
Display current libraries from the cache
# ldconfig -p | head -5
Display libraries from every directory
ldconfig -v | head
# cat /etc/ld.so.conf
------------------------------------------------------------------------------------------
# number the lines in a file
nl alphaservices | tee alphabetservices

$ cat file1
1. Asia:
2. Africa:
3. Europe:
4. North America:
Display the contents of file.txt in octal format (one byte per integer)
$ od -b file1
0000000 061 056 040 101 163 151 141 072 012 062 056 040 101 146 162 151
0000020 143 141 072 012 063 056 040 105 165 162 157 160 145 072 012 064
0000040 056 040 116 157 162 164 150 040 101 155 145 162 151 143 141 072
0000060 012
0000061
Display the contents of file.txt in ASCII (character) format, with byte offsets displayed as hexadecimal.
$ od -Ax -c file1
000000   1   .       A   s   i   a   :  \n   2   .       A   f   r   i
000010   c   a   :  \n   3   .       E   u   r   o   p   e   :  \n   4
000020   .       N   o   r   t   h       A   m   e   r   i   c   a   :
000030  \n
000031
------------------------------------------------------------------------------------------
echo -n "hola" | od -A n -t x1  | sed 's/ *//g'  | tr -d '\n' >> engineID_hex.txt #strips spaces  remove newlines
------------------------------------------------------------------------------------------
# merge all files in the directory and split 
ls | xargs cat | tee file1 | split -5
# printing
pr -h "title" file1
list mounted file systems
$ cat /etc/mtab

split -l 4 index.txt split_file #Split file based on number of lines
split index.txt -l 4 --verbose
split -l 4 -a 4 index.txt #Change in suffix length. By default, the suffix length is 2
split -l 4 -d index.txt #change the split files suffix to numeric
split -l 4 index.txt split_index_ # create split output files with index suffix,
split -l 4 -e index.txt #Avoid zero-sized split files
split -n 3 index.txt #Create n chunks output files
split -n 2 index.txt #Split the file into two files of equal length
#split the file index.txt into separate files called indexaa, indexab, …..with each file containing 16 bytes of data
split -b 16 index.txt index 
split -b=1M -d  file.txt file --additional-suffix=.txt
split -b 10M -d  system.log system_split.log


~$ cat test.txt | wc -l
40
~$ split --numeric-suffixes=2 --additional-suffix=.txt -l 22 test.txt file
$ ls -lai file*
 2139 -rw-rw-r-- 1 vagrant vagrant 660 Mar 21 11:01 file02.txt
 5482 -rw-rw-r-- 1 vagrant vagrant 660 Mar 21 11:01 file03.txt
 5483 -rw-rw-r-- 1 vagrant vagrant 660 Mar 21 11:01 file04.txt
18296 -rw-rw-r-- 1 vagrant vagrant 220 Mar 21 11:01 file05.txt
$ cat file04.txt | wc -l
12
$ cat file05.txt | wc -l
4
-----------------------------------------------------------------------------------------------------
u stands for user.
g stands for group.
o stands for others.
a stands for all.

same output:
chmod -R 755 /var/www/html #change the permissions of all files and subdirectories under the /var/www/html directory to 755
chmod +x somefile				(Based on umask value)
chmod a+x somefile, chmod ugo+x somefile 	(Without considering umask value), add the execute permission for everyone

chmod 644 a.txt
stat -c %a a.txt # verify permission granted is 644
------------------------------------------------------------------------------------------
Applying SUID Permission Numerically
# chmod 4755 /bin/ping
Removing SUID by Numerically
chmod 0755 /bin/ping
Applying SUID Permission to ping binary file Alphabetically
# chmod u+s /bin/ping
Removing SUID Permission
chmod u-s /bin/ping
------------------------------------------------------------------------------------------
# Applying SGID Permission
chmod g+s /database/
chmod 2775 database/
# Remove SGID Alphabetically
chmod g-s /database/
chmod 0775 /database
------------------------------------------------------------------------------------------
a sticky bit is now in place and only root, file or directory owners can rename and delete files
# chmod +t /var/share/
# ls -ld /var/share/
drwxrwxrwt. 2 root root 4096 Mar  5 11:21 /var/share/

chmod 0777 somefile (octal) 
chmod 777 somefile (decimal)

chmod 0710 mydir ; ls -ld mydir
chmod 00710 mydir ; ls -ld mydir
------------------------------------------------------------------------------------------
# quota settings
sudo apt update ; sudo apt install quota -y
quota --version
find /lib/modules/`uname -r` -type f -name '*quota_v*.ko*'
sudo mount -o remount /
cat /proc/mounts | grep ' /
sudo quotacheck -ugm /
sudo quotaon -v /
sudo setquota -u member1 200M 240M 0 0 /
sudo quota -vs member1
sudo setquota -t 864000 864000 /
sudo repquota -s /
------------------------------------------------------------------------------------------
# ldd (Unix) ldd (List Dynamic Dependencies)
ldd /bin/ls
# display unused direct dependencies
ldd -u /bin/ping
# more information
ldd -v /bin/ping
------------------------------------------------------------------------------------------
# rename root
$ head -2 /etc/passwd
root:x:0:0:root:/root:/bin/nologin
rootmon:x:0:0:root:/root:/bin/bash
$ sudo passwd rootmon
$ su - rootmon
# pwd
/root

#gain a root shell is by adding a new user to /etc/passwd who has the UID 0
#any user with UID 0 is effectively root
#root2 is the username
#WVLY0mgH0RtUI is the encrypted password we want him to have. Unencrypted, the password is mrcake, in this case
#0:0 means the user id and group id are both 0
#root is a comment field
#/root is the home directory
#/bin/bash is the default shell
root2:WVLY0mgH0RtUI:0:0:root:/root:/bin/bash

#Administrative databases in Unix,getent – get entries from administrative database
    passwd – can be used to confirm usernames, userids, home directories and full names of your users
    group – all the information about Unix groups known to your system
    services – all the Unix services configured on your system
    networks – networking information – what networks your system belongs to
    protocols – everything your system knows about network protocols

$ getent hosts # /etc/hosts file
$ getent hosts vg-ubuntu-01 double-check which IPs this hostname points to
$ getent networks #check the network and IP address of your system
$ getent services 20 #Use “services” with the port number to find the service name and its protocol

#List Users(system and normal users) on Linux using the /etc/passwd File, normal user has a real login shell and a home directory.
awk -F: '{ print $1}' /etc/passwd
cat /etc/passwd | awk -F: '{print $1}'
awk -F: '{ print $1}' /etc/passwd | wc -l # get the # of users
cut -d: -f1 /etc/passwd
cat /etc/passwd | cut -d: -f1
getent passwd # list users
getent passwd | awk -F ":" '{print $1}'
getent passwd | cut -d: -f1
getent passwd # equivalent to cat /etc/passwd
getent passwd rahul #details for a particular user
getent passwd 0 #find a username by UID

$ cut -d":" -f1 /etc/passwd #list all users

#list normal user names
awk -F: '{if($3 >= 1000 && $3 < 2**16-2) print $1}' /etc/passwd
awk -F: '{if(($3 >= 500)&&($3 <65534)) print $1}' /etc/passwd
awk -F: '{if(!(( $2 == "!!")||($2 == "*"))) print $1}' /etc/shadow 
grep -E ":[0-9]{4,6}:[0-9]{4,6}:" /etc/passwd | cut -d: -f1
$ getent passwd | awk 'NR==FNR { if ($1 ~ /^UID_(MIN|MAX)$/) m[$1] = $2; next }
{ split ($0, a, /:/);
  if (a[3] >= m["UID_MIN"] && a[3] <= m["UID_MAX"] && a[7] !~ /(false|nologin)$/)
    print a[1] }' /etc/login.defs -
$ getent passwd | \
nologin|false)> grep -vE '(nologin|false)$' | \
: -v mi> awk -F: -v min=`awk '/^UID_MIN/ {print $2}' /etc/login.defs` \
X/ {p> -v max=`awk '/^UID_MAX/ {print $2}' /etc/login.defs` \
$3 >= > '{if(($3 >= min)&&($3 <= max)) print $1}' | \
t -u> sort -u

grep -E '^UID_MIN|^UID_MAX' /etc/login.defs #Each user has a numeric user ID called UID. If not specified automatically selected from the /etc/login.defs
getent passwd {1000..60000} #list all normal users depending on UID_MIN/UID_MAX in /etc/login.defs
eval getent passwd {$(awk '/^UID_MIN/ {print $2}' /etc/login.defs)..$(awk '/^UID_MAX/ {print $2}' /etc/login.defs)} | cut -d: -f1
# generic,UID_MIN and UID_MIN values may be different, 
eval getent passwd {$(awk '/^UID_MIN/ {print $2}' /etc/login.defs)..$(awk '/^UID_MAX/ {print $2}' /etc/login.defs)}


awk -F ":" '{print $5}' /etc/passwd #print the fifth field
getent passwd $UID| awk -F ":" '{print $5}'
GECOS fields (which stands for "General Electric Comprehensive Operating System")
username:password:userid:groupid:gecos:home-dir:shell
GECOS are divided as:
:FullName,RoomAddress,WorkPhone,HomePhone,Others:

sally:x:0:529:Sally Jones:/home/myhome:/bin/passwd #might be used on, a Samba fle server or a POP mail server to enable users to change their passwords via SSH without granting login shell access.
------------------------------------------------------------------------------------------
# enable the root account
sudo passwd root
------------------------------------------------------------------------------------------
# send an email from command line
mail -s “Hello world” you@youremailid.com
echo “This will go into the body of the mail.” | mail -s “Hello world” you@youremailid.com
df -h | mail -s “disk space report” calvin@cnh.com
------------------------------------------------------------------------------------------
# check a file system for errors?
fsck
fsck.ext3
fsck.nfs
fsck.ext2
fsck.vfat
fsck.reiserfs
fsck.msdos

In order to run fsck on the root partition, the root partition must be mounted as readonly
------------------------------------------------------------------------------------------
# list of drives that are mounted at boot
/etc/fstab
# runs as a daemon and typically has PID 1
# change the default runlevel upon boot up.
/etc/inittab
chkconfig --list #list of all runlevels and services used by them
chkconfig vnicen.sh off #Ensure that the vnicen does not start upon reboot
chkconfig --list | grep vnicen
chkconfig --level 2345 sshd on #enable sshd startup
syslogd # daemon is responsible for tracking events on the system
# set which window man-ager you want to use when logging in to X from that account
# edit in your home directory to change which window manager you want to use
~/.xinitrc 
------------------------------------------------------------------------------------------
find the number of processing units (CPU) available on a system
nproc
nproc --all
echo "Threads/core: $(nproc --all)"

lscpu #the number of physical CPU cores
lscpu | egrep 'Model name|Socket|Thread|NUMA|CPU\(s\)'
lscpu -p

grep 'model name' /proc/cpuinfo | wc -l
grep 'cpu cores' /proc/cpuinfo | uniq
echo "CPU threads: $(grep -c processor /proc/cpuinfo)"
cat /proc/cpuinfo
grep -c ^processor /proc/cpuinfo 
cat /proc/cpuinfo | grep 'core id' #get the actual number of cores
getconf _NPROCESSORS_ONLN && echo "Number of CPU/cores online at $HOSTNAME: $(getconf _NPROCESSORS_ONLN)"
------------------------------------------------------------------------------------------
$ seq -s";" -w 1 12
01;02;03;04;05;06;07;08;09;10;11;12

# write dummy lines into a file
$ seq -s ' ' 23 > file && cat file
# read dummy lines from a file
$ awk '(NR % 6 == 1) {print; for(i=1; i<6 && getline ; i++) { print }; printf "\n"}' RS=' ' ORS=' ' file
1 2 3 4 5 6 
7 8 9 10 11 12 
13 14 15 16 17 18 
19 20 21 22 23

# Create a dummy file
echo -e "1\n2\n3\n4" > testfile.txt

$ echo "3997e1" > ids.txt #write
$ echo "45697676107" >> ids.txt #append
------------------------------------------------------------------------------------------
protection from inadvertently overwriting files when copying
~/.bashrc
alias cp='cp -i'
------------------------------------------------------------------------------------------
# list tree structure of files and folders

$ ls -R
.:
create_folders_files.sh  folder_1  folder_2  folder_3

./folder_1:
file_1.txt  file_2.txt  file_3.txt  file_4.txt

./folder_2:
file_1.txt  file_2.txt  file_3.txt  file_4.txt

./folder_3:
file_1.txt  file_2.txt  file_3.txt  file_4.txt


$ find .
.
./folder_2
./folder_2/file_1.txt
./folder_2/file_2.txt
./folder_2/file_3.txt
./folder_2/file_4.txt
./create_folders_files.sh
./folder_1
./folder_1/file_1.txt
./folder_1/file_2.txt
./folder_1/file_3.txt
./folder_1/file_4.txt
./folder_3
./folder_3/file_1.txt
./folder_3/file_2.txt
./folder_3/file_3.txt
./folder_3/file_4.txt


$ sudo tree -d /var/log/ --du -sch
/var/log/
├── [4.0K]  dist-upgrade
├── [4.0K]  fsck
├── [4.0K]  lxd
├── [4.0K]  apt
└── [4.0K]  unattended-upgrades
$ sudo tree /var/log/ --du -h

$ sudo tree -a  /var/log #display hidden files
$ tree -daC
$ tree -f #view the full path for each directory and file
$ sudo tree -f -L 3
$ sudo tree -f -P cata* #only list files that match cata*, so files such as Catalina.sh, catalina.bat, etc
$ tree -P "*.log"
$ sudo tree -f -I *log /var/log #-I option,display all the files that do not match the specified pattern
$ sudo tree -d -I *log /var/log 
$ tree -I "*.log"
$ sudo tree -f --prune #prune empty directories from the output 
$ sudo tree -f -p #-p which prints the file type and permissions for each file
$ sudo tree -f -pug #print the username,the group name
$ sudo tree -f -pugs #print the size of each file in bytes along with the name using the -s option
$ sudo tree -f -pugh #human-readable format, use the -h flag
$ sudo tree -f -pug -h -D  #display the date of the last modification time for each sub-directory or file
$ tree -d -L 3 # the depth of directory tree in output
tree -vr #sort the files from Z-A
$ tree -L 2
tree -J #the output is in JSON format
$ sudo tree -o direc_tree.txt
------------------------------------------------------------------------------------------
ipcs (InterProcess Communication System) provides a report on the semaphore, shared memory & message queue
ipcs -u
ipcs -m
------------------------------------------------------------------------------------------
nslookup github.com
nslookup 140.82.118.4
nslookup -query=mx github.com
nslookup -query=ns github.com
nslookup -query=any github.com
nslookup -query=soa github.com
nslookup -query=soa port=54 github.com
nslookup -debug github.com
------------------------------------------------------------------------------------------
The command shell interprets the && as the logical AND.the second command will be executed only when the first one has been succcefully executed
A double ampersand && in Bash means AND and can be used to separate a list of commands to be run sequentially.
Commands separated by a double ampersand && are to be run synchronously, with each one running only if the last did not fail (a fail is interpreted as returning a non-zero return status).

&& AND – execute both, return true of both succeed
; sequential execution, return status is that of the last in the list 

$ mkdir /workspace ; mkdir /entrypoint
mkdir: cannot create directory ‘/workspace’: Permission denied
mkdir: cannot create directory ‘/entrypoint’: Permission denied
$ mkdir /workspace && mkdir /entrypoint
mkdir: cannot create directory ‘/workspace’: Permission denied
------------------------------------------------------------------------------------------
mkdir -p first/second/third #If the first and second directories do not exist, mkdir creates these directories
mkdir -m a=rwx first/second/third #set the file modes, i.e. permissions, etc
------------------------------------------------------------------------------------------
disable and stop service
$ sudo systemctl disable --now zabbix-server.service
enable and start service
$ sudo systemctl enable --now zabbix-server.service # enable and start the service

chkconfig tgtd on #configure it to start Automatically while system start-up
chkconfig --list tgtd #verify that the run level configured correctly for the tgtd service
chkconfig --list #shows SysV services only and does not include native systemd services.
chkconfig | grep snmpd
systemctl list-units --all
systemctl list-unit-files
systemctl list-units --all --state=inactive
systemctl list-units --type=service #only active service units

systemctl cat sshd.service #Displaying a Unit File
sudo systemctl edit nginx.service
sudo systemctl edit --full nginx.service
sudo systemctl daemon-reload

systemctl list-unit-files --type=target
systemctl list-units --type=target

systemctl list-dependencies sshd.service #Displaying Dependencies
systemctl show sshd.service #Checking Unit Properties
systemctl show sshd.service -p Conflicts #display a single property,pass the -p flag with the property name
sudo systemctl mask nginx.service #the ability to mark a unit as completely unstartable, automatically or manually, by linking it to /dev/null. This is called masking the unit

------------------------------------------------------------------------------------------
ls -laZ ~/.ssh
# change the security context to system_u:object_r:usr_t:s0
chcon -R -v system_u:object_r:usr_t:s0 ~/.ssh/
------------------------------------------------------------------------------------------
problem: 
never edit directly '/etc/sudoers' file
$ sudo visudo
>>> /etc/sudoers: syntax error near line 28 <<<
sudo: parse error in /etc/sudoers near line 28
sudo: no valid sudoers sources found, quitting

fix:
pkexec visudo
#includedir /etc/sudoers -> #includedir /etc/sudoers.d #change last line

sudo mount /dev/sda1 /mnt #mount the installed Ubuntu system's root filesystem
sudo visudo -f /mnt/etc/sudoers #edit the installed system's sudoers file
pkexec visudo -f /etc/sudoers.d/filename #edit configuration files
------------------------------------------------------------------------------------------
problem: sleep: invalid time interval `2\r'
fix: sudo cat test.sh | sudo tr -d '\r' | sudo tee test2.sh
------------------------------------------------------------------------------------------
$ diff 1.txt 2.txt # display the differences in the files by comparing the files line by line
$ diff -c 1.txt 2.txt
$ diff 1.txt 2.txt -u
$ diff 1.txt 2.txt -i
$ diff 1.txt 2.txt --color
$ diff 1.txt 2.txt -s
$diff -i test_file_1.txt test_file_2.txt #ignoring the case sensitivity
$diff -y -W 60 test_file_1.txt test_file_2.txt #view the difference,The “-W” indicates the width between the content of two files
$diff -q test_file_1.txt test_file_2.txt #“-q” option with the “diff” command gives you output in one line
$diff -u test_file_1.txt test_file_2.txt #

#write the difference between two files into a file
diff a.txt b.txt|grep ">"|cut -c 3- > foo.txt

#-q, --brief report only when files differ
#-s, --report-identical-files report when two files are the same
diff -sq /tmp/file1 /tmp/file2

diff chap1.back chap1 #compare two files
#If two lines differ only in the number of spaces and tabs between words, the diff -w command considers them to be the same.
#compare two files compare two files while ignoring differences in the amount of white space
diff  -w prog.c.bak prog.c 
#create a file containing commands that the ed command can use to reconstruct one file from another
#creates a file named new.to.old.ed that contains the ed subcommands to change chap2 
#back into the version of the text found in chap2.old
diff  -e chap2 chap2.old >new.to.old.ed 
# in parentheses add 1,$p to the end of the editing commands sent to the ed editor. 
#The 1,$p causes the ed command to write the file to standard output after editing it
#then piped to the ed command (| ed), and the editor reads it as standard input
#The - flag causes the ed command not to display the file size and other extra information 
#because it would be mixed with the text of chap2.old.
(cat new.to.old.ed ; echo '1,$p') | ed - chap2 >chap2.old
#compare two text files containing UTF-8 characters and show the differences
diff -W filecodeset=UTF-8,pgmcodeset=IBM-1047 myUtf8File01 myUtf8File02
#compare two text files containing EBCDIC characters and show the differences
diff -B myMisTaggedFile01 myMisTaggedFile02
------------------------------------------------------------------------------------------
Local to Remote: rsync [OPTION]... -e ssh [SRC]... [USER@]HOST:DEST
Remote to Local: rsync [OPTION]... -e ssh [USER@]HOST:SRC... [DEST]

-v, –verbose – Using this option in the rsync command gives the status about transferred files.
-vv – Usually, this option is used to get information about the skipped files during file transfer.
-q, –quiet – This option simply suppress non-error messages.

rsync -av --rsync-path="rsync --log-file=/tmp/rlog" source/ destination/ #enable error log for rsync
#rsync exits with a non-zero code when the transfer fails,write details to log files.
rsync -avz -e ssh root@example.com:/ /mybackup/ > /var/log/rsync.log 2>&1

Problem:
rsync: failed to set times on "some_dir: Operation not permitted (1)
mkstemp "some_file" failed: Permission denied (13)
Fix:
if the user is 'abc' then 
the destination directory should be 
lrwxrwxrwx 1 abc abc 34 Jul 18 14:05 Destination_directory
chown -R abc:abc Destination_directory

rsync -aEim --delete /path/to/remote/ /path/to/local/ # rsync output to stdout with the -i flag

#Only files that rsync has fully successfully transferred are removed.
rsync -r -z -c --remove-source-files  /home/pi/queue root@server.mine.com:/home/foobar 

rsync -avz source destination #preserve permissions, ownership, and timestamp

#When the trailing slash  "/" is omitted the source directory will be copied inside the destination directory
#transfer the local directory to the directory on a remote machine
$ rsync -avz -e "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null" --progress /home/filerunner/dir1 vg-ubuntu-02:/tmp
$ ls /tmp/dir1
a.txt

#When the source directory has a trailing slash  "/", rsync will copy only the contents of the source directory to the destination directory
$ rsync -avz -e "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null" --progress /home/filerunner/dir1/ vg-ubuntu-02:/tmp
$ ls /tmp
a.txt

#dry run mode,
rsync -azhv -e "ssh -p 2212" --dry-run /home/bob/test_219 

#find out if the files are in sync, without actually doing a sync dry run mode
#-c, --checksum - skip based on checksum, not mod-time & size
#-r, --recursive - recurse into directories
#-n, --dry-run - perform a trial run with no changes made
#does not show anything if server2 has more files then server1
rsync -n -avrc /abc/home/sample1/* server2:/abc/home/sample2/
#dry-run mode verify
rsync -avzrch --progress --exclude=lost+found/ -e "ssh -i /home/vagrant/privatekey" --delete user@server:/mnt/files/ /mnt/disk1/ > /tmp/rsync_out 2>&1


#find out if the files are in sync, without actually doing a sync dry run mode
#--delete is needed to show if a file exists on server 2 but not server 1
rsync -n -avr --size-only --delete /abc/home/sample1/ server2:/abc/home/sample2/

#find out if the files are in sync, without actually doing a sync dry run mode
#Without --dry-run, it will automatically copy files of different sizes 
#if the sizes are identical, checksum them and copy if different
#The delete option will remove files from the target if not present on the source
rsync -cr --delete --dry-run source/ target/ > output_file 2>&1 &
#--size-only             skip files that match in size, no checksum
rsync -n -avr --size-only --delete /abc/home/sample1/ server2:/abc/home/sample2/

rsync -a -e "ssh -p 3322" /home/linuxize/images/ user@12.12.12.12:/var/www/images/ #if SSH is listening on port 3322

#transfer a single file /opt/file.zip from the local system to the /var/www/ directory on the remote system with IP 12.12.12.12
#If the file exists on the remote server it is overwritten
rsync -a /opt/file.zip user@12.12.12.12:/var/www/ 
#save the file under a different name
rsync -a /opt/file.zip user@12.12.12.12:/var/www/file2.zip

#transfer data from a remote to a local machine
rsync -a user@12.12.12.12:/var/www/file.zip /opt/

#synchronize the local and remote directory
rsync -a /home/linuxize/images/ user@12.12.12.12:/var/www/images/

#use the --delete option if you want to synchronize the local and remote directory
#delete files in the destination directory if they don’t exist in the source directory.
rsync -a --delete /home/linuxize/images/ user@12.12.12.12:/var/www/images/


#the “-r” option for “recursive” and the “-a” option for “all” (otherwise non-regular files will be skipped) 
#copy the “/etc” folder to the “/etc_backup” of the remote server
#with the “devconnected” username to server 192.168.178.35/24
rsync -ar /etc devconnected@192.168.178.35:/etc_backup

#Similarly,copy the content of the “/etc/ directory rather than the directory itself
rsync -ar /etc/* devconnected@192.168.178.35:/etc_backup/ 

# taggged with the current date
rsync -ar /etc/* devconnected@192.168.178.35:/etc_backup/etc_$(date "+%F")

#from local to remote server with private key
rsync -auvz -e "ssh -i private-key-file" source destination #Using rsync With SSH and Private Key 
rsync -auvz -e "ssh -i /home/yourUserName/.ssh/yourUserName-rsync-key" junk.txt yourUserName@calypso.nrel.colostate.edu
rsync -avzhe ssh backup.tar.gz root@192.168.0.141:/backups/
rsync -avzhe ssh --progress /root/rpmpkgs root@192.168.0.141:/root/rpmpkgs
 
#from remote to local server
rsync -avzh root@192.168.0.141:/root/rpmpkgs /tmp/myrpms
rsync -avze ssh --include 'R*' --exclude '*' root@192.168.0.141:/var/lib/rpm/ /root/rpm
#exclude lost+found dir
rsync --archive --no-compress --delete-before --info=progress2 --human-readable --exclude=lost+found/ /mnt/backup/ /mnt/backup-2/

#run rsycn on the background
rsync -avze ssh --include 'R*' --exclude '*' root@192.168.0.141:/var/lib/rpm/ /root/rpm > rsync.out 2>&1 &
tail -f rsync.out
------------------------------------------------------------------------------------------
#copy the “/etc” directory to a backup server located at 192.168.178.35 in the “/etc_backup” folder
scp -r /etc devconnected@192.168.178.35:/etc_backup/
# taggged with the current date
scp -r /etc devconnected@192.168.178.35:/etc_backup/etc_$(date "+%F")

   scp your_username@remotehost.edu:foobar.txt /some/local/directory-> Copy the file "foobar.txt" from a remote host to the local host
   scp file.txt remote_username@10.10.0.2:/remote/directory/newfilename.txt # save the file under a different name,Omitting the filename from the destination location copies the file with the original name.
   scp foobar.txt your_username@remotehost.edu:/some/remote/directory -> Copy the file "foobar.txt" from the local host to a remote host
   scp your_username@rh1.edu:/some/remote/directory/foobar.txt your_username@rh2.edu:/some/remote/directory/ ->Copy the file "foobar.txt" from remote host "rh1.edu" to remote host "rh2.edu"
   scp -P 2322 file.txt remote_username@10.10.0.2:/remote/directory #the remote host is listening on a port other than the default 22 
   scp -r /local/directory remote_username@10.10.0.2:/remote/directory #copy a directory from a local to remote system,use the -r flag for recursive
   
   # don’t have to log in to one of the servers to transfer files from one to another remote machine.
   #copy the file /files/file.txt from the remote host host1.com to the directory /files on the remote host host2.com
   scp user1@host1.com:/files/file.txt user2@host2.com:/files
   scp -3 user1@host1.com:/files/file.txt user2@host2.com:/files #route the traffic through the local host (machine on which the command is issued), use the -3 option
------------------------------------------------------------------------------------------
#cp interpret main as a directory to place scala,doesn't exist, cp will throw an error.
cp -av  /home/jake/transit/scalaProjects/scalaML/src/main/scala -t /home/jake/project/__workspace/scalaProjects/scalaML/src/main/

#Copy Directory Content Recursively	
cp -R bashdir bashdir-bck
cp -R /etc/* /etc_backup
cp -R /etc/* /home/* /backup_folder # copy the “/etc” directory and “/home” directory.

#copies the folder Misc and all its contents (the -r, or "recursive," option indicates the contents as well as the folder or file itself) into the folder /media/clh/4388-D5FE
cp -r Misc /media/clh/4388-D5FE #
#copy over only the new files,use the "update" and "verbose" options
cp -ruv Misc /media/clh/4388-D5FE
# a file called test1.py, which is the original, and another called test1.py.~1~, which is the backup file.
cp --force --backup=numbered test1.py test1.py 

cp /home/usr/dir/{file1,file2,file3,file4} /home/usr/destination/ #copy multiple files 
cp -rp /copying/from/{folder1/,folder2/,folder3/} path/to/folder #p is for copying the folder permission
cp /home/usr/dir/file{1..4} /tmp #if the all the files have the same prefix but different endings

------------------------------------------------------------------------------------------
#brace expansions

$ sudo cp ~/a.txt{,.orig} #backup of file in the current directory, copy shortcut
$ ls
a.txt  a.txt.orig

$ echo g{et,ot,it}em
getem gotem gitem
$ echo {00..8..2} #loop with increase 2
00 02 04 06 08
$ echo {D..T..4} #loop with increase 4
D H L P T

$ mv error.log{,.OLD} #expands to "mv error.log error.log.OLD")
------------------------------------------------------------------------------------------
#rename multiple files to change the extensions
$ mv *.txt *.tsv
mv: target 'd.tsv': Not a directory

#rename all the files with a .txt extension to .fg extension in the given directory
find . -type f -name "*.txt" -exec sh -c 'mv "$1" "${1%.txt}.fg"' _ {} \;

#bash script
for file in /path/to/directory/*.txt; do
  mv "$file" "${file%.txt}.fg"
done

# one liner version of the bash script above
find /path/to/directory -type f -name "*.txt" -exec bash -c 'mv "$0" "${0%.txt}.fg"' {} \;
------------------------------------------------------------------------------------------
cmp file1.txt file2.txt #cmp command reports the byte and line number if a difference is found
cmp --silent file1 file2 && echo 'SUCCESS: Files Are Identical' || echo 'Files Are Different'
cmp --silent $old $new || echo "files are different"

#if= defines the source drive and of= defines the file or location where data saved
# dd if=/dev/sda of=/dev/sdb
# dd if=/dev/sda of=/home/username/sdadisk.img #create an .img archive of the /dev/sda drive and save it to the home directory
# dd if=/dev/sda2 of=/home/username/partition2.img bs=4096
#if= takes the image to restore, and of= takes the target write the image
# dd if=sdadisk.img of=/dev/sdb
create a compressed image of a remote drive using SSH and save the resulting archive to local machine
# ssh username@54.98.132.10 "dd if=/dev/sda | gzip -1 -" | dd of=backup.gz
dd  if=text.ascii of=text.ebcdic conv=ebcdic #convert an ASCII text file to EBCDIC
#convert the variable-length record ASCII file /etc/passwd to a file of 132-byte fixed-length EBCDIC records
dd  if=/etc/passwd  cbs=132  conv=ebcdic  of=/tmp/passwd.ebcdic 
#convert the 132-byte-per-record EBCDIC file to variable-length ASCII lines in lowercase
dd  if=/tmp/passwd.ebcdic  cbs=132  conv=ascii  of=/tmp/passwd.ascii
#copy blocks from a tape with 1KB blocks to another tape using 2KB blocks
dd  if=/dev/rmt0  ibs=1024  obs=2048  of=/dev/rmt1
ls -l | dd  conv=ucase #displays a long listing of the current directory in uppercase.
dd if=/dev/zero of=/dev/sda1 #Wiping disks with dd,writing zeros
# dd if=/dev/urandom of=/dev/sda1 #Wiping disks with dd,writing random characters
# dd if=/dev/urandom | pv | dd of=/dev/sda1 #Monitoring dd operations,Pipe Viewer (sudo apt install pv on Ubuntu) 

#create a large file of random conten
$ dd if=/dev/urandom of=/tmp/file1 count=1K bs=1MB 
#copy file1 to file2, and append different characters to each file
$ cp /tmp/file1 /tmp/file2
$ echo 1 >> /tmp/file1
$ echo 2 >> /tmp/file2
#use the time command to measure the time taken
$ time cmp -s /tmp/file1 /tmp/file2 
$ time diff -sq /tmp/file1 /tmp/file2 
$ time sha1sum /tmp/file1
$ time sha1sum /tmp/file2

#Empty File Content by Redirecting to Null
# > access.log
# : > access.log #: is a shell built-in command
# true > access.log
# cat /dev/null > access.log
# cp /dev/null access.log
# dd if=/dev/null of=access.log
# echo "" > access.log
# echo > access.log
# echo -n "" > access.log #use the flag -n which tells echo to not output the trailing newline
# truncate -s 0 access.log


dd if=/dev/urandom of=test.file bs=1M count=100 ; time diff -q test.file test.copy && echo diff true || echo diff false ; \
time cmp -s test.file test.copy && echo cmp true || echo

vagrant@lampstack-01:~$ echo "file" > file1.txt
vagrant@lampstack-01:~$ cp file1.txt file2.txt
vagrant@lampstack-01:~$ cmp file1.txt file2.txt #cmp command reports the byte and line number if a difference is found
vagrant@lampstack-01:~$ sudo cmp file1.txt file2.txt
vagrant@lampstack-01:~$ echo "identical file1" >> file1.txt
vagrant@lampstack-01:~$ cat file1.txt
file
identical file1
vagrant@lampstack-01:~$ cat file2.txt
file
vagrant@lampstack-01:~$ cmp file1.txt file2.txt #cmp command reports the byte and line number if a difference is found
cmp: EOF on file2.txt after byte 5, line 1
vagrant@lampstack-01:~$ diff file1.txt file2.txt
2d1
< identical file1
------------------------- -----------------------------------------------------------------
# approval trick
$ yes | sudo yum install puppet
# user has to type 'y' for each query
$ yes | rm -ri test
------------------------- -----------------------------------------------------------------
#oracle java download

wget --no-cookies \
--no-check-certificate \
--header "Cookie: oraclelicense=accept-securebackup-cookie" \
"https://download.oracle.com/otn-pub/java/jdk/13.0.1+9/cec27d702aa74d5a8630c65ae61e4305/jdk-13.0.1_linux-x64_bin.tar.gz" \
-O jdk-7-linux-x64.tar.gz


curl --silent example.com | sha256sum
curl --silent --output - example.com | sha256sum #the o flag is redundant since the output is piped to bash (for execution) - not to a file
#-L in case the page has moved curl will redirect the request to the new address
#-o output to a file instead of stdout (usually the screen)
curl -LO http://example.com/

curl -LO -H "Cookie: oraclelicense=accept-securebackup-cookie" \
https://download.oracle.com/otn-pub/java/jdk/13.0.1+9/cec27d702aa74d5a8630c65ae61e4305/jdk-13.0.1_linux-x64_bin.tar.gz
------------------------------------------------------------------------------------------

------------------------------------------------------------------------------------------
  hostnamectl set-hostname vg-checkmk-client
  echo "172.28.128.15 vg-checkmk-client.local vg-checkmk-client" |sudo tee -a /etc/hosts
  echo "nameserver 8.8.8.8" |sudo tee -a /etc/resolv.conf

problem:
#append text to a file when using sudo
sudo echo "172.28.128.15 vg-checkmk-client.local vg-checkmk-client" >> /etc/hosts
-bash: /etc/hosts: Permission denied
fix:
#running bash/sh shell with root privileges and redirection took place in that shell session
$ sudo sh -c 'echo "172.28.128.15 vg-checkmk-client.local vg-checkmk-client" >> /etc/hosts'
$ sudo sh -c 'echo "JAVA_HOME=/usr/lib/jvm/java-6-sun" >> /etc/profile'
$ sudo bash -c 'echo "JAVA_HOME=/usr/lib/jvm/java-6-sun" >> /etc/profile'
$ sudo tee -a /etc/profile.d/java.sh << 'EOF'
# configures JAVA
JAVA_HOME=/usr/lib/jvm/java-8-oracle
export JAVA_HOME
export PATH=$PATH:$JAVA_HOME/bin
EOF
$ sudo sed -i '$a something' /etc/config_file
------------------------------------------------------------------------------------------	  
#File Creation Times
vagrant@lampstack-01:/tmp/nexus$ df -h
Filesystem                    Size  Used Avail Use% Mounted on
udev                          205M     0  205M   0% /dev
tmpfs                          48M  7.8M   41M  17% /run
/dev/mapper/vagrant--vg-root   62G  4.3G   55G   8% /
tmpfs                         240M     0  240M   0% /dev/shm
tmpfs                         5.0M     0  5.0M   0% /run/lock
tmpfs                         240M     0  240M   0% /sys/fs/cgroup
vagrant                       420G  375G   46G  90% /vagrant
tmpfs                          48M     0   48M   0% /run/user/1000
vagrant@lampstack-01:/tmp/nexus$ ls -i Dockerfile
3808483 Dockerfile
vagrant@lampstack-01:/tmp/nexus$ sudo debugfs -R 'stat <3808483>' /dev/mapper/vagrant--vg-root
debugfs 1.44.6 (5-Mar-2019)
vagrant@lampstack-01:/tmp/nexus$ vagrant@lampstack-01:/tmp/nexus$ sudo debugfs -R 'stat <3808483>' /dev/mapper/vagrant--vg-root | grep crtime
debugfs 1.44.6 (5-Mar-2019)
crtime: 0x5e4f0f92:b6a11330 -- Thu Feb 20 23:00:34 2020
------------------------------------------------------------------------------------------
#how to view gz gunzip files

zcat test2.txt.gz #see the content of the compressed file
zcat test.txt.gz test2.txt.gz #see the content of the compressed files,multiple inputs
zcat test2.txt #uncompress files that have the correct magic number whether they have a .gz suffix or not
zcat test2.txt.gz | more
zcat test2.txt.gz | less
zmore test2.txt.gz
zless test2.txt.gz
zless -f test2.txt #display file contents in output whether or not the file is compressed

# search string in multiple .gz file
 zgrep -i -H "pattern match" /somedir/filename*.gz
 zgrep -i -H "pattern match" /somedir/filename*.gz | grep "pattern 2nd"
 find /somedir/ -name "log.202011917*.gz" -exec zgrep "somestring"  \{\} \;
 find /somedir/ -name 'log.202011917' -print0 | xargs -0 zgrep "somestring" #prints file path inc. folder
------------------------------------------------------------------------------------------
    #Hosts File
    Windows 10 - "C:\Windows\System32\drivers\etc\hosts"
    Linux - "/etc/hosts"
    Mac OS X - "/private/etc/hosts"
------------------------------------------------------------------------------------------    
type -a ll #if command is an alias or not
type -p dash
------------------------------------------------------------------------------------------   
------------------------------------------------------------------------------------------
echo $? #get the exit status of the previously executed command, http://www.tldp.org/LDP/abs/html/exitcodes.html
echo $? # Expands to the exit status (exit code) of the most recently executed foreground pipeline,return the exit status of last command
exits with a status code 0 #success
exits with a status code 1 #failure

command && echo "success: $?" || echo "fail: $?" #test if the command failed
if [ $? -eq 0 ]; then echo "success: $?"; fi

$ echo "hola el mundo" > file.txt
$ cat file.txt && echo "success: $?" || echo "fail: $?"
hola el mundo
success: 0
$ cat filedoesnotexist.txt && echo "success: $?" || echo "fail: $?"
cat: filedoesnotexist.txt: No such file or directory
fail: 1

cat 'doesnotexist.txt' 2>/dev/null || exit 0 #suppress exit status
cat file.txt || exit 0

#suppress the error silently
$ cat filedoesnotexist.txt && echo "success: $?" || echo "fail: $?"
cat: filedoesnotexist.txt: No such file or directory
fail: 1
$ cat filedoesnotexist.txt || true && echo $?
cat: filedoesnotexist.txt: No such file or directory
0

$ fslint /tmp #lists the duplicate files
$ rdfind /tmp #delete the duplicates,remove the newer files.
$ rdfind -dryrun true /tmp #only report the changes
$ rdfind -deleteduplicates true /tmp

$ cksum *.html #computes checksums for files
$ find . -name "*.html" -exec cksum {} \; #search files by name or type and run the cksum command.

$ find . -name "not_existing_file" 
$ echo $?
-----------------------------------------------------------------------------------------------------
bash -x # runs the script <file> with tracing of each command executed
bash -x -c ls -lai #run a command in BASH, use -c option
test -x <file> #tests whether <file> has execute permissions for the current user
------------------------------------------------------------------------------------------  
#print variable
export BRANCH_NAME="main"
echo "BRANCH_NAME is..: $BRANCH_NAME"
------------------------------------------------------------------------------------------   
yum/apt install chrony
systemctl stop chronyd
chronyd -q 'pool pool.ntp.org iburst'
systemctl start chronyd
chronyc tracking #verify
systemctl restart chronyd ; watch chronyc tracking #realtime witnessing
chronyc sources
chronyc sources -v
chronyc
------------------------------------------------------------------------------------------
#concatenate strings
export strservice="libvirtd"
echo "${strservice} is still running."
echo $(ls)
echo "The date is $(date)"
echo `pwd`
echo $((3 + (4**3 /2))) #Direct calculation in the shell with echo and $(( )
------------------------------------------------------------------------------------------
#nfs server
exportfs -arv
df -h

cat /etc/exports
# /mnt/nfs_share  client_IP_1 (re,sync,no_subtree_check)
echo "$NFS_DIR  192.168.50.7(rw,sync,no_subtree_check)" | sudo tee -a /etc/exports
echo "$NFS_DIR  192.168.50.8(rw,sync,no_subtree_check)" | sudo tee -a /etc/exports

#nfs client  mount -t nfs NFS_SERVER_IP:NFS_SERVER_DIR NFS_CLIENT_DIR
mount -t nfs  10.20.20.8:/mnt/backups /mnt/backups
umount /mnt/backups
mount | grep nfs
showmount -e
------------------------------------------------------------------------------------------
#execute shell command produced using echo and sed
echo "mv /server/today/logfile1 /nfs/logs/ && gzip /nfs/logs/logfile1" | bash #
bash -c "$(echo "mv /server/today/logfile1 /nfs/logs/ && gzip /nfs/logs/logfile1")" #pass it as an argument to a shell
eval "$(echo "mv /server/today/logfile1 /nfs/logs/ && gzip /nfs/logs/logfile1")" #use the bash built-in eval
------------------------------------------------------------------------------------------
$ mycommand="wc -l department.txt"
$ eval $mycommand
------------------------------------------------------------------------------------------
$ cat /proc/sys/net/ipv4/ip_local_port_range
------------------------------------------------------------------------------------------
#redirection is done by the shell which doesn't has write permission
sudo echo 1 > /proc/sys/net/ipv4/ip_forward
bash: /proc/sys/net/ipv4/ip_forward: Permission denied

echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward #resolution-1

$ sudo sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward' #resolution-2

$ sudo -s #resoluton-3
# echo 1 > /proc/sys/net/ipv4/ip_forward

$ cat testscript.sh #resolution-4
#!/bin/sh
echo 1 > /proc/sys/net/ipv4/ip_forward

sudo echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward > /dev/null #same
$ sudo tee /proc/sys/net/ipv4/ip_forward > /dev/null << EOF	#same
1
EOF
------------------------------------------------------------------------------------------
#source tar build, no version typing
tar zfx rrdtool.tar.gz
cd rrdtool-*
------------------------------------------------------------------------------------------
echo 1 > /proc/sys/kernel/sysrq;echo f > /proc/sysrq-trigger;echo 0 > /proc/sys/kernel/sysrq #Trigger Out Of Memory (OOM) killer without reboot
------------------------------------------------------------------------------------------
ls -la .mozilla/firefox #user preferences,browser cookies,bookmarks,browser cache content etc.
------------------------------------------------------------------------------------------
#troubleshooting memory problems

#Suddenly killed tasks are often the result of the system running out of memory, when the so-called Out-of-memory (OOM) killer steps in
$ grep -i -r 'out of memory' /var/log/ #search the logs for messages of out of memory alerts

$ free -m #megabytes
$ free -m |head -n 2 |tail -n 1 |awk '{free=($4); print free}'
watch -n 5 -d '/bin/free -m'

$ top
$ top -i -u vagrant #ignore idle processes
$ top -n 1 -o RES | grep kvm

$ uptime
#"system load averages" that show the running thread (task) demand on the system as an average number of running plus waiting threads.
#show three averages, for 1, 5, and 15 minutes
#If the averages are 0.0, system is idle
#If the 1 minute average is higher than the 5 or 15 minute averages, then load is increasing
#If the 1 minute average is lower than the 5 or 15 minute averages, then load is decreasing.

$ ps -aylC $APACHE |grep "$APACHE" |awk '{print $8'} |sort -n |tail -n 1
$ ps -eL h -o state | egrep "R|D" | wc -l #The instantaneous number of such tasks
#Linux load average,the instantaneous load of a system the number of tasks (processes and threads) 
#that are willing to run at a given time t
#either in state R or D, either actually running or blocked on some resource (CPU, IO, ...) waiting for an opportunity to run

$ cat /proc/sys/vm/swappiness
#The Linux kernel moves out pages which are not active or being used at the moment to swap space on the disk. This process is known as swappiness.
#turn off swaping by changing t he value in /proc/sys/vm/swappiness to 0.The value ranges from 0 to 100 whe re 100 means aggressive swapping

vmstat –a 1 99 #show memory usage information
vmstat -n 1 # If 'si' and 'so' (stands for swapin and swapout) fields are always 0, then the system is currently not swapping

$ grep DirectMap /proc/meminfo
$ cat /proc/meminfo #Relevant fields from /proc/meminfo to match them against the output of free -k
    MemTotal — Total amount of physical RAM, in kilobytes.
    MemFree — The amount of physical RAM, in kilobytes, left unused by the system.
    Buffers — The amount of physical RAM, in kilobytes, used for file buffers.
    Cached — The amount of physical RAM, in kilobytes, used as cache memory.
    SwapCached — The amount of swap, in kilobytes, used as cache memory.
    Active — The total amount of buffer or page cache memory, in kilobytes, that is in active use. This is memory that has been recently used and is usually not reclaimed for other purposes.
    Inactive — The total amount of buffer or page cache memory, in kilobytes, that are free and available. This is memory that has not been recently used and can be reclaimed for other purposes.
    HighTotal and HighFree — The total and free amount of memory, in kilobytes, that is not directly mapped into kernel space. The HighTotal value can vary based on the type of kernel used.
    LowTotal and LowFree — The total and free amount of memory, in kilobytes, that is directly mapped into kernel space. The LowTotal value can vary based on the type of kernel used.
    SwapTotal — The total amount of swap available, in kilobytes.
    SwapFree — The total amount of swap free, in kilobytes.
    Dirty — The total amount of memory, in kilobytes, waiting to be written back to the disk. Writeback — The total amount of memory, in kilobytes, actively being written back to the disk.
    Mapped — The total amount of memory, in kilobytes, which have been used to map devices, files, or libraries using the mmap command.
    Slab — The total amount of memory, in kilobytes, used by the kernel to cache data structures for its own use.
    Committed_AS — The total amount of memory, in kilobytes, estimated to complete the workload. This value represents the worst case scenario value, and also includes swap memory. PageTables — The total amount of memory, in kilobytes, dedicated to the lowest page table level.
    VMallocTotal — The total amount of memory, in kilobytes, of total allocated virtual address space.
    VMallocUsed — The total amount of memory, in kilobytes, of used virtual address space.
    VMallocChunk — The largest contiguous block of memory, in kilobytes, of available virtual address space.
    HugePages_Total — The total number of hugepages for the system. The number is derived by dividing Hugepagesize by the megabytes set aside for hugepages specified in /proc/sys/vm/hugetlb_pool. This statistic only appears on the x86, Itanium, and AMD64 architectures.
    HugePages_Free — The total number of hugepages available for the system. This statistic only appears on the x86, Itanium, and AMD64 architectures.
    Hugepagesize — The size for each hugepages unit in kilobytes. By default, the value is 4096 KB on uniprocessor kernels for 32 bit architectures. For SMP, hugemem kernels, and AMD64, the default is 2048 KB. For Itanium architectures, the default is 262144 KB. This statistic only appears on the x86, Itanium, and AMD64 architectures.

Matching output of free -k to /proc/meminfo
free output 	coresponding /proc/meminfo fields
Mem: total 	MemTotal
Mem: used 	MemTotal - MemFree
Mem: free 	MemFree
Mem: shared (can be ignored nowadays. It has no meaning.) 	N/A
Mem: buffers 	Buffers
Mem: cached 	Cached
-/+ buffers/cache: used 	MemTotal - (MemFree + Buffers + Cached)
-/+ buffers/cache: free 	MemFree + Buffers + Cached
Swap: total 	SwapTotal
Swap: used 	SwapTotal - SwapFree
Swap: free 	SwapFree

------------------------------------------------------------------------------------------
cat newpass.txt | chpasswd #update passwords in batch mode
echo 'ubuntuser:ubuntupassword' | sudo chpasswd

$cat > pass.txt
user1:user1_password
user2:user2_password
user3:user3_password
$chpasswd < file_name.txt

CURRENT_USERS=$(who) #Assign Output of a Linux Command to a Variable
------------------------------------------------------------------------------------------
ls -1 #list one file per line,vertically using the -1 switch
------------------------------------------------------------------------------------------
sudo !! #Re-Run Last Executed Command as Root User, “sudo” followed by a space and two exclamation points. 
------------------------------------------------------------------------------------------
#If set, sudo will only run when the user is logged in to a real tty
#sudo can only be run from a login session and not via other means such as cron(8) or cgi-bin scripts
#enable sudo within scripts

sudo /usr/sbin/visudo

$ cat /etc/sudoers
Defaults:username !requiretty #Disable requiretty to particular user


#sudoers file allows both artbristol and bob to execute /path/to/program as root from a script
#artbristol needs no password whereas bob must have to enter a password
artbristol ALL = (root) NOPASSWD: /path/to/program
bob ALL = (root) /path/to/program
Defaults!/path/to/program !requiretty

#allows artbristol to run /path/to/program --option in a script, but not /path/to/program with other arguments.
Cmnd_Alias MYPROGRAM = /path/to/program --option  
artbristol ALL = (root) /path/to/program
artbristol ALL = (root) NOPASSWD: MYPROGRAM
Defaults!MYPROGRAM !requiretty
------------------------------------------------------------------------------------------
#This allows the source (the sending host) to specify the route, loosely or strictly, ignoring the routing tables of some or all of the routers
#source-based routing should be disabled. 
/sbin/sysctl -w net.ipv4.conf.all.accept_source_route=0 #drop packets with the SSR or LSR option set

#Disabling the forwarding of packets should also be done in conjunction with the above when possible (disabling forwarding may interfere with virtualization)
/sbin/sysctl -w net.ipv4.conf.all.forwarding=0
/sbin/sysctl -w net.ipv6.conf.all.forwarding=0
#These commands disable forwarding of all multicast packets on all interfaces
/sbin/sysctl -w net.ipv4.conf.all.mc_forwarding=0
/sbin/sysctl -w net.ipv6.conf.all.mc_forwarding=0

#Accepting ICMP redirects has few legitimate uses. Disable the acceptance and sending of ICMP redirected packets unless specifically required
 /sbin/sysctl -w net.ipv4.conf.all.accept_redirects=0
 /sbin/sysctl -w net.ipv6.conf.all.accept_redirects=0
#disables acceptance of secure ICMP redirected packets on all interfaces
/sbin/sysctl -w net.ipv4.conf.all.secure_redirects=0
# disables acceptance of all IPv4 ICMP redirected packets on all interfaces:
/sbin/sysctl -w net.ipv4.conf.all.send_redirects=0
#automatically disable sending of ICMP requests whenever you add a new interface
/sbin/sysctl -w net.ipv4.conf.default.send_redirects=0

#make these settings persistent across reboots, modify the /etc/sysctl.conf file
#disable acceptance of all IPv4 ICMP redirected packets on all interfaces, 
#open the /etc/sysctl.conf file with an editor running as the root user and add a line as follow
net.ipv4.conf.all.send_redirects=0
------------------------------------------------------------------------------------------
#Reverse Path Forwarding is used to prevent packets that arrived through one interface from leaving through a different interface
#unless you know that it is required, it is best enabled as it prevents users spoofing IP addresses from local subnets and reduces the opportunity for DDoS attacks. 
#permanent changes can be made by adding lines to the /etc/sysctl.conf
# make a temporary global change
sysctl -w  net.ipv4.conf.default.rp_filter=integer
sysctl -w net.ipv4.conf.all.rp_filter=integer

------------------------------------------------------------------------------------------
#Enabling Packet Forwarding
#enable packets arriving from outside of a system to be forwarded to another external host
#change the line which reads net.ipv4.ip_forward = 0 in the /etc/sysctl.conf file to the following
net.ipv4.ip_forward = 1
/sbin/sysctl -p #load the changes from the /etc/sysctl.conf file
/sbin/sysctl net.ipv4.ip_forward #check if IP forwarding is turned on,If it returns 1, then IP forwarding is enabled
/sbin/sysctl -w net.ipv4.ip_forward=1 #If it returns 0, turn it on manually
------------------------------------------------------------------------------------------
#check public IP,private (viewable within an internal network) or public (can be seen by other machines on the Internet)

#3rd party web-sites
$ wget -qO- http://ipecho.net/plain | xargs echo
$ curl ifconfig.co
$ curl ifconfig.me
$ curl icanhazip.com
$ curl -4 icanhazip.com
$ curl -6 icanhazip.com
$ curl ident.me
$ curl checkip.dyndns.org
$ curl api.ipify.org
$ curl ipinfo.io/ip
$ curl checkip.amazonaws.com
------------------------------------------------------------------------------------------
#The Internet Assigned Numbers Authority (IANA) has assigned several address ranges to be used by private networks

    Class A: 10.0.0.0 to 10.255.255.255 
    Class B: 172.16.0.0 to 172.31.255.255
    Class C: 192.168.0.0 to 192.168.255.255
    
    Class A: 10.0.0.0/8 (255.0.0.0)	
    Class B: 172.16.0.0/12 (255.240.0.0)
    Class C: 192.168.0.0/16 (255.255.0.0)


------------------------------------------------------------------------------------------
#Running GUI applications as root
sudo /usr/bin/etherape
------------------------------------------------------------------------------------------
chage -l ubuntu #last password change date
------------------------------------------------------------------------------------------
#read first, and if a match is found the connection is allowed and the search is stopped.
#If no allowed match if found, the hosts.deny file is read
/etc/hosts.allow
#If a match is found the connection is refused - otherwise it is allowed
#/etc/hosts.deny
------------------------------------------------------------------------------------------
# print server's IP on the wellcome page
echo $(ifconfig eth0 | grep 'inet addr' | awk -F: '{ print $2 }' | awk '{ print $1 }') >> /var/www/html/index.html
------------------------------------------------------------------------------------------
getfacl -a a.txt #file access control list of a file or directory.
getfacl -t a.txt
getfacl -n file #numeric user and group IDs
getfacl -d a.txt #the default access control list of a file or directory.
getfacl -R directory # the ACLs of all files and directories recursively (sub-directories)
getfacl -L -R directory #follow symbolic links to directories. The default behavior is to follow symbolic link arguments and skip symbolic links encountered in subdirectories
getfacl -P -R directory #do not follow symbolic links to directories,skip symbolic link arguments

setfacl -m u:deepak:rw a.txt #grant read and write permission
setfacl -b a.txt #remove all extended ACL entries,remove all entries
setfacl -x u:deepak a.txt #remove user
setfacl -x g:linux file #remove group
setfacl -m g:linux:rw -R directory #remove group  recursively (sub-directories)
setfacl -k file #remove the default access control list
setfacl --test -x g:linux -R dir1 #The ACLs are not modified in test mode. It only displays the changes that will take place
setfacl -dm "user:my_user:r--" /path/to/directory #Add a default entry to grant access to the user my_user on all newly created files within a directory


getfacl file1 | setfacl --set-file=- file2 #copy the ACL of one file to another
------------------------------------------------------------------------------------------
for i in *linux*; do rm $i; done #delete all the files in the current directory that contains the word “linux”
cat linux.txt | grep n #list the entries that start has the character ‘n’
cat linux.txt | grep ^a #ist the entries that start with the character ‘a’
echo "shutdown now" | at -m 18:00 #shut down the system at 6 pm today
vim -R <filename> #open a file in read-only mode 
vim +/<employee id to be searched> <filename> #search for a specific Employee ID in a file
------------------------------------------------------------------------------------------
cd $mydir && python3 -m http.server 8888 #Share a file quickly using a web server

podman run --rm -v .:/usr/share/nginx/html:ro,Z -p 30080:80 -d nginx # Expose a web directory using containers
------------------------------------------------------------------------------------------
$ sudo shutdown --halt 22:00 #--halt option stops the operating system
$ sudo shutdown --halt +5 # halt the system after a five-minute delay
$ sudo shutdown --halt +5 “Attention. The system is going down in five minutes.”
$ sudo shutdown -c #Cancel a timed shutdown
$ sudo shutdown -r now #restarting the system 
$ sudo systemctl reboot #restarting the system 
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#how to delete file with inode
find . -inum 1847 -ls
find . -inum 1847 -exec rm {} \;

find . -inum 782263 -exec rm -i {} \;

#how to delete directory/folder with inode
find . -inum 393232 -delete
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#The error message you're encountering seems to indicate a problem with the execution or syntax within the .bashrc file. The .bashrc file is a script that runs whenever a new terminal session is started for a user in Bash

nano ~/.bashrc

If there's no obvious syntax error, try validating the syntax of the .bashrc file using the bash command
bash -n ~/.bashrc

After making changes to the .bashrc file, restart the Bash shell or source the file to apply the changes

source ~/.bashrc
or
exec bash
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
 #Listing a Directory with Spaces
 ls "My Documents"

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
