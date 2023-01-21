#!/bin/bash

##
##

set -Eeuo pipefail
IFS=$'\n\t'
PROGNAME="$( basename $0 )"

# printf.color
# Arguments:
#   - 1: Color code (from: ansi-escape codes https://en.wikipedia.org/wiki/ANSI_escape_code#Colors)
#   - 2: Message
# Prints message in the color passed as the first argument. (no newline)
function printf.color {
  local color="$1"
  local message="$2"
  local no_color='\033[0m'

  printf "$color%s$no_color" "$message"
}

# printf.green
# Arguments:
#   - 1: Message
# Print message in color green. (no newline)
function printf.green {
  local green='\033[0;32m'
  local message="$1"

  printf.color "$green" "$message"
}

# printf.red
# Arguments:
#   - 1: Message
# Prints message in color red. (no newline)
function printf.red {
  local red='\033[0;31m'
  local message="$1"

  printf.color "$red" "$message"
}

# fail
# Arguments:
#   - 1: Line number (env-variable LINENO) (optional, default: "NAN")
#   - 2: Error message (optional, default: "Unknown Error")
#   - 3: Exit code (optional, default: 1)
# Facilitates failure communication
function fail {
  printf.red "$PROGNAME: ${2:-"Unknown Error"} [Line: #${1:-"NAN"}]" 1>&2
  echo 1>&2

  exit "${3:-1}"
}

# Ensure errors are properly handled
trap 'fail "$LINENO" "Unexpected error. Quitting."' ERR

#####
#####

#!/bin/bash

# Use -e to exit the script as soon as anything returns non-zero
set -eou pipefail


function usage() {
  echo ""
  echo "Template script for bash error handling."
  echo ""
  echo "Usage: ./scaledown"
  echo ""
}


# Define an error handling function
function onerror() {
  
  # Do what you want when catching an error
  exit 0
}
# Tell the script to trigger `onerror` immediantly before exit
trap onerror EXIT

# Whatever you want your script to do
function go() {
  echo "hi"
}

# Call your function
go

# Before a successfull exit, unhook the `onerror` function; otherwise
# it will trigger on exit
trap - EXIT

# Set your exit status
exit 0

#####
#####


# Bash error handling

(This article was published on [Enable Sysadmin: Learn Bash error handling by example](https://www.redhat.com/sysadmin/bash-error-handling))

On this article you will see a few tricks to handle error conditions; Some stricly do not fall under the category of error handling (a reactive way to handle the unexpected) but also some techniques to avoid errors before they happen (Did you ever watch [Minority report](https://www.imdb.com/title/tt0181689/). Exactly, but less creepy ;-))


## Case of study: Simple script that downloads a hardware report from multiple hosts and inserts it into a database. What could go wrong? :-)

Say that you have a little cron job on each one of your Linux HOME machines, and [you have a script to collect](https://github.com/josevnz/BashError/blob/main/collect_data_from_servers.sh) the hardware information from each:

```shell=
#!/bin/bash
# Script to collect the status of lshw output from home servers
# Dependencies:
# * LSHW: http://ezix.org/project/wiki/HardwareLiSter
# * JQ: http://stedolan.github.io/jq/
#
# On each machine you can run something like this from cron (Don't know CRON, no worries: https://crontab-generator.org/)
# 0 0 * * * /usr/sbin/lshw -json -quiet > /var/log/lshw-dump.json
# Author: Jose Vicente Nunez
#
declare -a servers=(
dmaf5
)

DATADIR="$HOME/Documents/lshw-dump"

/usr/bin/mkdir -p -v "$DATADIR"
for server in ${servers[*]}; do
    echo "Visiting: $server"
    /usr/bin/scp -o logLevel=Error ${server}:/var/log/lshw-dump.json ${DATADIR}/lshw-$server-dump.json &
done
wait
for lshw in $(/usr/bin/find $DATADIR -type f -name 'lshw-*-dump.json'); do
    /usr/bin/jq '.["product","vendor", "configuration"]' $lshw
done
```

If everything goes well then you collect your files, in parallel (as you don't have more than 10 machines you can afford to ssh to all of them at the same time, right) and then show the hardware details of each one (you are so proud of your babies :-)):

```
Visiting: dmaf5
lshw-dump.json                                                                                         100%   54KB 136.9MB/s   00:00    
"DMAF5 (Default string)"
"BESSTAR TECH LIMITED"
{
  "boot": "normal",
  "chassis": "desktop",
  "family": "Default string",
  "sku": "Default string",
  "uuid": "00020003-0004-0005-0006-000700080009"
}
```

But life is not perfect. Bad things happen:
* Your report didn't run because the server was down
* You could not create the directory where the files need to be saved
* The tools you need to run the script are missing
* You cannot collect the report because your remote machine crashed (too much Dog Coin mining ;-)
* One or more of the reports you just got is corrupt. 
* And the list of unexpected things that can go wrong goes on and on...

Current version of the script has a problem: It will run from the begining to the end, errors or not:

```shell=
./collect_data_from_servers.sh 
Visiting: macmini2
Visiting: mac-pro-1-1
Visiting: dmaf5
lshw-dump.json                                                                                         100%   54KB  48.8MB/s   00:00    
scp: /var/log/lshw-dump.json: No such file or directory
scp: /var/log/lshw-dump.json: No such file or directory
parse error: Expected separator between values at line 3, column 9

```

Keep reading, I'll show you a few things to make your script more robust and in some times recover from failure.

# The nuclear option: Failing hard, failing fast

The proper way to handle errors is to check if the program finished successfully or not, using return codes. Yeah, sounds obvious but return code (an integer number stored in bash $? or $! variable) have sometimes a broader meaning. ([Bash man page](https://man7.org/linux/man-pages/man1/bash.1.html)) tell us something:

> For the shell's purposes, a command which exits with a zero exit
       status has succeeded.  An exit status of zero indicates success.
       A non-zero exit status indicates failure.  When a command
       terminates on a fatal signal N, bash uses the value of 128+N as
       the exit status.

As usual, you should always read the man page of the scripts you are calling, to see what are the conventions. If you have programmed with a language like Java or Python then you are most likely familiar with with exceptions and their different meanings (and how not all them are handled the same way).

If you add ```set -o errexit``` to your script, from that point forward it will abort the execution if any command exists with a code != 0. But errexit isn’t used when executing functions inside an if condition, so instead of remembering that little gotcha I rather do explict error handling.

So let's take a look a [V2 of the script](https://github.com/josevnz/BashError/blob/main/collect_data_from_servers.v2.sh). It is slightly better:

```shell=
#!/bin/bash
# Script to collect the status of lshw output from home servers
# Dependencies:
# * LSHW: http://ezix.org/project/wiki/HardwareLiSter
# * JQ: http://stedolan.github.io/jq/
#
# On each machine you can run something like this from cron (Don't know CRON, no worries: https://crontab-generator.org/)
# 0 0 * * * /usr/sbin/lshw -json -quiet > /var/log/lshw-dump.json
# Author: Jose Vicente Nunez
#
set -o errtrace # Enable the err trap, code will get called when an error is detected
trap "echo ERROR: There was an error in ${FUNCNAME-main context}, details to follow" ERR
declare -a servers=(
macmini2
mac-pro-1-1
dmaf5
)

DATADIR="$HOME/Documents/lshw-dump"
if [ ! -d "$DATADIR" ]; then
    /usr/bin/mkdir -p -v "$DATADIR"|| "FATAL: Failed to create $DATADIR" && exit 100
fi
declare -A server_pid
for server in ${servers[*]}; do
    echo "Visiting: $server"
    /usr/bin/scp -o logLevel=Error ${server}:/var/log/lshw-dump.json ${DATADIR}/lshw-$server-dump.json &
    server_pid[$server]=$! # Save the PID of the scp  of a given server for later
done
# Iterate through all the servers and:
# Wait for the return code of each
# Check the exit code from each scp
for server in ${!server_pid[*]}; do
    wait ${server_pid[$server]}
    test $? -ne 0 && echo "ERROR: Copy from $server had problems, will not continue" && exit 100
done
for lshw in $(/usr/bin/find $DATADIR -type f -name 'lshw-*-dump.json'); do
    /usr/bin/jq '.["product","vendor", "configuration"]' $lshw
done

```

I did a few things:

1. Lines 11,12 I enable error trace and added a 'trap' to tell the user there was an error and there is turbulence ahead. You may want to kill your script here instead, I'll show you why that may not be the best
2. Line 20, if the directory doesn't exist then try to create it on line 21. If directory creation fails the exit with an error
3. On line 27, after running each background job, I capture the PID and associate that with the machine (1:1 relationship).
4. On lines 33-35 I wait for the scp task to finish, get the return code and if is an error abort
5. On line 37 I check than the file could be parsed, otherwise I exit with an error

So how does the error handling looks now?
```shell=
Visiting: macmini2
Visiting: mac-pro-1-1
Visiting: dmaf5
lshw-dump.json                                                                                         100%   54KB 146.1MB/s   00:00    
scp: /var/log/lshw-dump.json: No such file or directory
ERROR: There was an error in main context, details to follow
ERROR: Copy from mac-pro-1-1 had problems, will not continue
scp: /var/log/lshw-dump.json: No such file or directory

```

As you can see this version is better at detecting errors but it is very unforgiving. Also it doesn't detect all the errors, does it?

## When you get stuck and you wish you had an alarm

So our code looks better, except than sometimes our scp could get stuck on a server (while trying to copy a file) because the server is too busy to respond or just in a bad state. 

Let me give you another example: You try to access a directory through NFS, for example like this (say $HOME is mounted from a NFS server):

```shell=
/usr/bin/find $HOME -type f -name '*.csv' -print -fprint /tmp/report.txt
```

Only to discover hours later than the NFS mount point is stale and your script got stuck.

Would be nice to have a timeout? Well, [GNU timeout](https://www.gnu.org/software/coreutils/) comes to rhe rescue

```shell=
/usr/bin/timeout --kill-after 20.0s 10.0s /usr/bin/find $HOME -type f -name '*.csv' -print -fprint /tmp/report.txt
```

Here we try to regular kill (TERM signal) the process nicely after 10.0 seconds it has started, if is still running after 20.0 seconds then send a KILL signal (kill -9). In doubt check what signals are supported in your system (```kill -l```)

Not clear? Can you tell what the following script does?

```shell=
/usr/bin/time /usr/bin/timeout --kill-after=10.0s 20.0s /usr/bin/sleep 60s
real	0m20.003s
user	0m0.000s
sys	0m0.003s
```

Back to our original script, let's add a few more gizmos to the script and [we get version 3](https://github.com/josevnz/BashError/blob/main/collect_data_from_servers.v3.sh):
```=shell
#!/bin/bash
# Script to collect the status of lshw output from home servers
# Dependencies:
# * Open SSH: http://www.openssh.com/portable.html
# * LSHW: http://ezix.org/project/wiki/HardwareLiSter
# * JQ: http://stedolan.github.io/jq/
# * timeout: https://www.gnu.org/software/coreutils/
#
# On each machine you can run something like this from cron (Don't know CRON, no worries: https://crontab-generator.org/)
# 0 0 * * * /usr/sbin/lshw -json -quiet > /var/log/lshw-dump.json
# Author: Jose Vicente Nunez
#
set -o errtrace # Enable the err trap, code will get called when an error is detected
trap "echo ERROR: There was an error in ${FUNCNAME-main context}, details to follow" ERR

declare -a dependencies=(/usr/bin/timeout /usr/bin/ssh /usr/bin/jq)
for dependency in ${dependencies[@]}; do
    if [ ! -x $dependency ]; then
        echo "ERROR: Missing $dependency"
        exit 100
    fi
done

declare -a servers=(
macmini2
mac-pro-1-1
dmaf5
)

function remote_copy {
    local server=$1
    echo "Visiting: $server"
    /usr/bin/timeout --kill-after 25.0s 20.0s \
        /usr/bin/scp \
            -o BatchMode=yes \
            -o logLevel=Error \
            -o ConnectTimeout=5 \
            -o ConnectionAttempts=3 \
            ${server}:/var/log/lshw-dump.json ${DATADIR}/lshw-$server-dump.json
    return $?
}

DATADIR="$HOME/Documents/lshw-dump"
if [ ! -d "$DATADIR" ]; then
    /usr/bin/mkdir -p -v "$DATADIR"|| "FATAL: Failed to create $DATADIR" && exit 100
fi
declare -A server_pid
for server in ${servers[*]}; do
    remote_copy $server &
    server_pid[$server]=$! # Save the PID of the scp  of a given server for later
done
# Iterate through all the servers and:
# Wait for the return code of each
# Check the exit code from each scp
for server in ${!server_pid[*]}; do
    wait ${server_pid[$server]}
    test $? -ne 0 && echo "ERROR: Copy from $server had problems, will not continue" && exit 100
done
for lshw in $(/usr/bin/find $DATADIR -type f -name 'lshw-*-dump.json'); do
    /usr/bin/jq '.["product","vendor", "configuration"]' $lshw
done
```

What are the changes?:

* Between lines 16-22 check if all the required dependency tools are present. If cannot execute then '[Houston we have a problem](https://en.wikipedia.org/wiki/Houston,_we_have_a_problem)'
* Created a ```remote_copy``` function, uses a timeout to make sure the scp finishes on no later than 45.0s, line 33.
* Added A conection timeout of 5 seconds instead of the TCP default, line 37
* Added a retry to scp on line 38, 3 attempts that wait 1 second between each

Which is all great and all, but there are other ways to retry when thre is an error?

## Waiting for the end of the world (how and when to retry)

You noticed we added a retry to the scp command. But that retries only for failed connections, what if the command fails during the middle of the copy?

Bummer.

Sometimes you want to just fail because there is very little chance to recover from an issue (say a machine is really toasted and requires hardware fixes), or you can just failback to a degraded mode (meaning be able to continue your system work without the updated data). In those cases it makes no sense to wait forever but only until certain time.

I'll show you just the changes on the remote_copy, to keep this brief ([v4](https://github.com/josevnz/BashError/blob/main/collect_data_from_servers.v4.sh))

```shell=
#!/bin/bash
# Omitted code for clarity...
declare REMOTE_FILE="/var/log/lshw-dump.json"
declare MAX_RETRIES=3

# Blah blah blah...

function remote_copy {
    local server=$1
    local retries=$2
    local now=1
    status=0
    while [ $now -le $retries ]; do
        echo "INFO: Trying to copy file from: $server, attempt=$now"
        /usr/bin/timeout --kill-after 25.0s 20.0s \
            /usr/bin/scp \
                -o BatchMode=yes \
                -o logLevel=Error \
                -o ConnectTimeout=5 \
                -o ConnectionAttempts=3 \
                ${server}:$REMOTE_FILE ${DATADIR}/lshw-$server-dump.json
        status=$?
        if [ $status -ne 0 ]; then
            sleep_time=$(((RANDOM % 60)+ 1))
            echo "WARNING: Copy failed for $server:$REMOTE_FILE. Waiting '${sleep_time} seconds' before re-trying..."
            /usr/bin/sleep ${sleep_time}s
        else
            break # All good, no point on waiting...
        fi
        ((now=now+1))
    done
    return $status
}

DATADIR="$HOME/Documents/lshw-dump"
if [ ! -d "$DATADIR" ]; then
    /usr/bin/mkdir -p -v "$DATADIR"|| "FATAL: Failed to create $DATADIR" && exit 100
fi
declare -A server_pid
for server in ${servers[*]}; do
    remote_copy $server $MAX_RETRIES &
    server_pid[$server]=$! # Save the PID of the scp  of a given server for later
done

# Iterate through all the servers and:
# Wait for the return code of each
# Check the exit code from each scp
for server in ${!server_pid[*]}; do
    wait ${server_pid[$server]}
    test $? -ne 0 && echo "ERROR: Copy from $server had problems, will not continue" && exit 100
done

# Blah blah blah, process the files we just copied...
```

How does it look now? In this run I have 1 machine down (mac-pro-1-1) and one machine without the file (macmini2). You can see than the copy from server dmaf5 works right away, but for the other 2 we retry a random time between 1 and 60 seconds before giving up:
```shell=
INFO: Trying to copy file from: macmini2, attempt=1
INFO: Trying to copy file from: mac-pro-1-1, attempt=1
INFO: Trying to copy file from: dmaf5, attempt=1
scp: /var/log/lshw-dump.json: No such file or directory
ERROR: There was an error in main context, details to follow
WARNING: Copy failed for macmini2:/var/log/lshw-dump.json. Waiting '60 seconds' before re-trying...
ssh: connect to host mac-pro-1-1 port 22: No route to host
ERROR: There was an error in main context, details to follow
WARNING: Copy failed for mac-pro-1-1:/var/log/lshw-dump.json. Waiting '32 seconds' before re-trying...
INFO: Trying to copy file from: mac-pro-1-1, attempt=2
ssh: connect to host mac-pro-1-1 port 22: No route to host
ERROR: There was an error in main context, details to follow
WARNING: Copy failed for mac-pro-1-1:/var/log/lshw-dump.json. Waiting '18 seconds' before re-trying...
INFO: Trying to copy file from: macmini2, attempt=2
scp: /var/log/lshw-dump.json: No such file or directory
ERROR: There was an error in main context, details to follow
WARNING: Copy failed for macmini2:/var/log/lshw-dump.json. Waiting '3 seconds' before re-trying...
INFO: Trying to copy file from: macmini2, attempt=3
scp: /var/log/lshw-dump.json: No such file or directory
ERROR: There was an error in main context, details to follow
WARNING: Copy failed for macmini2:/var/log/lshw-dump.json. Waiting '6 seconds' before re-trying...
INFO: Trying to copy file from: mac-pro-1-1, attempt=3
ssh: connect to host mac-pro-1-1 port 22: No route to host
ERROR: There was an error in main context, details to follow
WARNING: Copy failed for mac-pro-1-1:/var/log/lshw-dump.json. Waiting '47 seconds' before re-trying...
ERROR: There was an error in main context, details to follow
ERROR: Copy from mac-pro-1-1 had problems, will not continue
```


## If I fail, do I have to do this all over again? Using a checkpoint

Say than the remote copy is the most expensive operation of this whole script. And that you are willing or able to re-run this script, maybe using cron or by hand a 2 times during the day to ensure you pick the files if one or more machines are down.

We could, for the day, create a small 'status cache', where we record only the successfull processing operations per machine. If a machine is in there then do not bother to check again for that day.

Some programs, like [Ansible](https://docs.ansible.com/), do something similar and allow you to retry a playbook on a limited number of machines after a failure (```--limit @/home/user/site.retry```).

A new version ([v5](https://github.com/josevnz/BashError/blob/main/collect_data_from_servers.v5.sh)) of the script has code to record the status of the copy (lines 15-33):

```shell=
declare SCRIPT_NAME=$(/usr/bin/basename $BASH_SOURCE)|| exit 100
declare YYYYMMDD=$(/usr/bin/date +%Y%m%d)|| exit 100
declare CACHE_DIR="/tmp/$SCRIPT_NAME/$YYYYMMDD"
# Logic to clean up the cache dir on daily basis is not shown here
if [ ! -d "$CACHE_DIR" ]; then
    /usr/bin/mkdir -p -v "$CACHE_DIR"|| exit 100
fi
trap "/bin/rm -rf $CACHE_DIR" INT KILL

function check_previous_run {
    local machine=$1
    test -f $CACHE_DIR/$machine && return 0|| return 1
}

function mark_previous_run {
    machine=$1
    /usr/bin/touch $CACHE_DIR/$machine
    return $?
}
```

Did you notice the ```trap``` on line 22? If the script is interrupted/ killed, I want to make sure the whole cache is invalidated.

And then we add this new helper logic into the ```remote_copy``` function (lines 52-81):

```shell=
function remote_copy {
    local server=$1
    check_previous_run $server
    test $? -eq 0 && echo "INFO: $1 ran successfully before. Not doing again" && return 0
    local retries=$2
    local now=1
    status=0
    while [ $now -le $retries ]; do
        echo "INFO: Trying to copy file from: $server, attempt=$now"
        /usr/bin/timeout --kill-after 25.0s 20.0s \
            /usr/bin/scp \
                -o BatchMode=yes \
                -o logLevel=Error \
                -o ConnectTimeout=5 \
                -o ConnectionAttempts=3 \
                ${server}:$REMOTE_FILE ${DATADIR}/lshw-$server-dump.json
        status=$?
        if [ $status -ne 0 ]; then
            sleep_time=$(((RANDOM % 60)+ 1))
            echo "WARNING: Copy failed for $server:$REMOTE_FILE. Waiting '${sleep_time} seconds' before re-trying..."
            /usr/bin/sleep ${sleep_time}s
        else
            break # All good, no point on waiting...
        fi
        ((now=now+1))
    done
    test $status -eq 0 && mark_previous_run $server
    test $? -ne 0 && status=1
    return $status
}
```

The first time it runs, a new new message for the cache directory is printed out:
```shell=
./collect_data_from_servers.v5.sh
/usr/bin/mkdir: created directory '/tmp/collect_data_from_servers.v5.sh'
/usr/bin/mkdir: created directory '/tmp/collect_data_from_servers.v5.sh/20210612'
ERROR: There was an error in main context, details to follow
INFO: Trying to copy file from: macmini2, attempt=1
ERROR: There was an error in main context, details to follow
```

If we run it again, then the script know than dma5f is good to go, no need to retry the copy:
```shell=
./collect_data_from_servers.v5.sh
INFO: dmaf5 ran successfully before. Not doing again
ERROR: There was an error in main context, details to follow
INFO: Trying to copy file from: macmini2, attempt=1
ERROR: There was an error in main context, details to follow
INFO: Trying to copy file from: mac-pro-1-1, attempt=1

```

Imagine now this speed up when you have more machines that should not be revisited.


## Leaving crumbs behind: What to log, how to log, verbose output

If you are like me, I like context to correlate when something happened. The echo statements on the script are nice but if we could add a timestamp to them.

If you use logger you can save the output on [journalctl](https://www.man7.org/linux/man-pages/man1/journalctl.1.html) for later review (even aggregation with other tools out there). The best part is that you will untap the power of journalctl right away.

So instead of just doing echo, we can also add a call to logger like this using a new bash function called 'message':
```shell=
SCRIPT_NAME=$(/usr/bin/basename $BASH_SOURCE)|| exit 100
FULL_PATH=$(/usr/bin/realpath ${BASH_SOURCE[0]})|| exit 100
set -o errtrace # Enable the err trap, code will get called when an error is detected
trap "echo ERROR: There was an error in ${FUNCNAME[0]-main context}, details to follow" ERR
declare CACHE_DIR="/tmp/$SCRIPT_NAME/$YYYYMMDD"

function message {
    message="$1"
    func_name="${2-unknown}"
    priority=6
    if [ -z "$2" ]; then
        echo "INFO:" $message
    else
        echo "ERROR:" $message
        priority=0
    fi
    /usr/bin/logger --journald<<EOF
MESSAGE_ID=$SCRIPT_NAME
MESSAGE=$message
PRIORITY=$priority
CODE_FILE=$FULL_PATH
CODE_FUNC=$func_name
EOF
}
```

You can see than we can store separate fields as part of the message, like the priority, the script that produced the message, etc.

So how this is useful? Well, you could gwt the messages between 1:26 PM and 1:27 PM, Only errors (priority=0) and only for our script (collect_data_from_servers.v6.sh) like this, output in JSON format:

```shell=
journalctl --since 13:26 --until 13:27 --output json-pretty PRIORITY=0 MESSAGE_ID=collect_data_from_servers.v6.sh
```

```json=
{
        "_BOOT_ID" : "dfcda9a1a1cd406ebd88a339bec96fb6",
        "_AUDIT_LOGINUID" : "1000",
        "SYSLOG_IDENTIFIER" : "logger",
        "PRIORITY" : "0",
        "_TRANSPORT" : "journal",
        "_SELINUX_CONTEXT" : "unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023",
        "__REALTIME_TIMESTAMP" : "1623518797641880",
        "_AUDIT_SESSION" : "3",
        "_GID" : "1000",
        "MESSAGE_ID" : "collect_data_from_servers.v6.sh",
        "MESSAGE" : "Copy failed for macmini2:/var/log/lshw-dump.json. Waiting '45 seconds' before re-trying...",
        "_CAP_EFFECTIVE" : "0",
        "CODE_FUNC" : "remote_copy",
        "_MACHINE_ID" : "60d7a3f69b674aaebb600c0e82e01d05",
        "_COMM" : "logger",
        "CODE_FILE" : "/home/josevnz/BashError/collect_data_from_servers.v6.sh",
        "_PID" : "41832",
        "__MONOTONIC_TIMESTAMP" : "25928272252",
        "_HOSTNAME" : "dmaf5",
        "_SOURCE_REALTIME_TIMESTAMP" : "1623518797641843",
        "__CURSOR" : "s=97bb6295795a4560ad6fdedd8143df97;i=1f826;b=dfcda9a1a1cd406ebd88a339bec96fb6;m=60972097c;t=5c494ed383898;x=921c71966b8943e3",
        "_UID" : "1000"
}
```

Nice, right?

Because this is structured data, other logs collectors can go through all your machines, aggregate your script logs and then you not only have data, but information.

You can take a loo at the whole [v6 of the script](https://github.com/josevnz/BashError/blob/main/collect_data_from_servers.v6.sh).


## Do not be so eager to replace your data until you have checked it

If you noticed from the very beginning, I've been copying a corrupted JSON file over an over:

```shell=
arse error: Expected separator between values at line 4, column 11
ERROR parsing '/home/josevnz/Documents/lshw-dump/lshw-dmaf5-dump.json'
```

That's easy to prevent. Copy the file into a temporary location and if the file is corrupted then do not attempt to replace the previous version (and leave the bad one for inspection. [Lines 99-107 of V7 of the script](https://github.com/josevnz/BashError/blob/main/collect_data_from_servers.v7.sh)):

```shell
function remote_copy {
    local server=$1
    check_previous_run $server
    test $? -eq 0 && message "$1 ran successfully before. Not doing again" && return 0
    local retries=$2
    local now=1
    status=0
    while [ $now -le $retries ]; do
        message "Trying to copy file from: $server, attempt=$now"
        /usr/bin/timeout --kill-after 25.0s 20.0s \
            /usr/bin/scp \
                -o BatchMode=yes \
                -o logLevel=Error \
                -o ConnectTimeout=5 \
                -o ConnectionAttempts=3 \
                ${server}:$REMOTE_FILE ${DATADIR}/lshw-$server-dump.json.$$
        status=$?
        if [ $status -ne 0 ]; then
            sleep_time=$(((RANDOM % 60)+ 1))
            message "Copy failed for $server:$REMOTE_FILE. Waiting '${sleep_time} seconds' before re-trying..." ${FUNCNAME[0]}
            /usr/bin/sleep ${sleep_time}s
        else
            break # All good, no point on waiting...
        fi
        ((now=now+1))
    done
    if [ $status -eq 0 ]; then
        /usr/bin/jq '.' ${DATADIR}/lshw-$server-dump.json.$$ > /dev/null 2>&1
        status=$?
        if [ $status -eq 0 ]; then
            /usr/bin/mv -v -f ${DATADIR}/lshw-$server-dump.json.$$ ${DATADIR}/lshw-$server-dump.json && mark_previous_run $server
            test $? -ne 0 && status=1
        else
            message "${DATADIR}/lshw-$server-dump.json.$$ Is corrupted. Leaving for inspection..." ${FUNCNAME[0]}
        fi
    fi
    return $status
}

```

## Choose the right tools for the task, prep your code from the first line

One very important aspect of error handling is proper coding. If you have bad logic in your code, no amount of error handling will make it better. To keep this short and Bash related, I'll give you below a few hints.

### You should ALWAYS check for error syntax before running your script:
```shell=
bash -n $my_bash_script.sh
```

Seriously. It should be like brushing your teeth after a meal (You brush your teeth, do you? :-))


### Read the Bash man page and get familiar with must know options

Like 
```shell=
set -xv
my_complicated_instruction1
my_complicated_instruction2
my_complicated_instruction3
set +xv
```

### Use ShellCheck to check your bash scripts

It is very easy to miss simple issues when your scripts start to grow large. [ShellCheck](https://github.com/koalaman/shellcheck) is one of those tools that will save you from making silly mistakes.

```shell=
shellcheck collect_data_from_servers.v7.sh

In collect_data_from_servers.v7.sh line 15:
for dependency in ${dependencies[@]}; do
                  ^----------------^ SC2068: Double quote array expansions to avoid re-splitting elements.


In collect_data_from_servers.v7.sh line 16:
    if [ ! -x $dependency ]; then
              ^---------^ SC2086: Double quote to prevent globbing and word splitting.

Did you mean: 
    if [ ! -x "$dependency" ]; then
...
```

If you are wondering, the final version of the script, after passing ShellCheck [is here](https://github.com/josevnz/BashError/blob/main/collect_data_from_servers.final.sh). Squeeke clean.


### You noticed something with the background scp processes...

* Yes!!!. You probably noticed than if the script is killed, it will leave some forked processes behind. _That is not good_ and this is one of the reasons I prefer to use tools like Ansible or Parallel to handle this type of tasks on multiple hosts, [letting the frameworks do proper cleanup for me](https://en.wikipedia.org/wiki/Reinventing_the_wheel). We can of course add more code to handle this situation.

* This Bash script could potentially create a fork bomb. It has no control of how many processes to spawn at the same time, which is a big problem in a real production environment. Also there is a limit on how many concurrent SSH sessions you can have (let alone consume bandwith). Again, I wrote this fictional example in Bash to show you how you can always improve a program to handle error betters.

## Summary

So let's recap what we learned here

1. You must check the return code of your commands. That could mean deciding to retry until a transitory condition improves or to short circuit the whole script
2. Speaking about transitory conditions,you don't need to start from scratch. You can save the status of successfull tasks and then retry from that point forward
3. Bash 'trap' is your friend. Use it for cleanup and error handling
4. When downloading data from any source, assume is corrupted. Never overwrite your good data set with fresh data until you have done some integrity checks.
5. Take advantage of journalctl and custom fields. You can perform sophisticated searches looking for issues, and even send that data to log aggregators
6. You can check the status of background tasks (including sub-shells). Just remember to save the PID and wait on it.
7. And finally: Use a Bash lint helper like [ShellCheck](https://github.com/josevnz/BashError/blob/main/collect_data_from_servers.final.sh). You can install it on your favorite editor (like VIM or PyCharm). You will be surprised how little errors go undetected on Bash scripts...

Let's have a conversation! Please drop your comments, I will do my best to get back to you with answers to your questions.

##
##

