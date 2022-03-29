################
#
#


https://www.thepythoncode.com/article/executing-bash-commands-remotely-in-python
#
#

Fabric is a high level Python (2.7, 3.4+) library designed to execute shell commands remotely over SSH, yielding useful Python objects in return. It builds on top of Invoke (subprocess command execution and command-line features) and Paramiko (SSH protocol implementation), extending their APIs to complement one another and provide additional functionality.

For a high level introduction, including example code, please see our main project website; or for detailed API docs, see the versioned API website.

https://docs.fabfile.org/en/1.11/usage/output_controls.html
<br>
<br>
###########
<br>
<br>
You can hide errors and output if you want with settings and have it captured in log file by putting everything in file. 
generally i like do this like.


#######################
#######################

#
#
#

# ip_list.txt
192.168.xxx.x
127.0.0.1:xxxx
174.xxx.xxx.xxx:xxxx

# fabfile.py
from fabric.api import env, run, sudo

def hosts():
  # Read ip list from ip_list.txt
  env.hosts = open('ip_list.txt', 'r').readlines()

def uname():
  sudo('uname -a')
What does your sat_ip_list file look like - is it one IP address per line?

Have you tried your script with just a very small number of hosts, like 2-3 IP addresses? Definitely no reason you shouldn't be able to do what you're trying to accomplish, your script basically works for me just as it is.

As a sanity check, you might want to print out the value of env.hosts, like so:

def hosts():
  env.hosts = open('sat_ip_list', 'r').readlines()
  print('Hosts:', env.hosts) 
In my case, that results in the following output:

me@machine:~$ fab hosts
('Hosts:', ['192.168.xxx.x\n', '127.0.0.1:xxxx\n', '174.xxx.xxx.xxx:xxxx\n'])

#######################
#######################
#######################
##
##


def checkinstallation():
    with hide('output','warnings','running'):
        try:
            startlog()
            ...................
            ...................
            log('task done')
        except Exception, e:
            #print "%s host is down :: %s"%(env.host,str(e))
            log('bad host %s::%s'%(env.host,str(e)))


def startlog():
    import datetime
    i = datetime.datetime.now()
    logfile = open("output.txt", "a+")
    logfile.close()


def log(msg):
    logfile=open("output.txt","a+")
    logfile.write(msg + "\n")
    logfile.close()
Other way around is using system out,

$ fab taskname 2>&1 | tee output.txt
This will display log in screen as well as save output in output.txt

@hacpai
 
Author
hacpai commented on Jul 9, 2015
@hardikdangar Thank you.

Your python code don't record output in output.txt.

What can I write output to output.txt?

@hardikdangar
 
hardikdangar commented on Jul 9, 2015
All you need to do is run your task in variable and print that in log like,

ls = run('ls -lah')
log(ls)
This will save log of command/task your executing. for any exceptions we are recording that via exception.

####################################
####################################




Managing output¶
The fab tool is very verbose by default and prints out almost everything it can, including the remote end’s stderr and stdout streams, the command strings being executed, and so forth. While this is necessary in many cases in order to know just what’s going on, any nontrivial Fabric task will quickly become difficult to follow as it runs.

Output levels
To aid in organizing task output, Fabric output is grouped into a number of non-overlapping levels or groups, each of which may be turned on or off independently. This provides flexible control over what is displayed to the user.

Note
All levels, save for debug and exceptions, are on by default.

Standard output levels
The standard, atomic output levels/groups are as follows:

status: Status messages, i.e. noting when Fabric is done running, if the user used a keyboard interrupt, or when servers are disconnected from. These messages are almost always relevant and rarely verbose.
aborts: Abort messages. Like status messages, these should really only be turned off when using Fabric as a library, and possibly not even then. Note that even if this output group is turned off, aborts will still occur – there just won’t be any output about why Fabric aborted!
warnings: Warning messages. These are often turned off when one expects a given operation to fail, such as when using grep to test existence of text in a file. If paired with setting env.warn_only to True, this can result in fully silent warnings when remote programs fail. As with aborts, this setting does not control actual warning behavior, only whether warning messages are printed or hidden.
running: Printouts of commands being executed or files transferred, e.g. [myserver] run: ls /var/www. Also controls printing of tasks being run, e.g. [myserver] Executing task 'foo'.
stdout: Local, or remote, stdout, i.e. non-error output from commands.
stderr: Local, or remote, stderr, i.e. error-related output from commands.
user: User-generated output, i.e. local output printed by fabfile code via use of the fastprint or puts functions.
Changed in version 0.9.2: Added “Executing task” lines to the running output level.

Changed in version 0.9.2: Added the user output level.

Debug output
There are two more atomic output levels for use when troubleshooting: debug, which behaves slightly differently from the rest, and exceptions, whose behavior is included in debug but may be enabled separately.

debug: Turn on debugging (which is off by default.) Currently, this is largely used to view the “full” commands being run; take for example this run call:

run('ls "/home/username/Folder Name With Spaces/"')
Normally, the running line will show exactly what is passed into run, like so:

[hostname] run: ls "/home/username/Folder Name With Spaces/"
With debug on, and assuming you’ve left shell set to True, you will see the literal, full string as passed to the remote server:

[hostname] run: /bin/bash -l -c "ls \"/home/username/Folder Name With Spaces\""
Enabling debug output will also display full Python tracebacks during aborts (as if exceptions output was enabled).

Note
Where modifying other pieces of output (such as in the above example where it modifies the ‘running’ line to show the shell and any escape characters), this setting takes precedence over the others; so if running is False but debug is True, you will still be shown the ‘running’ line in its debugging form.

exceptions: Enables display of tracebacks when exceptions occur; intended for use when debug is set to False but one is still interested in detailed error info.

Changed in version 1.0: Debug output now includes full Python tracebacks during aborts.

Changed in version 1.11: Added the exceptions output level.

Output level aliases
In addition to the atomic/standalone levels above, Fabric also provides a couple of convenience aliases which map to multiple other levels. These may be referenced anywhere the other levels are referenced, and will effectively toggle all of the levels they are mapped to.

output: Maps to both stdout and stderr. Useful for when you only care to see the ‘running’ lines and your own print statements (and warnings).
everything: Includes warnings, running, user and output (see above.) Thus, when turning off everything, you will only see a bare minimum of output (just status and debug if it’s on), along with your own print statements.
commands: Includes stdout and running. Good for hiding non-erroring commands entirely, while still displaying any stderr output.
Changed in version 1.4: Added the commands output alias.

Hiding and/or showing output levels
You may toggle any of Fabric’s output levels in a number of ways; for examples, please see the API docs linked in each bullet point:

Direct modification of fabric.state.output: fabric.state.output is a dictionary subclass (similar to env) whose keys are the output level names, and whose values are either True (show that particular type of output) or False (hide it.)

fabric.state.output is the lowest-level implementation of output levels and is what Fabric’s internals reference when deciding whether or not to print their output.

Context managers: hide and show are twin context managers that take one or more output level names as strings, and either hide or show them within the wrapped block. As with Fabric’s other context managers, the prior values are restored when the block exits.

See also
settings, which can nest calls to hide and/or show inside itself.

Command-line arguments: You may use the --hide and/or --show arguments to fab options and arguments, which behave exactly like the context managers of the same names (but are, naturally, globally applied) and take comma-separated strings as input.

Prefix output
By default Fabric prefixes every line of ouput with either [hostname] out: or [hostname] err:. Those prefixes may be hidden by setting env.output_prefix to False.

