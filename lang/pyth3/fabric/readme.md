################

# A Brief Introduction to Fabric

[Fabric](http://docs.fabfile.org) is a deployment management framework written in Python which makes remotely managing multiple servers incredibly easy. If you've ever had to issue a change to a group servers, this should look pretty familiar:

```bash
for s in $(cat servers.txt); do ssh $s service httpd graceful; done
```

Fabric improves on this process by providing a suite of functions to run commands on the servers, as well as a number of other features which just aren't possible in a simple for loop. While a working knowledge of Python is helpful when using Fabric, it certainly isn't necessary. This tutorial will cover the steps necessary to get started with the framework and introduce how it can be used to improve on administering groups of servers.

## Installing Fabric
One of the best things about Fabric is that the systems which you are remotely administering require nothing beyond the standard OpenSSH server. The master server which you are running Fabric from will, however, need a few things installed before you can get started. Let's get started.

#### Requirements

* Python 2.5+ with the development headers
* python-setuptools and pip (optional, but preferred)
* gcc

If you already have all of these dependencies, you can just run `pip install fabric` and move on to the next section. Otherwise, here are some instructions for getting them installed:

#### CentOS/RHEL 6.x
```
# yum install gcc python-devel python-setuptools
# easy_install pip
# pip install fabric
```

#### CentOS/RHEL 5.x
*Note:* Because Python 2.5+ is a requirement, older versions of RHEL and CentOS will need to use the [EPEL repositories](http://fedoraproject.org/wiki/EPEL) or install Python from source. We'll be working under the assumption that you are already using EPEL.

```
# yum install python26 python26-devel python26-setuptools gcc
# easy_install-2.6 pip
# pip install fabric
```

#### Ubuntu 10.04+
```
# apt-get install python-dev python-setuptools gcc
# easy_install pip
# pip install fabric
```

## Using Fabric

Now for the fun part. The installation process added a Python script called `fab` to a directory in your path (hopefully). This is the script which will be used to make magic happen with Fabric. However, just running `fab` from the command-line won't do much at all. In order to do anything interesting, we'll need to create our first fabfile. 

#### Creating a fabfile
The fabfile is where all of your functions, roles, configurations, etc. will be defined. It's just a little bit of Python which tells Fabric exactly what it needs to do. By convention, this file should be named `fabfile.py`, but you can name it anything you'd like. Just keep in mind that if it's something other than fabfile.py, you'll need to specify the path with `fab -f /path/to/notfabfile.py`. Here's a simple example which runs `uptime` locally:

**fabfile.py**

``` python
#!/usr/bin/env python
from fabric.api import local

def uptime():
  local('uptime')
```

Now, let's run the script by calling the uptime function with `fab uptime`:

```
# fab uptime
[localhost] local: uptime
 17:19:31 up 29 min,  1 user,  load average: 0.03, 0.04, 0.06

Done.
```

Sweet! Well, not really. There's nothing too special about just running commands locally. Let's learn some more about what Fabric can do so that we can get this show on the road.

#### Remote Administration

The Fabric API uses a configuration dictionary (Python's equivalent of an associative array orhash table) known as **env** to store values which control Fabric's behavior. There are [a number of options available](http://docs.fabfile.org/en/1.4.0/usage/env.html), but for the purposes of this tutorial, we will be focused on **env.hosts**. env.hosts is a list (Python array) of servers which you wish to connect to when running Fabric tasks. 

For instance, if you were managing 192.168.1.100-102 with your fabfile, you could configure the following env.hosts: 

``` python
#!/usr/bin/env python

from fabric.api import env

env.hosts = [ '192.168.1.100', '192.168.1.101', '192.168.1.102' ]
```

Obviously, this is a pretty contrived example. Without any tasks defined, Fabric won't do much at all. So let's make some. Fabric provides a set of functions which can be used to interact with these remote hosts. Here are the most commonly used ones:

* *run* - Run a shell command on a remote host.
* *sudo* - Run a shell command on a remote host, with superuser privileges.
* *get* - Download one or more files from a remote host.
* *put* - Upload one or more files to a remote host.

See the Fabric Wiki for a [full list of operations](http://docs.fabfile.org/en/1.4.0/api/core/operations.html).

Let's put this all together and create a basic fabfile.py which runs `uptime` on each of the remote hosts.

``` python
#!/usr/bin/env python

from fabric.api import env, run

env.hosts = [ '192.168.1.100', '192.168.1.101', '192.168.1.102' ]

def uptime():
  run('uptime')
```

Pretty simple, right? Now let's run it by calling `fab uptime` again from the command line:

```
# fab -P uptime
[192.168.1.100] Executing task 'uptime'
[192.168.1.101] Executing task 'uptime'
[192.168.1.102] Executing task 'uptime'
[192.168.1.100] run: uptime
[192.168.1.101] run: uptime
[192.168.1.102] run: uptime
[192.168.1.100] out:  12:42:05 up 15 min,  1 user,  load average: 0.00, 0.02, 0.03

[192.168.1.101] out:  12:42:05 up 16 min,  1 user,  load average: 0.00, 0.01, 0.01

[192.168.1.102] out:  12:42:05 up 16 min,  1 user,  load average: 0.00, 0.01, 0.02


Done.
```

You may have noticed the `-P` when I ran the task. This tells Fabric to run the commands asynchronously (in parallel). As with any other application, run `fab -h` for a full list of command line options.

## Conclusions
That's about it for this crash course on Fabric. Check out some of the additional reading to learn more about how to use Fabric.

#### Additional Reading
* [The Fabric Wiki](http://docs.fabfile.org/en/1.4.0/index.html)
* Read some [fabfile.py examples](https://www.google.com/search?q=site%3Agist.github.com+fabfile.py) on gist.github.com.
* Check out [Fabrack](https://github.com/DavidWittman/fabrack), my library for integrating Fabric with the Rackspace Cloud API


##
##
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

#
#
#########
#########
#
#

Roles
You can define roles in Fabric, and only run actions on servers tied to a
specific role. 

This script will run get_version on hosts members of the role "webservers",
by running first on www1, then www2 etc.
fab -R webservers
from fabric.api import *

# Define sets of servers as roles

env.roledefs = {
    'webservers': ['www1', 'www2', 'www3', 'www4', 'www5'],
    'databases': ['db1', 'db2']
}

# Set the user to use for ssh
env.user = 'fabuser'

# Restrict the function to the 'webservers' role

@roles('webservers')

def get_version():
    run('cat /etc/issue')
# To run get_version on both roles (webservers and databases);
$ fab get_version
@roles ('webservers', 'databases')

    def get_version():

 run('cat /etc/issue')
Any function you write in your fab script can be assigned to one or more roles. 

You can also include a single server in multiple roles.


##
##

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

