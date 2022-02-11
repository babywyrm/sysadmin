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
