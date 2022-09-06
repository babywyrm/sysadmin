#
https://stackoverflow.com/questions/6741523/using-python-fabric-without-the-command-line-tool-fab
#

##
##

##
##
##

  from fabric.api import env,run,execute,hosts

  # 1 - Set the (global) host_string
  env.host_string = "hamiltont@10.0.0.2"
  def foo():
    run("ps")
  execute(foo)

  # 2 - Set host string using execute's host param
  execute(foo, hosts=['hamiltont@10.0.0.2'])

  # 3 - Annotate the function and call it using execute
  @hosts('hamiltont@10.0.0.2')
  def bar():
    run("ps -ef")
  execute(bar)

##
##
##

9
Altough Fabric documentations refers to a way of using the library for SSH access without requiring the fab command-line tool and/or tasks, I can't seem to manage a way to do it.

I want to run this file (example.py) by only executing 'python example.py':

env.hosts = [ "example.com" ]
def ps():
    run("ps")
ps()
Thanks.

python
fabric
Share
Follow
asked Jul 19, 2011 at 2:05
user avatar
fabiopedrosa
2,46077 gold badges2929 silver badges4141 bronze badges
Add a comment
5 Answers
Sorted by:

Highest score (default)

16

I ended up doing this:

from fabric.api import env
from fabric.api import run

class FabricSupport:
    def __init__ (self):
        pass

    def run(self, host, port, command):
        env.host_string = "%s:%s" % (host, port)
        run(command)

myfab = FabricSupport()

myfab.run('example.com', 22, 'uname')
Which produces:

[example.com:22] run: uname
[example.com:22] out: Linux
Share
Follow
answered Dec 1, 2011 at 16:16
user avatar
blueFast
38.4k5555 gold badges189189 silver badges327327 bronze badges
Add a comment

Report this ad

4

#!/usr/bin/env python
from fabric.api import hosts, run, task
from fabric.tasks import execute

@task
@hosts(['user@host:port'])
def test():
    run('hostname -f')

if __name__ == '__main__':
   execute(test)
More information: http://docs.fabfile.org/en/latest/usage/library.html

Share
Follow
answered Dec 4, 2012 at 14:30
user avatar
semente
6,92933 gold badges3333 silver badges3535 bronze badges
Add a comment

4

Here are three different approaches all using the execute method

from fabric.api import env,run,execute,hosts

# 1 - Set the (global) host_string
env.host_string = "hamiltont@10.0.0.2"
def foo():
  run("ps")
execute(foo)

# 2 - Set host string using execute's host param
execute(foo, hosts=['hamiltont@10.0.0.2'])

# 3 - Annotate the function and call it using execute
@hosts('hamiltont@10.0.0.2')
def bar():
  run("ps -ef")
execute(bar)
For using keyfiles, you'll need to set either env.key or env.key_filename, as so:

env.key_filename = 'path/to/my/id_rsa'
# Now calls with execute will use this keyfile
execute(foo, hosts=['hamiltont@10.0.0.2'])
You can also supply multiple keyfiles and whichever one logs you into that host will be used

Share
Follow
edited Dec 13, 2014 at 3:01
community wiki
2 revs
Hamy
Can we pass the evn key in execute() – 
reetesh11
 Sep 22, 2017 at 10:16
Add a comment

Report this ad

3

Found my fix. I needed to provided my own *env.host_string* because changing env.user/env.keyfile/etc doesn't automatically updates this field.

Share
Follow
answered Jul 19, 2011 at 2:48
user avatar
fabiopedrosa
2,46077 gold badges2929 silver badges4141 bronze badges
3
Could you please post the complete code which was working for you? I can not seem to get it right from your answer. – 
blueFast
 Dec 1, 2011 at 14:43
Add a comment

1

This is what needs to be done:

in example.py

from fabric.api import settings, run

def ps():
  with settings(host_string='example.com'):
    run("ps")
ps()
see docs for using fabric as a library: http://docs.fabfile.org/en/1.8/usage/env.html#host-string

Share
Follow
