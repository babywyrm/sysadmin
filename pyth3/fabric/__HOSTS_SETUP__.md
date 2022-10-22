
##
##
#
https://stackoverflow.com/questions/2326797/how-to-set-target-hosts-in-fabric-file
#
##
##

Obvi.


    def set_hosts():
        env.hosts = open('hosts_file', 'r').readlines()  
    
##
##


I want to use Fabric to deploy my web app code to development, staging and production servers. My fabfile:

    def deploy_2_dev():
        deploy('dev')

    def deploy_2_staging():
        deploy('staging')

    def deploy_2_prod():
        deploy('prod')

    def deploy(server):
        print 'env.hosts:', env.hosts
        env.hosts = [server]
        print 'env.hosts:', env.hosts

Sample output:

host:folder user$ fab deploy_2_dev
env.hosts: []
env.hosts: ['dev']
No hosts found. Please specify (single) host string for connection:

When I create a set_hosts() task as shown in the Fabric docs, env.hosts is set properly. However, this is not a viable option, neither is a decorator. Passing hosts on the command line would ultimately result in some kind of shell script that calls the fabfile, I would prefer having one single tool do the job properly.

It says in the Fabric docs that 'env.hosts is simply a Python list object'. From my observations, this is simply not true.

Can anyone explain what is going on here ? How can I set the host to deploy to ?
python
host
fabric
Share
Follow
edited Mar 14, 2010 at 12:58
user avatar
skaffman
393k9696 gold badges805805 silver badges764764 bronze badges
asked Feb 24, 2010 at 14:45
user avatar
ssc
9,07688 gold badges5757 silver badges9090 bronze badges

    I have the same problem, have you found any solution to this? – 
    Martin M.
    Mar 8, 2010 at 10:47
    to run the same task against multiple servers, use "fab -H staging-server,production-server deploy"... more in my answer below: stackoverflow.com/a/21458231/26510 – 
    Brad Parks
    Jan 30, 2014 at 13:46
    Try this: docs.fabfile.org/en/1.13/usage/env.html#passwords – 
    Dhruv Aggarwal
    Nov 4, 2017 at 12:41
    This answer does not apply to fabric 2+. If someone more familiar with Stackoverflow conventions could edit the question or question title to refer to fabric 1 it might be helpful. – 
    Jonathan Berger
    May 7, 2019 at 0:12

Add a comment
15 Answers
Sorted by:
130

I do this by declaring an actual function for each environment. For example:

def test():
    env.user = 'testuser'
    env.hosts = ['test.server.com']

def prod():
    env.user = 'produser'
    env.hosts = ['prod.server.com']

def deploy():
    ...

Using the above functions, I would type the following to deploy to my test environment:

fab test deploy

...and the following to deploy to production:

fab prod deploy

The nice thing about doing it this way is that the test and prod functions can be used before any fab function, not just deploy. It is incredibly useful.
Share
Follow
answered Jan 14, 2011 at 0:53
user avatar
Zac
1,57911 gold badge1111 silver badges1010 bronze badges

    11
    Due to a bug in fabric (code.fabfile.org/issues/show/138#change-1497) it is better to include user in host string (like produser@prod.server.com) instead of setting env.user. – 
    Mikhail Korobov
    Feb 16, 2011 at 0:45
    1
    I had the same problem, and this seems like the best solution. I define the hosts, user and a lot of other settings in a YAML file that is loaded by the dev() and prod() functions. (So that I can reuse the same Fabric script for similar projects.) – 
    Christian Davén
    Apr 4, 2011 at 8:46
    @MikhailKorobov: When I followed your link, I saw "Welcome to nginx!". All the requests to code.fabfile.org domain have responses like that. – 
    Tadeck
    Apr 4, 2012 at 19:40
    Yeah, it seems all bugs were migrated to github. – 
    Mikhail Korobov
    Apr 4, 2012 at 22:32
    2
    Unfortunately, it looks like this no longer works - fabric won't run tasks without env.hosts already defined, and won't run functions in the fab A B C style without them being defined as tasks. – 
    DNelson
    Jul 2, 2015 at 17:00

Show 2 more comments
Report this ad
77

Use roledefs

from fabric.api import env, run

env.roledefs = {
    'test': ['localhost'],
    'dev': ['user@dev.example.com'],
    'staging': ['user@staging.example.com'],
    'production': ['user@production.example.com']
} 

def deploy():
    run('echo test')

Choose role with -R:

$ fab -R test deploy
[localhost] Executing task 'deploy'
...

Share
Follow
answered Jun 11, 2011 at 0:22
user avatar
thomie
1,39499 silver badges1818 bronze badges

    7
    Or if the task is always run on the same role, you can use the @roles() decorator on the task. – 
    Tom
    Aug 14, 2012 at 18:19
    2
    Sounds like roledefs is a better solution than defining them in separate tasks. – 
    Ehtesh Choudhury
    Oct 16, 2014 at 1:45
    Does anybody know how I can include a password for the provided username in a roledef? A further dictionary entry 'password': 'some_password' seems to be ignored and leads to a prompt at runtime. – 
    Dirk
    Jun 16, 2016 at 13:02
    @Dirk you can use env.passwords which is a dictionary containing user+host+port as key and password as value. E.g. env.passwords={'user@host:22' : 'password'} – 
    Jonathan
    Nov 11, 2016 at 11:17

Add a comment
49

Here's a simpler version of serverhorror's answer:

from fabric.api import settings

def mystuff():
    with settings(host_string='192.0.2.78'):
        run("hostname -f")

Share
Follow
edited May 18, 2020 at 7:51
answered Jun 17, 2011 at 8:31
user avatar
tobych
2,8512727 silver badges1818 bronze badges

    2
    Per the docs, the settings context manager is for overriding env variables, not for setting them initially. I think using roledefs, as thomie suggested, is more appropriate for defining hosts like stage, dev and test. – 
    Tony
    Feb 6, 2013 at 23:13 

Add a comment
Report this ad
21

Was stuck on this myself, but finally figured it out. You simply can't set the env.hosts configuration from within a task. Each task is executed N times, once for each Host specified, so the setting is fundamentally outside of task scope.

Looking at your code above, you could simply do this:

@hosts('dev')
def deploy_dev():
    deploy()

@hosts('staging')
def deploy_staging():
    deploy()

def deploy():
    # do stuff...

Which seems like it would do what you're intending.

Or you can write some custom code in the global scope that parses the arguments manually, and sets env.hosts before your task function is defined. For a few reasons, that's actually how I've set mine up.
Share
Follow
answered Mar 2, 2010 at 21:07
user avatar
GoldenBoy
1,37111 gold badge88 silver badges1111 bronze badges

    Found a way: from fabric.api import env; env.host_string = "dev" – 
    Roman
    Jan 20, 2017 at 11:12 

Add a comment
18

Since fab 1.5 this is a documented way to dynamically set hosts.

http://docs.fabfile.org/en/1.7/usage/execution.html#dynamic-hosts

Quote from the doc below.

    Using execute with dynamically-set host lists

    A common intermediate-to-advanced use case for Fabric is to parameterize lookup of one’s target host list at runtime (when use of Roles does not suffice). execute can make this extremely simple, like so:

from fabric.api import run, execute, task

# For example, code talking to an HTTP API, or a database, or ...
from mylib import external_datastore

# This is the actual algorithm involved. It does not care about host
# lists at all.
def do_work():
    run("something interesting on a host")

# This is the user-facing task invoked on the command line.
@task
def deploy(lookup_param):
    # This is the magic you don't get with @hosts or @roles.
    # Even lazy-loading roles require you to declare available roles
    # beforehand. Here, the sky is the limit.
    host_list = external_datastore.query(lookup_param)
    # Put this dynamically generated host list together with the work to be
    # done.
    execute(do_work, hosts=host_list)

Share
Follow
edited Dec 12, 2014 at 8:35
answered Aug 21, 2013 at 20:58
user avatar
j-a
1,75011 gold badge2121 silver badges1919 bronze badges

    3
    +1. A lot of really good answers toward the bottom of the page here. – 
    Matt Montag
    Aug 19, 2014 at 23:24

Add a comment
10

Contrary to some other answers, it is possible to modify the env environment variables within a task. However, this env will only be used for subsequent tasks executed using the fabric.tasks.execute function.

from fabric.api import task, roles, run, env
from fabric.tasks import execute

# Not a task, plain old Python to dynamically retrieve list of hosts
def get_stressors():
    hosts = []
    # logic ...
    return hosts

@task
def stress_test():
    # 1) Dynamically generate hosts/roles
    stressors = get_stressors()
    env.roledefs['stressors'] = map(lambda x: x.public_ip, stressors)

    # 2) Wrap sub-tasks you want to execute on new env in execute(...)
    execute(stress)

    # 3) Note that sub-tasks not nested in execute(...) will use original env
    clean_up()

@roles('stressors')
def stress():
    # this function will see any changes to env, as it was wrapped in execute(..)
    run('echo "Running stress test..."')
    # ...

@task
def clean_up():
    # this task will NOT see any dynamic changes to env

Without wrapping sub-tasks in execute(...), your module-level env settings or whatever is passed from the fab CLI will be used.
Share
Follow
answered Jun 3, 2013 at 3:06
user avatar
pztrick
3,6512828 silver badges3535 bronze badges

    This is the best answer if you want to dynamically set env.hosts. – 
    JahMyst
    Mar 16, 2016 at 17:11

Add a comment
9

You need to set host_string an example would be:

from fabric.context_managers import settings as _settings

def _get_hardware_node(virtualized):
    return "localhost"

def mystuff(virtualized):
    real_host = _get_hardware_node(virtualized)
    with _settings(
        host_string=real_host):
        run("echo I run on the host %s :: `hostname -f`" % (real_host, ))

Share
Follow
edited Mar 14, 2010 at 12:46
answered Mar 10, 2010 at 9:52
user avatar
Martin M.
78055 silver badges2020 bronze badges

    Sweet. I've posted a simpler version of the code in another answer here. – 
    tobych
    Jun 17, 2011 at 8:31

Add a comment
9

To explain why it's even an issue. The command fab is leveraging fabric the library to run the tasks on the host lists. If you try and change the host list inside a task, you're esentially attempting to change a list while iterating over it. Or in the case where you have no hosts defined, loop over an empty list where the code where you set the list to loop over is never executed.

The use of env.host_string is a work around for this behavior only in that it's specifying directly to the functions what hosts to connect with. This causes some issues in that you'll be remaking the execution loop if you want to have a number of hosts to execute on.

The simplest way the people make the ability to set hosts at run time, is to keep the env populatiing as a distinct task, that sets up all the host strings, users, etc. Then they run the deploy task. It looks like this:

fab production deploy

or

fab staging deploy

Where staging and production are like the tasks you have given, but they do not call the next task themselves. The reason it has to work like this, is that the task has to finish, and break out of the loop (of hosts, in the env case None, but it's a loop of one at that point), and then have the loop over the hosts (now defined by the preceding task) anew.
Share
Follow
answered Mar 28, 2011 at 21:50
user avatar
Morgan
4,1432626 silver badges3434 bronze badges
Add a comment
3

You need to modify env.hosts at the module level, not within a task function. I made the same mistake.

from fabric.api import *

def _get_hosts():
    hosts = []
    ... populate 'hosts' list ...
    return hosts

env.hosts = _get_hosts()

def your_task():
    ... your task ...

Share
Follow
answered Aug 10, 2010 at 14:24
user avatar
mlbright
2,13122 gold badges1717 silver badges1313 bronze badges
Add a comment
3

It's very simple. Just initialize the env.host_string variable and all of the following commands will be executed on this host.

from fabric.api import env, run

env.host_string = 'user@exmaple.com'

def foo:
    run("hostname -f")

Share
Follow
answered Nov 27, 2011 at 20:53
user avatar
Vladimir Osintsev
9622 silver badges44 bronze badges
Add a comment
3

I'm totally new to fabric, but to get fabric to run the same commands on multiple hosts (e.g. to deploy to multiple servers, in one command) you can run:

fab -H staging-server,production-server deploy 

where staging-server and production-server are 2 servers you want to run the deploy action against. Here's a simple fabfile.py that will display the OS name. Note that the fabfile.py should be in the same directory as where you run the fab command.

from fabric.api import *

def deploy():
    run('uname -s')

This works with fabric 1.8.1 at least.
Share
Follow
answered Jan 30, 2014 at 13:45
user avatar
Brad Parks
61.5k6161 gold badges248248 silver badges311311 bronze badges
Add a comment
3

So, in order to set the hosts, and have the commands run across all the hosts, you have to start with:

def PROD():
    env.hosts = ['10.0.0.1', '10.0.0.2']

def deploy(version='0.0'):
    sudo('deploy %s' % version)

Once those are defined, then run the command on the command line:

fab PROD deploy:1.5

What will run the deploy task across all of the servers listed in the PROD function, as it sets the env.hosts before running the task.
Share
Follow
answered Apr 4, 2014 at 22:00
user avatar
athros
3111 bronze badge

    Suppose the deployment on the first host worked but the one on the second failed, how do I do it again only on the second one? – 
    nos
    May 8, 2019 at 19:32

Add a comment
2

You can assign to env.hoststring before executing a subtask. Assign to this global variable in a loop if you want to iterate over multiple hosts.

Unfortunately for you and me, fabric is not designed for this use case. Check out the main function at http://github.com/bitprophet/fabric/blob/master/fabric/main.py to see how it works.
Share
Follow
answered May 11, 2010 at 22:51
user avatar
Andrew B.
1,20611 gold badge1313 silver badges1818 bronze badges
Add a comment
2

Here's another "summersault" pattern that enables the fab my_env_1 my_command usage:

With this pattern, we only have to define environments one time using a dictionary. env_factory creates functions based on the keynames of ENVS. I put ENVS in its own directory and file secrets.config.py to separate config from the fabric code.

The drawback is that, as written, adding the @task decorator will break it.

Notes: We use def func(k=k): instead of def func(): in the factory because of late binding. We get the running module with this solution and patch it to define the function.

secrets.config.py

ENVS = {
    'my_env_1': {
        'HOSTS': [
            'host_1',
            'host_2',
        ],
        'MY_OTHER_SETTING': 'value_1',
    },
    'my_env_2': {
        'HOSTS': ['host_3'],
        'MY_OTHER_SETTING': 'value_2'
    }
}

fabfile.py

import sys
from fabric.api import env
from secrets import config


def _set_env(env_name):
    # can easily customize for various use cases
    selected_config = config.ENVS[env_name]
    for k, v in selected_config.items():
        setattr(env, k, v)


def _env_factory(env_dict):
    for k in env_dict:
        def func(k=k):
            _set_env(k)
        setattr(sys.modules[__name__], k, func)


_env_factory(config.ENVS)

def my_command():
    # do work

Share
Follow
edited May 23, 2017 at 12:18
user avatar
CommunityBot
111 silver badge
answered Mar 26, 2017 at 17:03
user avatar
whp
1,28699 silver badges99 bronze badges
Add a comment
0

Using roles is currently considered to be the "proper" and "correct" way of doing this and is what you "should" do it.

That said, if you are like most of what you "would like" or "desire" is the ability to perform a "twisted syster" or switching target systems on the fly.

So for entertainment purposes only (!) the following example illustrates what many might consider to a risky, and yet somehow thoroughly satisfying, manoeuvre that goes something like this:

env.remote_hosts       = env.hosts = ['10.0.1.6']
env.remote_user        = env.user = 'bob'
env.remote_password    = env.password = 'password1'
env.remote_host_string = env.host_string

env.local_hosts        = ['127.0.0.1']
env.local_user         = 'mark'
env.local_password     = 'password2'

def perform_sumersault():
    env_local_host_string = env.host_string = env.local_user + '@' + env.local_hosts[0]
    env.password = env.local_password
    run("hostname -f")
    env.host_string = env.remote_host_string
    env.remote_password = env.password
    run("hostname -f")

Then running:

fab perform_sumersault

