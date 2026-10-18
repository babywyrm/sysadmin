
###################
##  https://github.com/fabric/fabric/issues/1351
##  https://gist.githubusercontent.com/jsleetw/1471085/raw/a52e4b61eff7957fb64928beb14009399a5f4711/fabfile.py
################### 

from fabric.api import *
from fabric.colors import green,red,blue,cyan,yellow
import os , sys
import socket
import datetime
import logging
import logging.handlers
#get logger for logging 
def initLoggerWithRotate():
    logname=''.join(env.host_string.split('.'))+'.log'
    logFileName="logs/%s"%logname
    logger = logging.getLogger("fabric")
    formater = logging.Formatter("%(asctime)s %(name)s %(levelname)s %(message)s","%Y-%m-%d %H:%M:%S")
    file_handler = logging.handlers.RotatingFileHandler(logFileName, maxBytes=104857600, backupCount=5)
    file_handler.setFormatter(formater)
    stream_handler = logging.StreamHandler(sys.stderr)
    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)
    logger.setLevel(logging.INFO)
    return logger
#mkdir
def runmkdir(dir):
    run(''' mkdir -p %s '''%dir)
#stp 1 check host
def checkhost(logger):
     host = env.host_string 
     s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
     flag_c = 0
     try:
         s.connect((host, 22))
         flag_c = 1
         logger.info( green( ' --> host %s can be reachable ' %host ) )
     except socket.error as e: 
         logger.warning( yellow( ' --> Error on connect %s' %e ) )
     s.close()
     return flag_c
#stp 2 check alive instance on target host 
def checkmysqlinstance(logger):
    try:
        wc = run(''' ps -ef |grep mysqld|grep  -v safe | grep -v grep | wc -l  ''') 
        if int(wc) > 0  : 
            logger.warning(yellow( ' --> %sinstance exist on the target host  '%wc )) 
            portraw = run('''  ps -ef |grep mysqld|grep -v safe |grep -v grep  |awk ' {for(i=1;i<=NF;i++){if($i ~/--port/ ){print $i}}}' |awk -F '=' '{print $2}'
            ''')
            ports = [x.strip() for x in portraw.split() ]
            logger.warning( yellow( ' --> existing instance port : [ %s ] '%( ','.join( ports ))))
            if port in ports:
                logger.error( red( ' --> Install port %s exist , install failed '%port))
                logger.error( red( ' <<<exit>>>>>  task on host %s stop & exit() '%thost))
                sys.exit()
    except Exception, e:
        logger.warning(yellow( ' --> checkmysqlinstance() exception : %s '%e )) 
        raise e 
#stp 3 initdir for installation
def createUser(logger,user='mysql',group='dba'):
    try:
        if int(run('grep "^mysql" /etc/passwd|wc -l')) == 0 :
            run('groupadd dba ')
            run('useradd -c "mysql software owner" -g dba -G dba mysql')
            run('mkdir -p /home/mysql ; chown -R mysql.dba /home/mysql ')
            logger.info(cyan( ' --> create user [ mysql ] in group [ dba ]  success ' )) 
        else : 
            logger.info(yellow ( ' --> user [ mysql ] in group [ dba ] exist & skip  ' )) 
    except Exception, e:
        logger.warning(yellow( ' --> createUser() exception : %s '%e )) 
        raise e
#stp 4 initail directory for mysql        
def initdir(logger,port=3306):  
    try :
        logger.info( green( ' --> begin to create dirs for installation '))
        datadir='/data/'
        logdir ='/log/'
        mandir = 'mysql%s'%port
        subddir ='/data/mysql%s/{data,log,run,tmp}'%(port)
        subldir ='/log/mysql%s/{binlog,iblog}'%(port) 
        #data
        ck1 = run(' df -vh  | grep  /data | wc -l ')
        if ck1  == 0 : 
            logger.error(green(' --> no /data/ partition exist' ) )
            #sys.exit()
        if int( run(' ls /  | grep  /data | wc -l ')) == 0 or int( run(' ls /data/ | grep -w %s | wc -l '%mandir) ) == 0 : 
            runmkdir(subddir) 
            logger.info(green(' --> /data/*** create Ok ' ) )
        else : 
            logger.info(green(' --> /data/mysql%s exsit '%port ))
            logger.info(green(' --> pls,handle it and restart this task '))
            sys.exit()
        #log 
        ck2 = run(' df -vh | grep /log/  | wc -l  ')
        if int( run(' df -vh | grep /log/  | wc -l  ') ) == 0  and int( run(' ls / | grep -w log  | wc -l  ') ) == 0: 
            logger.warning( yellow(' --> no /log/ partition exist') ) 
            logger.warning( yellow(' --> create link for /log/ --> /data/log/') ) 
            runmkdir('/data/log')
            run('ln -s /data/log  /log ')
            runmkdir(subldir) 
            logger.info(green(' --> /log/*** create Ok ' ) )
        else : 
            if  int(run(' ls /log/ | grep -w %s | wc -l '%mandir)) == 0: 
                runmkdir(subldir) 
                logger.info(green(' --> /log/*** create Ok ' ) )
            else : 
                logger.info(yellow(' --> /log/mysql%s exsit '%port ))
                logger.error(red(' --> pls,handle it and restart this task ' ))
                sys.exit() 
        #change 
        runmkdir('/data/tmp')
        logger.info(green(' --> change dirs owner&privs start'))
        run('chown -R mysql:dba /data/*')
        run('chown -R mysql:dba /log') 
        logger.info(green(' --> change dirs owner&privs done'))
    except Exception, e:
        logger.warning(yellow( ' --> initdir() exception : %s '%e )) 
        raise e 
#stp 5 put mysql install package
def copymysql(logger,version='5.7'): 
    try:
        dits = {
        'ubuntu':'mysql-server_5.6.21-1ubuntu12.04_amd64.deb-bundle.tar',
        'centos':'mysql-server.tar.gz'
        }
        issue = run ('cat /etc/issue') 
        ss = issue.lower()
        logger.info( green( ' %s '%ss))
        if int ( run( ' ls /usr/local/ | grep mysql | wc -l ') ) > 0 : 
            logger.info( yellow( ' --> mysql software installed , skip   ' )) 
            return
        plats = dits.keys()
        for x in plats: 
            if ss.find(x) != -1: 
                logger.info( green( ' --> the target host platform is %s'% x ) )
                put( local_path="configs/%s"%dits[x],remote_path="/tmp/%s"%dits[x] )
                logger.info( green( ' --> tar the ball to prop dir '))
                run( 'tar zxvf /tmp/%s -C /usr/local/ '%dits[x] )
                run( 'ln -s /usr/local/%s  /usr/local/mysql  '%dits[x][:-7] )
                break 
    except Exception, e:
        logger.warning(yellow( ' --> copymysql() exception : %s '%e )) 
        raise e 
#gen my.cnf file 
def getnewServerId(logger,port):  
    host = env.host_string
    print 'getnewServerId : ',host
    pics = host.split('.')
    a=int(pics[0])
    b=int(pics[1])
    c=int(pics[2])
    d=int(pics[3])
    suf = int(port) % 256
    server_id =  b * 256 * 256 * 256 + c * 256 * 256 + d * 256 + suf
    logger.info( cyan( ' --> gen server_id done , %s %s is %s '%( host , port , server_id) ) )
    return server_id
def genmycnf(logger,port=3306,itype='h'):
    host = env.host_string
    bps={
    "a":"48|32|3100|3000",
    "b":"62|40|4600|4500",
    'c':'94|64|7600|7500',
    'd':'94|32|3100|3000',
    'e':'125|75|10100|10000',
    'f':'188|120|15100|15000',
    'g':'188|60|7600|7500',
    'h':'1|256M|800|750'
    } 
    try:
        myfile=''.join(host.split('.'))+'.cnf'
        cpmycnf="""cp configs/my.cnf  tmp/%s """%myfile 
        local( 'rm -f  tmp/%s'%myfile  )
        local("cp configs/my.cnf tmp/%s "%myfile )  
        sid=getnewServerId(logger,port)
        keys=bps.keys()
        bpxs=bps[itype]
        mem,bpsize,maxc,maxuc=bpxs.split('|')
        if bpsize[-1] != "M":
            bpsize = bpsize +'g'
        chrgcmd="""  sed -i -e "s/3306/%s/g" -e "s/server_id=10000/server_id=%s/g" -e "s/=32g/=%s/g" -e "s/max_connections=3100/max_connections=%s/g" -e "s/max_user_connections=3000/max_user_connections=%s/g" tmp/%s """
        local( chrgcmd%(port,sid,bpsize,maxc,maxuc,myfile) ) 
        logger.info( green( ' --> gen my.cnf success  ') )
        logger.info( green( ' --> copy my.cnf to dist host ') )
        put( local_path="tmp/%s"%myfile, remote_path="/data/mysql%s/my.cnf"%(port) )
    except Exception, e:
        logger.warning(yellow( ' --> genmycnf() exception : %s '%traceback.format_exc()  ) ) 
        raise e 

############################

"""

This fabric file makes setting up and deploying a django application much
easier, but it does make a few assumptions. Namely that you're using Git,
Apache and mod_wsgi and your using Debian or Ubuntu. Also you should have 
Django installed on your local machine and SSH installed on both the local
machine and any servers you want to deploy to.

_note that I've used the name project_name throughout this example. Replace
this with whatever your project is called._

First step is to create your project locally:

    mkdir project_name
    cd project_name
    django-admin.py startproject project_name

Now add a requirements file so pip knows to install Django. You'll probably
add other required modules in here later. Creat a file called requirements.txt
and save it at the top level with the following contents:

    Django
    
Then save this fabfile.py file in the top level directory which should give you:
    
    project_name
        fabfile.py
        requirements.txt
        project_name
            __init__.py
            manage.py
            settings.py
            urls.py

You'll need a WSGI file called project_name.wsgi, where project_name 
is the name you gave to your django project. It will probably look 
like the following, depending on your specific paths and the location
of your settings module

    import os
    import sys

    # put the Django project on sys.path
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../")))

    os.environ["DJANGO_SETTINGS_MODULE"] = "project_name.settings"

    from django.core.handlers.wsgi import WSGIHandler
    application = WSGIHandler()

Last but not least you'll want a virtualhost file for apache which looks 
something like the following. Save this as project_name in the inner directory.
You'll want to change /path/to/project_name/ to the location on the remote
server you intent to deploy to.

    <VirtualHost *:80>
        WSGIDaemonProcess project_name-production user=project_name group=project_name threads=10 python-path=/path/to/project_name/lib/python2.6/site-packages
        WSGIProcessGroup project_name-production

        WSGIScriptAlias / /path/to/project_name/releases/current/project_name/project_name.wsgi
        <Directory /path/to/project_name/releases/current/project_name>
            Order deny,allow
            Allow from all
        </Directory>

        ErrorLog /var/log/apache2/error.log
        LogLevel warn

        CustomLog /var/log/apache2/access.log combined
    </VirtualHost>

Now create a file called .gitignore, containing the following. This
prevents the compiled python code being included in the repository and
the archive we use for deployment.

    *.pyc

You should now be ready to initialise a git repository in the top
level project_name directory.

    git init
    git add .gitignore project_name
    git commit -m "Initial commit"

All of that should leave you with 
    
    project_name
        .git
        .gitignore
        requirements.txt
        fabfile.py
        project_name
            __init__.py
            project_name
            project_name.wsgi
            manage.py
            settings.py
            urls.py

In reality you might prefer to keep your wsgi files and virtual host files
elsewhere. The fabfile has a variable (config.virtualhost_path) for this case. 
You'll also want to set the hosts that you intend to deploy to (config.hosts)
as well as the user (config.user).

The first task we're interested in is called setup. It installs all the 
required software on the remote machine, then deploys your code and restarts
the webserver.

    fab local setup

After you've made a few changes and commit them to the master Git branch you 
can run to deply the changes.
    
    fab local deploy

If something is wrong then you can rollback to the previous version.

    fab local rollback
    
Note that this only allows you to rollback to the release immediately before
the latest one. If you want to pick a arbitrary release then you can use the
following, where 20090727170527 is a timestamp for an existing release.

    fab local deploy_version:20090727170527

If you want to ensure your tests run before you make a deployment then you can 
do the following.

    fab local test deploy

"""

# globals

config.project_name = 'project_name'

# environments

def local():
    "Use the local virtual server"
    config.hosts = ['172.16.142.130']
    config.path = '/path/to/project_name'
    config.user = 'garethr'
    config.virtualhost_path = "/"

# tasks

def test():
    "Run the test suite and bail out if it fails"
    local("cd $(project_name); python manage.py test", fail="abort")

def setup():
    """
    Setup a fresh virtualenv as well as a few useful directories, then run
    a full deployment
    """
    require('hosts', provided_by=[local])
    require('path')
    
    sudo('aptitude install -y python-setuptools')
    sudo('easy_install pip')
    sudo('pip install virtualenv')
    sudo('aptitude install -y apache2')
    sudo('aptitude install -y libapache2-mod-wsgi')
    # we want rid of the defult apache config
    sudo('cd /etc/apache2/sites-available/; a2dissite default;')
    run('mkdir -p $(path); cd $(path); virtualenv .;')
    run('cd $(path); mkdir releases; mkdir shared; mkdir packages;', fail='ignore')
    deploy()

def deploy():
    """
    Deploy the latest version of the site to the servers, install any
    required third party modules, install the virtual host and 
    then restart the webserver
    """
    require('hosts', provided_by=[local])
    require('path')

    import time
    config.release = time.strftime('%Y%m%d%H%M%S')

    upload_tar_from_git()
    install_requirements()
    install_site()
    symlink_current_release()
    migrate()
    restart_webserver()

def deploy_version(version):
    "Specify a specific version to be made live"
    require('hosts', provided_by=[local])
    require('path')
    
    config.version = version
    run('cd $(path); rm releases/previous; mv releases/current releases/previous;')
    run('cd $(path); ln -s $(version) releases/current')
    restart_webserver()

def rollback():
    """
    Limited rollback capability. Simple loads the previously current
    version of the code. Rolling back again will swap between the two.
    """
    require('hosts', provided_by=[local])
    require('path')

    run('cd $(path); mv releases/current releases/_previous;')
    run('cd $(path); mv releases/previous releases/current;')
    run('cd $(path); mv releases/_previous releases/previous;')
    restart_webserver()
    
# Helpers. These are called by other functions rather than directly

def upload_tar_from_git():
    require('release', provided_by=[deploy, setup])
    "Create an archive from the current Git master branch and upload it"
    local('git archive --format=tar master | gzip > $(release).tar.gz')
    run('mkdir $(path)/releases/$(release)')
    put('$(release).tar.gz', '$(path)/packages/')
    run('cd $(path)/releases/$(release) && tar zxf ../../packages/$(release).tar.gz')
    local('rm $(release).tar.gz')

def install_site():
    "Add the virtualhost file to apache"
    require('release', provided_by=[deploy, setup])
    sudo('cd $(path)/releases/$(release); cp $(project_name)$(virtualhost_path)$(project_name) /etc/apache2/sites-available/')
    sudo('cd /etc/apache2/sites-available/; a2ensite $(project_name)') 

def install_requirements():
    "Install the required packages from the requirements file using pip"
    require('release', provided_by=[deploy, setup])
    run('cd $(path); pip install -E . -r ./releases/$(release)/requirements.txt')

def symlink_current_release():
    "Symlink our current release"
    require('release', provided_by=[deploy, setup])
    run('cd $(path); rm releases/previous; mv releases/current releases/previous;', fail='ignore')
    run('cd $(path); ln -s $(release) releases/current')

def migrate():
    "Update the database"
    require('project_name')
    run('cd $(path)/releases/current/$(project_name);  ../../../bin/python manage.py syncdb --noinput')

def restart_webserver():
    "Restart the web server"
    sudo('/etc/init.d/apache2 restart')


############################
############################

