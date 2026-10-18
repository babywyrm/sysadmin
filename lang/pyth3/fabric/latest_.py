#!/usr/bin/python3

#########################
#########################
##

import os,sys,re
from fabric.api import env, run, task

@task
def check_hosts():
    run('hostname')

#########################
## env.roledefs['webservers'] = ['www1', 'www2', 'www3']
##
## env.roledefs = {
##     'web': ['www1', 'www2', 'www3'],
##     'dns': ['ns1', 'ns2']
## }

#################################
env.hosts = ['root@executor.cloudmega.net', 'root@doomrocket.com:6969']

@task
def disk():
    run('df -h')

#################################

@task
def kernel():
    run('uname -a')
    run('lsmod')
    run('rpm -qa kern*')

#################################

@task
def last():
    run('last')

#################################

@task
def php():
    run('php -v')

#################################

@task
def ports():
    run('netstat -ano | grep tcp | grep LIST')

#################################

@task
def pip():
    run('pip3 list')

#################################

@task
def top():
    run('ps aux | sort -nrk 3,3 | head -n 7')

#################################

@task
def cpu():
    run('ps -eo pcpu,pid,user,args --no-headers| sort -t. -nk1,2 -k4,4 -r |head -n 7')

#################################

@task
def free():
    run('free -h ; vmstat')

#################################

@task
def proc():
    run('ls -d /proc/* | grep [0-9]|wc -l')
    run('ps auxwww | wc -l')

@task
def log4j():
    run ('rm -rf log4jscanner')
    run('git clone https://github.com/google/log4jscanner.git')
    with cd('log4jscanner'):
        run('go build -o log4jscanner')
        run('./log4jscanner -v / ')

##
##
#################################
##
## group = Targets('thing.cloudmega.us', 'things.cloudmega.us')
#################################

def disk_free():
    uname = run('uname -s', hide=True)
    if 'Linux' in uname.stdout:
        command = "df -h / | tail -n1 | awk '{print $5}'"
        return run(command, hide=True).stdout.strip()
    err = "No idea how to get disk space on {}!".format(uname)
    raise Exit(err)

#for cxn in env:
#    print("{}: {}".format(cxn, disk_free(cxn)))

from fabric.api import *

#####################################################
#####################################################
## @hosts('host1')
## def clean_and_upload():
##     local('find assets/ -name "*.DS_Store" -exec rm '{}' \;')
##     local('tar czf /tmp/assets.tgz assets/')
##     put('/tmp/assets.tgz', '/tmp/assets.tgz')
##     with cd('/var/www/myapp/'):
##         run('tar xzf /tmp/assets.tgz')from fabric.api import *
##
##
