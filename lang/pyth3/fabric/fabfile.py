#!/usr/bin/python3

#########################
#########################
##
##

import os,sys,re
from fabric.api import env, run

## env.roledefs['webservers'] = ['www1', 'www2', 'www3']
##
##
## env.roledefs = {
##     'web': ['www1', 'www2', 'www3'],
##     'dns': ['ns1', 'ns2']
## }

#################################
env.hosts = ['root@thing.thing.net', 'root@thing.com:22666']


def disk():
    run('df -h')

#################################

def kernel():
    run('uname -a')
    run('lsmod')
    run('rpm -qa kern*')

#################################

def last():
    run('last')

#################################

def php():
    run('php -v')

#################################

def ports():
    run('netstat -ano | grep tcp | grep LIST')

#################################

def pip():
    run('pip3 list')

#################################

def top():
    run('ps aux | sort -nrk 3,3 | head -n 7')

#################################

def cpu():
    run('ps -eo pcpu,pid,user,args --no-headers| sort -t. -nk1,2 -k4,4 -r |head -n 7')

#################################

def free():
    run('free -h ; vmstat')

#################################

def proc():
    run('ls -d /proc/* | grep [0-9]|wc -l')
    run('ps auxwww | wc -l')

##
##

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
##
