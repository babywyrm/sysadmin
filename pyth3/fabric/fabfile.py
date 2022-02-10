#!/usr/bin/python3

######################### obvi
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
env.hosts = ['USER@thing.thing.net', 'USER@thing.thing.io']


def disk():
    run('df -h')

#################################

def kernel():
    run('uname -a')

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
##
##

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
