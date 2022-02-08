###########
## https://gist.github.com/silent1mezzo/f5c2c154462588845adb2bf9b2aa65e2
###########

from fabric.api import *

env.hosts = ['host.name.com']
env.user = 'user'
env.key_filename = '/path/to/keyfile.pem'

def local_uname():
    local('uname -a')

def remote_uname():
    run('uname -a')
    
##################################
##################################
    
# -*- coding: utf-8 -*-
import json
import requests
import getpass
import random
from fabric.api import *
from fabric.operations import *

"""
    Set up servers locations. This can be programatically generated too.
"""
env.roledefs = {
    'training': ['10.0.0.1'],
    'web': ['10.0.1.1', '10.0.1.2'],
    'media': ['10.0.2.1'],
    'celery': ['10.0.3.1', '10.0.3.2'],
}

"""
    Set up various environment variables for the application path, virtualenv,
    pip and requirements files for later use.
"""
env.directory = '/var/www/app'
env.activate = 'source /opt/lib/virtualenvs/app/bin/activate'
env.pip = '/opt/lib/virtualenvs/app/bin/pip'
env.requirements = '{}/requirements.txt'.format(env.directory)

PRODUCTION = "production"
TRAINING = "training"


"""
    Each type of server (media, web and celery) requires us to pull down the latest version
    of the application and update requirements. We abstract this out to make it simpler
"""
def pull_and_install():
    sudo('git pull origin master')
    sudo('source {} && {} install -r {}'.format(env.activate, env.pip, env.requirements))


"""
    Command to run our database migrations. The `runs_once` decorator makes sure
    that we only run migrations once per fab script invocation.
"""
@runs_once
def migrate():
    run('python manage.py migrate')

    
"""
    On our media server we pull down the latest version of the application, install any requirements,
    collect static and finally compress our static files (JS & CSS). We only have to do this once.
"""
@roles('media')
def update_media():
    run('pull_and_install')
    run('python manage.py collectstatic --noinput')
    run('python manage.py compress --force')


"""
    On all of our web servers we pull down the latest version of the application,
    run any database migrations and then restart nginx. We run this in parallel across all of our
    webservers. Because the migrate function only runs once per invocation we can safely run
    this command in parallel.
"""
@roles('web')
@parallel
def update_and_restart():
    run('pull_and_install')
    run('migrate')
    sudo("service nginx restart")
    sudo("service uwsgi restart")


"""
    On our celery servers we simply have to pull down the code, install requirements and restart celery.
    We can do this in parallel as well to make sure it updates faster.
"""
@roles('celery')
@parallel
def update_celery():
    run('pull_and_install')
    sudo('/etc/init.d/celeryd restart')


"""
    Here's the entry point for our fabfile. We can run this by typing `fab deploy` (for training)
    or `fab deploy:production` to deploy to production.
"""
def deploy(environment=TRAINING):
    execute('update_media')
    execute('update_and_restart')
    execute('update_celery')
    
###############################
##
