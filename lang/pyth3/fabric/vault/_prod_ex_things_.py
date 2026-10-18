## Fabric script
## https://gist.github.com/paulocheque/5906909
######################################################
##
##

_localhost.json
{
    "python": "pypy",
    "url": "http://localhost:8000",
    "host": "localhost",
    "port": 8000,
    "heroku_app": null,
    "heroku_app_addons": [],
    "heroku_worker": null,
    "heroku_worker_addons": [],
    "heroku_cedar": null,
    "paths": []
}
_production.json
{
    "python": "pypy",
    "url": "http://codeart-benchmarks.herokuapp.com",
    "host": "codeart-benchmarks.herokuapp.com",
    "port": 80,
    "heroku_app": "codeart-benchmarks",
    "heroku_app_addons": ["newrelic", "papertrail", "redistogo", "mongolab"],
    "heroku_worker": null,
    "heroku_worker_addons": ["papertrail", "scheduler", "sendgrid", "mailgun", "mandrill"],
    "heroku_cedar": "cedar-14",
    "paths": []
}
_staging.json
{
    "python": "pypy",
    "url": "http://codeart-benchmarks-staging.herokuapp.com",
    "host": "codeart-benchmarks-staging.herokuapp.com",
    "port": 80,
    "heroku_app": "codeart-benchmarks-staging",
    "heroku_app_addons": ["newrelic", "papertrail", "redistogo", "mongolab"],
    "heroku_worker": null,
    "heroku_worker_addons": ["papertrail", "scheduler", "sendgrid", "mailgun", "mandrill"],
    "heroku_cedar": "cedar-14",
    "paths": []
}
fabfile.django.py
# coding: utf-8
from __future__ import with_statement
import codecs
import json
import os
import platform

from fabric.api import *
from fabric.colors import *

# Examples of Usage
# fab --list
# fab staging bootstrap
# fab staging deploy
# fab staging check
# fab staging send_file:'file1.txt'
# fab staging ping
# fab staging ssh

# Environments

@task
def localhost():
    common()
    env.run = local
    env.sudo = local
    env.hosts = ['localhost']
    env.key_filename = ''
    read_config_file('localhost.json')
    print(blue("Localhost"))

@task
def staging():
    common()
    env.ami = ''
    env.hosts = ['999.999.999.999'] # The Elastic IP to your server
    env.key_filename = 'ec2_security_group.pem'
    read_config_file('staging.json')
    print(blue("Staging"))

@task
def production():
    common()
    env.ami = ''
    env.hosts = ['999.999.999.999'] # The Elastic IP to your server
    env.key_filename = 'ec2_security_group.pem'
    read_config_file('production.json')
    print(blue("Production"))

def common():
    env.run = run
    env.sudo = sudo
    env.git_repository = ''
    env.app_path = '.'
    env.venv = 'env'
    env.user = 'ubuntu'
    env.python = 'pypy'

def read_config_file(filename):
    """
    Example of the file localhost.json:
    {
        "ami": "123",
        "hosts": ["a.com", "b.com"]
    }
    """
    if os.path.exists(filename):
        with codecs.open(filename, 'r', 'utf-8') as f:
           data = json.loads(f.read())
           print(data)
           env.update(data)


# Utilities

def isMac():
    return platform.system().lower() == 'darwin'

def isLinux():
    return platform.system().lower() == 'linux'

def venv():
    return 'source %(env)s/bin/activate' % dict(env=env.venv)

def python(command):
  return 'python %(command)s' % dict(command=command)

def manage(command):
  return 'python manage.py %(command)s' % dict(command=command)

def install(packages):
    packages = ' '.join(packages)
    if isMac():
        env.run('brew install %(packages)s' % dict(packages=packages))
    elif isLinux():
        env.sudo('apt-get install -y %(package)s' % dict(package=packages))


# Tasks

@task
def ami():
    print(red("Creating AMI"))
    env.sudo('apt-get update -y')
    env.sudo('apt-get upgrade -y')
    install('build-essential', 'screen', 'language-pack-en', 'git-all', 'pbcopy')
    install('python-setuptools', 'python-dev', 'python-pip', 'virtualenv', 'python3.3')
    print(green("AMI success"))

@task
def bootstrap():
    print(red("Configuring application"))
    env.run('mkdir %s' % env.app_path)
    with cd(env.app_path):
        env.run('git clone %(repo)s' % dict(repo=env.git_repository))
        env.run('virtualenv env -p %(python)s' % dict(python=env.python))
        with prefix(venv()):
            env.run('pip install -r requirements.txt')
            env.run(manage('migrate'))
            env.run(manage('createsuperuser'))
            start_server()
    print(green("Bootstrap success"))

@task
def check():
    ping(1)
    with cd(env.app_path), prefix(venv()):
        env.run(manage('check'))
        env.run(manage('validate'))
        env.run(manage('validate_templates'))
        env.run('supervisorctl status')

@task
def info():
    env.run('uname -a')
    with cd(env.app_path), prefix(venv()):
        env.run(python('--version'))
        env.run('supervisorctl status')


@task
def test():
    with cd(env.app_path), prefix(venv()):
        local(manage('test'))
        local(manage('test_coverage'))
        local(vrun('tox'))


@task
def update(tag=None):
    print(red("Updating"))
    with cd(env.app_path):
        env.run('git fetch')
        if tag:
            env.run('git checkout -f %(tag)s' % dict(tag=tag))
            env.run('git reset --hard %(tag)s' % dict(tag=tag))
        else:
            env.run('git checkout -f master')
            env.run('git reset --hard origin/master')
    print(green("Update success"))


@task
def deploy(tag=None):
    print(red("Deploying"))
    update(tag)
    with cd(env.app_path), prefix(venv()):
        # in priority order
        env.run('pip install -r requirements.txt')
        env.run(manage('clean_pyc')) # safe (run before migrate)
        env.run(manage('migrate'))
        env.run(manage('makemessages'))
        env.run(manage('compilemessages'))
        env.run(manage('collectstatic --noinput'))
        env.run(manage('compile_pyc')) # optimization
    server_restart()
    print(green("Deploy success"))


@task
def server_start():
    with cd(env.app_path), prefix(venv()):
        env.run('supervisord')
        env.run('supervisorctl start all')

@task
def server_stop():
    with cd(env.app_path), prefix(venv()):
        env.run('supervisorctl stop all')

@task
def server_restart():
    print(red("Restarting"))
    with cd(env.app_path), prefix(venv()):
        env.run('supervisorctl restart all')
    print(green("Restart success"))


@task
def send_file(filename):
    for host in env.hosts:
        with cd(env.app_path), prefix(venv()):
            env.run('scp -i %(pem)s -r %(file)s %(user)s@%(host)s:~' % dict(pem=user.key_filename,
                file=filename, user=env.user, host=host))


@task
def ssh():
    with cd(env.app_path), prefix(venv()):
        env.run('ssh -i %(pem)s %(user)s@%(domain)s' % dict(pem=user.key_filename, user=env.user, domain=host))


@task
def ping(time=3):
    local('ping -c %(time)s %(domain)s' % dict(time=time, domain=env.host_string))
fabfile.heroku.py
# coding: utf-8
from __future__ import with_statement
import codecs
import json
import os
import platform

from fabric.api import *
from fabric.colors import *

# Examples of Usage
# fab --list
# fab localhost bootstrap
# fab localhost start_server
# fab production bootstrap_heroku
# fab production deploy
# fab production rollback:v2
# fab staging check
# fab staging ping
# fab staging ssh

# Environments

@task
def localhost():
    common()
    env.run = local
    env.sudo = local
    env.hosts = ['localhost']
    env.host_string = 'localhost:5000'
    read_config_file('localhost.json')
    print(blue("Localhost"))

@task
def staging():
    common()
    env.heroku_server_git = 'heroku'
    env.heroku_server = 'politica-indecente'
    env.heroku_worker_git = None
    env.heroku_worker = None
    env.host_string = '%s.herokuapp.com' % env.heroku_server
    read_config_file('staging.json')
    print(blue("Staging"))

@task
def production():
    common()
    env.heroku_server_git = 'heroku'
    env.heroku_server = 'politica-indecente'
    env.heroku_worker_git = None
    env.heroku_worker = None
    env.host_string = '%s.herokuapp.com' % env.heroku_server
    read_config_file('production.json')
    print(blue("Production"))

def common():
    env.run = run
    env.sudo = sudo
    env.git_repository = ''
    env.app_path = '.'
    env.venv = 'env'
    env.user = 'ubuntu'
    env.python = 'pypy'

def read_config_file(filename):
    """
    Example of the file localhost.json:
    {
        "ami": "123",
        "hosts": ["a.com", "b.com"]
    }
    """
    if os.path.exists(filename):
        with codecs.open(filename, 'r', 'utf-8') as f:
           data = json.loads(f.read())
           print(data)
           env.update(data)


# Utilities

def isMac():
    return platform.system().lower() == 'darwin'

def isLinux():
    return platform.system().lower() == 'linux'

def venv():
    return 'source %(env)s/bin/activate' % dict(env=env.venv)

def python(command):
  return 'python %(command)s' % dict(command=command)

def manage(command):
  return 'python manage.py %(command)s' % dict(command=command)

def install(packages):
    packages = ' '.join(packages)
    if isMac():
        env.run('brew install %(packages)s' % dict(packages=packages))
    elif isLinux():
        env.sudo('apt-get install -y %(package)s' % dict(package=packages))


# Tasks

@task
def bootstrap():
    print(red("Configuring application"))
    with cd(env.app_path):
        env.run('virtualenv env -p %(python)s' % dict(python=env.python))
        with prefix(venv()):
            env.run('pip install -r requirements.txt')
            start_server()
    print(green("Bootstrap success"))

@task
def bootstrap_heroku():
    print(red("Configuring application"))
    if env.heroku_server_git and env.heroku_server:
        # env.run('heroku apps:create %s' % env.heroku_server)
        # env.run('heroku stack:set cedar-14 --app %s' % env.heroku_server)
        # env.run('git remote add heroku git@heroku.com:%s.git' % env.heroku_server)
        env.run('heroku addons:add newrelic --app %s' % env.heroku_server)
        # env.run('newrelic-admin generate-config YOUR_ID newrelic.ini')
        env.run('heroku addons:add papertrail --app %s' % env.heroku_server)
        # env.run('heroku addons:add loggly --app %s' % env.heroku_server)
        env.run('heroku addons:add redistogo --app %s' % env.heroku_server)
        env.run('heroku addons:add mongohq --app %s' % env.heroku_server)
        # env.run('heroku addons:add mongolab --app %s' % env.heroku_server)
        if env.host_string and not env.host_string.endswith('herokuapp.com'):
            env.run('heroku domains:add #{DOMAIN} --app %s' % env.heroku_server)

    if env.heroku_worker_git and env.heroku_worker:
        env.run('heroku apps:create %s' % env.heroku_worker)
        # env.run('heroku stack:set cedar-14 --app %s' % env.heroku_worker)
        env.run('git remote add heroku2 git@heroku.com:%s.git' % env.heroku_worker)
        # env.run('heroku addons:add newrelic --app %s' % env.heroku_worker)
        env.run('heroku addons:add papertrail --app %s' % env.heroku_worker)
        # env.run('heroku addons:add loggly --app %s' % env.heroku_worker)
        env.run('heroku addons:add scheduler --app %s' % env.heroku_worker)
        env.run('heroku addons:add sendgrid --app %s' % env.heroku_worker)
        # env.run('heroku addons:add postmark --app %s' % env.heroku_worker)
    print(green("Bootstrap success"))

@task
def check():
    ping(1)

@task
def info():
    env.run('uname -a')
    with cd(env.app_path), prefix(venv()):
        env.run(python('--version'))
    if env.heroku_server:
        env.run('heroku releases --app %s' % env.heroku_server)

@task
def test():
    with cd(env.app_path), prefix(venv()):
        local(vrun('nose'))
        local(vrun('tox'))


@task
def update(tag=None):
    print(red("Updating"))
    with cd(env.app_path):
        env.run('git fetch')
        if tag:
            env.run('git checkout -f %(tag)s' % dict(tag=tag))
            env.run('git reset --hard %(tag)s' % dict(tag=tag))
        else:
            env.run('git checkout -f master')
            env.run('git reset --hard origin/master')
    print(green("Update success"))

@task
def upload_static_files():
    print(red("Uploading static files to S3"))
    # env.run('sudo npm install uglify-js -g')
    # env.run('uglifyjs static/js/*.js -o static/js/code.min.js --source-map code.min.js.map -p relative -c -m')
    print(red("Uploaded succesful"))

@task
def set_env_vars():
    pass
    # shared_vars = { REDIS_URL: nil, REDISTOGO_URL: nil, MONGOHQ_URL: nil, DATABASE_URL: nil }
    # shared_vars.each { |var, value|
    #   value = `heroku config:get #{var} --app #{SERVER}` if SERVER
    #   value.strip! if SERVER
    #   shared_vars[var] = value
    # }

    # [SERVER, WORKER].each { |app|
    #   if app
    #     vars = ENV_VARS.map{ |k,v| "#{k}=#{v}" }.join(' ')
    #     if app == WORKER
    #       complement = shared_vars.map { |k, v| "#{k}=#{v}" if v }.join(" ")
    #       vars = vars + complement
    #     end
    #     puts vars
    #     sh "heroku config:set #{vars} --app #{app}"
    #   end
    # }

@task
def deploy(tag=None):
    print(red("Deploying"))
    with cd(env.app_path), prefix(venv()):
        # in priority order
        upload_static_files()
    if env.heroku_server_git:
        env.run('git push %s master' % env.heroku_server_git)
        env.run('heroku ps:scale web=1 --app %s' % env.heroku_server)
        env.run('heroku ps:scale worker=0 --app %s' % env.heroku_server)
    if env.heroku_worker_git:
        env.run('git push %s master' % env.heroku_worker_git)
        env.run('heroku ps:scale web=0 --app %s' % env.heroku_worker)
        env.run('heroku ps:scale worker=1 --app %s' % env.heroku_worker)
    print(green("Deploy success"))

@task
def rollback(tag=None):
    if tag:
        env.run('heroku rollback')
    else:
        env.run('heroku rollback %s' % tag)

@task
def start_server():
    with cd(env.app_path), prefix(venv()):
        # env.run('foreman start')
        env.run('python app.py')

@task
def ssh():
    if env.heroku_worker_git:
        env.run('heroku console --app %s' % env.heroku_worker)
    else:
        env.run('heroku console --app %s' % env.heroku_server)

@task
def ping(time=3):
    local('ping -c %(time)s %(domain)s' % dict(time=time, domain=env.host_string))


# localhost()
fabfile.images.py
# coding: utf-8
from __future__ import with_statement
import codecs
import json
import os
import platform

from fabric.api import *
from fabric.colors import *

# Examples of Usage
# fab --list
# fab prepare
# fab rename:extension=jpg
# fab resize:folder=output
# fab compress
# fab logos

# Utilities

def isMac():
    return platform.system().lower() == 'darwin'

def isLinux():
    return platform.system().lower() == 'linux'

def venv():
    return 'source %(env)s/bin/activate' % dict(env=env.venv)

def python(command):
  return 'python %(command)s' % dict(command=command)

def manage(command):
  return 'python manage.py %(command)s' % dict(command=command)

def pip(package):
  return 'pip install %(package)s' % dict(package=package)

def install(packages):
    packages = ' '.join(packages)
    if isMac():
        env.run('brew install %(packages)s' % dict(packages=packages))
    elif isLinux():
        env.sudo('apt-get install -y %(package)s' % dict(package=packages))


# Tasks

@task
def prepare():
    install('imagemagick')
    pip('boto')

@task
def rename(folder='.', extension=None):
    output = '%(folder)s/output' % dict(folder=folder)
    local('rm -rf %(output)s && mkdir %(output)s' % dict(output=output))
    (_, _, filenames) = os.walk(folder).next()
    i = 1
    for filename in filenames:
        name, ext = os.path.splitext(filename)
        ext = ext.lower()
        if extension is None or extension in ext:
            newfilename = str(i).zfill(4)
            newfile = '%(output)s/%(newfilename)s%(ext)s' % dict(output=output, newfilename=newfilename, ext=ext)
            local('cp %(filename)s %(newfile)s' % dict(filename=filename, newfile=newfile))
            i += 1

@task
def convert(options, source, result):
    local('convert %(options)s %(source)s %(result)s' % dict(options=options, source=source, result=result))

@task
def convert_all(options, folder='.'):
    output = '%(folder)s/output' % dict(folder=folder)
    local('rm -rf %(output)s && mkdir %(output)s' % dict(output=output))
    (_, _, filenames) = os.walk(folder).next()
    image_extensions = ['.jpg', '.jpeg', '.png', '.gif']
    for filename in filenames:
        name, ext = os.path.splitext(filename)
        if ext.lower() in image_extensions:
            source = '%(folder)s/%(input)s' % dict(folder=folder, input=filename)
            result = '%(output)s/%(input)s' % dict(output=output, input=filename)
            convert(options, source, result)

@task
def resize(folder='.'):
    # convert_all('-resize 50%%')
    convert_all('-resize 1024x768')

@task
def compress(folder='.'):
    # convert_all('-strip -interlace Plane -gaussian-blur 0.05 -quality 85%')
    convert_all('-strip -interlace Plane -gaussian-blur 0.05 -quality 75%')
    # convert_all('-strip -interlace Plane -gaussian-blur 0.05 -quality 60%')
    # convert_all('-strip -interlace Plane -gaussian-blur 0.05 -quality 55%')

@task
def logos():
    local('rm -rf output && mkdir output')
    square = 'logo-1024x1024.png'
    portrait = 'logo-1024x1024.png'
    landscape = 'logo-1024x1024.png'
    banner = 'logo-1024x1024.png'

    def logo(source, sizes):
        name, ext = os.path.splitext(source)
        for size in sizes:
            convert('-resize %(size)s\!' % dict(size=size), square, 'logo-%(size)s%(ext)s' % dict(size=size, ext=ext))

    # FB logos: 512, 180, 16
    # favicon: 32, 16
    sizes = ['512x512', '180x180', '144x144', '114x114', '72x72', '57x57', '32x32', '16x16']
    logo(square, sizes)

    # Mobile Portrait
    sizes = ['1536x2008', '640x1136', '768x1004', '640x960', '320x480']
    logo(portrait, sizes)

    # Mobile Landscape
    sizes = ['2048x1496', '1024x748']
    logo(landscape, sizes)

    # Banners
    # 800x150 FB app cover image
    # 400x150 FB cover image
    # 155x100 FB app web banner
    # 200x60 Site logo
    # 150x50 PagSeguro logo
    # 150x50 Site logo
    # 140x40 Site logo
    sizes = ['800x150', '400x150', '155x100', '200x60', '150x50', '140x40']
    logo(banner, sizes)
fabfile.py
# coding: utf-8
from __future__ import with_statement
from functools import partial
import os, os.path, time
import functools

from fabric.api import *
from fabric.contrib.files import append, exists, comment, contains
from fabric.contrib.files import upload_template as orig_upload_template

# Debug mode
env.abort_on_prompts = True
from fabric.api import local as run

# run
# local
# cd
# with
# env.hosts = ['my_server'] username@hostname:port
# env.roledefs = {
#     'web': ['www1', 'www2', 'www3'],
#     'dns': ['ns1', 'ns2']
# }
# $ fab mytask:hosts='host1;host2'

# from fabric.api import hosts, run
# @hosts('host1', 'host2')
# def task(): pass

# union of all hosts: in hosts and hosts in roles
# from fabric.api import env, hosts, roles, run
# env.roledefs = {'role1': ['b', 'c']}
# @hosts('a', 'b')
# @roles('role1')
# def mytask():
#     run('ls /var/www')
# test
# production
# env.user = 'implicit_user'
# env.hosts = ['host1', 'explicit_user@host2', 'host3']
# $ fab -H localhost,linuxbox host_type

# env.use_ssh_config to True

import inspect
def s(template, **kwargs):
    '''Usage: s(string, **locals())'''
    if not kwargs:
        frame = inspect.currentframe()
        try:
            kwargs = frame.f_back.f_locals
        finally:
            del frame
        if not kwargs:
            kwargs = globals()
    return template.format(**kwargs)


def colorize(message, color='blue'):
  color_codes = dict(black=30, red=31, green=32, yellow=33, blue=34, magenta=35, cyan=36, white=37)
  code = color_codes.get(color, 34)
  msg =  s('\033[{code}m{message}\033[0m')
  # print(msg)
  return msg


def self_update():
    from urllib2 import urlopen
    files = {
        'fabfile.py': 'https://gist.github.com/paulocheque/5906909/raw/fabfile.py',
        'test_fabfile.py': 'https://gist.github.com/paulocheque/5906909/raw/test_fabfile.py'
    }
    for filepath, url in files.items():
        data = urlopen(url).read()
        dirpath = os.path.dirname(os.path.realpath(__file__))
        fo = open(s('{dirpath}/downloaded_{filepath}'), 'w')
        fo.write(data)
        fo.close()
        local(s('cp {dirpath}/{filepath} {dirpath}/{filepath}.bak'))
        local(s('cp {dirpath}/downloaded_{filepath} {dirpath}/{filepath}'))


def prepare_env():
    ProgramsInstaller.install('build-essential', 'screen', 'language-pack-en', 'git-all', 'pbcopy')
    ProgramsInstaller.install('python-setuptools', 'python-dev', 'python-pip', 'virtualenv', 'python3.3')
    ProgramsInstaller.install('ruby1.9.1', 'rake', 'rubygems')
    Pip.install('virtualenv', 'httpie', 'nose')


class Bash(object):
    @staticmethod
    def clear():
        run('clear')

    @staticmethod
    def check_env_var(var):
        if Bash.get_env_var(var) is None:
            msg = s('{var} environment variable not defined. Try Bash.set_env_var("{var}")')
            print(colorize(msg, 'red'))
            raise Exception(msg)

    @staticmethod
    def set_env_var(var, value):
        if not value:
            os.unsetenv(var)
            del os.environ[var]
        else:
            # TODO: add to bash_rc/bash_profile?
            os.putenv(var, str(value))
            os.environ[var] = str(value)

    @staticmethod
    def get_env_var(var):
        return os.getenv(s('{var}'), None)

    @staticmethod
    def run_in_dir(dir, command):
        with cd(dir):
            run(command)
        # run(s('cd {dir} && {command}'))

    @staticmethod
    def permissions(filepath, user=env.user, group=env.user):
        run(s('chown -R {user}:{group} {filepath}'))

    @staticmethod
    def find_file(name, dir='.'):
        run(s('find {dir} -type f -name {name}'))

    @staticmethod
    def find_dir(name, dir='.'):
        run(s('find {dir} -type d -name {name}'))

    @staticmethod
    def find_link(name, dir='.'):
        run(s('find {dir} -type l -name {name}'))


class Zip(object):
    @staticmethod
    def pack(package_file, files, exclude_list=None):
        files = ' '.join(files)
        # puts colorize('Packing to #{package_file}', :blue)
        exclude_command = '--exclude=\*.DS_Store\* --exclude=\*~ '
        # exclude_list.each { | term |
        #   exclude_command += '--exclude=#{term}
        # }
        run(s('zip -y -qdgds 1m {package_file} -r {files} {exclude_command}'))
        print(colorize('Package created: ', 'green') + s('{package_file}'))


class SSH(object):
    @staticmethod
    def create_key(email, passphrase='""', filepath='~/.ssh/id_rsa'):
        run('echo -e "y" | ' + s('ssh-keygen -t rsa -C "{email}" -f {filepath} -N {passphrase}'))

    @staticmethod
    def copy_public_key(filepath='~/.ssh/id_rsa.pub'):
        run(s('pbcopy < {filepath}'))


class ProgramsInstaller(object):
    pass


class Apt(ProgramsInstaller):
    @staticmethod
    def install(*pkgs):
        Bash.clear()
        sudo('apt-get install -y %s' % ' '.join(pkgs))

    @staticmethod
    def upgrade():
        Bash.clear()
        sudo('apt-get update -y')
        sudo('apt-get upgrade -y')


class Brew(ProgramsInstaller):
    @staticmethod
    def install(*pkgs):
        Bash.clear()
        sudo('brew install %s' % ' '.join(pkgs))

    @staticmethod
    def upgrade():
        pass


class Git(object):
    @staticmethod
    def init():
        run('git init')

    @staticmethod
    def show_largest_files():
        script = '''
#!/bin/bash
#set -x
# @see http://stubbisms.wordpress.com/2009/07/10/git-script-to-show-largest-pack-objects-and-trim-your-waist-line/
# @author Antony Stubbs
# set the internal field spereator to line break, so that we can iterate easily over the verify-pack output
IFS=$'\n';
# list all objects including their size, sort by size, take top 10
objects=`git verify-pack -v .git/objects/pack/pack-*.idx | grep -v chain | sort -k3nr | head`
echo "All sizes are in kB's. The pack column is the size of the object, compressed, inside the pack file."
output="size,pack,SHA,location"
for y in $objects
do
    # extract the size in bytes
	size=$((`echo $y | cut -f 5 -d ' '`/1024))
	# extract the compressed size in bytes
	compressedSize=$((`echo $y | cut -f 6 -d ' '`/1024))
	# extract the SHA
	sha=`echo $y | cut -f 1 -d ' '`
	# find the objects location in the repository tree
	other=`git rev-list --all --objects | grep $sha`
	#lineBreak=`echo -e "\n"`
	output="${output}\n${size},${compressedSize},${other}"
done
echo -e $output | column -t -s ', '
'''
        run(script)

    @staticmethod
    def clean(filename=None):
        '''Your Git repository is too big? filename can be: *.zip`'''
        if filename:
            run('git count-objects -v')
            run(s('git filter-branch -f --index-filter 'git rm -rf --cached --ignore-unmatch {filename}' --prune-empty -- --all'))
            run('rm -rf .git/refs/original')
            run('rm -rf .git/logs')
            run('git reflog expire --expire=now --all')
            run('git gc --aggressive --prune=now')
            run('git count-objects -v')
            #run('git push --tags -f origin master')
        else:
            run('git gc --aggressive --prune=now')



    @staticmethod
    def config(username, email, env='--global'):
        run(s('git config {env} user.email {email}'))
        run(s('git config {env} user.name {username}'))
        run(s('git config {env} color.ui true'))
        run(s('git config {env} format.pretty oneline'))
        run(s('git config {env} core.autocrl input'))
        run(s('git config {env} core.fileMode true'))
        run(s(r'''git config {env} alias.lg "log --color --graph --pretty=format:'%Cred%h%Creset -%C(yellow)%d%Creset %s %Cgreen(%cr) %C(bold blue)<%an>%Creset' --abbrev-commit"'''))

    @staticmethod
    def reset(remote='origin', branch='master'):
        run(s('git reset --hard {remote} {branch}'))

    @staticmethod
    def rebase(remote='origin', branch='master'):
        run(s('git fetch {remote} && git rebase {remote}/{branch}'))

    @staticmethod
    def push(remote='origin', branch='master'):
        Git.rebase(remote, branch)
        run(s('git push {remote} {branch}'))

    @staticmethod
    def tag(tag, remote='origin'):
        run(s('git tag {tag} && git push {remote} {tag}'))

    @staticmethod
    def reset_tag(tag, remote='origin'):
        run(s('git tag -d {tag} && git push origin :refs/tags/{tag}'))
        run(s('git tag {tag} && git push {remote} {tag}'))

    @staticmethod
    def remove_old_branches():
        # Removing obsolete remote Git branches from your local copy:
        run('git remote prune origin')


class Http(object):
    @staticmethod
    def request(url, data='{}', method='POST', content_type='--json'):
        run(s('echo "{data}" | http {method} {url} {content_type}'))


class Python(object):
    @staticmethod
    def create_virtual_env(dir='env27', python='python2.7'):
      run(s('virtualenv {dir} -p {python}'))

    @staticmethod
    def run_on_virtual_env(command, env='env27'):
      run(s('source {env}/bin/activate && {command}'))

    @staticmethod
    def install(envs=['env27']):
        for env in envs:
            print(colorize(s('Environment {env}'), 'blue'))
            requirements = ['requirements.txt', 'requirements-test.txt']
            for requirement in requirements:
                if os.path.exists(requirement):
                    Python.run_on_virtual_env(s('pip install -r {requirements}'), env=env)

    @staticmethod
    def tests(envs=['env27']):
        for env in envs:
            print(colorize(s('Environment {env}'), 'blue'))
            requirements = ['requirements.txt', 'requirements-test.txt']
            for requirement in requirements:
                if os.path.exists(requirement):
                    Python.run_on_virtual_env('nosetests --process-timeout=3 --verbosity=2', env=env)

    @staticmethod
    def package():
        Python.tests()
        Python.run_on_virtual_env('python setup.py sdist')


class Vagrant(object):
    @staticmethod
    def ssh(user, machine, pem_key):
        run(s('ssh -i {pem_key} {user}@{machine}'))

    @staticmethod
    def send_files(user, machine, files, pem_key, output_dir='~'):
        Bash.clear()
        files = ' '.join(files)
        run(s('scp -i {pem_key} -r {files} {user}@{machine}:{output_dir}'))

    @staticmethod
    def command(dirpath, command, log_level='info'):
        Bash.clear()
        with cd(dirpath):
            run(s('VAGRANT_LOG={log_level} vagrant {command}'))

    @staticmethod
    def up(dirpath, log_level='info'):
        Vagrant.command(dirpath, 'up', log_level)

    @staticmethod
    def up_aws(dirpath, log_level='info'):
        Vagrant.command(dirpath, 'plugin install vagrant-aws', log_level)
        Vagrant.command(dirpath, 'up --provider=aws', log_level)

    @staticmethod
    def reload(dirpath, log_level='info'):
        Vagrant.command(dirpath, 'reload', log_level)

    @staticmethod
    def destroy(dirpath, log_level='info'):
        Vagrant.command(dirpath, 'destroy', log_level)


class Machine(object):
    import platform
    # history of commands (command: string, labels[]). label => color mapping
    @staticmethod
    def info():
        run('uname -s')

    @staticmethod
    def isMac():
        return platform.system().lower() == 'darwin'

    @staticmethod
    def isLinux():
        return platform.system().lower() == 'linux'

    @staticmethod
    def isWindows():
        return platform.system().lower().contains('win')


class Heroku(Machine):
    @staticmethod
    def deploy(remote='heroku', branch='master'):
        Bash.clear()
        local(s('git push {remote} {branch}'))

    @staticmethod
    def rollback():
        Bash.clear()
        local('heroku rollback')

    @staticmethod
    def start():
        Bash.clear()

    @staticmethod
    def stop():
        Bash.clear()

    @staticmethod
    def restart():
        Bash.clear()
        local('heroku restart')

    @staticmethod
    def log():
        Bash.clear()
        local('heroku logs')

    @staticmethod
    def log_tail():
        Bash.clear()
        local('heroku logs --tail')


class Worker(Machine):
    # get runtime
    # save PID
    # signals: pre, pos
    # get runtime
    @staticmethod
    def deploy():
        Bash.clear()

        # save current commit
        # save current requirements
        # save dir logo
        Worker.restart()

    @staticmethod
    def rollback():
        Bash.clear()

    @staticmethod
    def start():
        Bash.clear()
        run(s('nohup {process} -- {args} &'))
        self.pid = run('$!')
        print(self.pid)

    @staticmethod
    def stop():
        Bash.clear()
        if self.pid:
            run(s('kill {self.pid}'))
            # run(s('kill -9 {self.pid}'))

    @staticmethod
    def restart():
        Worker.stop()
        Worker.start()

    @staticmethod
    def log():
        Bash.clear()

    @staticmethod
    def log_tail():
        Bash.clear()


# git commit
# git push
# git rebase
# git tag
# git reset_tag

def dev_env(): pass
def dev_dependencies(): pass
def dev_tests(): pass
def dev_server(): pass
def dev_worker(): pass # (runtime)

def server_deploy(): pass
def server_rollback(): pass # (last tag-commit)
def server_start(): pass
def server_stop(): pass
def server_restart(): pass
def server_log(): pass
def server_log_tail(): pass

def worker_deploy(): pass
def worker_rollback(): pass
def worker_start(): pass
def worker_stop(): pass
def worker_restart(): pass #  killall run
def worker_log(): pass
def worker_log_tail(): pass
fabfile_heroku.py
# coding: utf-8
from __future__ import with_statement
import codecs
import json
import os
import platform
import subprocess
import sys

from fabric.api import *
from fabric.colors import *
from fabric.utils import abort
from fabric.contrib.console import confirm

# Examples of Usage
# fab -f fabfile_heroku.py --list
# fab --list
# fab localhost bootstrap
# fab localhost info
# fab localhost test
# fab localhost start_server
# fab production/staging bootstrap_heroku
# fab production/staging upload_static_files
# fab production/staging set_env_vars
# fab production/staging deploy
# fab production/staging rollback
# fab production/staging logs
# fab production/staging ssh
# fab localhost/production/staging ping
# fab localhost/production/staging warmup
# fab localhost/production/staging benchmark
# fab localhost/production/staging browse


# Environments

@task
def localhost():
    common()
    read_config_file('_localhost.json')
    env.heroku_app_git_remote = None
    env.heroku_worker_git_remote = None
    env.heroku_deploy_branch = None
    env.aws_bucket = 'codeart-localhost'
    print(blue("Localhost"))

@task
def staging():
    common()
    if current_git_branch() != 'staging':
        if not confirm('Using staging environment without staging branch (%s). Are you sure?' % current_git_branch()):
            abort('cancelled by the user')
    env.venv = 'envstaging'
    read_config_file('_staging.json')
    env.heroku_app_git_remote = 'heroku-staging'
    env.heroku_worker_git_remote = 'heroku-worker-staging'
    env.heroku_deploy_branch = 'staging:master'
    env.aws_bucket = env.heroku_app
    print(blue("Staging"))

@task
def production():
    common()
    if current_git_branch() != 'master':
        if not confirm('Using production environment without master branch (%s). Are you sure?' % current_git_branch()):
            abort('cancelled by the user')
    read_config_file('_production.json')
    env.heroku_app_git_remote = 'heroku'
    env.heroku_worker_git_remote = 'heroku-worker'
    env.heroku_deploy_branch = 'master'
    env.aws_bucket = env.heroku_app
    print(blue("Production"))

def common():
    env.python = 'python2.7'
    env.url = 'http://localhost:8000'
    env.host = 'localhost'
    env.port = 8000
    env.heroku_app = None
    env.heroku_app_addons = []
    env.heroku_worker = None
    env.heroku_worker_addons = []
    env.heroku_cedar = None
    env.paths = []

    env.run = local
    env.sudo = local
    env.cd = lcd
    env.venv = 'env'


# Utilities

def read_config_file(filename):
    """
    Example of the file localhost.json:
    {
        "ami": "123",
        "hosts": ["a.com", "b.com"]
    }
    """
    if os.path.exists(filename):
        with codecs.open(filename, 'r', 'utf-8') as f:
           data = json.loads(f.read())
           print(data)
           env.update(data)

def current_git_branch():
    label = subprocess.check_output(['git', 'rev-parse', '--abbrev-ref', 'HEAD'])
    return label.strip()

def isMac():
    return platform.system().lower() == 'darwin'

def isLinux():
    return platform.system().lower() == 'linux'

def venv():
    return 'source %(env)s/bin/activate' % dict(env=env.venv)

def python(command):
    return 'python %(command)s' % dict(command=command)

def manage(command):
    return 'python manage.py %(command)s' % dict(command=command)

def install(packages):
    packages = ' '.join(packages)
    if isMac():
        env.run('brew install %(packages)s' % dict(packages=packages))
    elif isLinux():
        env.sudo('apt-get install -y %(package)s' % dict(package=packages))

def bootstrap_heroku(app_name, addons, branch=None, domain=None, cedar=None):
    print(red("Configuring heroku"))
    env.run('heroku apps:create %s' % app_name)
    if branch:
        env.run('git remote add %s git@heroku.com:%s.git' % (branch, app_name))
    if cedar:
        env.run('heroku stack:set %s --app %s' % (cedar, app_name))
    for addon in addons:
        env.run('heroku addons:add %s --app %s' % (addon, app_name))
        if addon == 'newrelic':
            newrelic_key = env.run('heroku config:get NEW_RELIC_LICENSE_KEY --app %s' % (app_name), capture=True)
            env.run('newrelic-admin generate-config %s newrelic.ini' % newrelic_key)
    if domain and not domain.endswith('herokuapp.com'):
        env.run('heroku domains:add %s --app %s' % (domain, app_name))
    print(green("Bootstrap success"))

def get_bucket_policy(bucket, host):
    policy = """
    {
      "Version":"2012-10-17",
      "Id":"http referer policy example",
      "Statement":[
        {
          "Sid":"Allow get requests originated from www.example.com and example.com",
          "Effect":"Allow",
          "Principal":"*",
          "Action":"s3:GetObject",
          "Resource":"arn:aws:s3:::%s/*",
          "Condition":{
            "StringLike":{"aws:Referer":["http://www.%s/*","http://%s/*","https://www.%s/*","https://%s/*"]}
          }
        }
      ]
    }""" % (bucket, host, host, host, host)
    return policy.strip()

def get_or_create_bucket(name, public=True, cors=None):
    import boto
    from boto.s3.cors import CORSConfiguration
    conn = boto.connect_s3() # read AWS env vars
    bucket = conn.lookup(name)
    if bucket is None:
        print('Creating bucket %s' % name)
        bucket = conn.create_bucket(name)
        if public:
            bucket.set_acl('public-read')
        if cors:
            cors_cfg = CORSConfiguration()
            cors_cfg.add_rule(['GET', 'POST'], 'http://*', allowed_header='*', max_age_seconds=604800)
            cors_cfg.add_rule(['GET', 'POST'], 'https://*', allowed_header='*', max_age_seconds=604800)
            cors_cfg.add_rule('GET', '*', allowed_header='*', max_age_seconds=604800)
            bucket.set_cors(cors_cfg)
            bucket.set_policy(get_bucket_policy(name, cors), headers=None)
    return bucket

def upload_file_to_s3(bucket_name, filename, public=True, static_headers=False, gzip=False):
    bucket = get_or_create_bucket(bucket_name, cors=True)
    print('Uploading %s to Amazon S3 bucket %s' % (filename, bucket_name))
    k = bucket.new_key(filename)
    if static_headers:
        content_types = {
            '.gz': 'application/x-gzip',
            '.js': 'application/x-javascript',
            '.map': 'application/json',
            '.json': 'application/json',
            '.css': 'text/css',
            '.html': 'text/html',
            '.jpg': 'image/jpeg',
            '.jpeg': 'image/jpeg',
            '.gif': 'image/gif',
            '.png': 'image/png',
            '.pdf': 'application/pdf',
        }
        dir_filename, extension = os.path.splitext(filename)
        k.set_metadata('Content-Type', content_types.get(extension, 'text/plain'))
        k.set_metadata('Cache-Control', 'max-age=31536000')
        k.set_metadata('Expires', 'Thu, 31 Dec 2015 23:59:59 GM')
        if gzip:
            k.set_metadata('Content-Encoding', 'gzip')
    def percent_cb(complete, total):
        sys.stdout.write('.')
        sys.stdout.flush()
    k.set_contents_from_filename(filename, cb=percent_cb, num_cb=10)
    if public:
        k.set_acl('public-read')

def minify_js(jsfile):
    if jsfile.endswith('.js'):
        # env.run('sudo npm install uglify-js -g')
        dir_filename, extension = os.path.splitext(jsfile)
        fmin = dir_filename + '.min' + extension
        fmap = dir_filename + '.min' + extension + '.map'
        env.run('uglifyjs %s -o %s --source-map %s -p relative -c' % (jsfile, fmin, fmap))
        return fmin, fmap
    return jsfile, jsfile

def compress(textfile):
    env.run('gzip -k -f -9 %s' % textfile)
    dir_filename, extension = os.path.splitext(textfile)
    gzipped_file = '%s.gz%s' % (dir_filename, extension)
    env.run('mv %s.gz %s' % (textfile, gzipped_file))
    return gzipped_file

def upload_js(bucket_name, filename, minify=True, gzip=True):
    if minify:
        fmin, fmap = minify_js(filename)
        upload_file_to_s3(bucket_name, fmin, public=True, static_headers=True, gzip=False)
        upload_file_to_s3(bucket_name, fmap, public=True, static_headers=True, gzip=False)
        if gzip:
            upload_file_to_s3(bucket_name, compress(fmin), public=True, static_headers=True, gzip=True)
            upload_file_to_s3(bucket_name, compress(fmap), public=True, static_headers=True, gzip=True)
    if gzip:
        upload_file_to_s3(bucket_name, compress(filename), public=True, static_headers=True, gzip=True)
    upload_file_to_s3(bucket_name, filename, public=True, static_headers=True, gzip=False)

def upload_css(bucket_name, filename, gzip=True):
    if gzip:
        filename_gz = compress(filename)
        upload_file_to_s3(bucket_name, filename_gz, public=True, static_headers=True, gzip=True)
    upload_file_to_s3(bucket_name, filename, public=True, static_headers=True, gzip=False)

def upload_file(bucket_name, filename):
    if filename.endswith('.js'):
        upload_js(bucket_name, filename)
    elif filename.endswith('.css'):
        upload_css(bucket_name, filename)
    elif filename.endswith('.jpg') or filename.endswith('.jpeg') or filename.endswith('.gif') or filename.endswith('.png'):
        upload_file_to_s3(bucket_name, filename, public=True, static_headers=True, gzip=False)
    else:
        upload_file_to_s3(bucket_name, filename, public=True, static_headers=False, gzip=False)

def weighttp(requests=10000, concurrency=50, threads=5):
    # http://adventuresincoding.com/2012/05/how-to-get-apachebenchab-to-work-on-mac-os-x-lion
    # install('Weighttp')
    for path in env.paths:
        env.run('weighttp -n %s -c %s -t %s -k %s%s' % (requests, concurrency, threads, env.url, path))

# Tasks Localhost

@task
def bootstrap():
    print(red("Configuring application"))
    env.run('virtualenv %(env)s -p %(python)s' % dict(env=env.venv, python=env.python))
    with prefix(venv()):
        env.run('pip install -r requirements.txt')
        start_server()
    print(green("Bootstrap success"))

@task
def info():
    env.run('uname -a')
    env.run('ulimit -aH')
    with prefix(venv()):
        env.run(python('--version'))
    if env.heroku_app:
        env.run('heroku config --app %s' % env.heroku_app)
    if env.heroku_worker:
        env.run('heroku config --app %s' % env.heroku_worker)

@task
def test():
    with prefix(venv()):
        env.run(vrun('tox'))

@task
def start_server():
    with prefix(venv()):
        # env.run('foreman start -p %s' % env.port)
        env.run('python app.py')

# Tasks Production/Staging

@task
def bootstrap_heroku():
    if env.heroku_app:
        bootstrap_heroku(env.heroku_app, env.heroku_app_addons,
            branch=env.heroku_app_git_remote, domain=env.host, cedar=env.heroku_cedar)
    if env.heroku_worker:
        bootstrap_heroku(env.heroku_worker, env.heroku_worker_addons,
            branch=env.heroku_app_git_remote, domain=env.host, cedar=env.heroku_cedar)

@task
def upload_static_files():
    print(red("Uploading static files to S3"))
    folder = 'static'
    for (current_dir, dirs, files) in os.walk(folder):
        for filename in files:
            block = ['.gz', '.min', '.map']
            skip = False
            for b in block:
                if b in filename:
                    skip = True
                    break
            if not skip:
                path = os.path.join(current_dir, filename)
                upload_file(env.aws_bucket, path)
    print(red("Uploaded succesful"))

@task
def set_env_vars():
    def vars_line(data):
        return ' '.join(['%s=%s' % (var, value) for var, value in data.items()])
    env_vars = dict(
        AWS_ACCESS_KEY_ID=os.getenv('AWS_ACCESS_KEY_ID', '').strip(),
        AWS_SECRET_ACCESS_KEY=os.getenv('AWS_SECRET_ACCESS_KEY', '').strip(),
        AWS_REGION=os.getenv('AWS_REGION', '').strip(),
    )
    shared_vars = dict(REDISTOGO_URL='', REDIS_URL='', MONGOHQ_URL='', MONGOLAB_URI='', DATABASE_URL='')
    if env.heroku_app:
        env.run('heroku config:set %(vars)s --app %(app)s' % dict(vars=vars_line(env_vars), app=env.heroku_app))
        for var, _ in shared_vars.items():
            value = env.run('heroku config:get %(var)s --app %(app)s' % dict(var=var, app=env.heroku_app), capture=True)
            shared_vars[var] = value

    if env.heroku_worker:
        env.run('heroku config:set %(vars)s --app %(app)s' % dict(vars=vars_line(env_vars), app=env.heroku_worker))
        env.run('heroku config:set %(vars)s --app %(app)s' % dict(vars=vars_line(shared_vars), app=env.heroku_worker))

@task
def deploy(tag=None):
    print(red("Deploying"))
    with prefix(venv()):
        upload_static_files()

    if env.heroku_app:
        set_env_vars()
        env.run('git push %s %s' % (env.heroku_app_git_remote, env.heroku_deploy_branch))
        env.run('heroku ps:scale web=1 --app %s' % env.heroku_app)
        if env.heroku_worker:
            env.run('heroku ps:scale worker=0 --app %s' % env.heroku_app)

    if env.heroku_worker:
        env.run('git push %s %s' % (env.heroku_worker_git_remote, env.heroku_deploy_branch))
        if env.heroku_app:
            env.run('heroku ps:scale web=0 --app %s' % env.heroku_worker)
        env.run('heroku ps:scale worker=1 --app %s' % env.heroku_worker)

    warmup()
    print(green("Deploy success"))

@task
def rollback(tag=None, worker=False):
    app = env.heroku_worker if worker else env.heroku_app
    env.run('heroku releases --app %s' % app)
    if not confirm('Rollback (tag %s). Are you sure?' % tag):
        abort('cancelled by the user')
    if tag:
        env.run('heroku rollback --app %s' % app)
    else:
        env.run('heroku rollback %s --app %s' % (tag, app))

@task
def logs(worker=False):
    app = env.heroku_app if not worker else env.heroku_worker
    env.run('heroku logs -n 100 --app %s' % app)
    env.run('heroku logs --tail --app %s' % app)

@task
def ssh(worker=False):
    if env.heroku_worker or worker:
        env.run('heroku run python --app %s' % env.heroku_worker)
    else:
        env.run('heroku run python --app %s' % env.heroku_app)

# Tasks Localhost/Production/Staging

@task
def ping(time=3):
    env.run('ping -c %(time)s %(host)s:%(port)s' % dict(time=time, host=env.host, port=env.port))

@task
def warmup():
    weighttp(requests=5000, concurrency=10)

@task
def benchmark():
    weighttp(requests=10000, concurrency=50)

@task
def browse():
    env.run('open %s' % env.url)
test_fabfile.py
# coding: utf-8
import unittest

from fabfile import *


class UtilTests(unittest.TestCase):
    def test_colorize(self):
        colorize('test')
        colorize('test', 'blue')

    def test_s(self):
        self.assertEquals(s('x'), 'x')
        x = 1
        self.assertEquals(s('{x}'), '1')


class BashTests(unittest.TestCase):
    def test_clear(self):
        Bash.clear()

    def test_env_var(self):
        Bash.check_env_var('PATH')
        self.assertEquals(Bash.get_env_var('PATH2'), None)

        Bash.set_env_var('PATH2', 1)
        self.assertEquals(Bash.get_env_var('PATH2'), '1')

        Bash.set_env_var('PATH2', None)
        self.assertEquals(Bash.get_env_var('PATH2'), None)

    def test_run_in_dir(self):
        Bash.run_in_dir('.', 'ls')

    def test_permissions(self):
        Bash.permissions('tests.py', group='staff')

    def test_find_file(self):
        Bash.find_file('x')
        Bash.find_file('x', dir='.')

    def test_find_dir(self):
        Bash.find_dir('x')
        Bash.find_dir('x', dir='.')

    def test_find_link(self):
        Bash.find_link('x')
        Bash.find_link('x', dir='.')


class ZipTests(unittest.TestCase):
    def test_pack(self):
        Zip.pack('x.zip', ['fabfile.py', 'tests.py'])


class SSHTests(unittest.TestCase):
    def test_create_key(self):
        SSH.create_key('test@test.com', filepath='./testSSHKey')

    def test_copy_public_key(self):
        SSH.copy_public_key()


class GitTests(unittest.TestCase):
    def setUp(self):
        Git.init()

    def test_config(self):
        Git.config('test', 'test@test.com', env='--local')

    def test_clean(self):
        Git.clean()

    # def test_reset(self):
    #     Git.reset()


class HttpTests(unittest.TestCase):
    def test_request(self):
        Http.request('google.com')
