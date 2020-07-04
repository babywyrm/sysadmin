Creating a Basic Nginx Salt Formula
Introduction
As the intern at the special-interest publication Apartment 42, you have been tasked with creating an Nginx Salt formula so the web developer can explore the possibility of using Nginx to host their# Creating a Basic Nginx Salt Formula

Introduction
As the intern at the special-interest publication Apartment 42, you have been tasked with creating an Nginx Salt formula so the web developer can explore the possibility of using Nginx to host their new website. He is currently testing this on CentOS-based servers, and requests that you present him an Nginx formula that can install Nginx, manage the default configuration file at /etc/nginx/nginx.conf, and a restart state that will trigger whenever the configuration file is updated.

A copy of the nginx.conf file is provided for your here. The CentOS 7 server provided works as both a master and a minion. Note that the epel-release repository also needs to be installed to add Nginx; creating a separate state for this is advised.

Solution
Log in to the Salt Master lab server using the credentials provided on the hands-on lab page:

ssh cloud_user@PUBLIC_IP_ADDRESS
Create an Nginx State That Adds the Epel Repository
Change the directory:

cd /srv/salt/
Make a nginx directory and move into it:

mkdir nginx
cd nginx/
Create and edit the epel.sls file:

vim epel.sls
Add the following text to the file:

add_epel:
  pkg.installed:
    - name: epel-release
Save the changes and exit the editor.

Edit the init.sls file:

vim init.sls
Add the following text to the file:

include:
  - nginx.epel

install_nginx:
  pkg.installed:
    - name: nginx
  service.running:
    - name: nginx
    - enable: true
Save the changes and exit the editor.

Test the changes.

sudo salt 'salt' state.sls nginx test=true
Set Up the Nginx Configuration File
Make a config directory and transfer into it:

mkdir config
cd config
Pull down the configuration file:

wget https://raw.githubusercontent.com/linuxacademy/using-salt-nginx/master/config/.nginx.conf
Rename the config file:

mv .nginx.conf nginx.conf
Edit the config file.

vim nginx.conf
Add a note to the top of the file:

# This file is managed by Salt. Please do not make changes.
Save the changes and exit the editor.

Return to the nginx folder:

cd ..
Create and edit the config file:

vim config.sls
Add the following text to the file:

nginx_configuration:
  file.managed:
    - name: /etc/nginx/nginx.conf
    - source: salt://nginx/config/nginx.conf
    - require:
      - pkg: nginx
Save the changes and exit the editor.

Create a State to Trigger a Restart Whenever the Configuration File Changes
Create and edit a restart.sls file:

vim restart.sls
Add the following text to this file:

nginx_restart:
  module.wait:
    - name: service.restart
    - m_name: nginx
    - onchanges:
      - nginx_configuration
Save the changes and exit the editor.

Verify Nginx is installed:

sudo salt 'salt' state.sls nginx
Test the configuration changes:

sudo salt 'salt' state.sls nginx,nginx.config,nginx.restart test=true
After verifying the results, run the command:

sudo salt 'salt' state.sls nginx,nginx.config,nginx.restart
