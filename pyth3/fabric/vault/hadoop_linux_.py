
""" Fab file created by prem = kry496@my.utsa.edu for Apache Hadoop Cluster deployment in Ubuntu or CentOs """
# Deploy multi-node Apache Hadoop cluster with Fabric Library and Python
#Fabric is a ssh/fscp/ftp/bash-login-shell wrapper to run commands on local and remote hosts
# Project was built using Fabric 1.13 Package - Stable version as of Dec 2016
#Tested on Ubuntu  ; support for CentOS/RHEL with SE will be added in few months
# Create Terminalbox( install fabric here) to run your script
#all vms should be of same distribution
# Hadoop related VMs - one MasterNode and ANY number of Slave nodes, use Virtual box. 
# On virtual box -create the VMs with one Regular NAT adapter to use ur host os's Internet
# and create one other network adapter with Virtual box host only mode
#This way you get a pre interconnected Set of VMS
# Pre-interconnected nodes or cluster with IP addresses on virtual adapter which we use.
# use the Private IPs that are generated and add it to the env values in the scripts
#Pre-requisites for the script to function ->  properly install fabric as root
# use command -> pip install fabric==1.13     is the command that you need.
# if its a new server(terminal-box) run the yum /apt upgrade before starting this script even the script calls it.


# import all the fabric functions that we are going to use, a standard list use fabfile.org docs if you need additional funcitons:

from fabric.api import env, roles, sudo, execute, put, run, local, lcd, prompt, cd, parallel, settings, hide, quiet 
from fabric.contrib.files import exists, append, contains
from  fabric.operations import put

# import platform module to test the machine type of the terminal box.
# Non Fabric library fabric related imports: import entire module to enable code & namespace management at scale. so you know when direct function is called, if it is fabric's function call
import platform

# import the os module to get file basenames
import os


#add to bash file on all hadoop nodes

bashrc_updates = """
#add to bash file 
# Set Hadoop-related environment variables
export HADOOP_HOME=/usr/local/hadoop/hadoop
export HADOOP_MAPRED_HOME=$HADOOP_HOME
export HADOOP_COMMON_HOME=$HADOOP_HOME
export HADOOP_HDFS_HOME=$HADOOP_HOME
export YARN_HOME=$HADOOP_HOME
export HADOOP_CONF_DIR=$HADOOP_HOME/etc/hadoop
export HADOOP_JAR=/usr/local/hadoop/hadoop/share/hadoop/mapreduce
# Set JAVA_HOME (we will also configure JAVA_HOME directly for Hadoop later on)
export JAVA_HOME=/usr/lib/jvm/default-java

# Some convenient aliases and functions for running Hadoop-related commands
#unalias fs &> /dev/null
#alias fs="hdfs"
#unalias hls &> /dev/null
#alias hls="fs -ls"


# If you have LZO compression enabled in your Hadoop cluster and
# compress job outputs with LZOP (not covered in this tutorial):
# Conveniently inspect an LZOP compressed file from the command
# line; run via:
#
# $ lzohead /hdfs/path/to/lzop/compressed/file.lzo
# Note : we are not compressing  !!!!!!  Yet !!!!
# Requires installed 'lzop' command.
#

# Add Hadoop bin/ directory to PATH

export PATH=$PATH:$HADOOP_HOME/bin:$HADOOP_HOME/sbin

"""

# Update the roledefs environment variable to define the set of master and slave nodes for the hadoop configuration.
env.roledefs = {
    'masternode': ['192.168.56.184'],
    'slavenodes': ['192.168.56.185', '192.168.56.186','192.168.56.187'],
}

# List Comprehension to define all sevever in a single list to apply certain settings to all servers 
env.roledefs['all'] = [x for y in env.roledefs.values() for x in y]

#add to /etc/hosts file

hosts_file_update='''
192.168.56.184 master
192.168.56.185 slave1
192.168.56.186 slave2
192.168.56.187 slave3
'''
#updates to /etc/sysctl for disabling ipv6

sysctl_update='''
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1'''



# Define the list of packages required. # setting up the dictionary for scaling the script.
#packages_required = {
#   'masternode': ['default-jdk','openssh-server',],
#   'slavenodes': ['default-jdk','openssh-server',]
#}
# update the env user variable

env.user='hduser'


# lets create a hadoop user 
# dont use  parallel decorator here, since user creating command is interactive.
# use roles decorator and call all the servers in the roledefs python sub dictionary class.
# run vs sudo  -> regular user vs privelaged user execution styles

@roles('all')
def create_hduser():
	with settings (warn_only=True):
		if run('id -u hduser').return_code == 1:
			sudo('addgroup hadoopadmin && adduser --ingroup hadoopadmin hduser && usermod -aG sudo hduser', user='root', pty=True)
		else:
			print " hduser exists"

		
# The hadoop Mapreduce test files and hadoop 2.7.3 tar files that needs to be downloaded
test_files = {
    'masternode' : ['http://www.gutenberg.org/cache/epub/2041/pg2041.txt',
                    'http://www.gutenberg.org/files/5000/5000-8.txt',
					'http://www.gutenberg.org/files/4300/4300-0.txt',
					]
					}

download_hadoop = {
	'masternode' : ['http://www-eu.apache.org/dist/hadoop/core/hadoop-2.7.3/hadoop-2.7.3.tar.gz']
}


#we download the files in a folder and change permissions
# need to add a quiet setting below once functionality is tested
@parallel
@roles('all')
def download_files():
	hadoop_dir = "/usr/local/hadoop"
	if exists('/usr/local/hadoop/hadoop-2.7.3.tar.gz') == True:
		print ' hadoop is already downloaded'
	else:
		sudo('mkdir -p %s' %hadoop_dir, pty=True)
		sudo('chown hduser:hadoopadmin %s' % hadoop_dir, pty=True)
		sudo('chmod g+s %s' %hadoop_dir, pty=True)
		with cd(hadoop_dir):
			for url in download_hadoop['masternode']:
				filename = "%s/%s" %(hadoop_dir, os.path.basename(url))
				run('wget --no-cache %s -O %s' %(url, filename))
	

@roles('masternode')
def download_test_files():
	test_dir = '/home/hduser/test'
	if exists('/home/hduser/test/') == True:
		print 'test folder already exists'
	else:
		sudo('mkdir -p %s' %test_dir, user='hduser', pty=True)
		#sudo('chown -R hduser:hadoopadmin %s' %test_dir, pty=True)
		#sudo('chmod g+s %s' %test_dir, pty=True)
		with cd(test_dir):
			for url in test_files['masternode']:
				testfilename = "%s/%s" %(test_dir, os.path.basename(url))
				platform.node()
				run('wget --no-cache %s -O %s' %(url, testfilename))


# Install JDK depending on the linux distribution
# the underscore makes the function un - callable with fab command. a private function.
def _java_distro():
	with settings (warn_only=True):
		if 'ubuntu' in platform.platform().lower():
			sudo('apt-get -y install default-jdk')
		elif 'centos' in platform.platform().lower():
			sudo('yum install -y default-jdk')
		else:
                        print 'this script works only on ubuntu or centos linux distribution'
			print 'exiting the script'


#parallely execute on all nodes in the cluster

@parallel			
@roles('all')	
def  java_install():
	with quiet():
		a =  run('which java')
       		if a.return_code >= 1:
        		_java_distro()
	        elif a.return_code  == 0:
	        	print ' java is installed'
		else:
			print 'unknown return_code'
# generate the ssh key on the hadoop master
	
@roles('all')
def create_ssh_key():
	with settings (warn_only=True):
		if exists('/home/hduser/.ssh/id_rsa') == True:
			print 'ssh key already exists'
		else:
			sudo('ssh-keygen -t rsa -P "" -f /home/hduser/.ssh/id_rsa', user='hduser', pty=True)
			sudo("cat /home/hduser/.ssh/id_rsa.pub >> /home/hduser/.ssh/authorized_keys", user='hduser', pty=True)
			sudo("chmod 600 /home/hduser/.ssh/authorized_keys", user='hduser', pty=True)
			sudo("/etc/init.d/ssh reload")


# pull the master node's key from all the slave nodes

@roles('masternode')
def copy_ssh_key():
	with settings (warn_only=True):
		if exists('/home/hduser/.ssh/id_rsa.pub') == True:
			slaves = raw_input('enter number of slaves')
			sl = int(slaves)+1
			for x in range(1,sl):
				run('ssh-copy-id -i ~/.ssh/id_rsa.pub slave%s' %(x))


				
		

# lets append the bashrc_updates text to the bashrc file of HDUSER
# fabric.contrib.files.append(filename, text, use_sudo=False, partial=False, escape=True, shell=False)
# we putting hadoop specific variable and updating the path ENV.. etc
@parallel				  
@roles('all')
def update_bashrc():
	with settings (warn_only=True):
		if exists('/home/hduser/.bashrc') == True:
			if contains('/home/hduser/.bashrc', "HADOOP") == False:
				append('/home/hduser/.bashrc', bashrc_updates, use_sudo=True)
				sudo('source /home/hduser/.bashrc', pty=True)
			else:
				print " HADOOP ENVs are already updated"
		else:
			print 'hduser doesnt exist'


# update the host file on all the nodes
@roles('all')
def update_hostfile():
	with settings (warn_only=True):
		if contains('/etc/hosts', 'master') == False:

			append('/etc/hosts', hosts_file_update, use_sudo=True)
		else:
			print ' the etc host file is already updated'


# GO parallel mode and IPV6 needs to be disabled for the Hadoop Cluster to work
@parallel
@roles('all')
def disable_ipv6():
	with settings (warn_only=True):
		if contains('/proc/sys/net/ipv6/conf/all/disable_ipv6', '1') == False:
			append('/etc/sysctl.conf', sysctl_update, use_sudo=True)
			sudo('sysctl -p', pty=True)
		else:
			print 'IPV6 is already disable'


#un-zip and move the hadoop files
#@parallel
@roles('all')
def unzip_hadoop():
	with settings (warn_only=True), cd('/usr/local/hadoop'):
		if exists('/usr/local/hadoop/hadoop') == True:
			print 'Already unzipped'
		else:
			sudo('tar xzf hadoop-2.7.3.tar.gz', pty=True, user='hduser')
			sudo('mv hadoop-2.7.3 hadoop', pty=True, user='hduser')


#not using right now 
#def copy_hadoop_files():
#	with settings (warn_only=True):
#		put('/usr/local/hadoop/hadoop-2.7.3.tar.gz', '/usr/local/hadoop/hadoop-2.7.3.tar.gz', mode=0750)
#push the hadoop config files with pre-saved text files from git
#@parallel
@roles('all')
def update_hadoop_config():
	with settings (warn_only=True), lcd('/temp_hadoop/hadoop_config_files'):
		put('hadoop-env.sh', '/usr/local/hadoop/hadoop/etc/hadoop/hadoop-env.sh')
		put('core-site.xml', '/usr/local/hadoop/hadoop/etc/hadoop/core-site.xml')
		put('hdfs-site.xml', '/usr/local/hadoop/hadoop/etc/hadoop/hdfs-site.xml')
		put('mapred-site.xml', '/usr/local/hadoop/hadoop/etc/hadoop/mapred-site.xml')
		put('yarn-site.xml', '/usr/local/hadoop/hadoop/etc/hadoop/yarn-site.xml')
		put('slaves', '/usr/local/hadoop/hadoop/etc/hadoop/slaves')


@roles('all')
def create_hdfs():
	with settings (warn_only=True):
		if exists('/app/hadoop/tmp') == True:
			print ' /app/hadoop/tmp exists'
		else:
			sudo('mkdir -p /app/hadoop/tmp', pty=True)
			sudo('chown -R hduser:hadoopadmin /app/hadoop/tmp', pty=True)
			sudo('chmod 750 /app/hadoop/tmp', pty=True)
		

@roles('masternode')
def create_name_data_node():
	with settings (warn_only=True):
		sudo("mkdir -p /usr/local/hadoop/hadoop/yarn/yarn_data/hdfs/namenode", user='hduser', pty=True)
		sudo("mkdir -p /usr/local/hadoop/hadoop/yarn/yarn_data/hdfs/datanode", user='hduser', pty=True)
	

@roles('masternode')
def format_namenode():
	with settings (warn_only=True), cd('/usr/local/hadoop/hadoop/bin'):
		run('pwd')
		run('./hadoop namenode -format', pty=True)


@roles('masternode')
def start_hadoop():
	with settings (warn_only=True), cd('/usr/local/hadoop/hadoop/sbin/'):
		sudo('./start-all.sh', user='hduser', pty=True)
		sudo('./mr-jobhistory-daemon.sh start historyserver', user='hduser', pty=True)

@roles('all')
def test_hadoop():	
	with settings (warn_only=True):
		sudo('jps', user='hduser', pty=True)
		#sudo('netstat -plten | grep java', user='hduser', pty=True)


#yum and apt upgrades for all servers		

@roles("all") 
def upgrade_servers():
	if 'ubuntu' in platform.platform().lower():
		sudo('apt-get -y upgrade', pty=True)
	elif 'centos' in platform.platform().lower():
		sudo("yum -y upgrade",pty=True)
	else:
        	print 'this script works only on ubuntu or centos linux distribution'
		print 'exiting the script'

#write code to pop the browser for given address only on masternode
#@roles('masternode')
#def pop_browser():
#import code and pop browser
#http://master:50070

#move the three files into HDFS for word count program to check run its mapreduce

@roles('masternode')
def load_test_files():
	with settings (warn_only=True), cd('/usr/local/hadoop/hadoop/bin'):
		run('./hdfs dfs -copyFromLocal /home/hduser/test /a')
		run('./hdfs dfs -ls /a')

#run the jar file for wordcount program and place the output in /ba in hdfs
@roles('masternode')
def test_mapreduce():
	with settings (warn_only=True), cd('/usr/local/hadoop/hadoop/bin'):
		run('./hadoop jar /usr/local/hadoop/hadoop/share/hadoop/mapreduce/hadoop-mapreduce-examples-2.7.3.jar wordcount /a /y')


#inspece the contents for successful verification
@roles('masternode')
def verify_mapreduce():
	with settings (warn_only=True), cd('/usr/local/hadoop/hadoop/bin'):
		run('./hdfs dfs -ls /y')
		#run('./hdfs -cat /ba/part-r-00000')
	#run the broswer load code

#move the final output out of of HDFS into the client folder
@roles('masternode')
def moveout():
	with settings (warn_only=True), cd('/usr/local/hadoop/hadoop/bin'):
		run('./hdfs dfs -getmerge /y /home/hduser/test/final_output')

#shutdown the hdfs cluster
@roles('masternode')
def stop_hadoop():
	with settings (warn_only=True), cd('/usr/local/hadoop/hadoop/sbin'):
		sudo('./stop-all.sh', user='hduser', pty=True)
		sudo('./mr-jobhistory-daemon.sh stop historyserver', user='hduser', pty=True)


@roles('masternode')
def manual_ssh():
	with settings (warn_only=True):
		for x in env.roledefs['slavenodes']:
 			sudo(' ssh hduser@%s' %(x), user='hduser', pty=True)


@roles('all')
def turnoff_firewall():
	with settings (warn_only=True):
		sudo('ufw disable', pty=True)


@roles('all')
def reboot_vms():
	with settings (warn_only=True), quiet():
		sudo('reboot', pty=True)
 

# this is the main function we will be calling to get it all running
def deploy():
    # note here that the execute function has the names of the functions we
    # are calling, but we are excluding the parenthesis()
    #execute(create_hduser)
    execute(update_hostfile)
    #execute(upgrade_servers)
    execute(java_install)
    execute(create_ssh_key)
    execute(copy_ssh_key)	
    execute(update_bashrc)
    execute(disable_ipv6)
    execute(download_files)
    execute(download_test_files)
    execute(unzip_hadoop)
    execute(update_hadoop_config)
    execute(create_hdfs)
    execute(format_namenode)
    execute(start_hadoop)
    execute(test_hadoop)
    #execute(pop_browser)
    execute(load_test_files)
    execute(test_mapreduce)
    execute(verify_mapreduce)
    execute(moveout)
    execute(stop_hadoop)
