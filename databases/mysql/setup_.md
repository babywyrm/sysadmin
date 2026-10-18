# MySQL Essentials

##
#
https://gist.github.com/shivanshthapliyal/79501b9cff55e7f36b9c8bb0d78efbf8
#
##

> :bust_in_silhouette: Shivansh Thapliyal  

## Contents
- [Installation](#installation)
	- [Installing MYSQL Centos](#installing-mysql-on-centos)
	- [Installing MYSQL on Amazon Linux 2](#installing-mysql-on-amazon-linux-2)
	- [Installing MYSQL on Ubuntu](#installing-mysql-on-ubuntu)
- [Other Actions](#other-actions)
	- [Allow remote access](#allow-remote-access)
	- [Configure interfaces](#configure-interfaces)
	- [Start the mysql shell](#start-the-mysql-shell)
	- [View users](#view-users)
	- [Create a database](#create-a-database)
	- [Add a database user](#add-a-database-user)
	- [Grant database user permissions](#grant-database-user-permissions)
- [Troubleshooting](#troubleshooting)
	- [Reset MySQL root password](#reset-mysql-root-password)
	- [Permissions problem](#permissions-problem)


---

# Installation 

## Installing MYSQL on CentOS:

    sudo wget https://dev.mysql.com/get/mysql57-community-release-el7-9.noarch.rpm
    sudo rpm -ivh mysql57-community-release-el7-9.noarch.rpm
    sudo yum install mysql-server
    sudo systemctl start mysqld.service
    
Refer [link.](https://dev.mysql.com/downloads/repo/yum/)
    
## Installing MYSQL on Amazon Linux 2:

    sudo wget https://dev.mysql.com/get/mysql57-community-release-el7-11.noarch.rpm
    sudo yum localinstall mysql57-community-release-el7-11.noarch.rpm
    sudo yum install mysql-community-server
    sudo systemctl start mysqld.service

## Installing MYSQL on Ubuntu:

    sudo apt-get update
    sudo apt-get install mysql-server

The installer installs MySQL and all dependencies.

If the secure installation utility does not launch automatically after the installation completes, enter the following command:

    sudo mysql_secure_installation utility

# Other Actions

### Configuring MySQL
During the installation process, a temporary password is generated for the MySQL root user. Locate it in the mysqld.log with this command:

	sudo grep 'temporary password' /var/log/mysqld.log

Use this command to run the security script.

	sudo mysql_secure_installation
	
This will prompt you for the default root password. As soon as you enter it, you will be required to change it.

### Allow remote access
If you have iptables enabled and want to connect to the MySQL database from another machine, you must open a port in your server’s firewall (the default port is 3306). You don’t need to do this if the application that uses MySQL is running on the same server.

Run the following command to allow remote access to the mysql server:

    sudo ufw enable
    sudo ufw allow mysql
    
Start the MySQL service
After the installation is complete, you can start the database service by running the following command. If the service is already started, a message informs you that the service is already running:

    sudo systemctl start mysql
    
Launch at reboot
To ensure that the database server launches after a reboot, run the following command:

    sudo systemctl enable mysql

### Configure interfaces
MySQL, by default is no longer bound to ( listening on ) any remotely accessible interfaces. Edit the “bind-address” directive in /etc/mysql/mysql.conf.d/mysqld.cnf:

    bind-address		= 127.0.0.1 ( The default. )
    bind-address		= XXX.XXX.XXX.XXX ( The ip address of your Public Net interface. )
    bind-address		= ZZZ.ZZZ.ZZZ.ZZZ ( The ip address of your Service Net interface. )
    bind-address		= 0.0.0.0 ( All ip addresses. )

Restart the mysql service.

    sudo systemctl restart mysql

### Start the mysql shell

At the command prompt, run the following command to launch the mysql shell and enter it as the root user:

    /usr/bin/mysql -u root -p
When you’re prompted for a password, enter the one that you set at installation time, or if you haven’t set one, press Enter to submit no password.

The following mysql shell prompt should appear:

    mysql>
Set the root password
If you logged in by entering a blank password, or if you want to change the root password that you set, you can create or change the password.

For versions earlier than MySQL 5.7, enter the following command in the mysql shell, replace password with your new password:

    UPDATE mysql.user SET Password = PASSWORD('password') WHERE User = 'root';
For version MySQL 5.7 and later, enter the following command in the mysql shell, replacing password with your new password:

    UPDATE mysql.user SET authentication_string = PASSWORD('password') WHERE User = 'root';
To make the change take effect, reload the stored user information with the following command:

    FLUSH PRIVILEGES;


### View users
MySQL stores the user information in its own database. The name of the database is mysql. Inside that database the user information is in a table, a dataset, named user. If you want to see what users are set up in the MySQL user table, run the following command:

    SELECT User, Host, authentication_string FROM mysql.user;
    

### Create a database


To create a database, log in to the mysql shell and run the following command, replacing demodb with the name of the database that you want to create:

    CREATE DATABASE demodb;

After the database is created, you can verify its creation by running a query to list all databases. The following example shows the query and example output:

    SHOW DATABASES;
    +--------------------+
    | Database           |
    +--------------------+
    | information_schema |
    | demodb             |
    | mysql              |
    +--------------------+
    3 rows in set (0.00 sec)

### Add a database user
When applications connect to the database using the root user, they usually have more privileges than they need. You can add users that applications can use to connect to the new database. In the following example, a user named demouser is created.

To create a new user, run the following command in the mysql shell:

    INSERT INTO mysql.user (User,Host,authentication_string,ssl_cipher,x509_issuer,x509_subject)
    VALUES('demouser','localhost',PASSWORD('demopassword'),'','','');

When you make changes to the user table in the mysql database, tell MySQL to read the changes by flushing the privileges, as follows:

    FLUSH PRIVILEGES;

Verify that the user was created by running a SELECT query again:

    SELECT User, Host, authentication_string FROM mysql.user;

    +------------------+-----------+-------------------------------------------+
    | User             | Host      | Password                                  |
    +------------------+-----------+-------------------------------------------+
    | root             | localhost | *756FEC25AC0E1823C9838EE1A9A6730A20ACDA21 |
    | mysql.session    | localhost | *THISISNOTAVALIDPASSWORDTHATCANBEUSEDHERE |
    | mysql.sys        | localhost | *THISISNOTAVALIDPASSWORDTHATCANBEUSEDHERE |
    | debian-sys-maint | localhost | *27E7CA2445405AB10C656AFD0F86AF76CCC57692 |
    | demouser         | localhost | *0756A562377EDF6ED3AC45A00B356AAE6D3C6BB6 |
    +------------------+-----------+-------------------------------------------+
### Grant database user permissions
Right after you create a new user, it has no privileges. The user can log in, but can’t be used to make any database changes.

Give the user full permissions for your new database by running the following command:

    GRANT ALL PRIVILEGES ON demodb.* to demouser@localhost;
Flush the privileges to make the change official by running the following command:

    FLUSH PRIVILEGES;
To verify that those privileges are set, run the following command:

    SHOW GRANTS FOR 'demouser'@'localhost';
    2 rows in set (0.00 sec)
MySQL returns the commands needed to reproduce that user’s permissions if you were to rebuild the server. USAGE on \*.\* means the users gets no privileges on anything by default. That command is overridden by the second command, which is the grant you ran for the new database.

    +-----------------------------------------------------------------------------------------------------------------+
    | Grants for demouser@localhost                                                                                   |
    +-----------------------------------------------------------------------------------------------------------------+
    | GRANT USAGE ON *.* TO 'demouser'@'localhost' IDENTIFIED BY PASSWORD '*0756A562377EDF6ED3AC45A00B356AAE6D3C6BB6' |
    | GRANT ALL PRIVILEGES ON `demodb`.* TO 'demouser'@'localhost'                                                    |
    +-----------------------------------------------------------------------------------------------------------------+
    2 rows in set (0.00 sec)

 # Troubleshooting
 ## Reset MySQL root password
 - Stop the MySQL service
	(Ubuntu operating system and Debian) Run the following command:

		sudo /etc/init.d/mysql stop

	(CentOS, Fedora, and Red Hat Enterprise Linux) Run the following command:

		sudo /etc/init.d/mysqld stop

- Start MySQL without a password
	Run the following command. The ampersand (&) at the end of the command is required.

   	 sudo mysqld_safe --skip-grant-tables &
	 
	If you get an error like: mysqld_safe Directory '/var/run/mysqld' for UNIX socket file don't exists
	Then:
		
		mkdir -p /var/run/mysqld
		chown mysql:mysql /var/run/mysqld

- Connect to MySQL
	Run the following command:

	    mysql -uroot
- Set a new MySQL root password
	Run the following command:

		use mysql;

		update user set authentication_string=PASSWORD("mynewpassword") where User='root';

		flush privileges;

		quit
- Stop and start the MySQL service
	(Ubuntu operating system and Debian) Run the following commands:

		sudo /etc/init.d/mysql stop
		...
		sudo /etc/init.d/mysql start
	(CentOS, Fedora, and Red Hat Enterprise Linux) Run the following commands:

		sudo /etc/init.d/mysqld stop
		...
		sudo /etc/init.d/mysqld start
- Log in to the database
	Test the new password by logging in to the database.

		mysql -u root -p
	Enter your new password when prompted.
    
## Permissions problem
	sudo grep 'temporary password' /var/log/mysqld.log
	sudo /usr/bin/mysql_secure_installation 
## ERROR 1819 (HY000): Your password does not satisfy the current policy requirements

### Set the Password_Policy to low:

Default Password level of plugin can be changed at runtime or using config file. To do this, default authentication plugin has to be checked.

	SHOW VARIABLES LIKE ‘default authentication plugin’;

For checking the current variables for validating the password you should run the following command.

	SHOW VARIABLES LIKE 'validate_password%';
Validate_password is a variable that is used to inform the server about the validate_password plugin. This plugin tests the passwords and improve security. Following output will be displayed, if you run the above command.

	mysql> SHOW VARIABLES LIKE 'validate_password%';


There are three policies in Validate_password_policy. The policies are used to define the strength of the password. The default policy value will be Medium and the value is changed to Low which has the password length of minimum 8 characters and it is used only to check the length of the password. Password policy value is set using the following command.

	SET GLOBAL validate_password_policy=LOW;
	Set same variable in my.cnf file:

My.cnf file is the configuration file and frequently used options don’t want to be entered in command line. Start-up options can be read from these file. Following command is used in my.cnf file to set the password policy value.

[mysqld]

	validate_password_policy=LOW
	mysqld has to be restated after changing the password policy value.

	sudo service mysqld restart


### Uninstall Plugin used for Password Validation

This error is rectified by uninstalling the plugin. Only root user of the database can uninstall the plugin. The root user gets all the privileges by default. The following command is used to set the root user.

	# mysql -u root –p

The statement given below is used to remove the installed validate_password plugin.

	UNINSTALL PLUGIN validate_password;

## Steps 

1. Stop mysql:
systemctl stop mysqld

2. Set the mySQL environment option 
systemctl set-environment MYSQLD_OPTS="--skip-grant-tables"

3. Start mysql usig the options you just set
systemctl start mysqld

4. Login as root
mysql -u root

5. Update the root user password with these mysql commands
mysql> UPDATE mysql.user SET authentication_string = PASSWORD('MyNewPassword')
    -> WHERE User = 'root' AND Host = 'localhost';
mysql> FLUSH PRIVILEGES;
mysql> quit

*** Edit ***
As mentioned my shokulei in the comments, for 5.7.6 and later, you should use 
   mysql> ALTER USER 'root'@'localhost' IDENTIFIED BY 'MyNewPass';
Or you'll get a warning

6. Stop mysql
systemctl stop mysqld

7. Unset the mySQL envitroment option so it starts normally next time
systemctl unset-environment MYSQLD_OPTS

8. Start mysql normally:
systemctl start mysqld

Try to login using your new password:
7. mysql -u root -p
