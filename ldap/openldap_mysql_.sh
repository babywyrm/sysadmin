## installation openldap with backend mysql
sudo apt update && sudo apt upgrade -y && sudo reboot
sudo apt install mysql-server unixodbc make gcc libmysqlclient-dev unixodbc-dev groff ldap-utils

## mysql login as root
sudo mysql -u root

CREATE DATABASE ldap
CREATE USER 'ldap'@'%' IDENTIFIED BY 'S3cureP4ssw0rd$';
GRANT ALL PRIVILEGES ON ldap.* TO 'ldap'@'%';
CREATE USER 'ldap'@'localhost' IDENTIFIED BY 'S3cureP4ssw0rd$';
GRANT ALL PRIVILEGES ON ldap.* TO 'ldap'@'localhost';
FLUSH PRIVILEGES;
EXIT

## create table to ldap database
git clone https://gist.github.com/mahirrudin/bdde7e60fe2a4a3e7b17c5ee28bf02c0 init-ldap.sql
wget https://github.com/openldap/openldap/blob/6b57448bcc1913b79640f2c2c5cdc0560270bed0/servers/slapd/back-sql/rdbms_depend/mysql/testdb_metadata.sql
wget https://github.com/openldap/openldap/blob/6b57448bcc1913b79640f2c2c5cdc0560270bed0/servers/slapd/back-sql/rdbms_depend/mysql/testdb_data.sql
sudo mysql -u root ldap < init-ldap.sql
sudo mysql -u root ldap < testdb_metadata.sql
sudo mysql -u root ldap < testdb_data.sql

## install mysql odbc connector
wget https://dev.mysql.com/get/Downloads/Connector-ODBC/8.0/mysql-connector-odbc-8.0.11-linux-ubuntu18.04-x86-64bit.tar.gz
tar -xvzf mysql-connector-odbc-8.0.11-linux-ubuntu18.04-x86-64bit.tar.gz
cd mysql-connector-odbc-*/
sudo cp lib/libmyodbc8* /usr/lib/x86_64-linux-gnu/odbc/

## create file /etc/odbcinst.ini
[MySQL Unicode]
Description = MySQL ODBC 8.0 Unicode Driver
Driver = /usr/lib/x86_64-linux-gnu/odbc/libmyodbc8w.so
Setup = /usr/lib/x86_64-linux-gnu/odbc/libmyodbc8S.so
FileUsage = 1

[MySQL ANSI]
Description = MySQL ODBC 8.0 ANSI Driver
Driver = /usr/lib/x86_64-linux-gnu/odbc/libmyodbc8a.so
Setup = /usr/lib/x86_64-linux-gnu/odbc/libmyodbc8S.so
FileUsage = 1

## edit /etc/odbc.ini
[ldap]
Description = MySQL Connector for LDAP
Driver = MySQL Unicode
Database = ldap
Server = 127.0.0.1
User = ldap
Password = S3cureP4ssw0rd$
Port = 3306

## check ldap connection if it works
sudo echo "show databases" | isql -v ldap

+---------------------------------------+
| Connected!                            |
|                                       |
| sql-statement                         |
| help [tablename]                      |
| quit                                  |
|                                       |
+---------------------------------------+
SQL> show databases
+-----------------------------------------------------------------+
| Database                                                        |
+-----------------------------------------------------------------+
| information_schema                                              |
| ldap                                                            |
+-----------------------------------------------------------------+

## download, compile, and install openldap from source
## more information http://www.linuxfromscratch.org/blfs/view/svn/server/openldap.html
wget ftp://ftp.openldap.org/pub/OpenLDAP/openldap-release/openldap-2.4.46.tgz
tar -xvzf openldap-2.4.46.tgz
sudo mv openldap-2.4.* /opt/openldap
cd /opt/openldap
sudo ./configure --prefix=/usr --exec-prefix=/usr --bindir=/usr/bin --sbindir=/usr/sbin --sysconfdir=/etc --datadir=/usr/share --localstatedir=/var --mandir=/usr/share/man --infodir=/usr/share/info --enable-sql --disable-bdb --disable-ndb --disable-hdb
sudo make depend
sudo make
sudo make install

## create password for openldap configuration
sudo /usr/sbin/slappasswd -h {SSHA}
> input: mit

## edit /etc/openldap/slapd.conf

################### Start of Configuration ############################
# OpenLDAP Configuration by mahirrudin
#######################################################################

include		/etc/openldap/schema/core.schema
include		/etc/openldap/schema/cosine.schema
include		/etc/openldap/schema/inetorgperson.schema

pidfile		/var/run/slapd.pid
argsfile	/var/run/slapd.args

#######################################################################
# SQL database definitions
#######################################################################

database	sql
suffix		"dc=example,dc=com"
rootdn		"cn=Mitya Kovalev,dc=example,dc=com"
rootpw    {SSHA}JvQPNRew1UBxGZoqYoMy+tXYfVE0ZnVT

# SQL configuration
dbname ldap
dbuser ldap
dbpasswd S3cureP4ssw0rd$
has_ldapinfo_dn_ru no
subtree_cond "ldap_entries.dn LIKE CONCAT('%',?)"

################### End of Configuration ##############################

## running openldap
sudo /opt/openldap/servers/slapd/slapd -d 5 -h 'ldap:/// ldapi:///' -f /etc/openldap/slapd.conf &

## check if ldap working normally
ldapsearch -x -b "dc=example,dc=com"

##
##
##
