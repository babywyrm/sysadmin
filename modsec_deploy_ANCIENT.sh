#!/bin/bash
#
#
##
##   __consider_refactoring_&_modernizing_
##   __see_gists_for_owasp_and_comodo_modsec_rules_
##   
##
###############################
##
## https://github.com/StafDehat/scripts/blob/master/fs-old/modsec-install.sh
## c/o Messiah, (Truly)
##
###############################
################################################################################
# Author: Andrew Howard
# #############################                                                #
# After this has executed, the following file paths will be true:              #
#   /etc/httpd/conf.d/modsec.conf               -Main Config, Plesk            #
#   /etc/httpd/conf/modsec.conf                 -Main Config, Non-Plesk        #
#   /etc/httpd/conf/modsec.user.conf            -Includes the rulesets         #
#   /etc/httpd/conf/modsec-rules/core           -Static ruleset                #
#   /etc/httpd/conf/modsec-rules/dynamic        -Converted snort rules         #
#                                                                              #
# The script configures fsadmin's SSH key-access and grants ownership to       #
# fsadmin of mod_security rule sets.                                           #
#                                                                              #
################################################################################
# regular colors
K="\033[0;30m"    # black
R="\033[0;31m"    # red
G="\033[0;32m"    # green
Y="\033[0;33m"    # yellow
B="\033[0;34m"    # blue
P="\033[0;35m"    # purple
C="\033[0;36m"    # cyan
W="\033[0;37m"    # white
# emphasized (bolded) colors
EMK="\033[1;30m"
EMR="\033[1;31m"
EMG="\033[1;32m"
EMY="\033[1;33m"
EMB="\033[1;34m"
EMP="\033[1;35m"
EMC="\033[1;36m"
EMW="\033[1;37m"
NORMAL=`tput sgr0 2> /dev/null`


# Ensure this hasn't already been done
if [ -e /var/opt/modsec-fs ]; then
  echo -e "${EMR}Mod_security already installed."
  echo -e "Exiting.$NORMAL"
  exit 1
fi

# Can't handle 64-bit yet.  Check for it.
if [ `uname -a | grep x86_64 | wc -l` -gt 0 ]; then
  echo -e "${EMR}This installer is ill-equipped for 64-bit systems."
  echo -e "Exiting.$NORMAL"
  exit 1
fi

# Handle command-line arguments
while getopts ":h" arg
do
  case $arg in
    h  ) echo "Usage: $ME"
         exit 1;;
       # Print help
    *  ) echo "Unknown argument: $arg"
         exit 1;;
       # Default
  esac
done



#---------------------------------#
#----- Environment Detection -----#
#---------------------------------#
CWD=`pwd`
ME=$0

# Are we root?
if [ "$(id -u)" != "0" ]; then
   echo "We gots ta be root. Sry."
   exit 1
fi

# This is the one change that is made regardless of exit status
# Verify /etc/httpd/conf/ works/exists
if [ ! -d /etc/httpd ]; then
  ln -s /usr/local/apache /etc/httpd
fi

if [ ! -e /etc/httpd/conf/httpd.conf ]; then
  echo -e "${EMR}Unable to determine apache ServerRoot$NORMAL"
  exit 1
fi

# Set the package manager install command
if [ -e /etc/yum.conf ]; then
  echo -e "${EMG}Detected yum$NORMAL"
  PAKMAN="yum -y install"
elif [ -e /etc/sysconfig/rhn/sources ]; then
  echo "${EMG}Detected up2date$NORMAL"
  PAKMAN="up2date"
else
  echo "${EMR}This only works on RedHat-based systems.  Exiting.$NORMAL"
  exit 1
fi

# Apache details
#if [[ "`rpm -q httpd`" =~ "not installed" ]]; then #Incompatible with Cent-3
if [ `rpm -q httpd | grep "not installed" | wc -l` -gt 0 ]; then
  RPMINSTALL=0
  VER=`/etc/httpd/bin/httpd -v | grep version | sed 's/^.*Apache\/\([0-9]\+\(\.[0-9]\+\)*\).*/\1/g'`
else
  RPMINSTALL=1
  VER=`/usr/sbin/httpd -v | grep version | sed 's/^.*Apache\/\([0-9]\+\(\.[0-9]\+\)*\).*/\1/g'`
fi


# METHOD: Numeric, corresponds to case statement below
METHOD=-1

if [ -z $VER ]; then
  echo -e "${EMR}Unable to determine apache version.$NORMAL"
  METHOD=0
elif [ -e /usr/local/cpanel/version ]; then #cPanel system
  echo -e "${EMG}cPanel detected.$NORMAL"
  if [ $RPMINSTALL -eq 0 ]; then #Source Install
    echo -e "${EMG}Source apache detected.$NORMAL"
    METHOD=1
    #if [[ $VER =~ "^1\." ]]; then #Apache 1
    if [ `echo $VER | grep -E '^1\.' | wc -l` -gt 0 ]; then # Apache 1
      echo -e "${EMG}Apache version $VER detected.$NORMAL"
      METHOD=1
    elif [ `echo $VER | grep -E '^2\.' | wc -l` -gt 0 ]; then # Apache 2
      echo -e "${EMG}Apache version $VER detected.$NORMAL"
      METHOD=7
    else
      echo -e "${EMG}Apache version $VER detected.$NORMAL"
      METHOD=0
    fi # End version test
  else #RPM Install
    echo -e "${EMG}RPM installation detected.$NORMAL"
    METHOD=0
  fi # End source/rpm test
elif [ -e /usr/local/psa/version ]; then #Plesk System
  echo -e "${EMG}Plesk detected.$NORMAL"
  if [ $RPMINSTALL -eq 0 ]; then #Source Install
    echo -e "${EMG}Source installation detected.$NORMAL"
    METHOD=0
  else #RPM Install
    #if [[ $VER =~ "^2\." ]]; then
    if [ `echo $VER | grep -E '^2\.' | wc -l` -gt 0 ]; then
      echo -e "${EMG}Apache version $VER detected.$NORMAL"
      METHOD=2
    else
      echo -e "${EMG}Apache version $VER detected.$NORMAL"
      METHOD=0
    fi #End Version Test
  fi #End RPM Test
else #No Panel
  echo -e "${EMG}No control panel detected.$NORMAL"
  if [ $RPMINSTALL -eq 0 ]; then #Source Install
    echo -e "${EMG}Source installation detected.$NORMAL"
    if [ -d /usr/local/cpanel/apache ]; then #EasyApache
      echo -e "${EMG}EasyApache-compiled apache detected.$NORMAL"
      #if [[ $VER =~ "^1\." ]]; then #EasyApache-1
      if [ `echo $VER | grep -E '^1\.' | wc -l` -gt 0 ]; then
        echo -e "${EMG}Apache version $VER detected.$NORMAL"
        METHOD=3
      else #EasyApache-2+
        echo -e "${EMG}Apache version $VER detected.$NORMAL"
        METHOD=0
      fi
    else
      echo -e "${EMG}Raw source apache detected.$NORMAL"
      #if [[ $VER =~ "^1\." ]]; then #Apache 1
      if [ `echo $VER | grep -E '^1\.' | wc -l` -gt 0 ]; then #Apache 1
        echo -e "${EMG}Apache version $VER detected.$NORMAL"
        METHOD=5
      elif [ `echo $VER | grep -E '^2\.' | wc -l` -gt 0 ]; then #Apache 2
        echo -e "${EMG}Apache version $VER detected.$NORMAL"
        METHOD=6
      else
        echo -e "${EMG}Apache version $VER detected.$NORMAL"
        METHOD=0
      fi # End version test
    fi
  else #RPM Install
    echo -e "${EMG}RPM installation detected.$NORMAL"
    #if [[ $VER =~ "^2\." ]]; then #RPM Apache 2
    if [ `echo $VER | grep -E '^2\.' | wc -l` -gt 0 ]; then #RPM Apache 2
      echo -e "${EMG}Apache version $VER detected.$NORMAL"
      METHOD=4
    else
      echo -e "${EMG}Apache version $VER detected.$NORMAL"
      METHOD=0
    fi
  fi
fi



#-------------------#
#----- fsadmin -----#
#-------------------#
# Ensure fsadmin exists
useradd fsadmin

# Grant Atma access
HOMEDIR=`echo 'echo $HOME' | su - fsadmin | tail -1`
if [ ! -d $HOMEDIR ]; then
  mkdir $HOMEDIR
fi
if [ ! -d $HOMEDIR/.ssh ]; then
  mkdir $HOMEDIR/.ssh
fi
touch $HOMEDIR/.ssh/authorized_keys
chmod 700 $HOMEDIR $HOMEDIR/.ssh
chown fsadmin.fsadmin $HOMEDIR $HOMEDIR/.ssh $HOMEDIR/.ssh/authorized_keys
wget -nv -O - http://SERVER/modsec/pubkey >> $HOMEDIR/.ssh/authorized_keys



#-------------------#
#----- Install -----#
#-------------------#
case $METHOD in
  0 ) # Combination unsupported by this installer
      echo -e "${EMR}Unsupported environment!"
      echo -e "Exiting$NORMAL"
      exit 1;;

  1 ) # cPanel / easyapache / version 1
      $PAKMAN pcre pcre-devel
      cd /usr/src
      wget -nv SERVER/modsec/modsecurity-apache_1.9.5.tar.gz
      tar -xzf modsecurity-apache_1.9.5.tar.gz
      cd modsecurity-apache_1.9.5/apache1
      /etc/httpd/bin/apxs -I/usr/include/pcre -DEAPI -DUSE_PCRE -cia /usr/src/modsecurity-apache_1.9.5/apache1/mod_security.c
      RET=$?
      # Load PCRE into apache
      ln -s /usr/lib/libpcre.so /etc/httpd/libexec/libpcre.so
      sed -i /"LoadModule\s*security_module\s*libexec\/mod_security.so"/s/^/"LoadFile libexec\/libpcre.so\n"/ /etc/httpd/conf/httpd.conf
      if [ -e /usr/local/apache/conf/includes/pre_main_1.conf ]; then
        sed -i '/LoadFile.*libpcre.so/d' /usr/local/apache/conf/includes/pre_main_1.conf
      fi
      echo "LoadFile libexec/libpcre.so" >> /usr/local/apache/conf/includes/pre_main_1.conf
      # Configuration
      sed -i /"AddModule\s*mod_security.c"/s/$/"\nInclude \"\/etc\/httpd\/conf\/modsec.conf\""/ /etc/httpd/conf/httpd.conf
      wget -nv -O /etc/httpd/conf/modsec.conf SERVER/modsec/modsec.conf
      touch /etc/httpd/conf/modsec.user.conf
      echo 1.9.5 > /var/cpanel/addonmoduleversions/modsecurity
      sed -i /modsecurity/d /var/cpanel/addonmodules
      echo modsecurity >> /var/cpanel/addonmodules
      if [ -e /usr/local/cpanel/bin/apache_conf_distiller ]; then
        /usr/local/cpanel/bin/apache_conf_distiller --update
        /usr/local/cpanel/bin/build_apache_conf
      fi
      echo -e "${EMG}Installation complete$NORMAL";;

  2 ) # Plesk / RPM / version 2
      $PAKMAN httpd-devel libtool gcc
      cd /usr/src
      wget -nv SERVER/modsec/modsecurity-apache_1.9.5.tar.gz
      tar -xzf modsecurity-apache_1.9.5.tar.gz
      cd modsecurity-apache_1.9.5/apache2
      /usr/sbin/apxs -DUSE_PCRE -cia mod_security.c
      RET=$?
      if [ $RET -ne 0 ]; then
        echo -e "${EMR}Modsecurity module installation failed$NORMAL"
        exit $RET
      fi
      sed -n /mod_security/p /etc/httpd/conf/httpd.conf > /etc/httpd/conf.d/modsec.conf
      sed -i /mod_security/d /etc/httpd/conf/httpd.conf
      wget -nv -O - SERVER/modsec/modsec.conf >> /etc/httpd/conf.d/modsec.conf
      ln -s /etc/httpd/conf.d/modsec.conf /etc/httpd/conf/modsec.conf
      touch /etc/httpd/conf/modsec.user.conf
      echo -e "${EMG}Installation complete$NORMAL";;

  3 ) # No Panel / EasyApache / Version 1
      # Install mod_security
      cd /usr/src
      wget -nv SERVER/modsec/modsecurity-apache_1.9.5.tar.gz
      tar -xzf modsecurity-apache_1.9.5.tar.gz
      # Install PCRE for regex optimization
      $PAKMAN pcre pcre-devel
      # Compile the module
      cd modsecurity-apache_1.9.5/apache1
      /etc/httpd/bin/apxs -I/usr/include/pcre -DEAPI -DUSE_PCRE -cia /usr/src/modsecurity-apache_1.9.5/apache1/mod_security.c
      # Load PCRE into apache
      ln -s /usr/lib/libpcre.so /etc/httpd/libexec/libpcre.so
      sed -i /"LoadModule\s*security_module\s*.*mod_security.so"/s/^/"LoadFile libexec\/libpcre.so\n"/ /etc/httpd/conf/httpd.conf
      # Configuration
      sed -i /"AddModule\s*mod_security.c"/s/$/"\nInclude \"\/etc\/httpd\/conf\/modsec.conf\""/ /etc/httpd/conf/httpd.conf
      wget -nv -O /etc/httpd/conf/modsec.conf SERVER/modsec/modsec.conf
      touch /etc/httpd/conf/modsec.user.conf
      echo -e "${EMG}Installation complete$NORMAL";;

  4 ) # No Panel / RPM / Version 2
      $PAKMAN httpd-devel libtool gcc
      cd /usr/src
      wget -nv SERVER/modsec/modsecurity-apache_1.9.5.tar.gz
      tar -xzf modsecurity-apache_1.9.5.tar.gz
      cd modsecurity-apache_1.9.5/apache2
      /usr/sbin/apxs -DUSE_PCRE -cia mod_security.c
      RET=$?
      if [ $RET -ne 0 ]; then
        echo -e "${EMR}Modsecurity module installation failed$NORMAL"
        exit $RET
      fi
      sed -i /"LoadModule\s*security_module\s*.*mod_security.so"/s/$/"\nInclude \"\/etc\/httpd\/conf\/modsec.conf\""/ /etc/httpd/conf/httpd.conf
      wget -nv -O /etc/httpd/conf/modsec.conf SERVER/modsec/modsec.conf
      touch /etc/httpd/conf/modsec.user.conf
      echo -e "${EMG}Installation complete$NORMAL";;

  5 ) # No Panel / Source / Version 1
      echo -e "${EMR}Unsupported environment!"
      echo -e "Exiting$NORMAL"
      exit 1;;

  6 ) # No Panel / Source / Version 2
      echo -e "${EMR}Unsupported environment!"
      echo -e "Exiting$NORMAL"
      exit 1;;

  7 ) # cPanel / EasyApache / Version 2
      if [ `/usr/local/apache/bin/httpd -l 2>&1 | grep mod_security2.c | wc -l` -ne 0 ]; then
        echo -e "${EMR}Detected statically-compiled Mod_Security2 module!"
        echo -e "Exiting$NORMAL"
        exit 1
      fi
      if [ `/usr/local/apache/bin/httpd -L 2>&1 | grep security_module | wc -l` -ne 0 ]; then
        echo -e "${EMR}Detected statically-compiled Mod_Security2 module!"
        echo -e "Exiting$NORMAL"
        exit 1
      fi
      cd /usr/src
      wget -nv SERVER/modsec/modsecurity-apache_1.9.5.tar.gz
      tar -xzf modsecurity-apache_1.9.5.tar.gz
      cd modsecurity-apache_1.9.5/apache2
      /etc/httpd/bin/apxs -cia mod_security.c
      RET=$?
      if [ $RET -ne 0 ]; then
        echo -e "${EMR}Failed to compile mod_security.c module!"
        echo -e "Exiting$NORMAL"
        exit 1
      fi
      # Configuration
      sed -i /"LoadModule\s*security_module\s*.*mod_security.so"/s/$/"\nInclude \"\/etc\/httpd\/conf\/modsec.conf\""/ /etc/httpd/conf/httpd.conf
      wget -nv -O /etc/httpd/conf/modsec.conf SERVER/modsec/modsec.conf
      touch /etc/httpd/conf/modsec.user.conf
      echo 1.9.5 > /var/cpanel/addonmoduleversions/modsecurity
      sed -i /modsecurity/d /var/cpanel/addonmodules
      echo modsecurity >> /var/cpanel/addonmodules
      if [ -e /usr/local/cpanel/bin/apache_conf_distiller ]; then
        /usr/local/cpanel/bin/apache_conf_distiller --update
        /usr/local/cpanel/bin/build_apache_conf
      fi
      echo -e "${EMG}Installation complete$NORMAL";;

  * ) # This should never happen
      echo -e "${EMR}Unknown error!"
      echo -e "Exiting$NORMAL"
      exit 1;;
esac



#------------------#
#----- Config -----#
#------------------#
# Rule configuration
wget -nv -O /etc/httpd/conf/modsec.user.conf SERVER/modsec/modsec.user.conf
mkdir /etc/httpd/conf/modsec-rules
mkdir /etc/httpd/conf/modsec-rules/dynamic
cd /etc/httpd/conf/modsec-rules
wget -nv SERVER/modsec/core.tgz && tar -xzf core.tgz && rm -f core.tgz
for x in `sed -n /Include/p /etc/httpd/conf/modsec.user.conf | awk -F \" '{print $2}'`; do
  touch $x;
done
# Grant fsadmin access
chown -R fsadmin.fsadmin /etc/httpd/conf/modsec-rules
chown fsadmin.fsadmin /etc/httpd/conf/modsec.user.conf
# Logrotate
wget -nv -O /etc/logrotate.d/modsec SERVER/modsec/logrotate
# Check configuration
/etc/init.d/httpd configtest
RET=$?
if [ $RET -eq 0 ]; then
  /etc/init.d/httpd restart
fi


#-----------------#
#----- Brand -----#
#-----------------#
touch /var/opt/modsec-fs
# Record this host, in case someone forgets to make the .cfg
PORT=`grep -iE '^\s*Port\s' /etc/ssh/sshd_config | awk '{print $2}'`
if [ -z $PORT ]; then
  PORT=22
fi
wget -q -O /dev/null http://SERVER/modsec/register.php?port=$PORT


cd $CWD
rm -f $ME

echo -e "Run 'history -c'.  Do that now.  Yes, right now!$NORMAL"

exit $RET

#######################
##
##
