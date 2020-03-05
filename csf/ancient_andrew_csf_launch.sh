#!/bin/bash


##
##  _holy_shit_this_is_old___
##
##
# Author: Andrew Howard, #Messiah
##
##
##
######################################################

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


cd /root


TESTING=1
AUTOUDP=0
AUTOTCP=0
NOCONF=0
# Handle command-line arguments
while getopts ":T:U:toh" arg
do
  case $arg in
    # TCP_IN ports for CSF
    T  ) TCPIN=$OPTARG
         AUTOTCP=1;;
    # UDP_IN ports for CSF
    U  ) UDPIN=$OPTARG
         AUTOUDP=1;;
    # Testing mode toggle
    t  ) TESTING=0;;
    # Flag to indicate no port configuration
    o  ) NOCONF=1;;
    # Help menu
    h  ) echo "Usage: $0 [-h] [-t] [-T tcp_ports] [-U udp_ports]"
         echo "  -h  Display this help"
         echo "  -t  Disable TESTING mode"
         echo "  -T  Open this comma-separated list of ports for TCP traffic"
         echo "      Example: 21,22,25,53,80,110"
         echo "  -U  Open this comma-separated list of ports for UDP traffic"
         echo "      Example: 53,161"
         echo "  -o  Leave everything open.  No port configuration."
         exit 1;;
    # Catch-all, error message
    *  ) echo "Unknown argument: $arg"
         exit 1;;
  esac
done

# Disable portsentry.  It conflicts.
/etc/init.d/portsentry stop
/sbin/chkconfig portsentry off
/etc/init.d/iptables restart

# Set the package manager install command
if [ -e /etc/yum.conf ]; then
  echo -e "${EMG}Detected yum$NORMAL"
  PAKMAN="yum -y install"
elif [ -e /etc/sysconfig/rhn/sources ]; then
  echo -e "${EMG}Detected up2date$NORMAL"
  PAKMAN="up2date"
else
  echo -e "${EMR}This only works on RedHat-based systems.  Exiting.$NORMAL"
  exit 1
fi

# Verify some prerequisites
if [ -e /usr/local/cpanel/version ]; then
  /scripts/realperlinstaller LWP::UserAgent
else
  $PAKMAN perl-libwww-perl
fi

# Grab the installer and extract
rm -fv csf.tgz
wget http://www.configserver.com/free/csf.tgz
tar -xzf csf.tgz
rm -fv csf.tgz
cd csf

# Remove prior apf installs
if [ -d /etc/apf ]; then
  /root/csf/disable_apf_bfd.sh
fi

# Check for prior CSF installs
if [ -d /etc/csf ]; then
  echo -e "${EMR}CSF already installed."
  echo -e "${EMG}Updating...$NORMAL"
  csf -u
  echo -e "${EMG}CSF updated$NORMAL"
  exit 2
fi

# Install
sh install.sh

# Sanity check
if [[ !(-d /etc/csf) ]]; then
  echo -e "${EMR}There was an error installing CSF.$NORMAL"
  exit 1
fi


# Get in the right place
cd /etc/csf/

# Grab our best practice csf.conf file
if [ -e "/usr/local/cpanel/version" ]; then
  wget SERVER/csf/csf.conf.cpanel -O /etc/csf/csf.conf -o /dev/null
elif [ -e "/usr/local/psa/version" ]; then
  wget SERVER/csf/csf.conf.plesk -O /etc/csf/csf.conf -o /dev/null
else
  wget SERVER/csf/csf.conf.nopanel -O /etc/csf/csf.conf -o /dev/null
fi

if [ -e /var/cpanel/smtpgidonlytweak ]; then
  rm -f /var/cpanel/smtpgidonlytweak
  sed -i s/'SMTP_BLOCK = "0"'/'SMTP_BLOCK = "1"'/ /etc/csf/csf.conf
fi


# Disable TESTING mode if proper argument is received
if [ $TESTING -ne 1 ]; then
  sed -i "/^TESTING\s*=\s*\"/s/1/0/" /etc/csf/csf.conf
fi


##### Port Filtering #####
# If ports were passed in via arguments, TCPIN/UDPIN/AUTOTCP/AUTOUDP are already set

# Download listports.sh whether or not we end up using it
wget -nv -O listports.sh SERVER/csf/listports.sh

# TCP Config: If TCP ports were not passed as arguments
if [ $AUTOTCP -ne 1 ]; then
  # If APF was already configured, use it's port config
  if [ -d /etc/apf ]; then
    TCPIN=`sed -n '/^IG_TCP/s/.*\"\(.*\)\"/\1/p' /etc/apf/conf.apf`
    AUTOTCP=1
  # Else figure out the open ports yourself
  elif [ $NOCONF -eq 0 ]; then
    TCPIN=`sh listports.sh -t`
    AUTOTCP=1
  fi
fi

# UDP Config: If UDP ports were not passed as arguments
if [ $AUTOUDP -ne 1 ]; then
  # If APF was already configured, use it's port config
  if [ -d /etc/apf ]; then
    UDPIN=`sed -n '/^IG_UDP/s/.*\"\(.*\)\"/\1/p' /etc/apf/conf.apf`
    AUTOUDP=1
  # Else figure out the open ports yourself
  elif [ $NOCONF -eq 1 ]; then
    UDPIN=`sh listports.sh -u`
    AUTOUDP=1
  fi
fi

# Delete listports.sh
rm -f listports.sh

# Configure port filtering
if [ $AUTOTCP -eq 1 ]; then
  sed -i "/^TCP_IN\s*=\s*\"/s/1:65535/$TCPIN/" /etc/csf/csf.conf
fi
if [ $AUTOUDP -eq 1 ]; then
  sed -i "/^UDP_IN\s*=\s*\"/s/1:65535/$UDPIN/" /etc/csf/csf.conf
fi


cd /root/
rm -rf csf
csf -u
/etc/init.d/lfd restart
/etc/init.d/csf restart

#Whitelist our subnets
wget http://SERVER/fsofficesubnets.txt
SUBNETS=`cat fsofficesubnets.txt`
for x in $SUBNETS; do
  csf -a $x Internal Subnet
done
rm -f fsofficesubnets.txt


# Report what remains to be done
echo -e "${EMG}The following needs to be done:"
if [ $AUTOTCP -ne 1 ]; then
  echo " -Configure TCP port filtering"
fi
if [ $AUTOUDP -ne 1 ]; then
  echo " -Configure UDP port filtering"
fi
if [ $TESTING -ne 0 ]; then
  echo " -Disable TESTING mode"
fi
echo -e " -Run 'history -c'$NORMAL"

exit 0
########################################################
#############################################
