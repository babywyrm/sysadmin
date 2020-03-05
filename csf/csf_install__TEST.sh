#!/bin/bash
##
##
########### _this_might_be_absolutely_fossilized___
##
########### ___or_not____
##

# Script to install ConfigServer Security & Firewall
# Author: Márk Sági-Kazár (sagikazarmark@gmail.com)
# This script installs CSF on several Linux distributions with Webmin.
#
# Version: 6.33

# Variable definitions
DIR=$(cd `dirname $0` && pwd)
NAME="ConfigServer Security & Firewall"
SLUG="csf"
VER="6.33"
DEPENDENCIES=("perl" "tar")
TMP="/tmp/$SLUG"
INSTALL_LOG="$TMP/install.log"
ERROR_LOG="$TMP/error.log"

# Cleaning up
rm -rf $TMP
mkdir -p $TMP
cd $TMP
chmod 777 $TMP


# Function definitions

## Echo colored text
e()
{
	local color="\033[${2:-34}m"
	local log="${3:-$INSTALL_LOG}"
	echo -e "$color$1\033[0m"
	log "$1" "$log"
}

## Exit error
ee()
{
	local exit_code="${2:-1}"
	local color="${3:-31}"

	has_dep "dialog"
	[ $? -eq 0 ] && clear
	e "$1" "$color" "$ERROR_LOG"
	exit $exit_code
}

## Log messages
log()
{
	local log="${2:-$INSTALL_LOG}"
	echo "$1" >> "$log"
}

## Install required packages
install()
{
	[ -z "$1" ] && { e "No package passed" 31; return 1; }

	e "Installing package: $1"
	${install[1]} "$1" >> $INSTALL_LOG 2>> $ERROR_LOG || ee "Installing $1 failed"
	e "Package $1 successfully installed"

	return 0
}

## Check installed package
check()
{
	[ -z "$1" ] && { e "No package passed" 31; return 2; }

	[ `which "$1" 2> /dev/null` ] && return 0

	case ${install[2]} in
		dpkg )
			${install[3]} -s "$1" &> /dev/null
			;;
		rpm )
			${install[3]} -qa | grep "$1"  &> /dev/null
			;;
	esac
	return $?
}

## Add dependency
dep()
{
	has_dep "$1"
	if [ ! -z "$1" -a $? -eq 1 ]; then
		DEPENDENCIES+=("$1")
		return 0
	fi
	return 1
}

## Dependency is added or not
has_dep()
{
	for dep in ${DEPENDENCIES[@]}; do [ "$dep" == "$1" ] && return 0; done
	return 1
}

## Install dependencies
install_deps()
{
	e "Checking dependencies..."
	for dep in ${DEPENDENCIES[@]}; do
		check "$dep"
		[ $? -eq 0 ] || install "$dep"
	done
}

## Download required file
download()
{
	[ -z "$1" ] && { e "No package passed" 31; return 1; }

	local text="${2:-files}"
	e "Downloading $text"
	$download "$1" >> $INSTALL_LOG 2>> $ERROR_LOG || ee "Downloading $text failed"
	e "Downloading $text finished"
	return 0
}

## Install init script
init()
{
	[ -z "$1" ] && { e "No init script passed" 31; return 1; }

	$init "$1" >> $INSTALL_LOG 2>> $ERROR_LOG || ee "Error during init"
	return 0
}

## Cleanup
cleanup()
{
	has_dep "dialog"
	[ $? -eq 0 ] && clear
	e "Cleaning up"
	cd $TMP 2> /dev/null || return 1
	find * -not -name '*.log' | xargs rm -rf
}

# CTRL_C trap
ctrl_c()
{
	echo
	cleanup
	e "Installation aborted by user!" 31
}
trap ctrl_c INT


# Basic checks

## Checking root access
if [ $EUID -ne 0 ]; then
	ee "This script has to be ran as root!"
fi

## Check for wget or curl or fetch
e "Checking for HTTP client..."
if [ `which curl 2> /dev/null` ]; then
	download="$(which curl) -s -O"
elif [ `which wget 2> /dev/null` ]; then
	download="$(which wget) --no-certificate"
elif [ `which fetch 2> /dev/null` ]; then
	download="$(which fetch)"
else
	dep "wget"
	download="$(which wget) --no-certificate"
	e "No HTTP client found, wget added to dependencies" 31
fi

## Check for package manager (apt or yum)
e "Checking for package manager..."
if [ `which apt-get 2> /dev/null` ]; then
	install[0]="apt"
	install[1]="$(which apt-get) -y --force-yes install"
elif [ `which yum 2> /dev/null` ]; then
	install[0]="yum"
	install[1]="$(which yum) -y install"
else
	ee "No package manager found."
fi

## Check for package manager (dpkg or rpm)
if [ `which dpkg 2> /dev/null` ]; then
	install[2]="dpkg"
	install[3]="$(which dpkg)"
elif [ `which rpm 2> /dev/null` ]; then
	install[2]="rpm"
	install[3]="$(which rpm)"
else
	ee "No package manager found."
fi

## Check for init system (update-rc.d or chkconfig)
e "Checking for init system..."
if [ `which update-rc.d 2> /dev/null` ]; then
	init="$(which update-rc.d)"
elif [ `which chkconfig 2> /dev/null` ]; then
	init="$(which chkconfig) --add"
else
	ee "Init system not found, service not started!"
fi


# Adding dependencies
case ${install[2]} in
	dpkg )
		dep "libgd-graph-perl"
		;;
	rpm )
		dep "perl-libwww-perl"
		dep "perl-GDGraph"
		;;
esac

install_deps


# Fedora 17 fix
[ -d "/etc/cron.d" ] || mkdir "/etc/cron.d"

if [ -f $DIR/csf.tgz ]; then
	cp -r $DIR/csf.tgz $TMP
else
	download http://configserver.com/free/csf.tgz "CSF files"
fi

e "Installing $NAME $VER"

tar -xzf csf.tgz >> $INSTALL_LOG 2>> $ERROR_LOG

cd csf
sh install.sh >> $INSTALL_LOG 2>> $ERROR_LOG || ee "Installing $NAME $VER failed"

e "Removing APF"
sh /etc/csf/remove_apf_bfd.sh  >> $INSTALL_LOG 2>> $ERROR_LOG || ee "Removing APF failed"

e "Checking installation"
perl /etc/csf/csftest.pl  >> $INSTALL_LOG 2>> $ERROR_LOG || ee "Test failed"

cleanup

if [ -s $ERROR_LOG ]; then
	e "Error log is not empty. Please check $ERROR_LOG for further details." 31
fi

e "Installation done."

##
##
#################################
##
