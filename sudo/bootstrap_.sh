#!/bin/sh
#
# Script for adding and removing user from /etc/sudoers file used by sudo
# for bootstrapping perl soap framework 
# NOTES:
# This code assuming that user being added to sudo file has been already created

PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin:/usr/X11R6/bin:/root/bin
export PATH

SUDOERS_PATH='/etc /usr/local/etc'
SUDOERS="sudoers"
# FIXME: XXX Add getting owner and perms from file before editing?
MKTEMP_TEMPLATE='/tmp/tmp.XXXXXX'
DEFAULT_MODE="440"
DEFAULT_OWNER="root:root"

#ALLOWED_BINS='perl '
SUDOERS_LOCK_POSTFIX=".lock"
SUDOERS_POSTFIX=' ALL=(root) NOPASSWD: ALL'

err() {
	echo "ERROR: $*" >&2
	exit 1
}

usage() {
	err  "Usage: $0 [-r|-a] username"
	exit 1
}

set_def_perms_on_file() {
	chmod ${DEFAULT_MODE} $1 || err "Can't chmod $1"

    chown ${DEFAULT_OWNER} $1 || err "Can't chown $1"
}

while getopts r:a: _option
do	case "$_option" in
	r)	username="$OPTARG"
		remove=1 ;;
	a)	username="$OPTARG"
		add=1	;;
	[?]) err "Usage: $0 [-r|-a] username" ;;
	esac
done

# Sanity check for options
if [ -n "$remove" -a -n "$add" ]; then
	usage
elif [ -z "$remove" -a -z "$add" ]; then
	usage
elif [ -z "$username" ]; then
	usage
fi

# Check username for UNIX user name regex
if ! echo $username | grep "^[A-Za-z][A-Za-z0-9_\.\-]*\$*$" >/dev/null 2>&1; then
	err "Supplied username ($username) doesn't match regex"
fi

# Searching sudoers file
for _dir in ${SUDOERS_PATH}; do
	if [ -f "$_dir/$SUDOERS" ]; then
		found_sudoers="$_dir/$SUDOERS"
		break
	fi
done

if [ -z "$found_sudoers" ]; then
	err "Can't find sudoers file"
# Checking if visudo doesn't support 'q' and 'c' flags
elif visudo -qc 2>&1 | grep 'usage' >/dev/null 2>&1; then
	break
elif ! visudo -qc > /dev/null 2>&1; then
	err "$found_sudoers has invalid syntax"
fi

# Sudoers lock file for simu access
sudoers_lock="${found_sudoers}${SUDOERS_LOCK_POSTFIX}"

while [ -f ${sudoers_lock} ]; do
	sleep 1
done   

trap "rm -f ${sudoers_lock}; exit $?" INT TERM EXIT

touch ${sudoers_lock} || err "Can't create lock file: ${sudoers_lock}"

# Default entry
DEFAULTS_OPTION="Defaults"
REQUIRE_TTY_OPTION="requiretty"

default_tty_entry="${DEFAULTS_OPTION}	${REQUIRE_TTY_OPTION}"
veeam_tty_entry="#.*#Veeam Commented"
user_tty_entry="${DEFAULTS_OPTION}:${username} !${REQUIRE_TTY_OPTION}"
grep_user_tty_entry=`echo "${user_tty_entry}" | sed 's/\*/\\\*/g'` # Escape '*'

# Sudoers entry
sudoers_entry="$username ${SUDOERS_POSTFIX}"
grep_sudoers_entry=`echo "${sudoers_entry}" | sed 's/\*/\\\*/g'` # Escape '*'

# Uncommenting if commented by us (deprecated)
if grep "^${veeam_tty_entry}" ${found_sudoers} >/dev/null 2>&1; then
	_tempfile=`mktemp -q  ${MKTEMP_TEMPLATE}` || \
	err "Can't create temporary file for disabling requretty option"

	sed -e "s/${veeam_tty_entry}/${default_tty_entry}/g" ${found_sudoers} > ${_tempfile} || \
	err "Can't write substituted sudoers to $_tempfile"

	mv $_tempfile $found_sudoers || err "Can't move $_tempfile to $found_sudoers"
	set_def_perms_on_file $found_sudoers
fi

if [ -n "$add" ]; then
	# Add Defaults:user !requiretty
	if ! grep "^${grep_user_tty_entry}" ${found_sudoers} >/dev/null 2>&1; then
		echo "${user_tty_entry}" >> $found_sudoers || err "Can't add entry to $found_sudoers"
	fi

	# Add rights
	if ! grep "$grep_sudoers_entry" $found_sudoers >/dev/null 2>&1; then
		echo "${sudoers_entry}" >> $found_sudoers || err "Can't add entry to $found_sudoers"
	fi
elif [ -n "$remove"  ]; then 
	_tempfile=`mktemp -q  ${MKTEMP_TEMPLATE}` || \
	err "Can't create temporary file" 

	grep -v -e "${grep_sudoers_entry}" -e "${grep_user_tty_entry}" $found_sudoers > $_tempfile || \
	err "Can't write to $_tempfile"

	mv $_tempfile $found_sudoers || err "Can't move $_tempfile to $found_sudoers"
	set_def_perms_on_file $found_sudoers
fi

rm -f ${sudoers_lock} || err "Can't remove lock file: ${sudoers_lock}"
trap - INT TERM EXIT

# Checking if visudo doesn't support 'q' and 'c' flags
if visudo -qc 2>&1 | grep 'usage' >/dev/null 2>&1 ; then
	break	
elif ! visudo -qc > /dev/null 2>&1; then
	err "Syntax of $found_sudoers is wrong"
fi

##
##
