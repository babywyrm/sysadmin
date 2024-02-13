#!/bin/bash

##
## https://github.com/fwxs/sh_cleaner/blob/master/sh_cleaner.sh
##


# Author pacmanator
# Email mrpacmanator at gmail dot com

HISTFILE=''

##### Clear the shell history, cache memory, buffer and swap memory. #####

function clear_shell_history_urandom
{
	echo "[*] Overwritting $HISTFILE 10 times with /dev/urandom."
	for (( i = 0; i < 10; i++ )); do
		cat /dev/urandom > "$HISTFILE"
	done
	
	echo "[*] Nulling $HISTFILE."
	cat /dev/null > "$HISTFILE"
	
	if [ $SHELL == "/bin/bash" ]; then
		clear_bash_history;
	fi
	
	sync
}


function clear_shell_history
{	
	SHRED=$(which shred)
	if [ $? -eq 1 ]; then
		echo "[!] Hmmmmmm, Looks like shred is not installed. Weird sh|7."
		echo "[!] Using /dev/urandom."
		clear_shell_history_urandom;
	else
		echo "[*] Shredding $HISTFILE."
		$SHRED --random-source=/dev/urandom "$HISTFILE"
		echo "[*] Nulling $HISTFILE."
		cat /dev/null > "$HISTFILE";
	fi
}

function clear_bash_history
{
	clear_shell_history
	history -c && history -w
}

function cleaner
{
	clear_shell_history
	
	echo "[*] Dropping pagecache, dentries and inode data."
	# Clear pagecache, dentries and inode data.
	echo '3' > /proc/sys/vm/drop_caches
	
	echo "[*] Flushing swap files."
	# Clear swap memory.
	swapon -a
	sleep 2
	swapoff -a
	sync
}

if [ $# != 1 ]; then
	echo "Usage: $0 <shell history file>"
	exit
fi

HISTFILE=$1

#Check if user is root
if [ $(id -u ) -ne 0 ]; then
	echo "[!] You aren't root. Clearing shell history."
	if [ $SHELL != "/bin/bash" ]; then
		clear_shell_history;
	else
		clear_shell_history;
	fi
else
	echo "[:D] Good job!! You are root!"
	echo "[!] Clearing shell history and emptying memory cache, buffer and swap file."
	cleaner;
fi

echo "Done! Have a nice day! :D"
