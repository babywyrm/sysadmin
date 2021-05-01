#!/bin/sh

##
##
#################################################
#################################################

sourcedir=etc
backupdir=backups
hostname=$(/usr/bin/hostnamectl | grep hostname | cut -d: -f2 | sed 's/^[[:space:]]*//')
today=$(date +%Y-%m-%d)

# check if the current user is root
if [[ $(/usr/bin/id -u) != "0" ]]; then
    echo -e "This looks like a 'non-root' user.\nPlease switch to 'root' and run the script again."
    exit
fi

# check if the backup location exists - /backups
if [ ! -d "$backupdir"  ]; then
    mkdir /$backupdir
fi

# Backup /etc and move it to /backup
tar czf /$backupdir/etc-${hostname}-${today}.tar.gz /$sourcedir && logger "Backed up /$sourcedir"

####
##
##
