#!/bin/sh

##
##
############### refactor_modernize_this
##
##
#############################################


# First, delete all the old logs.
find /root/update-logs/csf/ -type f -mtime +60 -delete

# Location of the current update log.
LOG_LOCATION=/root/update-logs/csf/csf-update-latest.log
# Location of the update archive logs
LOG_ARCHIVE_LOCATION=/root/update-logs/csf/`date +\%Y-\%m-\%d`.log

# Check for CSF Update
/usr/sbin/csf -c > $LOG_LOCATION 2>&1

check_for_available_updates() {

	if grep -q already "$LOG_LOCATION";
	then
		#Already at the latest version.
		echo "Already at the latest version."
	else
		echo "New version available."
		#Mail the latest log file.
		cat $LOG_LOCATION | mail -s "CSF: `hostname`" -r mail*@*from.com mail*@*to.com
	fi
}

# Check for available updates in the log file
check_for_available_updates

# Move Log File to archive.
mv ${LOG_LOCATION} ${LOG_ARCHIVE_LOCATION}

##
##
#Donejo, tho.

##################
#############################################
