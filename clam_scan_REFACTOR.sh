#!/bin/bash

############
########
##
##  _might_need_refactor_for_modern_times___
##
##
# Author: Andrew Howard

TO='"Andrew Howard" <ahoward@test.com>, "Andrew Again" <ahoward@gmail.com>'
FROM="clamscan@`hostname`"
SUBJECT="ClamAV scan results for `hostname`"


LOCK_FILE=/var/lock/`basename $0`
(set -C; : > $LOCK_FILE) 2> /dev/null
if [ $? != "0" ]; then
  echo "Lock File exists - exiting"
  exit 1
fi
function cleanup {
  echo "Caught exit signal - deleting trap file"
  rm -f rm $LOCK_FILE
  exit 2
}
trap 'cleanup' 1 2 9 15 17 19 23


sendmail -t -f$FROM <<EOF
To: $TO
Reply-to: $FROM
From: $FROM
Subject: $SUBJECT
Output of "/usr/bin/clamscan -ri --exclude-dir=/proc --exclude-dir=/dev --exclude-dir=/sys --exclude-dir=/var/lib/mysql /"
`/usr/bin/clamscan -ri --exclude-dir=/proc --exclude-dir=/dev --exclude-dir=/sys --exclude-dir=/var/lib/mysql /`
.
EOF


trap 'rm $LOCK_FILE' EXIT

#####################################
##
##
