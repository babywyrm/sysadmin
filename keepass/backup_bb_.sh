#!/bin/sh

## https://gist.github.com/harryf/d23a1ceda84806a099782558fc317adb
##
##

# Cron job
# 15 10 * * * /Users/<username>/bin/backup-passwords
# may need some hacks to get crontab running on OSX

DIR="$HOME/GoogleDrive/passwords"
PASSWDF="$DIR/passwords2.kdbx"
BACKUPF="$DIR/passwords2-"$(date "+%Y%m%d")".kdbx"

if [ ! -e "$PASSWDF" ]
then
  >2& echo "$PASSWDF not found"
  exit
fi

LASTBKF=$(ls -r $DIR/passwords2-????????.kdbx | head -1)

DIFF=`diff $PASSWDF $LASTBKF`

if [ "$DIFF" != "" ]
then
    cp "$PASSWDF" "$BACKUPF"
fi


###########
###########
# @harryf
# Author
# harryf commented on Jan 20, 2020
# Gives you files in the $HOME/GoogleDrive/passwords directory like this, where passwords2.kdbx is the active database
#
# $ ls -t1
# passwords2-20200110.kdbx
# passwords2.kdbx
# passwords2-20191220.kdbx
# passwords2-20191216.kdbx
# passwords2-20191206.kdbx
# passwords2-20191203.kdbx
