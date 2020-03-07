#!/bin/bash

##
###
##################################
## Author: Andrew Howard
##
## +|+ but this is also an easy perl one-liner +|+ ##
##
## lol, FastServers.Net, lol ##
## No one knows, what that is. 
## https://github.com/StafDehat/scripts/blob/master/zonefile-ip-substitution.sh
##
##
##################################
##
##
# Replace any occurrence of an IP in /var/named/*.db with another IP.
# 

if [ $# -eq 0 ]; then
  echo "Usage: $0 [-h] [-f map_file]"
  echo "  -h  Display this help"
  echo "  -f  Specify a map file.  Map file syntax should be two IPs per line, "
  echo "      separated by whitespace.  The left IP is the old, and the right"
  echo "      IP is the new.  For example:"
  echo "OldIP1 NewIP1"
  echo "OldIP2 NewIP2"
  exit 1
fi

while getopts ":f:h" arg
do
  case $arg in
    # map file
    f  ) MAPFILE=$OPTARG;;
    # Help menu
    h  ) echo "Usage: $0 [-h] [-f map_file]"
         echo "  -h  Display this help"
         echo "  -f  Specify a map file.  Map file syntax should be two IPs per line, "
         echo "      separated by whitespace.  The left IP is the old, and the right"
         echo "      IP is the new.  For example:"
         echo "OldIP1 NewIP1"
         echo "OldIP2 NewIP2"
         exit 1;;
    # Catch-all, error message
    *  ) echo "Unknown argument: $arg"
         exit 1;;
  esac
done

LINENUM=1
cat $MAPFILE | while read LINE; do
  # Read an IP pair from map file
  OLDIP=`echo $LINE | awk '{print $1}'`
  NEWIP=`echo $LINE | awk '{print $2}'`
  
  # Attempt to prevent syntax errors by assuring this matches an IP address regex
  echo $OLDIP | egrep '^([0-9]{1,3}\.){3}[0-9]{1,3}$' &>/dev/null
  if [ $? -ne 0 ]; then
    echo "Error: Syntax error on line $LINENUM of map file"
    echo "       Could not read old IP"
    exit 1
  fi
  echo $NEWIP | egrep '^([0-9]{1,3}\.){3}[0-9]{1,3}$' &>/dev/null
  if [ $? -ne 0 ]; then
    echo "Error: Syntax error on line $LINENUM of map file"
    echo "       Could not read new IP"
    exit 1
  fi

  # Perform the replace
  sed -i "s/\s$OLDIP\(\s\|$\)/ $NEWIP/g" /var/named/*.db

  # Increment counter, for good error reporting
  LINENUM=$(( $LINENUM + 1 ))
done

sed -i s/'[0-9]\{10\}'/`date +%Y%m%d%H`/ /var/named/*.db

##
##
#########################################
