#!/bin/sh
# fake_time_machine.sh

##
## https://gist.githubusercontent.com/pmarreck/1237806/raw/a82707ed0550095af1705683e93a37d286a948b9/fake_time_machine.sh
##

# Fake Time Machine
# by Peter Marreck
# Based on ideas in http://blog.interlinked.org/tutorials/rsync_time_machine.html
# 9/2011

# E_BADARGS=85
# if [ -z "$1" ]
# then
#   echo "Usage: `basename $0` filename"
#   exit $E_BADARGS
# fi

cat <<EOS
Fake Time Machine is now in session.
EOS

date=`date "+%Y-%m-%d-%H%M%S"`
SOURCE=/
current=Latest
DESTINATION_VOLUME=/Volumes/Backup
DESTINATION_ROOT=$DESTINATION_VOLUME/FakeBackups.backupdb
DESTINATION=$DESTINATION_ROOT/peter  # omit trailing slash even though it's a dir
user_at_machine_prefix=''  # ex:  'user@machine.com'
hard_drive_name=''
rsync_settings_dir=$HOME/.rsync
exclude_file=$rsync_settings_dir/exclude
REMOTE_FLAG=0
PRIORITY=19 # -20 to 20, 20 is lowest, I'm tired of time machine slowing down my groove

extra_flags=''
rsync_flags=''
mac_os_extra_flags=E
mac_os=0
# add E flag to preserve resource forks, for Mac OS X
if [ `uname` = 'Darwin' ]; then
  extra_flags="$extra_flags$mac_os_extra_flags"
  mac_os=1
fi

# figure out what the name of the root hard drive is by checking for symbolic links in /Volumes/. (Any better way to do this??)
curdir=`pwd`
cd /Volumes
if [ $mac_os -eq 1 ]; then
  for file in *
  do
    if [ -L "$file" ]; then
      hard_drive_name="$file/"
    fi
  done
fi
cd "$curdir"

# This is a list of files/paths to exclude for OS X boot backups. Current as of OS X Lion, sourced from a couple places
# The first time you do a boot backup on OS X, the contents of this are output to a file which is then used by rsync to exclude these paths/files.
osx_boot_file_excludes="/.DocumentRevisions-V100
/.fseventsd
/.hotfiles.btree
/.MobileBackups
/.MobileBackups.trash
/.Spotlight-V100
/.TemporaryItems
/.Trashes
/.vol
/automount
/Backups.backupdb
/cores
/Desktop\ DB
/Desktop\ DF
/dev
/home
/Library/Caches
/Library/Logs
/Library/Updates
/MobileBackups.trash
/net
/Network
/Network/Servers
/Previous\ Systems
/private/Network
/private/tftpboot
/private/tmp
/private/var/automount
/private/var/db/dhcpclient
/private/var/db/dyld
/private/var/db/efw_cache
/private/var/db/fseventsd
/private/var/db/Spotlight
/private/var/db/Spotlight-V100
/private/var/folders
/private/var/lib/postfix/greylist.db
/private/var/log
/private/var/run
/private/var/spool/cups
/private/var/spool/fax
/private/var/spool/uucp
/private/var/tmp
/private/var/vm
/System/Library/Caches
/System/Library/Extensions/Caches
/tmp
/Users/admin/Library/Calendars/Calendar Cache
/Users/admin/Library/Safari/WebpageIcons.db
/Users/Guest
/Users/Shared/SC Info
/Volumes
Library/Application\ Support/Google/Chrome/Default/Cache
"

if [ $mac_os -eq 1 ]; then
  echo "Hello Mac OS X!"
fi

excluding_files=0
if [ $mac_os -eq 1 -a $SOURCE = '/' ]; then
  if [ ! -d $rsync_settings_dir ]; then
    mkdir -pv $rsync_settings_dir
  fi
  if [ ! -e $exclude_file ]; then
    echo "$osx_boot_file_excludes" > $exclude_file
  fi
  excluding_files=1
fi

while [ $# -gt 0 ]
do
    case $1 in
        -s|--source)
            shift
            SOURCE=$1
            ;;
        -d|--destination)
            # omit trailing slash for directories
            shift
            DESTINATION=$1
            ;;
        -c|--current)
            shift
            current=$1
            ;;
        -r|--remote)
            shift
            user_at_machine_prefix=$1
            REMOTE_FLAG=1
            ;;
        --datestamp)
            shift
            date=`date "$1"`
            ;;
        -p|--priority)
            shift
            PRIORITY=$1
            ;;
        --)  # all other flags after this get passed directly to rsync
            while [ $# -gt 0 ]
            do
              shift
              rsync_flags="$rsync_flags $1"
            done
            ;;
        *)
            shift # ignore unrecognized options for now
            ;;
        
        # -u|--usage)
        #     Usage
        #     exit 0
        #     ;;
        # *)
        #     echo "Syntax Error"
        #     Usage
        #     exit 1
        #     ;;
    esac
    shift
done

# set this script's job priority. $$ is the process ID of the currently running script/shell
renice $PRIORITY $$

link_dest='--link-dest="$DESTINATION/$current/$hard_drive_name"'
rm_link="&& rm -vf '$DESTINATION/$current'"
exclusions="--exclude-from=$exclude_file" # For some reason, it is difficult to quote this path in the event it has spaces in it without rsync erroring
if [ $excluding_files -eq 0 ]; then
  exclusions=''
fi

echo "I will be copying files from $SOURCE"
echo "I will be copying new files to $DESTINATION/$date.inProgress/$hard_drive_name"
if [ $excluding_files -eq 1 ]; then
  echo "Since this is an OS X boot backup, I will be excluding files that match patterns in the file $exclude_file"
fi

if [ $REMOTE_FLAG -eq 1 ]; then
  # do a remote backup.
  # For the ssh command, this assumes you already have public keys set up, etc.
  echo "This will be a remote copy."
  # TODO: check for whether this is a new backup, remotely
  ssh $user_at_machine_prefix "rm -rf \"$DESTINATION/*.inProgress\""
  rsync -azPpizh$extra_flags \
    --del \
    --delete-excluded \
    --ignore-errors \
    --stats \
    $exclusions \
    $link_dest \
    $rsync_flags \
    "$SOURCE" $user_at_machine_prefix:'"$DESTINATION/$date.inProgress/$hard_drive_name"' \
    && ssh $user_at_machine_prefix \
    "mv \"$DESTINATION/$date.inProgress\" \"$DESTINATION/$date\" \
    && rm -f \"$DESTINATION/$current\" \
    && ln -s \"$DESTINATION/$date\" \"$DESTINATION/$current\" \
    && touch \"$DESTINATION/$current/.com.apple.TMCheckpoint\""
else
  # do a local backup
  echo "This will be a local copy."
  if [ ! -d "$DESTINATION_ROOT" ]; then
    mkdir -pv "$DESTINATION_ROOT"
    if [ ! -d "$DESTINATION" ]; then
      mkdir -pv "$DESTINATION"
      if [ ! -e "$DESTINATION/$current" ]; then
        link_dest=''
        rm_link=''
        echo "Looks like this is your first backup. Hopefully I won't break, eh?"
      fi
    fi
  else
    echo "I will be comparing the source files to the files currently in $DESTINATION/$current/$hard_drive_name and hard-linking files that have not changed."
  fi
  rm -rdfv $DESTINATION/*.inProgress
  mkdir -pv "$DESTINATION/$date.inProgress/$hard_drive_name"
  rsync -azPpih$extra_flags \
    --del \
    --delete-excluded \
    --ignore-errors \
    --stats \
    --cache \
    $exclusions \
    $link_dest \
    $rsync_flags \
    "$SOURCE" "$DESTINATION/$date.inProgress/$hard_drive_name" \
    && mv -v "$DESTINATION/$date.inProgress" "$DESTINATION/$date" \
    $rm_link \
    && ln -sv "$DESTINATION/$date" "$DESTINATION/$current" \
    && touch "$DESTINATION/$current/.com.apple.TMCheckpoint"
fi

##
##
