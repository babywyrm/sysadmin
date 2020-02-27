#!/usr/bin/env bash
##
##
### Backup specified PostgreSQL Databases to file
# Original script:  MySQL Backup Script
#      VER. 2.5 - http://sourceforge.net/projects/automysqlbackup/
#      Copyright (c) 2002-2003 wipe_out@lycos.co.uk
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#

# Version Number
VER=0.9.17

set -e  # treat any error as fatal

### EXIT CODES
# 0 = OK
# 1 = Unspecified Error
# 2 = Configuration File Error
# 3 = Permission Denied
# 4 = Dependency Error

# not user configurable, but set here to allow easy changing in future
ENCRYPTION_CIPHER='aes-256-cbc'

function set_config_defaults() {
  CONFIG_PGUSER='postgres'
  CONFIG_PGPASSWORD=''
  CONFIG_PGHOST='localhost'
  CONFIG_PGPORT='5432'
  CONFIG_PGDATABASE='postgres'
  CONFIG_DBNAMES='all'
  CONFIG_BACKUPDIR=''
  CONFIG_MAILCONTENT='stdout'
  CONFIG_MAXATTSIZE='4000'
  CONFIG_MAILADDR='root'
  CONFIG_DBEXCLUDE=''
  CONFIG_CREATE_DATABASE='yes'
  CONFIG_DUMP_GLOBALS='yes'
  CONFIG_DOWEEKLY='1'
  CONFIG_COMP='none'
  CONFIG_LATEST='1'
  CONFIG_SOCKET=''
  CONFIG_DUMPFORMAT='custom'
  CONFIG_UMASK='0077'
  CONFIG_PREBACKUP=''
  CONFIG_POSTBACKUP=''
  CONFIG_ENCRYPT=no

  CONFIG_PG_DUMP=$(command -v pg_dump || true)
  CONFIG_PG_DUMPALL=$(command -v pg_dumpall || true)
  CONFIG_PSQL=$(command -v psql || true)
  CONFIG_MAILX=$(command -v mail || true)
  CONFIG_GZIP=$(command -v gzip || true)
  CONFIG_BZIP2=$(command -v bzip2 || true)
  CONFIG_XZ=$(command -v xz || true)
  CONFIG_OPENSSL=$(command -v openssl || true)
}

usage() {
  printf 'Usage: %s [-d /path/to/backups] [-d dbname]\n' "$0"
  printf 'PostreSQL Backup Utility; maintain rolling backups of PostgreSQL databases.\n'
  printf 'Example: %s -d /mnt/backups/pgsql\n\n' "$0"
  printf 'Options:\n'
  printf '   %-20s %-50s\n' \
    '-c /path/to/rcfile'  'Use specified rc configuration file' \
    '-d /path/'           'Write backups to /path/' \
    '-D dbname'           'Only backup the named database (dbname)' \
    '-h'                  'This help'
}

# process the cmdline arguments
while getopts ":hc:D:d:" opt; do
  case $opt in
    c)  CMDLINE_RCFNAME="$OPTARG"   ;;
    d)  CMDLINE_BACKUPDIR="$OPTARG" ;;
    D)  CMDLINE_DBNAMES="$OPTARG"   ;;
    h)  usage
        exit 0              ;;
    \?) echo "ERROR: Invalid option: -$OPTARG" >&2
        usage
        exit 1              ;;
    :)  echo "ERROR: Option -$OPTARG requires an argument." >&2
        exit 1              ;;
  esac
done

# Path to options file
if [[ -n "$CMDLINE_RCFNAME" ]] ; then
  if [[ -f "$CMDLINE_RCFNAME" ]] ; then
    rc_fname="$CMDLINE_RCFNAME"
  else
    printf "Configuration file '%s' not found\n" "$CMDLINE_RCFNAME" >&2
    exit 2
  fi
elif [[ -f '~/.pgsql-backup.conf' ]] ; then
  rc_fname='~/.pgsql-backup.conf'
elif [[ -f '/etc/pgsql-backup.conf' ]] ; then
  rc_fname='/etc/pgsql-backup.conf'
elif [[ -f '/etc/pgsql-backup/options.conf' ]] ; then
  rc_fname='/etc/pgsql-backup/options.conf'
else
  echo 'Configuration file not found!' >&2
  exit 2
fi

# set our path before set_config_defaults() because we need it there
PATH='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'

# set our default config options before we source the config file
set_config_defaults

# make sure the config file has secure permissions and then load it
if [[ $(stat -c %a "$rc_fname") -gt 600 ]] ; then
  echo "Configuration file permissions are too open. They should be 600 or less" >&2
  echo "   To fix this error: chmod 600 $rc_fname" >&2
  exit 2
fi
[[ ! -r "$rc_fname" ]] && { echo "Unable to read configuration file: $rc_fname; Permission Denied" >&2; exit 3; }
source $rc_fname || { echo "Error reading configuration file: $rc_fname" >&2; exit 2; }

# override rc file options with cmdline options
[[ -n "$CMDLINE_BACKUPDIR" ]] && CONFIG_BACKUPDIR="$CMDLINE_BACKUPDIR"
[[ -n "$CMDLINE_DBNAMES" ]]   && CONFIG_DBNAMES="$CMDLINE_DBNAMES"

# Make sure our binaries are good
missing_bin=''
[[ ! -x "$CONFIG_PG_DUMP" ]]    && missing_bin="$missing_bin\t'pgdump' not found: $CONFIG_PG_DUMP\n"
[[ ! -x "$CONFIG_PG_DUMPALL" ]] && missing_bin="$missing_bin\t'pgdumpall' not found: $CONFIG_PG_DUMPALL\n"
[[ ! -x "$CONFIG_PSQL" ]]       && missing_bin="$missing_bin\t'psql' not found: $CONFIG_PSQL\n"
[[ ! -x "$CONFIG_MAILX" ]]      && missing_bin="$missing_bin\t'mail' not found: $CONFIG_MAILX\n"
[[ ! -x "$CONFIG_GZIP"    && "$CONFIG_COMP" == 'gzip' ]]   && missing_bin="$missing_bin\t'gzip' not found: $CONFIG_GZIP\n"
[[ ! -x "$CONFIG_BZIP2"   && "$CONFIG_COMP" == 'bzip2' ]]  && missing_bin="$missing_bin\t'bzip2' not found: $CONFIG_BZIP2\n"
[[ ! -x "$CONFIG_XZ"      && "$CONFIG_COMP" == 'xz' ]]     && missing_bin="$missing_bin\t'xz' not found: $CONFIG_XZ\n"
[[ ! -x "$CONFIG_OPENSSL" && "$CONFIG_ENCRYPT" == 'yes' ]] && missing_bin="$missing_bin\t'openssl' not found: $CONFIG_OPENSSL\n"
if [[ -n "$missing_bin" ]] ; then
  echo "Some required programs were not found. Please check $rc_fname to ensure correct paths are set." >&2
  echo "The missing files are:" >&2
  echo -e $missing_bin >&2
  exit 4
fi

# strip any trailing slash from BACKUPDIR
CONFIG_BACKUPDIR="${CONFIG_BACKUPDIR%/}"

# we need a temporary directory to work with and we'll throw in
# an EXIT hook to make sure it is cleaned up when we're finished
function cleanup() {
  rm -Rf "$TEMP_PATH"
}
declare -r TEMP_PATH=$(mktemp -d --tmpdir '.pgsqlbup.XXXX')
trap cleanup EXIT

# set our umask
umask $CONFIG_UMASK

# Make all config from options.conf READ-ONLY
declare -r CONFIG_PGUSER
declare -r CONFIG_PGPASSWORD
declare -r CONFIG_PGHOST
declare -r CONFIG_PGPORT
declare -r CONFIG_BACKUPDIR
declare -r CONFIG_MAILCONTENT
declare -r CONFIG_MAXATTSIZE
declare -r CONFIG_MAILADDR
declare -r CONFIG_DBEXCLUDE
declare -r CONFIG_CREATE_DATABASE
declare -r CONFIG_DUMP_GLOBALS
declare -r CONFIG_DOWEEKLY
declare -r CONFIG_COMP
declare -r CONFIG_LATEST
declare -r CONFIG_PG_DUMP
declare -r CONFIG_PG_DUMPALL
declare -r CONFIG_PSQL
declare -r CONFIG_GZIP
declare -r CONFIG_BZIP2
declare -r CONFIG_MAILX
declare -r CONFIG_UMASK
declare -r CONFIG_XZ
declare -r CONFIG_ENCRYPT
declare -r CONFIG_ENCRYPT_PASSPHRASE

# export PG environment variables for libpq
export PGUSER="$CONFIG_PGUSER"
export PGPASSWORD="$CONFIG_PGPASSWORD"
export PGHOST="$CONFIG_PGHOST"
export PGPORT="$CONFIG_PGPORT"
export PGDATABASE="$CONFIG_PGDATABASE"

declare -r FULLDATE=$(date +%Y-%m-%d_%Hh%Mm)  # Datestamp e.g 2002-09-21_11h52m
declare -r DOW_NAME=$(date +%A)               # Day of the week e.g. "Monday"
declare -r DOW_NUMBER=$(date +%u)             # Day number of the week 1 to 7 where 1 represents Monday
declare -r DOM=$(date +%d)                    # Date of the Month e.g. 27
declare -r MONTH_NAME=$(date +%B)             # Month e.g "January"
declare -r WEEK_NUMBER=$(date +%V)            # Week Number e.g 37
backupfiles=""
declare PG_DUMP_OPTS="--blobs"    # options for use with pg_dump (format is appended below)
declare PG_DUMPALL_OPTS=""        # options for use with pg_dumpall

# Does backup dir exist and can we write to it?
[[ ! -n "$CONFIG_BACKUPDIR" ]]  && { echo "Configuration option 'CONFIG_BACKUPDIR' is not optional!" >&2; exit 2; }
[[ ! -d "$CONFIG_BACKUPDIR" ]]  && { echo "Destination $CONFIG_BACKUPDIR does not exist or is inaccessible; Aborting" >&2; exit 1; }
[[ ! -w "$CONFIG_BACKUPDIR" ]]  && { echo "Unable to write to $CONFIG_BACKUPDIR; Aborting" >&2; exit 3; }

# Create required directories
[[ ! -d "$CONFIG_BACKUPDIR/daily" ]]    && mkdir "$CONFIG_BACKUPDIR/daily"
[[ ! -d "$CONFIG_BACKUPDIR/weekly" ]]   && mkdir "$CONFIG_BACKUPDIR/weekly"
[[ ! -d "$CONFIG_BACKUPDIR/monthly" ]]  && mkdir "$CONFIG_BACKUPDIR/monthly"
if [[ "$CONFIG_LATEST" == "yes" ]] ; then
  [[ ! -d "$CONFIG_BACKUPDIR/latest" ]] && mkdir "$CONFIG_BACKUPDIR/latest"
  # cleanup previous 'latest' links
  rm -f $CONFIG_BACKUPDIR/latest/*
fi

# Output Extension (depends on the output format)
case "$CONFIG_DUMPFORMAT" in
'tar')
  OUTEXT='tar'
  ;;
'plain')
  OUTEXT='sql'
  ;;
'custom')
  OUTEXT='dump'
  ;;
*)
  echo "Invalid output format configured. Defaulting to 'custom'" >&2
  DUMPFORMAT='custom'
  OUTEXT='dump'
  ;;
esac
PG_DUMP_OPTS="$PG_DUMP_OPTS --format=${CONFIG_DUMPFORMAT}"

# IO redirection for logging.
log_stdout="$TEMP_PATH/$CONFIG_PGHOST-$$.log" # Logfile Name
log_stderr="$TEMP_PATH/$CONFIG_PGHOST-$$.err" # Error Logfile Name
touch $log_stdout
exec 6>&1           # Link file descriptor #6 with stdout.
exec > $log_stdout  # stdout replaced with file $log_stdout.
touch $log_stderr
exec 7>&2           # Link file descriptor #7 with stderr.
exec 2> $log_stderr # stderr replaced with file $log_stderr.

#########################
# Functions

# Database dump function
function dbdump() {
  local _args="$1"
  local _output_fname="$2"
  $CONFIG_PG_DUMP $PG_DUMP_OPTS $_args > $_output_fname
  return $?
}
function dump_globals() {
  local _output_fname="$1"
  $CONFIG_PG_DUMPALL $PG_DUMPALL_OPTS --globals-only > $_output_fname
  return $?
}

function compress_file() {
  local _fname="$1"
  local _suffix=""

  if [[ "$CONFIG_COMP" == "gzip" ]] ; then
    _suffix=".gz"
    $CONFIG_GZIP --force --suffix ".gz" "$_fname" 2>&1
  elif [[ "$CONFIG_COMP" == "bzip2" ]] ; then
    _suffix=".bz2"
    $CONFIG_BZIP2 --compress --force $_fname 2>&1
  elif [[ "$CONFIG_COMP" == "xz" ]] ; then
    _suffix=".xz"
    $CONFIG_XZ --compress --force --suffix=".xz" $_fname 2>&1
  elif [[ "$CONFIG_COMP" == 'none' ]] && [[ "$CONFIG_DUMPFORMAT" == 'custom' ]] ; then
    # the 'custom' dump format compresses by default inside pg_dump if postgres
    # was built with zlib at compile time.
    true
  elif [[ "$CONFIG_COMP" == "none" ]] ; then
    true
  else
    echo "ERROR: No valid compression option set, Check advanced settings" >&2
    exit 2
  fi
  echo "${_fname}${_suffix}"
  return 0
}

function encrypt_file() {
  local _fname="$1"
  local _new_fname="${_fname}.${ENCRYPTION_CIPHER}.enc"

  ### are we actually configured for encyption?
  if [[ "$CONFIG_ENCRYPT" != 'yes' ]] ; then
    echo "$_fname"
    return 0
  fi

  # we want to store the passphrase in a temporary file rather than
  # pass it to openssl on the command line where it would be visible
  # in the process tree
  local _passphrase_file="$TEMP_PATH/opensslpass"
  touch "$_passphrase_file"
  chmod 600 "$_passphrase_file"
  echo "$CONFIG_ENCRYPT_PASSPHRASE" > "$_passphrase_file"

  $CONFIG_OPENSSL $ENCRYPTION_CIPHER -a -salt -pass file:"$_passphrase_file" -in "$_fname" -out "${_new_fname}"
  echo "${_new_fname}"

  rm -f "$_passphrase_file" "$_fname"
  return 0
}

function realpath() {
  # the `realpath` utility requires coreutils 8.15 stable distros like
  # rhel don't package yet, so we'll emulate the behavior we need in
  # this function.
  # this can be replaced in the future with:
  #    realpath --relative-to /mnt/latest $fname
  source="$1"
  target="$2"

  common_part="$source"
  back=
  while [ "${target#$common_part}" = "${target}" ]; do
    common_part=$(dirname $common_part)
    back="../${back}"
  done

  echo ${back}${target#$common_part/}
}

function link_latest() {
  local _fname="$1"
  if [[ "$CONFIG_LATEST" == 'yes' ]] ; then
    link_target="$(realpath "$CONFIG_BACKUPDIR/latest/" "${_fname}")"
    ln -sf "$link_target" "$CONFIG_BACKUPDIR/latest/"
  fi
  return 0
}

#########################################

# Hostname for LOG information; also append socket to
if [[ "$CONFIG_PGHOST" == "localhost" ]] ; then
  HOST="$HOSTNAME"
  if [[ "$CONFIG_SOCKET" ]] ; then
    PG_DUMP_OPTS="$PG_DUMP_OPTS --host=$CONFIG_SOCKET"
    PG_DUMPALL_OPTS="$PG_DUMPALL_OPTS --host=$CONFIG_SOCKET"
  fi
else
  HOST=$CONFIG_PGHOST
fi

cat <<EOT
===============================================================================
Backup of PostgreSQL Database Server - $HOST
Started $(date)
  => PostgreSQL URI:  ${CONFIG_PGUSER}:*****@${CONFIG_PGHOST}:${CONFIG_PGPORT}/${CONFIG_PGDATABASE}
  => Databases:       $CONFIG_DBNAMES
       Excluding:     $CONFIG_DBEXCLUDE
  => Dump Format:     $CONFIG_DUMPFORMAT
  => Destination:     $CONFIG_BACKUPDIR
  => Compression:     $CONFIG_COMP
  => Encryption:      $CONFIG_ENCRYPT
===============================================================================
EOT

# Run command before we begin
if [[ -n "$CONFIG_PREBACKUP" ]] ; then
  echo ======================================================================
  echo "Prebackup command output:"
  echo
  eval "$CONFIG_PREBACKUP"
  echo
  echo ======================================================================
  echo
fi

# ask pg_dump to include CREATE DATABASE in the dump output?
if [[ "$CONFIG_CREATE_DATABASE" == "no" ]] ; then
  PG_DUMP_OPTS="$PG_DUMP_OPTS --no-create"
else
  PG_DUMP_OPTS="$PG_DUMP_OPTS --create"
fi

# If backing up all DBs on the server
if [[ "$CONFIG_DBNAMES" == "all" ]] ; then
  DBNAMES=$($CONFIG_PSQL -P format=Unaligned -tqc 'SELECT datname FROM pg_database;' | sed 's/ /%/g')

  # If DBs are excluded
  for exclude in $CONFIG_DBEXCLUDE ; do
    DBNAMES=$(echo $DBNAMES | sed "s/\b$exclude\b//g")
  done
else
  # user has specified a list of databases to dump
  DBNAMES="$CONFIG_DBNAMES"
fi

# what part of the rotation are we dumping this time?
declare -u write_monthly write_weekly write_daily
if [[ $DOM == "01" ]] ; then
  # Monthly Backup
  write_monthly='yes'
elif [[ $DOW_NUMBER == $CONFIG_DOWEEKLY ]] ; then
  # Weekly Backup
  write_weekly='yes'
else
  # Daily Backup
  write_daily='yes'
fi

for DB in $DBNAMES ; do
  # Create Seperate directory for each DB
  [[ ! -d "$CONFIG_BACKUPDIR/monthly/$DB" ]]  && mkdir "$CONFIG_BACKUPDIR/monthly/$DB"
  [[ ! -d "$CONFIG_BACKUPDIR/weekly/$DB" ]]   && mkdir "$CONFIG_BACKUPDIR/weekly/$DB"
  [[ ! -d "$CONFIG_BACKUPDIR/daily/$DB" ]]    && mkdir "$CONFIG_BACKUPDIR/daily/$DB"

  if [[ -n "$write_monthly" ]] ; then
    # Monthly Backup
    echo Monthly Backup of $DB...
    # note we never automatically delete old monthly backups
    outfile="${CONFIG_BACKUPDIR}/monthly/${DB}/${DB}_${FULLDATE}.${MONTH_NAME}.${OUTEXT}"
  elif [[ -n "$write_weekly" ]] ; then
    # Weekly Backup
    echo "Weekly Backup of Database '$DB'"
    echo "Rotating 5 weeks Backups..."
    if [ $WEEK_NUMBER -le 5 ] ; then
      REMW="$(expr 48 + $WEEK_NUMBER)"
    elif [ $WEEK_NUMBER -lt 15 ];then
      REMW="0$(expr $WEEK_NUMBER - 5)"
    else
      REMW="$(expr $WEEK_NUMBER - 5)"
    fi
    rm -f $CONFIG_BACKUPDIR/weekly/$DB/${DB}_week.${REMW}.*
    outfile="$CONFIG_BACKUPDIR/weekly/$DB/${DB}_week.${WEEK_NUMBER}.$FULLDATE.${OUTEXT}"
  elif [[ -n "$write_daily" ]] ; then
    # Daily Backup
    echo "Daily Backup of Database '$DB'"
    echo "Rotating last weeks Backup..."
    rm -f $CONFIG_BACKUPDIR/daily/$DB/*.${DOW_NAME}.*
    outfile="$CONFIG_BACKUPDIR/daily/$DB/${DB}_$FULLDATE.${DOW_NAME}.${OUTEXT}"
  else
    # this is a bug if we get here
    echo "Ooops! Bug detected."
    exit -1
  fi

  # do the dump now we know where to write to
  dbdump "${DB}" "$outfile"
  outfile=$(compress_file "$outfile")
  outfile=$(encrypt_file "$outfile")
  link_latest "$outfile"
  echo "Backup written to $(basename $outfile)"
  backupfiles="${backupfiles} $outfile"
  echo
  echo '----------------------------------------------------------------------'
done

# dump globals (eg, login roles etc)
if [[ "$CONFIG_DUMP_GLOBALS" == 'yes' ]] ; then
  if [[ -n "$write_monthly" ]] ; then
    echo Monthly Backup of globals...
    # note we never automatically delete old monthly backups
    outfile="${CONFIG_BACKUPDIR}/monthly/globals_${FULLDATE}.${MONTH_NAME}.${OUTEXT}"
  elif [[ -n "$write_weekly" ]] ; then
    # Weekly Backup
    echo "Weekly Backup of globals"
    echo "Rotating 5 weeks backups..."
    if [ $WEEK_NUMBER -le 5 ] ; then
      REMW="$(expr 48 + $WEEK_NUMBER)"
    elif [ $WEEK_NUMBER -lt 15 ] ; then
      REMW="0$(expr $WEEK_NUMBER - 5)"
    else
      REMW="$(expr $WEEK_NUMBER - 5)"
    fi
    rm -f $CONFIG_BACKUPDIR/weekly/globals_week.${REMW}.*
    outfile="$CONFIG_BACKUPDIR/weekly/globals_week.${WEEK_NUMBER}.$FULLDATE.${OUTEXT}"
  elif [[ -n "$write_daily" ]] ; then
    # Daily Backup
    echo "Daily Backup of globals"
    echo "Rotating last weeks backups..."
    rm -f $CONFIG_BACKUPDIR/daily/globals*.${DOW_NAME}.*
    outfile="$CONFIG_BACKUPDIR/daily/globals_$FULLDATE.${DOW_NAME}.${OUTEXT}"
  else
    # this is a bug if we get here
    echo "Ooops! Bug detected."
    false;
  fi

  dump_globals "$outfile"
  outfile=$(compress_file "$outfile")
  outfile=$(encrypt_file "$outfile")
  echo "Globals written to $(basename $outfile)"
  backupfiles="${backupfiles} $outfile"
  echo
  echo '----------------------------------------------------------------------'
fi

if [[ "$CONFIG_ENCRYPT" == 'yes' ]] ; then
  cat <<EOT
!!! IMPORTANT !!!
The output backup files have been encrypted. To decrypt them:
  openssl $ENCRYPTION_CIPHER -d -a -pass 'pass:XXX' -in file.enc -out file
======================================================================
EOT
fi

cat <<EOT
Total disk space used for backup storage:
$(du -h --max-depth=1 "$CONFIG_BACKUPDIR")
======================================================================
pgsql-backup $VER - http://github.com/fukawi2/pgsql-backup
EOT

# Run command when we're done
if [[ -n "$CONFIG_POSTBACKUP" ]] ; then
  echo ======================================================================
  echo "Postbackup command output."
  echo
  new_backupfiles=$($CONFIG_POSTBACKUP $backupfiles)
  [[ -n "$new_backupfiles" ]] && backupfiles=$new_backupfiles
  echo
  echo ======================================================================
fi

# Clean up IO redirection
exec 1>&6 6>&-      # Restore stdout and close file descriptor #6.
exec 1>&7 7>&-      # Restore stdout and close file descriptor #7.

case "$CONFIG_MAILCONTENT" in
'files')
  if [[ -s "$log_stderr" ]] ; then
    # Include error log if is larger than zero.
    backupfiles="$backupfiles $log_stderr"
    ERRORNOTE="WARNING: Error Reported - "
  fi
  # Get backup size
  size_of_attachments=$(du -c $backupfiles | grep "[[:digit:][:space:]]total$" | sed s/\s*total//)
  if [[ $CONFIG_MAXATTSIZE -lt $size_of_attachments ]] ; then
    cat "$log_stdout" | $CONFIG_MAILX -s "WARNING! - PostgreSQL Backup exceeds set maximum attachment size on $HOST - $FULLDATE" $CONFIG_MAILADDR
  fi
  ;;
'log')
  cat "$log_stdout" | $CONFIG_MAILX -s "PostgreSQL Backup Log for $HOST - $FULLDATE" $CONFIG_MAILADDR
  if [[ -s "$log_stderr" ]] ; then
    cat "$log_stderr" | $CONFIG_MAILX -s "ERRORS REPORTED: PostgreSQL Backup error Log for $HOST - $FULLDATE" $CONFIG_MAILADDR
  fi
  ;;
'quiet')
  if [[ -s "$log_stderr" ]] ; then
    $CONFIG_MAILX -s "ERRORS REPORTED: PostgreSQL Backup error Log for $HOST - $FULLDATE" $CONFIG_MAILADDR <<EOT
=============================================
!!!!!! WARNING !!!!!!
Errors reported during pgsql-backup execution... BACKUP FAILED.
$(cat $log_stderr)
=============================================
Full Log Below
=============================================
$(cat $log_stdout)
=============================================
EOT
  fi
;;
*)
  if [[ -s "$log_stderr" ]] ; then
    cat <<EOT
=============================================
!!!!!! WARNING !!!!!!
Errors reported during pgsql-backup execution... BACKUP FAILED.
$(cat $log_stderr)
=============================================
Full Log Below
=============================================
$(cat $log_stdout)
=============================================
EOT
  else
    cat "$log_stdout"
  fi
;;
esac

if [[ -s "$log_stderr" ]]; then
    STATUS=1
else
    STATUS=0
fi

exit $STATUS
