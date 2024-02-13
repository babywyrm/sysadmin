#!/bin/bash

##
## https://github.com/drwetter/automate_tomcat/blob/main/automate_tomcat.sh
##

MIRROR_URL='https://ftp.fau.de/apache/tomcat/tomcat-8/'
SIGN_URL='https://downloads.apache.org/tomcat/tomcat-8/'
TOMCAT_USER="${TOMCAT_USER:-tomcat}"
TOMCAT_GROUP="${TOMCAT_GROUP:-tomcat}"
CURL="/usr/bin/curl"

# terminal is per default verbose
VERBOSE=${VERBOSE:-false}
tty -s && VERBOSE=true

declare _sysVersion=""
declare _webVersion=""

FORCE=false
INIT=false
CLEANME=${CLEANME:-false}

# This is where all *downloaded* tomcat version resides before installing the bin # and lib part
DL_DIR=${DR_DIR:-/var/lib/tomcats/}

# here it is where they will be copied to (could be linked to /var/lib/tomcat8)
CATALINA_BASE=${CATALINA_BASE:-/usr/share/tomcat8}
CATALINA_HOME=$CATALINA_BASE

# Installation eventually takes place in /usr/share/tomcat8 (similar but not 1:1 as CentOS/RHEL 7):
# (SELinux attritbutes aren't supplied by this script, yet)
#
# host:/usr/share/tomcat 0# ls -alZ  | sed 's/system_u:object_r//'
# drwxrwxr-x. root tomcat :usr_t:s0       .
# drwxr-xr-x. root root   :usr_t:s0       ..
# drwxr-xr-x. root root   :bin_t:s0       bin
# lrwxrwxrwx. root tomcat :usr_t:s0       conf -> /etc/tomcat
# lrwxrwxrwx. root tomcat :lib_t:s0       lib -> /usr/share/java/tomcat
# lrwxrwxrwx. root tomcat :usr_t:s0       logs -> /var/log/tomcat
# lrwxrwxrwx. root tomcat :usr_t:s0       temp -> /var/cache/tomcat/temp
# lrwxrwxrwx. root tomcat :usr_t:s0       webapps -> /var/lib/tomcat/webapps
# lrwxrwxrwx. root tomcat :usr_t:s0       work -> /var/cache/tomcat/work
# host:/usr/share/tomcat 0# ls -lLZ  | sed 's/system_u:object_r//'
# drwxr-xr-x. root   root   :bin_t:s0            bin
# drwxr-xr-x. root   tomcat :etc_t:s0            conf
# drwxr-xr-x. root   root   :usr_t:s0            lib
# drwxrwx---. tomcat root   :tomcat_log_t:s0     logs
# drwxrwx---. root   tomcat :tomcat_cache_t:s0   temp
# drwxrwxr-x. root   tomcat :tomcat_var_lib_t:s0 webapps
# drwxrwx---. root   tomcat :tomcat_cache_t:s0   work
# host:/usr/share/tomcat 0#
#
# See also https://de.wikipedia.org/wiki/Apache_Tomcat#Verzeichnisstruktur)
#


install_dirs() {
     mkdir -m 775 $CATALINA_BASE
     mkdir -p -m 755 ${CATALINA_BASE}/{bin,lib}
     mkdir -p -m 755 /etc/tomcat8
     mkdir -p -m 770 /var/log/tomcat8 /var/cache/tomcat8/temp /var/cache/tomcat8/work
     mkdir -p -m 775 /var/lib/tomcat8/webapps

     chgrp $TOMCAT_GROUP $CATALINA_BASE /var/cache/tomcat8/temp /var/cache/tomcat8/work /var/lib/tomcat8/webapps
     chown $TOMCAT_USER /var/log/tomcat8

     ln -sn /etc/tomcat8 ${CATALINA_BASE}/conf
     ln -sn /var/log/tomcat8 ${CATALINA_BASE}/logs
     ln -sn /var/cache/tomcat8/temp ${CATALINA_BASE}/
     ln -sn /var/lib/tomcat8/webapps ${CATALINA_BASE}/
     ln -sn /var/cache/tomcat8/work ${CATALINA_BASE}/

     mkdir -m 775 /etc/tomcat8/Catalina
     mkdir -m 755 /etc/tomcat8/conf.d
     chgrp -R $TOMCAT_GROUP /etc/tomcat8

     return 0
}


chacls_files() {

     # ensure
     chgrp -R $TOMCAT_GROUP /etc/tomcat8

     # files:
     find /etc/tomcat8 -type f | xargs chmod 644
     chmod 640 /etc/tomcat8/{tomcat-users.xml,web.xml,server.xml}

     chmod 644 ${CATALINA_BASE}/{bin,lib}/*
     chmod 755 ${CATALINA_BASE}/bin/*

     return 0
}


cleanup_dirs() {

     "$VERBOSE" && echo "remove all dirs ..."
     rm -rf $DL_DIR /var/lib/tomcat8
     rm -rf /etc/tomcat8
     rm -rf /var/log/tomcat8 /var/cache/tomcat8/temp /var/cache/tomcat8/work /var/lib/tomcat8/webapps

     # some safety measure:
     [[ -d "$CATALINA_BASE" ]] && [[ "$CATALINA_BASE" =~ tomcat ]] && rm -rf "$CATALINA_BASE"

     if grep -q ':18888:0:99999:7:::' /etc/shadow && grep -q 'x:53:53:Apache Tomcat' /etc/passwd; then
          "$VERBOSE" && echo "remove previously created tomcat accounts"
          username=$(awk -F':' '/:18888:0:99999:7:::/ { print $1 }' /etc/shadow)
          [[ -n "$username" ]] && userdel "$username"
          groupname=$(awk -F':' '/:x:53:/ { print $1 }' /etc/group)
          [[ -n "$groupname" ]] && groupdel "$groupname"
     else
          "$VERBOSE" && echo "no previously created tomcat accounts found"
     fi

     "$CLEANME" && rm $0

     return 0
}


error() {
     local msg="$1"
     local exitcode="${2:-0}"

     echo -e "\nFatal: $msg\n" 1>&2
     exit $exitcode
}

check_tomcat_ids() {
     local tmp=""

     if ! getent passwd $TOMCAT_USER >/dev/null 2>&1; then
          echo -n "Tomcat user \"$TOMCAT_USER\" doesn't exist"
          tmp=$(awk -F':' '/tomcat/ { print $1 }' /etc/passwd| tail -1)
          #FIXME: on one system there were tomcat7 and tomcat8
          if [[ -n "$tmp" ]]; then
               export TOMCAT_USER="$tmp"
               echo "... using existing $TOMCAT_USER"
          else
               # userid seems to work on debian, ubuntu, centos, rhel, suse
               echo "$TOMCAT_USER:x:53:53:Apache Tomcat:/usr/share/tomcat:/sbin/nologin" >>/etc/passwd
               echo "$TOMCAT_USER:*:18888:0:99999:7:::" >>/etc/shadow
               echo "... created user $TOMCAT_USER"
          fi
     fi
     if ! getent group $TOMCAT_GROUP >/dev/null 2>&1; then
          echo -n "Tomcat group \"$TOMCAT_GROUP\" doesn't exist"
          tmp=$(awk -F':' '/tomcat/ { print $1 }' /etc/group| tail -1)
          #FIXME: on one system there were tomcat7 and tomcat8
          if [[ -n "$tmp" ]]; then
               export TOMCAT_GROUP="$tmp"
               echo "... using existing $TOMCAT_GROUP"
          else
               # userid seems to work on debian, ubuntu, centos, rhel, suse
               echo "$TOMCAT_GROUP:x:53:" >>/etc/group
               echo "... created group $TOMCAT_GROUP"
          fi
     fi
     return 0
}


check_new_version() {
     local tmp=""
     local version=""

     if ! $CURL -s -I $MIRROR_URL >/dev/null ; then
          if env | grep -iEq 'http_proxy|https_proxy' ; then
               error "Curl connect problem to $MIRROR_URL" 2
          else
               error "Curl connect problem to $MIRROR_URL. Did you forget to define a proxy?" 2
          fi
     fi

     $CURL -s -I $MIRROR_URL >/dev/null || error "Curl connect problem to $MIRROR_URL" 2

     tmp="$($CURL -so - $MIRROR_URL | grep -E -o 'v8.5.[0-9]{1,2}' | sort -u | tail -1)"
     if [[ $(wc -l <<< "$tmp") -ne 1 ]]; then
          error "Please check version @ $MIRROR_URL.\n I was not able determine the latest one for sure" 2
     fi
     version="${tmp//v/}"
     [[ ! "$version" =~ 8.5.[0-9]{1,2} ]] && error "Please check version @ $MIRROR_URL.\n Does not look like a 8.5.xx version" 2
     echo "$version"
}


determine_system_version() {
     local latest=""

     cd "$DL_DIR" 2>/dev/null
     if [[ $? -ne 0 ]]; then
          error "Was not able to cd to $DL_DIR. Make sure it exists" 3
     fi
     latest="$(ls -d apache-tomcat-8.5.* 2>/dev/null | sort -n | tail -1)"
     echo "$latest"
}


download() {
     local version="$1"
     local trail_url=""
     local signing_key=""

     "$VERBOSE" && echo -en "Downloading version $_webVersion ... "
     trail_url="v${version}/bin/"
     $CURL -so apache-tomcat-${version}.tar.gz $MIRROR_URL/${trail_url}/apache-tomcat-${version}.tar.gz || \
          error "Download binary from $MIRROR_URL." 1
     $CURL -so apache-tomcat-${version}.tar.gz.asc $SIGN_URL/${trail_url}/apache-tomcat-${version}.tar.gz.asc || \
          error "Download signature from $SIGN_URL." 1
     "$VERBOSE" && echo "success"

     # Get signing key --> it maybe has to be deployed before if autoretrieval is not enabled / possible
     # So we verify it's is there
     signing_key=$(gpg --verify apache-tomcat-${version}.tar.gz.asc apache-tomcat-${version}.tar.gz 2>&1 | awk '/using.*key/ { print $NF }')
     gpg --list-key $signing_key 2>&1 >/dev/null
     [[ $? -ne 0 ]] && error "Please install PGP signer key $signing_key" 8
     "$VERBOSE" && echo -n "Verify downloaded $_webVersion (PGP)... "
     gpg --verify apache-tomcat-${version}.tar.gz.asc apache-tomcat-${version}.tar.gz 2>/dev/null || \
          error "Signature of apache-tomcat-${version}.tar.gz couldn't be verified" 3
     "$VERBOSE" && echo "success"
     return 0
}


extract_update() {
     f="$1"

     cd "$DL_DIR" 2>/dev/null || error "Was not able to cd to $DL_DIR" 2
     "$VERBOSE" && echo -n "extracting version $(basename $f) to $DL_DIR ..."
     tar xzf $f || error "Was not able to extract $f into $DL_DIR" 4
     "$VERBOSE" && echo " success"
     return 0
}


copy2destination() {
     local srcdir="$1"
     local init="$2"

     cd "$srcdir/bin/" 2>/dev/null || error "Was not able to cd to $srcdir/bin/" 2
     "$VERBOSE" && echo -n "upgrade binaries ..."
     cp -f * "${CATALINA_BASE}/bin/" || error "Was not able to copy from $srcdir/bin/ into ${CATALINA_BASE}/bin/ " 5
     "$VERBOSE" && echo " success"

     cd "$srcdir/lib/" || error "Was not able to cd to $srcdir/lib/" 2
     "$VERBOSE" && echo -n "upgrade libraries ..."
     cp -f * "${CATALINA_BASE}/lib/" || error "Was not able to copy from $srcdir/lib/ into ${CATALINA_BASE}/lib/ " 5
     "$VERBOSE" && echo " success"

     if [[ "$init" =~ init ]]; then
          # we copy the conf files also when cmd line == init
          cd "$srcdir/conf/" 2>/dev/null || error "Was not able to cd to $srcdir/conf/" 2
          "$VERBOSE" && echo -n "Copy standard config files. keeping existing ones ..."
          cp -n * "${CATALINA_BASE}/conf/" || error "Was not able to copy from $srcdir/conf/ into ${CATALINA_BASE}/conf/ " 5
          "$VERBOSE" && echo " success"
     fi

     return 0
}


set_custom_acls() {

     if [[ ! -e "${CATALINA_BASE}/conf/db.conf" ]]; then
          return 0
     fi
     "$VERBOSE" && echo "ensure proper Unix ACLs for db.* ..."
     chmod 640 "${CATALINA_BASE}/conf/db.conf" "${CATALINA_BASE}/conf/db.key"
     chown $TOMCAT_USER:$TOMCAT_GROUP "${CATALINA_BASE}/conf/db.conf" "${CATALINA_BASE}/conf/db.key"

     return 0
}

help() {
     cat << EOF

 Syntax:

    $0  <OPTION>

  where OPTION is one of

          --help    what you are loooking at
          --check   checks the latest already downloaded version against the one available from Apache
                    (return code 11 means: you're running an old version)
          --update  you have a working installation previously generated by this script and you want to
                    update the installation. Config files won't get overwritten
          --init    bare Tomcat installation from Apache web site. Adds a tomcat user/group if not available.
                    After this need to supply the webapp and edit config files
          --force   force installation, all files will NOT be overwritten
          --remove  ATTENTION: dangerous: it wipes the whole tomcat installation off the disk
                    and removes any added tomcat user/group.

Using a terminal the default is to get status info what the program is doing. When you use
--check in a cronjob, and if you're behind the actual release a notification will be sent
to the specified (cron) mail recipient.


Use it at your own risk. Usage without any warranty. It's recommended to backup
your files before usage.

EOF
}



##### main #####


     [[ ! -x $CURL ]] && error "$CURL not found or not executable\n" 1
     CURL="$CURL --connect-timeout 10"

     if [[ $# -gt 1 ]] || [[ $# -eq 0 ]] ; then
          help
          exit 1;
     fi

     if [[ "$1" =~ ^(--check|--init|--update|--force)$ ]]; then
          [[ $(whoami) == root ]] || error "Please run this script as root" 1
          umask 0002
     fi

     case $1 in
          --help)
               help
               exit 0
               ;;
          --remove)
               # Better be safe than sorry (catch empty var):
               [[ -z "$DL_DIR" ]] && error "$DL_DIR empty" 255
               cleanup_dirs
               exit 0
               ;;
          --force)
               FORCE=true
               ;;
          --update)
               ;;
          --init)
               INIT=true
               [[ ! -d $DL_DIR ]] && mkdir -m 700 /var/lib/tomcats/
               ;;
          --check)
               # Otherwise we can't exit from a subshell
               set -o errexit
               _sysVersion=$(determine_system_version)
               if [[ ${#_sysVersion} -eq 0 ]] ; then
                    echo "There's no previously downloaded version"
               else
                    _sysVersion="${_sysVersion//apache-tomcat-/}"
               fi
               _webVersion=$(check_new_version)
               set +o errexit
               if [[ "$_webVersion" == $_sysVersion ]]; then
                    "$VERBOSE" && echo "Latest downloaded version is  $_sysVersion"
                    "$VERBOSE" && echo "Latest version from Apache is $_webVersion"
                    exit 0
               else
                    echo "Latest downloaded version is  $_sysVersion"
                    echo "Latest version from Apache is $_webVersion"
                    # This also signals an update is needed
                    exit 11
               fi
               ;;
          *) help
               exit 1
               ;;
     esac

     # Otherwise we can't exit from a subshell
     set -o errexit
     _sysVersion=$(determine_system_version)
     set +o errexit
     if [[ ${#_sysVersion} -eq 0 ]] ; then
          if "$INIT"; then
               _sysVersion=init
          else
               error "There doesn't seem to be tomcat in $DL_DIR.\nRerun \"$0\" with parameter init" 3
          fi
     else
          _sysVersion="${_sysVersion//apache-tomcat-/}"
          "$VERBOSE" && echo "Latest downloaded version available is $_sysVersion"
     fi

     set -o errexit
     "$VERBOSE" && echo -n "Check latest version available for download ..."
     _webVersion=$(check_new_version)
     set +o errexit
     "$VERBOSE" && echo " $_webVersion"

     if [[ "$_webVersion" == $_sysVersion ]]; then
          if "$FORCE"; then
               echo "continue forced download"
          else
               if "$VERBOSE"; then
                    echo -e "\nno download/upgrade necessary\n"
                    exit 0
               fi
          fi
     fi

     _tempdir="$(mktemp -d "/tmp/$(basename $0 .sh).XXXXXXX")"
     cd $_tempdir || error " making temp dir mktemp" 1
     download $_webVersion $_tempdir

     check_tomcat_ids

     install_dirs 2>/dev/null
     # install_dirs
     extract_update "$_tempdir/apache-tomcat-${_webVersion}.tar.gz"

     copy2destination "$DL_DIR/apache-tomcat-${_webVersion}" "$1"

     # no need to change file acls as they have been retained when we don't start from stretch
     [[ "$1" =~ init ]] && chacls_files
     set_custom_acls

     if [[ "$_sysVersion" == init ]]; then
          echo -e "\nSuccessfully installed Tomcat $_webVersion"
     else
          echo -e "\nSuccessfully upgraded Tomcat $_sysVersion to $_webVersion"
          echo  "(don't forget to restart tomcat manually)"
     fi

exit 0



# vim:tw=95:ts=5:sw=5:expandtab
