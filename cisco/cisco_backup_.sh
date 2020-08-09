#!/bin/bash
# backs up cisco switch configurations from switch filesystem
# https://github.com/jalavoy/cisco-switch-backup
# jalavoy 12.30.2017
####################################
##
##

# BEGIN EDITS
# list of switch names, must be resolvable
switches=( 'core' );
# path that backups should be dumped to
backup_path='/Storage/Backup/switch_configs';
# copies to keep
copies=7
# user to login to the switch with
user='admin'
# switch filesystem to config
config_filesystem='nvram'
# switch config filename
config_file='startup-config'
# END EDITS

function main () {
    check;
    for switch in ${switches[@]}; do
        echo "[*] Getting config for $switch";
        get_config $switch;
        cleanup $switch;
    done
}

function check () {
    if [[ ! -d $backup_path ]]; then
        exit "[!] Backup mount location is not available";
    fi
}

function get_config () {
    switch=$1;
    if [[ ! -d $backup_path/$switch ]]; then
        /usr/bin/mkdir -p $backup_path/$switch;
    fi
    /usr/bin/scp $user@$switch:$config_filesystem:/$config_file $backup_path/$switch >/dev/null 2>&1;
    if [[ ! $? ]]; then
        echo "[!] Copy of config from $switch failed!\n";
        return;
    fi;
    timestamp=$(date +%s);
    echo "[*] Found $config_file for $switch, saving as $backup_path/$switch/$config_file.$timestamp"
    /bin/mv $backup_path/$switch/$config_file $backup_path/$switch/$config_file.$timestamp;
    rotate $switch;
}

function rotate () {
    switch=$1;
    files=( $(/usr/bin/ls -t $backup_path/$switch/) );
    new=${files[0]};
    old=${files[1]};
    if [[ ! -f $backup_path/$switch/$old ]]; then
        return;
    fi
    new_MD5=$(/usr/bin/md5sum $backup_path/$switch/$new |awk '{print $1}');
    old_MD5=$(/usr/bin/md5sum $backup_path/$switch/$old |awk '{print $1}');
    if [[ $new_MD5 == $old_MD5 ]]; then
        echo "[*] No changes found in config, removing old copy of config $backup_path/$switch/$old";
        /usr/bin/rm -f $backup_path/$switch/$old;
    else 
        echo "[*] New config found";
    fi 
}

function cleanup () {
    switch=$1;
    while [[ $(/usr/bin/ls -1 $backup_path/$switch/ | wc -l) -gt $copies ]]; do
        files=( $(/usr/bin/ls -rt $backup_path/$switch/) );
        echo "[*] Rotating configs, deleting $backup_path/$switch/${files[0]}";
        /usr/bin/rm -f $backup_path/$switch/${files[0]};
    done
}

main

##################
##
##
