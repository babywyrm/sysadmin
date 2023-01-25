
#!/bin/bash
##########################################################################################
# AWS VM Import Instance Checker 1.2                                                     #
#                                                                                        #
# The script has been implemented to simplify the VM Import process of the virtual       #
# environment in AWS.                                                                    #
#                                                                                        #
# The script checks that the requirements to import a VM in AWS are verified.            #
# Please make a backup of the VM before to proceed.                                      #
#                                                                                        #
# This software is provided "as is" without warranty of any kind.                        #
#                                                                                        #
# Please be aware that AWS does not accept any responsibility or liability               #
# for the accuracy, content, completeness, or reliability of the script.                 #
#                                                                                        #
# CHANGELOG:                                                                             #
# 1.1                                                                                    #
# Added check for SLES wickedd dhcp.                                                     #
# Added check on the user running the script.                                            #
# Added Centos 7.2 to Supported OS.                                                      #
# 1.2                                                                                    #
# Fixed check on root filesystem using pivot_root # df -k / | grep '/$'                  #
# 1.3                                                                                    #
# Added check for block device for currently booted kernel root device                   #
# Check for last fsck on root device if ext                                              #
# 1.4                                                                                    #
# Added Centos 6.7, 6.8, 6.9 and 7.3                                                     #
# Added RHEL 6.7, 6.8, 6.9, 7.2, and 7.3                                                 #
# Added Ubuntu 16.04 and 16.10                                                           #
# Added sanity check for available filesystem space                                      #
# 1.5                                                                                    #
# Added fstab check for secondary  volumes                                               #
# 1.6                                                                                    #
# Improved ethernet identification                                                       #
# Move advice to function                                                                #
##########################################################################################

set_defaults() {
    day=`date +%d`
    month=`date +%m`
    year=`date +%Y`
    hour=`date +%H`
    minute=`date +%M`
    OS_RELEASE=`cat /etc/*release|grep PRETTY|awk -F '"' '{ print $2 }'|awk '{ print $1 }'`
    if [ $TRACE -eq 0 ]; then
     LOGFILE="/dev/null"
    else
     LOGFILE="vm-check-script-$day-$month-$year.$hour.$minute.trace.log"
    fi
}


splash_screen() {

clear
echo "    ___        ______   __     ____  __   ___                            _   "
echo "   / \ \      / / ___|  \ \   / /  \/  | |_ _|_ __ ___  _ __   ___  _ __| |_ "
echo "  / _ \ \ /\ / /\___ \   \ \ / /| |\/| |  | ||  _   _ \|  _ \ / _ \| '__| __|"
echo " / ___ \ V  V /  ___) |   \ V / | |  | |  | || | | | | | |_) | (_) | |  | |_ "
echo "/_/   \_\_/\_/  |____/     \_/  |_|  |_| |___|_| |_| |_|  __/ \___/|_|   \__|"
echo "                                                       |_|                   "
echo " ___           _                              _               _             "
echo "|_ _|_ __  ___| |_ __ _ _ __   ___ ___    ___| |__   ___  ___| | _____ _ __ "
echo " | || '_ \/ __| __/ _  |  _ \ / __/ _ \  / __|  _ \ / _ \/ __| |/ / _ \  __|"
echo " | || | | \__ \ || (_| | | | | (_|  __/ | (__| | | |  __/ (__|   <  __/ |   "
echo "|___|_| |_|___/\__\__,_|_| |_|\___\___|  \___|_| |_|\___|\___|_|\_\___|_|   "
echo " "
echo " "

}


check_running_user() {
	USER_RUNNING=`whoami`
	if [[ $USER_RUNNING != "root" ]] ; then
		echo -e "[\033[31mKO\e[0m] Please run the script as root user or using sudo!"
		exit 1
	fi
}

check_os() {

        ORACLE_OS_RELEASE=/etc/oracle-release
        SUSE_OS_RELEASE=/etc/SuSE-release
        UBUNTU_OS_RELEASE=/etc/lsb-release
	grep "Ubuntu" /etc/lsb-release >> /dev/null 2>&1
	IS_UBUNTU=$?
        DEBIAN_OS_RELEASE=/etc/debian_version
        CENTOS_OS_RELEASE=/etc/centos-release
	FEDORA_OS_RELEASE=/etc/fedora-release
        REDHAT_OS_RELEASE=/etc/redhat-release
        grep "Red Hat" /etc/redhat-release >> /dev/null 2>&1
        IS_REDHAT=$?
        if [[ -f $ORACLE_OS_RELEASE ]] ; then
                ORACLE_REL=`cat /etc/oracle-release|awk '{ print $5 }'`
                if [[ $ORACLE_REL == 6.1 ]] || [[ $ORACLE_REL == 6.2 ]] || [[ $ORACLE_REL == 6.3 ]] || [[ $ORACLE_REL == 6.4 ]] || [[ $ORACLE_REL == 6.5 ]] || [[ $ORACLE_REL == 6.6 ]] || [[ $ORACLE_REL == 7.0 ]] || [[ $ORACLE_REL == 7.1 ]] ; then
                echo -e "[\033[32mOK\e[0m] The operating system is Oracle Enterprise Linux release $ORACLE_REL..."
                else echo -e "[\033[31mKO\e[0m] The operating system is not supported!!!"
                fi
        elif [[ -f $SUSE_OS_RELEASE ]] ; then
		SUSE_VERSION=`cat /etc/SuSE-release |grep VERSION|awk '{ print $3 }'`
		SUSE_PATCH=`cat /etc/SuSE-release |grep PATCH|awk '{ print $3 }'`
                SUSE_REL=$SUSE_VERSION"."$SUSE_PATCH
		if [[ $SUSE_VERSION == 11 ]] || [[ $SUSE_VERSION == 12 ]] ; then
                echo -e "[\033[32mOK\e[0m] The operating system is SUSE Linux Enterprise Server $SUSE_REL..."
		else echo -e "[\033[31mKO\e[0m] The operating system is not supported!!!"
		fi
        elif [[ -f $UBUNTU_OS_RELEASE ]] && [[ $IS_UBUNTU -eq 0 ]] ; then
		UBUNTU_REL=`cat /etc/lsb-release |grep DISTRIB_RELEASE|awk -F "=" '{ print $2 }'`
		if [[ $UBUNTU_REL == 12.04 ]] || [[ $UBUNTU_REL == 12.10 ]] || [[ $UBUNTU_REL == 13.04 ]] || [[ $UBUNTU_REL == 13.10 ]] || [[ $UBUNTU_REL == 14.04 ]] || [[ $UBUNTU_REL == 14.10 ]] || [[ $UBUNTU_REL == 15.04 ]] || [[ $UBUNTU_REL == 16.04 ]] || [[ $UBUNTU_REL == 16.10 ]]; then
                echo -e "[\033[32mOK\e[0m] The operating system is Ubuntu $UBUNTU_REL..."
		else echo -e "[\033[31mKO\e[0m] The operating system is not supported!!!"
		fi
        elif [[ -f $DEBIAN_OS_RELEASE ]] ; then
		DEBIAN_REL=`cat /etc/debian_version`
		if [[ $DEBIAN_REL == 6.0.0 ]] || [[ $DEBIAN_REL == 6.0.1 ]] || [[ $DEBIAN_REL == 6.0.2 ]] || [[ $DEBIAN_REL == 6.0.3 ]] || [[ $DEBIAN_REL == 6.0.4 ]] || [[ $DEBIAN_REL == 6.0.5 ]] || [[ $DEBIAN_REL == 6.0.6 ]] || [[ $DEBIAN_REL == 6.0.7 ]] || [[ $DEBIAN_REL == 6.0.8 ]] || [[ $DEBIAN_REL == 7.0 ]] || [[ $DEBIAN_REL == 7.1 ]] || [[ $DEBIAN_REL == 7.2 ]] || [[ $DEBIAN_REL == 7.3 ]] || [[ $DEBIAN_REL == 7.4 ]] || [[ $DEBIAN_REL == 7.5 ]] || [[ $DEBIAN_REL == 7.6 ]] || [[ $DEBIAN_REL == 7.7 ]] || [[ $DEBIAN_REL == 7.8 ]] || [[ $DEBIAN_REL == 8.0 ]] ; then
                echo -e "[\033[32mOK\e[0m] The operating system is Debian $DEBIAN_REL..."
		else echo -e "[\033[31mKO\e[0m] The operating system is not supported!!!"
		fi
        elif [[ -f $CENTOS_OS_RELEASE ]] ; then
		CENTOS_REL=`cat /etc/centos-release|grep CentOS|sed 's/[^0-9.]//g'|awk -F "." '{ print $1"."$2 }'`
		if [[ $CENTOS_REL == 5.1 ]] || [[ $CENTOS_REL == 5.2 ]] || [[ $CENTOS_REL == 5.3 ]] || [[ $CENTOS_REL == 5.4 ]] || [[ $CENTOS_REL == 5.5 ]] || [[ $CENTOS_REL == 5.6 ]] || [[ $CENTOS_REL == 5.7 ]] || [[ $CENTOS_REL == 5.8 ]] || [[ $CENTOS_REL == 5.9 ]] || [[ $CENTOS_REL == 5.10 ]] || [[ $CENTOS_REL == 5.11 ]] || [[ $CENTOS_REL == 6.1 ]] || [[ $CENTOS_REL == 6.2 ]] || [[ $CENTOS_REL == 6.3 ]] || [[ $CENTOS_REL == 6.4 ]] || [[ $CENTOS_REL == 6.5 ]] || [[ $CENTOS_REL == 6.6 ]] || [[ $CENTOS_REL == 6.7 ]] || [[ $CENTOS_REL == 6.8 ]] || [[ $CENTOS_REL == 6.9 ]] || [[ $CENTOS_REL == 7.0 ]] || [[ $CENTOS_REL == 7.1 ]] || [[ $CENTOS_REL == 7.2 ]] || [[ $CENTOS_REL == 7.3 ]]; then
                echo -e "[\033[32mOK\e[0m] The operating system is CentOS $CENTOS_REL..."
		else echo -e "[\033[31mKO\e[0m] The operating system is not supported!!!"
		fi
	elif [[ -f $FEDORA_OS_RELEASE ]] ; then
		FEDORA_REL=`cat /etc/fedora-release|grep Fedora|sed 's/[^0-9]//g'`
		if [[ $FEDORA_REL == 19 ]] || [[ $FEDORA_REL == 20 ]] || [[ $FEDORA_REL == 21 ]] ; then
		echo -e "[\033[32mOK\e[0m] The operating system is Fedora $FEDORA_REL..."
		else echo -e "[\033[31mKO\e[0m] The operating system is not supported!!!"
		fi
        elif [[ -f $REDHAT_OS_RELEASE ]] && [[ $IS_REDHAT -eq 0 ]] ; then
		REDHAT_REL=`cat /etc/redhat-release|grep Red |sed 's/[^0-9.]//g'|awk -F "." '{ print $1"."$2 }'`
		if [[ $REDHAT_REL == 5.1 ]] || [[ $REDHAT_REL == 5.2 ]] || [[ $REDHAT_REL == 5.3 ]] || [[ $REDHAT_REL == 5.4 ]] || [[ $REDHAT_REL == 5.5 ]] || [[ $REDHAT_REL == 5.6 ]] || [[ $REDHAT_REL == 5.7 ]] || [[ $REDHAT_REL == 5.8 ]] || [[ $REDHAT_REL == 5.9 ]] || [[ $REDHAT_REL == 5.10 ]] || [[ $REDHAT_REL == 5.11 ]] || [[ $REDHAT_REL == 6.1 ]] || [[ $REDHAT_REL == 6.2 ]] || [[ $REDHAT_REL == 6.3 ]] || [[ $REDHAT_REL == 6.4 ]] || [[ $REDHAT_REL == 6.5 ]] || [[ $REDHAT_REL == 6.6 ]] || [[ $REDHAT_REL == 6.7 ]] || [[ $REDHAT_REL == 6.8 ]] || [[ $REDHAT_REL == 6.9 ]] || [[ $REDHAT_REL == 7.0 ]] || [[ $REDHAT_REL == 7.1 ]] || [[ $REDHAT_REL == 7.2 ]] || [[ $REDHAT_REL == 7.3 ]]; then
                echo -e "[\033[32mOK\e[0m] The operating system is Red Hat $REDHAT_REL..."
		else echo -e "[\033[31mKO\e[0m] The operating system is not supported!!!"
		fi
        else
		echo -e "[\033[31mKO\e[0m] The operating system is not supported!!!"
        fi

}

vm_checks() {
        uname -a|grep x86_64 > /dev/null 2>&1
        OS_X86_64=$?
        if [[ $OS_X86_64 -eq 0 ]] ; then
            echo -e "[\033[32mOK\e[0m] The kernel of the OS is x86_64!"
            echo -e "[\033[33mWARNING\e[0m]: Some restrictions are applied with some specific kernel releases."
        else echo -e "[\033[31mKO\e[0m] The Operating System is not x86_64!"
        fi

        ROOT_DISK_SIZE=`fdisk -l 2>/dev/null|grep -m1 Disk|awk '{print $5}'`
        if [[ $ROOT_DISK_SIZE -lt 1099511627776 ]] ; then
                echo -e  "[\033[32mOK\e[0m] The root volume disk size is less than 1TB!"
        else echo -e "[\033[31mKO\e[0m] The root volume disk size is more than 1TB!"
        fi

	ROOT_DISK=`fdisk -l 2>/dev/null|grep -m1 Disk|awk '{print $2}'|tr -d ':'`
        fdisk -l $ROOT_DISK 2>/dev/null |grep gpt > /dev/null 2>&1
        IS_GPT=$?
        if [[ $IS_GPT -eq 0 ]] ; then
                echo -e "[\033[31mKO\e[0m] The GUID Partition Table (GPT) disk import is not supported!!!"
        else echo -e "[\033[32mOK\e[0m] The Partition table appears to be MBR."
        fi

	ROOT_FS_SPACE_AVAIL=`df -k / |grep "/$"|awk '{ print $4}'`
        if [[ $ROOT_FS_SPACE_AVAIL == *"%" ]]; then
           ROOT_FS_SPACE_AVAIL=`df -k / |grep "/$"|awk '{ print $3}'`
        fi
	BOOT_FS_SPACE_AVAIL=`df -k /boot|grep "/$" |awk '{ print $4}'`
        if [[ $BOOT_FS_SPACE_AVAIL == *"%" ]]; then
           BOOT_FS_SPACE_AVAIL=`df -k /boot |grep "/$"|awk '{ print $3}'`
        fi
	ETC_FS_SPACE_AVAIL=`df -k /etc|grep "/$" |awk '{ print $4}'`
        if [[ $ETC_FS_SPACE_AVAIL == *"%" ]]; then
           ETC_FS_SPACE_AVAIL=`df -k /etc |grep "/$"|awk '{ print $3}'`
        fi
	TMP_FS_SPACE_AVAIL=`df -k /tmp|grep "/$" |awk '{ print $4}'`
        if [[ $TMP_FS_SPACE_AVAIL == *"%" ]]; then
           TMP_FS_SPACE_AVAIL=`df -k /tmp |grep "/$"|awk '{ print $3}'`
        fi
	VAR_FS_SPACE_AVAIL=`df -k /var|grep "/$" |awk '{ print $4}'`
        if [[ $VAR_FS_SPACE_AVAIL == *"%" ]]; then
           VAR_FS_SPACE_AVAIL=`df -k /var |grep "/$"|awk '{ print $3}'`
        fi
	USR_FS_SPACE_AVAIL=`df -k /usr|grep "/$" |awk '{ print $4}'`
        if [[ $USR_FS_SPACE_AVAIL == *"%" ]]; then
           USR_FS_SPACE_AVAIL=`df -k /usr |grep "/$"|awk '{ print $3}'`
        fi
        if [[ $ROOT_FS_SPACE_AVAIL -gt 256000 ]] && [[ $BOOT_FS_SPACE_AVAIL -gt 256000 ]] && [[ $ETC_FS_SPACE_AVAIL -gt 256000 ]] && [[ $TMP_FS_SPACE_AVAIL -gt 256000 ]] && [[ $VAR_FS_SPACE_AVAIL -gt 256000 ]] && [[ $USR_FS_SPACE_AVAIL -gt 256000 ]] ; then
                echo -e  "[\033[32mOK\e[0m] There is enough space to install EC2 drivers!"
        else echo -e "[\033[31mKO\e[0m] It is needed at least 250MB of space available to install the EC2 drivers!"
        fi

        VMWARE_TOOLS_INST=`lsmod|grep vmw`
        IS_VMWARE_TOOLS_INST=$?
        if [[ $IS_VMWARE_TOOLS_INST -eq 0 ]] ; then
                echo -e "[\033[31mKO\e[0m] VMware tools are installed on the system!"
        else echo -e "[\033[32mOK\e[0m] VMware tools not installed."
        fi

        ACTIVE_ETH=`ifconfig -a |grep eth[0-9]|wc -l`
        ACTIVE_EN=`ifconfig -a|grep en[a-z]|wc -l`

        
        if [[ $ACTIVE_ETH == 1 ]] ; then
                echo -e  "[\033[32mOK\e[0m] Only one active eth adapter found!"
        elif [[ $ACTIVE_EN == 1 ]] ; then
                echo -e  "[\033[32mOK\e[0m] Only one active en adapter found!"
        else echo -e "[\033[31mKO\e[0m] Only one active adapter should be active to convert the VM!"
        fi
	
	#check for dhclient pid with pidof, if there return code is 0, therefore dhclient is running
	DHCLIENT_RC=`pidof dhclient >> /dev/null ; echo $?`
	#SLES using wickedd instead of dhclient
	WICKEDD_RC=`pidof wickedd-dhcp4 >> /dev/null ; echo $?`
	#if grep match "0.0.0.0:68 " and the return code is 0 means that dhclient is listening
	DHCLIENT_NETSTAT=`netstat -na|grep -i '0.0.0.0:68 ' >> /dev/null; echo $?`
	if [[ $DHCLIENT_RC == 0 || $WICKEDD_RC == 0 ]] && [[ $DHCLIENT_NETSTAT == 0 ]] ; then
		echo -e "[\033[32mOK\e[0m] DHCP client is running"
	else echo -e "[\033[31mKO\e[0m] dhcp must be enabled to import the vm correctly!" # enabled 
	fi

	SSH_RUNNING=`ps aux|grep sshd|grep -v grep`
        IS_SSH_RUNNING=$?
        if [[ $IS_SSH_RUNNING -eq 0 ]] ; then
                echo -e "[\033[32mOK\e[0m] The SSH daemon is up and running!"
        else echo -e "[\033[31mKO\e[0m] Check the SSH is up and running!"
        fi


        IPTABLES_DROP=`iptables -L |grep -i drop`
        IS_IPTABLES_DROP=$?
        if [[ $IS_IPTABLES_DROP -eq 0 ]] ; then
                echo -e "[\033[31mKO\e[0m] Found a drop in the iptables rules!"
		echo -e "[\033[33mWARNING\e[0m]:Check iptables doesn't block SSH before you start the conversion!"
        else echo -e "[\033[32mOK\e[0m] Not found any drop in the iptables!"
        fi

	CDROM_PRESENT=`dmesg | grep cdrom`
        IS_CDROM_PRESENT=$?
        CDRW_PRESENT=`dmesg | grep cd/rw`
	IS_CDRW_PRESENT=$?
	DVD_PRESENT=`dmesg | grep dvd`
	IS_DVD_PRESENT=$?
	WRITER_PRESENT=`dmesg | grep writer`
	IS_WRITER_PRESENT=$?
        if [[ $IS_CDROM_PRESENT -eq 0 ]] || [[ $IS_CDRW_PRESENT -eq 0 ]] || [[ $IS_DVD_PRESENT -eq 0 ]] || [[ $IS_WRITER_PRESENT -eq 0 ]] ; then
                echo -e "[\033[31mKO\e[0m] CD-ROM or DVD device detected! Please remove it!"
        else echo -e "[\033[32mOK\e[0m] No CD-ROM or DVD device detected."
        fi

}

check_grub() {
        GRUB_ROOT_DEVICE=$(sudo cat /proc/cmdline | awk 'match($0, /root=.*/) { print substr($0, RSTART, RLENGTH) }' | awk '{print $1}')
        
        if [[ $(echo ${GRUB_ROOT_DEVICE} | awk -F'=' '{print NF}') == 3 ]]; then
                DEV_DEF=$(echo ${GRUB_ROOT_DEVICE} | awk -F'=' {'print $3'})
                echo -e "[\033[32mOK\e[0m] The currently active root volume is defined by LABEL or UUID: ${DEV_DEF} which is a good practice for imports."
        elif [[ $(echo ${GRUB_ROOT_DEVICE} | awk -F'=' '{print NF}') == 2 ]]; then
                DEV_DEF=$(echo ${GRUB_ROOT_DEVICE} | awk -F'=' {'print $2'})
                echo -e "[\033[33mWARNING\e[0m]: The current kernel boot command is referencing the root volume using block device IDs. In some cases, this can cause issues with the import process. We recommend using the UUID instead where possible."           
        fi

}

check_fs() {
        ROOT_FS_TYPE=$(df -T / | tail -1 | awk '{print $2}')

        if [[ ${ROOT_FS_TYPE} == "ext"*  ]]; then
                FS_CHECK_DATE=$(tune2fs -l $(mount | grep 'on / ' | awk '{print $1}') | grep 'Last checked' | awk 'match($0, /Sat.*|Sun.*|Mon.*|Tue.*|Wed.*|Thu.*|Fri.*/) { print substr($0, RSTART, RLENGTH) }')
                FS_SHORT_DATE=$(date -d "${FS_CHECK_DATE}" +%s)
                CURR_SHORT_DATE=$(date +%s)
                DATEDIFF=$(echo \(${CURR_SHORT_DATE}-${FS_SHORT_DATE}\)/60/60/24 | bc)
                
                if [[ "${DATEDIFF}" -gt 15 ]]; then
                        echo -e "[\033[33mWARNING\e[0m] Your EXT root filesystem has not been checked in more than 2 weeks - please run fsck before importing your VM."
                fi
        else
                echo -e "[\033[32mOK\e[0m] Please ensure you run a filesystem check against the root volume before importing your VM."
        fi
}

check_fstab() {
    root_dev=$(mount | grep 'on / ' | awk '{print $1}')

    root_uuid=$(blkid | grep ${root_dev} | grep -ow 'UUID=\S*' | sed s/\"//g)
    root_label=$(blkid | grep ${root_dev} | grep -ow 'LABEL=\S*' | sed s/\"//g)

    for block_dev in $(cat /etc/fstab | grep '^/dev' | awk '{print $1}' | sed s/\"//g)
    do
        if  [[ "${block_dev}" == "${root_dev}" ]]; then
            true
        else
            secondary_dev_array+=" ${block_dev}"
        fi
    done

    for block_label in $(cat /etc/fstab | grep '^LABEL' | awk '{print $1}' | sed s/\"//g)
    do
        if  [[ "${block_label}" == "${root_label}" ]]; then
            true
        else
            secondary_label_array+=" ${block_label}"
        fi
    done

    for block_uuid in $(cat /etc/fstab | grep '^UUID' | awk '{print $1}' | sed s/\"//g)
    do
        if  [[ "${block_uuid}" == "${root_uuid}" ]]; then
            true
        else
            secondary_uuid_array+=" ${block_uuid}"
        fi
    done

    if [[ -n ${secondary_dev_array} ]]; then
        for dev in ${secondary_dev_array[@]}
            do 
                echo -e "[\033[31mKO\e[0m]: Secondary volume configured in /etc/fstab for this VM: ${dev} - please ensure they are included
               in the import definition or comment them out of the fstab when preparing the VM for import. "
            done
    fi

    if [[ -n ${secondary_label_array} ]]; then
        for dev in ${secondary_label_array[@]}
            do 
                echo -e "[\033[33mWARNING\e[0m]: Secondary volume configured in /etc/fstab for this VM: ${dev} - please ensure they are included
               in the import definition or comment them out of the fstab when preparing the VM for import. "
            done
    fi

    if [[ -n ${secondary_uuid_array} ]]; then
        for dev in ${secondary_uuid_array[@]}
            do 
                echo -e "[\033[33mWARNING\e[0m]: Secondary volume configured in /etc/fstab for this VM: ${dev} - please ensure they are included
                in the import definition or comment them out of the fstab when preparing the VM for import. "
            done
    fi

    if [[ -z ${secondary_label_array} && -z  ${secondary_label_array} && -z ${secondary_uuid_array} ]]; then
        echo -e "[\033[32mOK\e[0m]: It seems only the root volume is defined in /etc/fstab. "
    fi
}

print_advice() {
    echo " "
    echo "For further informations about the prerequisites of the VM Import check:"
    echo "http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/VMImportPrerequisites.html"
    echo " "
}
set_defaults
splash_screen
check_running_user
check_os
vm_checks
check_grub

check_fs
check_fstab
print_advice

exit
