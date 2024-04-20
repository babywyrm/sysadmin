#!/bin/bash

##
## https://gist.github.com/ThinGuy/63d6baa3103d806b9aaf7c91fcab3741
##

##############################################################################
# ossa.sh - Open Source Security Assessment 
#
#
#  Author(s): Craig Bender <craig.bender@canonical.com>
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, version 3 of the License.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#  Copyright (C) 2020 Canonical Ltd.
#
##############################################################################


# Start Timer
TZ=UTC export NOW=$(date +%s)sec


################
# SET DEFAULTS #
################

export PROG=${0##*/}
export OSSA_DIR='/tmp/ossa_files'
export OSSA_SUFFX="$(hostname -s).$(lsb_release 2>/dev/null -sc)"
export OSSA_PURGE=false
export OSSA_KEEP=false
export OSSA_COPY_SOURCE=true
export OSSA_COPY_PARTS=true
export OSSA_COPY_CREDS=false
export OSSA_ENCRYPT=false
export OSSA_PW=
export OSSA_SCAN=false
export OSSA_SUDO=false

#########
# USAGE #
#########

ossa-Usage() {
	printf "\n\e[2GScript: ${FUNCNAME%%-*}.sh\n"
	printf "\e[2GUsage: ${FUNCNAME%%-*}.sh [ Options ] \n"
	printf "\e[2GOptions:\n\n"
	printf "\e[3G -d, --dir\e[28GDirectory to store Open Source Security Assessment Data (Default: /tmp/ossa_files)\n\n"
	printf "\e[3G -s, --suffix\e[28GAppend given suffix to collected files (Default: \".$(hostname -f).$(lsb_release 2>/dev/null -cs)\"\n\n"
	printf "\e[3G -o, --override\e[28GCopy apt list file regardless if they contain embedded credentials (Default: false)\n\n"
	printf "\e[3G -p, --purge\e[28GPurge existing OSSA Directory (Default: False)\n\n"
	printf "\e[3G -k, --keep\e[28GKeep OSSA Directory after script completes (Default: False)\n\n"
	printf "\e[3G -e, --encrypt\e[28GEncrypt OSSA Datafiles with given passphrase (Default: False)\n\n"
	printf "\e[3G -S, --scan\e[28GInstall OpenSCAP & scan manifest for CVEs. Require sudo access\n\e[28Gif OpenSCAP is not installed. (Default: False)\n\n"
	printf "\e[3G -h, --help\e[28GThis message\n\n"
	printf "\e[2GExamples:\n\n"
	printf "\e[4GChange location of collected data:\n"
	printf "\e[6G${FUNCNAME%%-*}.sh -d \$HOME/ossa_files\n"
	printf "\n\e[4GSet custom file suffix:\n"
	printf "\e[6G${FUNCNAME%%-*}.sh -s \$(hostname -f).\$(lsb_release 2>/dev/null -sr)\n"
	printf "\n\e[4GPurge existing/leftover directory, perform CVE Scan, encrypt compressed archive of collected data, and\n\e[6Gkeep data directory after run\n\n"
	printf '\e[6G'${FUNCNAME%%-*}'.sh -pSke '"'"'MyP@ssW0rd!'"'"' \n\n'
};export -f ossa-Usage


################
# ARGS/OPTIONS #
################

ARGS=$(getopt -o s::d:e:Spokh --long suffix::,dir:,encrypt:,scan,purge,override,keep,help -n ${PROG} -- "$@")
eval set -- "$ARGS"
while true ; do
	case "$1" in
		-d|--dir) export OSSA_DIR=${2};shift 2;;
		-e|--encrypt) export OSSA_ENCRYPT=true;export OSSA_PW="${2}";shift 2;;
		-s|--suffix) case "$2" in '') export OSSA_SUFFX="";; *) export OSSA_SUFFX="${2}";;esac;shift 2;continue;;
		-p|--purge) export OSSA_PURGE=true;shift 1;;
		-o|--override) export OSSA_COPY_CREDS=true;shift 1;;
		-k|--keep) export OSSA_KEEP=true;shift 1;;
		-S|--scan) export OSSA_SCAN=true;shift 1;;
		-h|--help) ossa-Usage;exit 2;;
		--) shift;break;;
	esac
done


########
# ToDo #
########

# Idea to handle systems that use mirrors
# Parse /var/lib/apt/lists/*Release files and see if the mirror's origin is Ubuntu
# Then convert the Release file to a URL and add to temp copy of mirror.cfg
#http://ubuntu-archive.orangebox.me/ubuntu/
#http://canonical-archive.orangebox.me/ubuntu/
#http://cloud-archive.orangebox.me/ubuntu/
#http://ppa-archive.orangebox.me/maas/2.7/ubuntu
#http://private-ppa.orangebox.me/maas-image-builder-partners/stable/ubuntu/
#http://security-archive.orangebox.me/ubuntu/


###################
# START OF SCRIPT #
###################

# Trap interupts and exits so we can restore the screen 
trap 'tput sgr0; tput cnorm; tput rmcup; exit 0' SIGINT SIGTERM EXIT

# Save screen contents, clear the screen and turn off the cursor
tput smcup; tput civis 


############################
# DISPLAY SELECTED OPTIONS #
############################

# Print config/option data
printf "\n\e[1G\e[1mOpen Source Security Assessment Configuration\e[0m\n"
printf "\e[2G - \e[38;2;0;160;200mINFO\e[0m: OSSA Data will be stored in \e[38;2;0;160;200m${OSSA_DIR}\e[0m\n"
printf "\e[2G - \e[38;2;0;160;200mINFO\e[0m: Purge Existing Directory option is \e[38;2;0;160;200m${OSSA_PURGE^^}\e[0m\n"
printf "\e[2G - \e[38;2;0;160;200mINFO\e[0m: Keep OSSA Data option is \e[38;2;0;160;200m${OSSA_KEEP^^}\e[0m\n"
printf "\e[2G - \e[38;2;0;160;200mINFO\e[0m: Override Password Protection option is \e[38;2;0;160;200m${OSSA_COPY_CREDS^^}\e[0m\n"
printf "\e[2G - \e[38;2;0;160;200mINFO\e[0m: Archive Encryption option is \e[38;2;0;160;200m${OSSA_ENCRYPT^^}\e[0m\n"
[[ ${OSSA_ENCRYPT} = true ]] && { printf "\e[2G - \e[38;2;0;160;200mINFO\e[0m: Encryption Passphrase is \"\e[38;2;0;160;200m${OSSA_PW}\e[0m\"\n"; }
[[ ${OSSA_ENCRYPT} = true ]] && { printf "\e[2G - \e[38;2;0;160;200mINFO\e[0m: Performing cracklib-check against \${OSSA_PW}. Result: $(cracklib-check <<< ${OSSA_PW}|awk -F': ' '{print $2}')\n"|sed 's/\ OK.*$/'$(printf "\e[38;2;0;255;0m&\e[0m")'/g;s/\ it.*$/'$(printf "\e[38;2;255;0;0m&\e[0m")'/g;s/\ it/\ It/g'; }
# If Suffix is set, ensure that it starts with a period
if [[ -n ${OSSA_SUFFX} ]];then
	[[ ${OSSA_SUFFX:0:1} = '.' ]] || export OSSA_SUFFX=".${OSSA_SUFFX}"
	printf "\e[2G - \e[38;2;0;160;200mINFO\e[0m: A Suffix of \"\e[38;2;0;160;200m${OSSA_SUFFX}\e[0m\" will be appended to each file collected\n"
else
	export OSSA_SUFFX=
	printf "\e[2G - \e[38;2;0;160;200mINFO\e[0m: File suffix is \e[38;2;0;160;200mNULL\e[0m\n"
fi
# Added ability to scan for CVEs
# This requires either that OpenSCAP is already installed or root level access to install the package
printf "\e[2G - \e[38;2;0;160;200mINFO\e[0m: Scan option is \e[38;2;0;160;200m${OSSA_SCAN^^}\e[0m\n"
if [[ ${OSSA_SCAN} = true ]];then
	if [[ $(dpkg -l openscap-daemon|awk '/openscap-daemon/{print $1}') = ii ]];then
		printf "\e[2G - \e[38;2;0;160;200mINFO\e[0m: OpenSCAP is \e[1malready installed\e[0m.  \e[38;2;0;255;0mRoot-level access is not required\e[0m.\n"
	else
		printf "\e[2G - \e[38;2;0;160;200mINFO\e[0m: OpenSCAP is \e[1mNOT\e[0m installed.  \e[38;2;255;0;0mRoot-level access is required\e[0m.  Checking credentials...\n"
		#Root/sudo check
		[[ ${EUID} -eq 0 ]] && { export SCMD="";[[ ${DEBUG} = True ]] && { printf "\e[38;2;255;200;0mDEBUG:\e[0m User is root\n\n";export OSSA_SUDO=true; }; } || { [[ ${EUID} -ne 0 && -n $(id|grep -io sudo) ]] && { export SCMD=sudo;export OSSA_SUDO=true; } || { export SCMD="";printf "\e[38;2;255;0;0mERROR:\e[0m User (${USER}) does not have sudo permissions.\e[0m Quitting.\e[0m\n\n";export OSSA_SUDO=false; }; }
		[[ ${OSSA_SUDO} = false ]] && { export OSSA_SCAN=false;printf "\e[2G - \e[38;2;0;160;200mINFO\e[0m: Insufficent sudo privilages.  CVE Scanning will not occur\n"; }
		[[ ${OSSA_SUDO} = true ]] && { export OSSA_SCAN=true;printf "\e[2G - \e[38;2;0;160;200mINFO\e[0m: User has sufficent sudo privilages to install packages.  CVE Scanning occur as desired\n"; }
		[[ ${OSSA_SUDO} = true && ${OSSA_SCAN} = true ]] && { printf "\e[2G - \e[38;2;0;160;200mINFO\e[0m: Installing OpenSCAP to scan for high and critical CVEs\n";${SCMD} apt 2>/dev/null install openscap-daemon -yqq >/dev/null 2>&1; }
		[[ ${OSSA_SUDO} = true && ${OSSA_SCAN} = true ]] && { [[ $(dpkg -l openscap-daemon|awk '/openscap-daemon/{print $1}') = ii ]];printf "\e[2G - \e[38;2;0;255;0mSUCCESS\e[0m: OpenSCAP installed sucessfully\n"; } || { printf "\e[2G - \e[38;2;255;0;0mERROR\e[0m: OpenSCAP did not appear to install correctly.  Cancelling CVE Scan\n";export OSSA_SCAN=false; }
	fi
fi


# Create OSSA Directory to store files
printf "\n\e[2G\e[1mCreate OSSA Data Directory\e[0m\n"

# Remove existing directory if user chose that option
if [[ ${OSSA_PURGE} = true ]];then
	printf "\e[2G - \e[38;2;0;160;200mINFO\e[0m: Removing existing directory: ${OSSA_DIR}\n"
	[[ -d ${OSSA_DIR} ]] && { rm -rf ${OSSA_DIR}; } || { printf "\e[2G - \e[38;2;0;160;200mINFO\e[0m: Existing directory does not exist.\n"; } 
	[[ -d ${OSSA_DIR} ]] && { printf "\e[2G - \e[38;2;255;0;0mERROR\e[0m: Could not remove existing directory ${OSSA_DIR}\n"; } || { printf "\e[2G - \e[38;2;0;255;0mSUCCESS\e[0m: Removed existing directory ${OSSA_DIR}\n"; }
fi

# Create OSSA Directory using a given name
mkdir -p ${OSSA_DIR}/{apt/package-files,apt/release-files,apt/source-files,util-output,manifests,oval_data,reports}
[[ -d ${OSSA_DIR} ]] && { printf "\e[2G - \e[38;2;0;255;0mSUCCESS\e[0m: Created directory ${OSSA_DIR}\n"; } || { printf "\e[2G - \e[38;2;255;0;0mERROR\e[0m: Could not create directory ${OSSA_DIR}\n";exit; }

export PKG_DIR=${OSSA_DIR}/apt/package-files
export REL_DIR=${OSSA_DIR}/apt/release-files
export SRC_DIR=${OSSA_DIR}/apt/source-files
export UTIL_DIR=${OSSA_DIR}/util-output
export MFST_DIR=${OSSA_DIR}/manifests
export OVAL_DIR=${OSSA_DIR}/oval_data
export RPRT_DIR=${OSSA_DIR}/reports

#####################################
# LINUX STANDARD BASE (lsb_release) #
#####################################

# Fetch lsb-release file if it exists, otherwise generate a similar file
printf "\n\e[2G\e[1mGather Linux Standard Base Information (lsb_release)\e[0m\n"
if [[ -f /etc/lsb-release ]];then
  printf "\e[2G - \e[38;2;0;160;200mINFO\e[0m: Copying /etc/lsb-release to ${UTIL_DIR}/\n"
	cp /etc/lsb-release ${UTIL_DIR}/lsb-release${OSSA_SUFFX}
else
	if [[ -n $(command -v lsb_release) ]];then
		printf "\e[2G - \e[38;2;0;160;200mINFO\e[0m: Creating lsb-release file using $(which lsb_release)\n"
		for i in ID RELEASE CODENAME DESCRIPTION;do echo DISTRIB_${i}=$(lsb_release -s$(echo ${i,,}|cut -c1)); done|tee 1>/dev/null ${UTIL_DIR}/lsb-release${OSSA_SUFFX}
	else
		printf "\e[2G - \e[38;2;255;0;0mERROR\e[0m: Cannot find binary for \"lsb_release\"\n"
	fi
fi
[[ -s ${UTIL_DIR}/lsb-release${OSSA_SUFFX} ]] && { printf "\e[2G - \e[38;2;0;255;0mSUCCESS\e[0m: Copied lsb-release information\n"; } || { printf "\e[2G - \e[38;2;255;0;0mERROR\e[0m: Could not copy lsb-release information\n"; }


#########################
# CREATE MANIFEST FILES #
#########################

# Create a variety of manifest files
printf "\n\e[2G\e[1mCreate Package Manifest Files\e[0m\n"

# Create classic manifest file
printf "\e[2G - \e[38;2;0;160;200mINFO\e[0m: Creating classic manifest file\n"
(dpkg -l|awk '/^ii/&&!/^$/{gsub(/:amd64/,"");print $2"\t"$3}'|sort -uV)|tee 1>/dev/null ${MFST_DIR}/manifest.classic${OSSA_SUFFX}
[[ -s ${MFST_DIR}/manifest.classic${OSSA_SUFFX} ]] && { printf "\e[2G - \e[38;2;0;255;0mSUCCESS\e[0m: Created classic manifest file\n"; } || { printf "\e[2G - \e[38;2;255;0;0mERROR\e[0m: Could not create classic manifest file\n"; }

# Get madison information for classic manifest and show a spinner while it runs
((awk '{print $1}' ${MFST_DIR}/manifest.classic${OSSA_SUFFX} |xargs -rn1 -P0 bash -c 'apt-cache madison $0|sort -k3|head -n1'|sed 's/^[ \t]*//;s/ |[ \t]*/|/g'|sed -r 's,/ubuntu ,_ubuntu_dists_,g;s,amd64,binary-amd64,g;s,/| ,_,g;s,http:__,/var/lib/apt/lists/,g'|tee 1>/dev/null ${MFST_DIR}/madison.classic${OSSA_SUFFX}) &)
export SPID=$(pgrep -of 'apt-cache madison')
tput civis
trap 'tput sgr0;tput cnorm;trap - INT TERM EXIT;return' INT TERM EXIT
declare -ag CHARS=($(printf "\u22EE\u2003\b") $(printf "\u22F0\u2003\b") $(printf "\u22EF\u2003\b") $(printf "\u22F1\u2003\b"))
while [[ $(pgrep 2>/dev/null -of 'apt-cache madison') ]];do
	for c in ${CHARS[@]};do printf "\r\e[2G - \e[38;2;0;160;200mINFO\e[0m: Gathering \"madison\" information for classic manifest. Please wait  %s\e[K\e[0m" $c;sleep .10;done
done
wait $(pgrep 2>/dev/null -of 'apt-cache madison')
[[ $? -eq 0 ]] && { printf "\r\e[K\r\e[2G - \e[38;2;0;255;0mSUCCESS\e[0m: Created ${MFST_DIR}/madison.classic${OSSA_SUFFX}\n"; } || { printf "\r\e[K\r\e[2G - \e[38;2;255;0;0mERROR\e[0m: Creating ${MFST_DIR}/madison.classic${OSSA_SUFFX}\n"; }
trap - INT TERM EXIT
tput cnorm

# Create a manifest file based on packages that were expressly manually installed
printf "\e[2G - \e[38;2;0;160;200mINFO\e[0m: Creating manifest of manually installed packages\n"
(apt 2>/dev/null list --manual-installed|awk -F"/| " '!/^$|^Listing/{print $1"\t"$3}')|tee 1>/dev/null ${MFST_DIR}/manifest.manual${OSSA_SUFFX}
[[ -s ${MFST_DIR}/manifest.manual${OSSA_SUFFX} ]] && { printf "\e[2G - \e[38;2;0;255;0mSUCCESS\e[0m: Created manually-installed manifest file\n"; } || { printf "\e[2G - \e[38;2;255;0;0mERROR\e[0m: Could not create manually-installed packages manifest file\n"; }

# Create a manifest file based on packages that were automatically installed (dependency, pre-req)
printf "\e[2G - \e[38;2;0;160;200mINFO\e[0m: Creating manifest of automatically installed packages\n"
(apt 2>/dev/null list --installed|awk -F"/| " '!/^$|^Listing/&&/,automatic\]/{print $1"\t"$3}')|tee 1>/dev/null ${MFST_DIR}/manifest.automatic${OSSA_SUFFX}
[[ -s ${MFST_DIR}/manifest.automatic${OSSA_SUFFX} ]] && { printf "\e[2G - \e[38;2;0;255;0mSUCCESS\e[0m: Created automatically-installed packages manifest file\n"; } || { printf "\e[2G - \e[38;2;255;0;0mERROR\e[0m: Could not create automatically-installed packages manifest file\n"; }

######################
# COPY PACKAGE FILES #
######################

printf "\n\e[2G\e[1mCollect Repository Package files\e[0m\n"
if [[ -n $(find 2>/dev/null /var/lib/apt/lists -iname "*_Packages") ]];then
	printf "\e[2G - \e[38;2;0;160;200mINFO\e[0m: Searching Repository Package files\n"
	find 2>/dev/null /var/lib/apt/lists -iname "*_Packages" -exec cp {} ${PKG_DIR}/ \;
	[[ -n $(find 2>/dev/null ${PKG_DIR}/ -iname "*_Packages") ]] && { printf "\e[2G - \e[38;2;0;255;0mSUCCESS\e[0m: Copied Package files to ${PKG_DIR}\n"; } || { printf "\e[2G - \e[38;2;255;0;0mERROR\e[0m: Could not copy Package files to ${PKG_DIR}\n"; }
else
	printf "\e[2G - \e[38;2;0;160;200mINFO\e[0m: Could not find Repository Package files. Skipping.\n"
fi
#######################
# COPY PACKAGE STATUS #
#######################

printf "\n\e[2G\e[1mCollect dpkg status file\e[0m\n"
if [[ -f /var/lib/dpkg/status ]];then
	printf "\e[2G - \e[38;2;0;160;200mINFO\e[0m: Searching for dpkg status file\n"
	cp /var/lib/dpkg/status ${PKG_DIR}/dpkg.status${OSSA_SUFFX}
	[[ -f ${PKG_DIR}/dpkg.status${OSSA_SUFFX} ]] && { printf "\e[2G - \e[38;2;0;255;0mSUCCESS\e[0m: Copied dpkg status file\n"; } || { printf "\e[2G - \e[38;2;255;0;0mERROR\e[0m: Could not copy dpkg status file\n"; }
else
	printf "\e[2G - \e[38;2;0;160;200mINFO\e[0m: Could not find dpkg status file. Skipping.\n"
fi

######################
# COPY RELEASE FILES #
######################

printf "\n\e[2G\e[1mCollect Repository Release files\e[0m\n"
if [[ -n $(find 2>/dev/null /var/lib/apt/lists -iname "*Release") ]];then
	printf "\e[2G - \e[38;2;0;160;200mINFO\e[0m: Gathering Repository Release files\n"
	find 2>/dev/null /var/lib/apt/lists -iname "*Release" -exec cp {} ${REL_DIR}/ \;
	[[ -n $(find 2>/dev/null ${REL_DIR}/ -iname "*Release") ]] && { printf "\e[2G - \e[38;2;0;255;0mSUCCESS\e[0m: Copied Release files to ${REL_DIR}\n"; } || { printf "\e[2G - \e[38;2;255;0;0mERROR\e[0m: Could not copy Release files to ${REL_DIR}\n"; }
else
	printf "\e[2G - \e[38;2;0;160;200mINFO\e[0m: Could not find Repository Release files. Skipping.\n"
fi

####################
# APT SOURCE FILES #
####################

# Discover and evaluate sources.list(.d) for embedded credentials
printf "\n\e[2G\e[1mCollect Apt Source List and Part Files\e[0m\n"

# Get defined sources.list file from apt-config
printf "\e[2G - \e[38;2;0;160;200mINFO\e[0m: Deriving location of sources.list from \"apt-config dump\"\n"
export SOURCES_LIST=$(apt-config dump|awk '/^Dir\ |^Dir::Etc\ |^Dir::Etc::sourcel/{gsub(/"|;$/,"");print "/"$2}'|sed -r ':a;N;$! ba;s/\/\/|\n//g')

# Check for stored password in defined sources.list file
if [[ -s ${SOURCES_LIST} ]];then
	printf "\e[2G - \e[38;2;0;160;200mINFO\e[0m: Checking ${SOURCES_LIST} for embedded credentials\n"
	[[ -n $(grep -lRE 'http?(s)://[Aa-Zz-]+:[Aa-Zz0-9-]+@' ${SOURCES_LIST}) ]] && { export OSSA_COPY_SOURCE=false;printf "\e[2G - \e[38;2;255;200;0mWARNING\e[0m: ${SOURCES_LIST} appears to have credentials stored in the URIs\n"; } || { export OSSA_COPY_SOURCE=true; }
fi

# if OSSA_COPY_SOURCE has credentials in it, OSSA_COPY_SOURCE will be set to false.
# Only using -o,--override option will allow the copy if set to true
if [[ ${OSSA_COPY_SOURCE} = true || ${OSSA_COPY_CREDS} = true ]];then
	# Get configured source list file and make copy of it
	[[ -f ${SOURCES_LIST} ]] && { cp ${SOURCES_LIST} ${SRC_DIR}/sources.list${OSSA_SUFFX}; }
	[[ -s ${SRC_DIR}/sources.list${OSSA_SUFFX} ]] && { printf "\e[2G - \e[38;2;0;255;0mSUCCESS\e[0m: Copied sources.list file\n"; } || { printf "\e[2G - \e[38;2;255;0;0mERROR\e[0m: Could not copy sources.list file from ${SOURCES_LIST}\n" ; }
else
	printf "\e[2G - \e[38;2;255;200;0mWARNING\e[0m: Skipping copying file ${SOURCES_LIST} due to possible embedded credentials\n\e[14GUse -o,--override option to force the copy\n\n"
fi

# Get defined sources part list files from apt-config
printf "\e[2G - \e[38;2;0;160;200mINFO\e[0m: Deriving location of source part files from \"apt-config dump\"\n"
export SOURCES_LIST_D=$(apt-config dump|awk '/^Dir\ |^Dir::Etc\ |^Dir::Etc::sourcep/{gsub(/"|;$/,"");print "/"$2}'|sed -r ':a;N;$! ba;s/\/\/|\n//g')
# Check for stored password in defined sources part list files
if [[ -n $(find ${SOURCES_LIST_D} -type f) ]];then
	printf "\e[2G - \e[38;2;0;160;200mINFO\e[0m: Checking for embedded credentials in source parts files (${SOURCES_LIST_D}/*) \n"
	[[ -n $(grep -lRE 'http?(s)://[Aa-Zz-]+:[Aa-Zz0-9-]+@' ${SOURCES_LIST_D}/) ]] && { export OSSA_COPY_PARTS=false;printf "\e[2G - \e[38;2;255;200;0mWARNING\e[0m: The following source part files appear to have credentials stored in the URIs: $(grep -lRE 'http?(s)://[Aa-Zz-]+:[Aa-Zz0-9-]+@' ${SOURCES_LIST_D}/)\n"; } || { export OSSA_COPY_PARTS=true; }
fi

if [[ ${OSSA_COPY_PARTS} = true || ${OSSA_COPY_CREDS} = true ]];then
	[[ -d ${SOURCES_LIST_D} ]] && { find ${SOURCES_LIST_D} -type f -iname "*.list" -o -type l -iname "*.list"|xargs -rn1 -P0 bash -c 'cp ${0} ${SRC_DIR}/${0##*/}${OSSA_SUFFX}'; }
	[[ -n $(find ${SRC_DIR}/ -type f) ]] && { printf "\e[2G - \e[38;2;0;255;0mSUCCESS\e[0m: Copied source parts lists from ${SOURCES_LIST_D} to ${SRC_DIR}\n"; } || { printf "\e[2G - \e[38;2;255;0;0mERROR\e[0m: Could not copy sources.list file from ${SOURCES_LIST} to ${SRC_DIR}\n" ; }
else
	printf "\e[2G - \e[38;2;255;200;0mWARNING\e[0m: Skipped copying files from ${SOURCES_LIST_D}/* due to possible embedded credentials\n\e[14GUse -o,--override option to force the copy\n\n"
fi


#########################
# UBUNTU SUPPORT STATUS #
#########################

# Create a ubuntu-support-status file
printf "\n\e[2G\e[1mRun ubuntu-support-status\e[0m\n"
if [[ -n $(command -v ubuntu-support-status) ]];then
	printf "\e[2G - \e[38;2;0;160;200mINFO\e[0m: Running ubuntu-support-status\n"
	ubuntu-support-status --list|tee 1>/dev/null ${UTIL_DIR}/ubuntu-support-status${OSSA_SUFFX}
	[[ -s ${UTIL_DIR}/ubuntu-support-status${OSSA_SUFFX} ]] && { printf "\e[2G - \e[38;2;0;255;0mSUCCESS\e[0m: Created ubuntu-support-status output file\n"; } || { printf "\e[2G - \e[38;2;255;0;0mERROR\e[0m: Could not create ubuntu-support-status output file\n" ; }
else
	printf "\e[2G - \e[38;2;0;160;200mINFO\e[0m: Cannot find binary ubuntu-support-status. Skipping\n"
fi

##########################
# UBUNTU SECURITY STATUS #
##########################
export USS_B64='IyEvdXNyL2Jpbi9weXRob24zCgppbXBvcnQgYXB0CmltcG9ydCBhcmdwYXJzZQppbXBvcnQgZGlzdHJvX2luZm8KaW1wb3J0IG9zCmltcG9ydCBzeXMKaW1wb3J0IGdldHRleHQKaW1wb3J0IHN1YnByb2Nlc3MKCmZyb20gZGF0ZXRpbWUgaW1wb3J0IGRhdGV0aW1lCmZyb20gdGV4dHdyYXAgaW1wb3J0IHdyYXAKZnJvbSB1cmxsaWIuZXJyb3IgaW1wb3J0IFVSTEVycm9yLCBIVFRQRXJyb3IKZnJvbSB1cmxsaWIucmVxdWVzdCBpbXBvcnQgdXJsb3BlbgoKIyBUT0RPIG9wdHBhcnNlIGhhbmRsaW5nIGFuZCBiZXN0IGNvbW1hbmRsaW5lIHN5cy5leGl0IHByYWN0aWNlcwpERUJVRyA9IEZhbHNlClZFUkJPU0UgPSBGYWxzZQoKCmNsYXNzIFBhdGNoU3RhdHM6CiAgICAiIiJUcmFja3Mgb3ZlcmFsbCBwYXRjaCBzdGF0dXMKICAgIFRoZSByZWxhdGlvbnNoaXAgYmV0d2VlbiBhcmNoaXZlcyBlbmFibGVkIGFuZCB3aGV0aGVyIGEgcGF0Y2ggaXMgZWxpZ2libGUKICAgIGZvciByZWNlaXZpbmcgdXBkYXRlcyBpcyBub24tdHJpdmlhbC4gV2UgdHJhY2sgaGVyZSBhbGwgdGhlIGltcG9ydGFudAogICAgYnVja2V0cyBhIHBhY2thZ2UgY2FuIGJlIGluOgogICAgICAgIC0gV2hldGhlciBpdCBpcyBzZXQgdG8gZXhwaXJlIHdpdGggbm8gRVNNIGNvdmVyYWdlCiAgICAgICAgLSBXaGV0aGVyIGl0IGlzIGluIGFuIGFyY2hpdmUgY292ZXJlZCBieSBFU00KICAgICAgICAtIFdoZXRoZXIgaXQgcmVjZWl2ZWQgTFRTIHBhdGNoZXMKICAgICAgICAtIHdoZXRoZXIgaXQgcmVjZWl2ZWQgRVNNIHBhdGNoZXMKICAgIFdlIGFsc28gdHJhY2sgdGhlIHRvdGFsIHBhY2thZ2VzIGNvdmVyZWQgYW5kIHVuY292ZXJlZCwgYW5kIGZvciB0aGUKICAgIHVuY292ZXJlZCBwYWNrYWdlcywgd2UgdHJhY2sgd2hlcmUgdGhleSBvcmlnaW5hdGUgZnJvbS4KICAgIFRoZSBVYnVudHUgbWFpbiBhcmNoaXZlIHJlY2VpdmVzIHBhdGNoZXMgZm9yIDUgeWVhcnMuCiAgICBDYW5vbmljYWwtb3duZWQgYXJjaGl2ZXMgKGV4Y2x1ZGluZyBwYXJ0bmVyKSByZWNlaXZlIHBhdGNoZXMgZm9yIDEwIHllYXJzLgogICAgICAgIHBhdGNoZXMgZm9yIDEwIHllYXJzLgogICAgIiIiCiAgICBkZWYgX19pbml0X18oc2VsZik6CiAgICAgICAgIyBUT0RPIG5vLXVwZGF0ZSBGSVBTIGlzIG5ldmVyIHBhdGNoZWQKICAgICAgICBzZWxmLnBrZ3NfdW5jb3ZlcmVkX2ZpcHMgPSBzZXQoKQoKICAgICAgICAjIGxpc3Qgb2YgcGFja2FnZSBuYW1lcyBhdmFpbGFibGUgaW4gRVNNCiAgICAgICAgc2VsZi5wa2dzX3VwZGF0ZWRfaW5fZXNtaSA9IHNldCgpCiAgICAgICAgc2VsZi5wa2dzX3VwZGF0ZWRfaW5fZXNtYSA9IHNldCgpCgogICAgICAgIHNlbGYucGtnc19tciA9IHNldCgpCiAgICAgICAgc2VsZi5wa2dzX3VtID0gc2V0KCkKICAgICAgICBzZWxmLnBrZ3NfdW5hdmFpbGFibGUgPSBzZXQoKQogICAgICAgIHNlbGYucGtnc190aGlyZHBhcnR5ID0gc2V0KCkKICAgICAgICAjIHRoZSBiaW4gb2YgdW5rbm93bnMKICAgICAgICBzZWxmLnBrZ3NfdW5jYXRlZ29yaXplZCA9IHNldCgpCgoKZGVmIHByaW50X2RlYnVnKHMpOgogICAgaWYgREVCVUc6CiAgICAgICAgcHJpbnQocykKCgpkZWYgd2hhdHNfaW5fZXNtKHVybCk6CiAgICBwa2dzID0gc2V0KCkKICAgICMgcmV0dXJuIGEgc2V0IG9mIHBhY2thZ2UgbmFtZXMgaW4gYW4gZXNtIGFyY2hpdmUKICAgIHRyeToKICAgICAgICByZXNwb25zZSA9IHVybG9wZW4odXJsKQogICAgZXhjZXB0IChVUkxFcnJvciwgSFRUUEVycm9yKToKICAgICAgICAjIHByaW50KCdmYWlsZWQgdG8gbG9hZDogJXMnICUgdXJsKQogICAgICAgIHJldHVybiBwa2dzCiAgICB0cnk6CiAgICAgICAgY29udGVudCA9IHJlc3BvbnNlLnJlYWQoKS5kZWNvZGUoJ3V0Zi04JykKICAgIGV4Y2VwdCBJT0Vycm9yOgogICAgICAgIHByaW50KCdmYWlsZWQgdG8gcmVhZCBkYXRhIGF0OiAlcycgJSB1cmwpCiAgICAgICAgc3lzLmV4aXQoMSkKICAgIGZvciBsaW5lIGluIGNvbnRlbnQuc3BsaXQoJ1xuJyk6CiAgICAgICAgaWYgbm90IGxpbmUuc3RhcnRzd2l0aCgnUGFja2FnZTonKToKICAgICAgICAgICAgY29udGludWUKICAgICAgICBlbHNlOgogICAgICAgICAgICBwa2cgPSBsaW5lLnNwbGl0KCc6ICcpWzFdCiAgICAgICAgICAgIHBrZ3MuYWRkKHBrZykKICAgIHJldHVybiBwa2dzCgoKZGVmIGxpdmVwYXRjaF9pc19lbmFibGVkKCk6CiAgICAiIiIgQ2hlY2sgdG8gc2VlIGlmIGxpdmVwYXRjaCBpcyBlbmFibGVkIG9uIHRoZSBzeXN0ZW0iIiIKICAgIHRyeToKICAgICAgICBjX2xpdmVwYXRjaCA9IHN1YnByb2Nlc3MucnVuKFsiL3NuYXAvYmluL2Nhbm9uaWNhbC1saXZlcGF0Y2giLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICJzdGF0dXMiXSwKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN0ZG91dD1zdWJwcm9jZXNzLlBJUEUsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzdGRlcnI9c3VicHJvY2Vzcy5QSVBFKQogICAgIyBpdCBjYW4ndCBiZSBlbmFibGVkIGlmIGl0IGlzbid0IGluc3RhbGxlZAogICAgZXhjZXB0IEZpbGVOb3RGb3VuZEVycm9yOgogICAgICAgIHJldHVybiBGYWxzZQogICAgaWYgY19saXZlcGF0Y2gucmV0dXJuY29kZSA9PSAwOgogICAgICAgIHJldHVybiBUcnVlCiAgICBlbGlmIGNfbGl2ZXBhdGNoLnJldHVybmNvZGUgPT0gMToKICAgICAgICByZXR1cm4gRmFsc2UKCgpkZWYgZXNtX2lzX2VuYWJsZWQoKToKICAgICIiIiBDaGVjayB0byBzZWUgaWYgZXNtIGlzIGFuIGF2YWlsYWJsZSBzb3VyY2UiIiIKCiAgICBhY3AgPSBzdWJwcm9jZXNzLlBvcGVuKFsiYXB0LWNhY2hlIiwgInBvbGljeSJdLAogICAgICAgICAgICAgICAgICAgICAgICAgICBzdGRvdXQ9c3VicHJvY2Vzcy5QSVBFLCBzdGRlcnI9c3VicHJvY2Vzcy5QSVBFKQogICAgZ3JlcCA9IHN1YnByb2Nlc3MucnVuKFsiZ3JlcCIsICItRiIsICItcSIsICJodHRwczovLyVzIiAlIGVzbV9zaXRlXSwKICAgICAgICAgICAgICAgICAgICAgICAgICBzdGRpbj1hY3Auc3Rkb3V0LCBzdGRvdXQ9c3VicHJvY2Vzcy5QSVBFKQogICAgaWYgZ3JlcC5yZXR1cm5jb2RlID09IDA6CiAgICAgICAgcmV0dXJuIFRydWUKICAgIGVsaWYgZ3JlcC5yZXR1cm5jb2RlID09IC0xOgogICAgICAgIHJldHVybiBGYWxzZQoKCmRlZiB0cmltX2FyY2hpdmUoYXJjaGl2ZSk6CiAgICByZXR1cm4gYXJjaGl2ZS5zcGxpdCgiLSIpWy0xXQoKCmRlZiB0cmltX3NpdGUoaG9zdCk6CiAgICAjICouZWMyLmFyY2hpdmUudWJ1bnR1LmNvbSAtPiBhcmNoaXZlLnVidW50dS5jb20KICAgIGlmIGhvc3QuZW5kc3dpdGgoImFyY2hpdmUudWJ1bnR1LmNvbSIpOgogICAgICAgIHJldHVybiAiYXJjaGl2ZS51YnVudHUuY29tIgogICAgcmV0dXJuIGhvc3QKCgpkZWYgbWlycm9yX2xpc3QoKToKICAgIG1fZmlsZSA9ICcvdXNyL3NoYXJlL3VidW50dS1yZWxlYXNlLXVwZ3JhZGVyL21pcnJvcnMuY2ZnJwogICAgaWYgbm90IG9zLnBhdGguZXhpc3RzKG1fZmlsZSk6CiAgICAgICAgcHJpbnQoIk9mZmljaWFsIG1pcnJvciBsaXN0IG5vdCBmb3VuZC4iKQogICAgd2l0aCBvcGVuKG1fZmlsZSkgYXMgZjoKICAgICAgICBpdGVtcyA9IFt4LnN0cmlwKCkgZm9yIHggaW4gZl0KICAgIG1pcnJvcnMgPSAgW3Muc3BsaXQoJy8vJylbMV0uc3BsaXQoJy8nKVswXSBmb3IgcyBpbiBpdGVtcwogICAgICAgICAgICAgICAgaWYgbm90IHMuc3RhcnRzd2l0aCgiIyIpIGFuZCBub3QgcyA9PSAiIl0KICAgICMgZGRlYnMudWJ1bnR1LmNvbSBpc24ndCBpbiBtaXJyb3JzLmNmZyBmb3IgZXZlcnkgcmVsZWFzZQogICAgbWlycm9ycy5hcHBlbmQoJ2RkZWJzLnVidW50dS5jb20nKQogICAgcmV0dXJuIG1pcnJvcnMKCgpkZWYgb3JpZ2luc19mb3IodmVyOiBhcHQucGFja2FnZS5WZXJzaW9uKSAtPiBzdHI6CiAgICBzID0gW10KICAgIGZvciBvcmlnaW4gaW4gdmVyLm9yaWdpbnM6CiAgICAgICAgaWYgbm90IG9yaWdpbi5zaXRlOgogICAgICAgICAgICAjIFdoZW4gdGhlIHBhY2thZ2UgaXMgaW5zdGFsbGVkLCBzaXRlIGlzIGVtcHR5LCBhcmNoaXZlL2NvbXBvbmVudAogICAgICAgICAgICAjIGFyZSAibm93L25vdyIKICAgICAgICAgICAgY29udGludWUKICAgICAgICBzaXRlID0gdHJpbV9zaXRlKG9yaWdpbi5zaXRlKQogICAgICAgIHMuYXBwZW5kKCIlcyAlcy8lcyIgJSAoc2l0ZSwgb3JpZ2luLmFyY2hpdmUsIG9yaWdpbi5jb21wb25lbnQpKQogICAgcmV0dXJuICIsIi5qb2luKHMpCgoKZGVmIHByaW50X3dyYXBwZWQoc3RyKToKICAgIHByaW50KCJcbiIuam9pbih3cmFwKHN0ciwgYnJlYWtfb25faHlwaGVucz1GYWxzZSkpKQoKCmRlZiBwcmludF90aGlyZHBhcnR5X2NvdW50KCk6CiAgICBwcmludChnZXR0ZXh0LmRuZ2V0dGV4dCgidXBkYXRlLW1hbmFnZXIiLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgIiVzIHBhY2thZ2UgaXMgZnJvbSBhIHRoaXJkIHBhcnR5IiwKICAgICAgICAgICAgICAgICAgICAgICAgICAgICIlcyBwYWNrYWdlcyBhcmUgZnJvbSB0aGlyZCBwYXJ0aWVzIiwKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGxlbihwa2dzdGF0cy5wa2dzX3RoaXJkcGFydHkpKSAlCiAgICAgICAgICAiezo+e3dpZHRofX0iLmZvcm1hdChsZW4ocGtnc3RhdHMucGtnc190aGlyZHBhcnR5KSwgd2lkdGg9d2lkdGgpKQoKCmRlZiBwcmludF91bmF2YWlsYWJsZV9jb3VudCgpOgogICAgcHJpbnQoZ2V0dGV4dC5kbmdldHRleHQoInVwZGF0ZS1tYW5hZ2VyIiwKICAgICAgICAgICAgICAgICAgICAgICAgICAgICIlcyBwYWNrYWdlIGlzIG5vIGxvbmdlciBhdmFpbGFibGUgZm9yICIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICJkb3dubG9hZCIsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAiJXMgcGFja2FnZXMgYXJlIG5vIGxvbmdlciBhdmFpbGFibGUgZm9yICIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICJkb3dubG9hZCIsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBsZW4ocGtnc3RhdHMucGtnc191bmF2YWlsYWJsZSkpICUKICAgICAgICAgICJ7Oj57d2lkdGh9fSIuZm9ybWF0KGxlbihwa2dzdGF0cy5wa2dzX3VuYXZhaWxhYmxlKSwgd2lkdGg9d2lkdGgpKQoKCmRlZiBwYXJzZV9vcHRpb25zKCk6CiAgICAnJydQYXJzZSBjb21tYW5kIGxpbmUgYXJndW1lbnRzLgogICAgUmV0dXJuIHBhcnNlcgogICAgJycnCiAgICBwYXJzZXIgPSBhcmdwYXJzZS5Bcmd1bWVudFBhcnNlcigKICAgICAgICBkZXNjcmlwdGlvbj0nUmV0dXJuIGluZm9ybWF0aW9uIGFib3V0IHNlY3VyaXR5IHN1cHBvcnQgZm9yIHBhY2thZ2VzJykKICAgIHBhcnNlci5hZGRfYXJndW1lbnQoJy0tdGhpcmRwYXJ0eScsIGFjdGlvbj0nc3RvcmVfdHJ1ZScpCiAgICBwYXJzZXIuYWRkX2FyZ3VtZW50KCctLXVuYXZhaWxhYmxlJywgYWN0aW9uPSdzdG9yZV90cnVlJykKICAgIHJldHVybiBwYXJzZXIKCgppZiBfX25hbWVfXyA9PSAiX19tYWluX18iOgogICAgIyBnZXR0ZXh0CiAgICBBUFAgPSAidXBkYXRlLW1hbmFnZXIiCiAgICBESVIgPSAiL3Vzci9zaGFyZS9sb2NhbGUiCiAgICBnZXR0ZXh0LmJpbmR0ZXh0ZG9tYWluKEFQUCwgRElSKQogICAgZ2V0dGV4dC50ZXh0ZG9tYWluKEFQUCkKCiAgICBwYXJzZXIgPSBwYXJzZV9vcHRpb25zKCkKICAgIGFyZ3MgPSBwYXJzZXIucGFyc2VfYXJncygpCgogICAgZXNtX3NpdGUgPSAiZXNtLnVidW50dS5jb20iCgogICAgdHJ5OgogICAgICAgIGRwa2cgPSBzdWJwcm9jZXNzLmNoZWNrX291dHB1dChbJ2Rwa2cnLCAnLS1wcmludC1hcmNoaXRlY3R1cmUnXSkKICAgICAgICBhcmNoID0gZHBrZy5kZWNvZGUoKS5zdHJpcCgpCiAgICBleGNlcHQgc3VicHJvY2Vzcy5DYWxsZWRQcm9jZXNzRXJyb3I6CiAgICAgICAgcHJpbnQoImZhaWxlZCBnZXR0aW5nIGRwa2cgYXJjaGl0ZWN0dXJlIikKICAgICAgICBzeXMuZXhpdCgxKQoKICAgIHRyeToKICAgICAgICBsc2IgPSBzdWJwcm9jZXNzLmNoZWNrX291dHB1dChbJ2xzYl9yZWxlYXNlJywgJy1jJywgJy1zJ10sCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdW5pdmVyc2FsX25ld2xpbmVzPVRydWUpCiAgICAgICAgY29kZW5hbWUgPSBsc2Iuc3RyaXAoKQogICAgZXhjZXB0IHN1YnByb2Nlc3MuQ2FsbGVkUHJvY2Vzc0Vycm9yOgogICAgICAgIHByaW50KCJmYWlsZWQgZ2V0dGluZyByZWxlYXNlIGNvZGVuYW1lIikKICAgICAgICBzeXMuZXhpdCgxKQoKICAgIGNhY2hlID0gYXB0LkNhY2hlKCkKICAgIHBrZ3N0YXRzID0gUGF0Y2hTdGF0cygpCiAgICBkaSA9IGRpc3Ryb19pbmZvLlVidW50dURpc3Ryb0luZm8oKQogICAgbHRzID0gZGkuaXNfbHRzKGNvZGVuYW1lKQogICAgcmVsZWFzZV9leHBpcmVkID0gVHJ1ZQogICAgaWYgY29kZW5hbWUgaW4gZGkuc3VwcG9ydGVkKCk6CiAgICAgICAgcmVsZWFzZV9leHBpcmVkID0gRmFsc2UKICAgICMgZGlzdHJvLWluZm8tZGF0YSBpbiBVYnVudHUgMTYuMDQgTFRTIGRvZXMgbm90IGhhdmUgZW9sLWVzbSBkYXRhCiAgICBpZiBjb2RlbmFtZSAhPSAneGVuaWFsJzoKICAgICAgICBlb2xfZGF0YSA9IFsoci5lb2wsIHIuZW9sX2VzbSkKICAgICAgICAgICAgICAgICAgICBmb3IgciBpbiBkaS5fcmVsZWFzZXMgaWYgci5zZXJpZXMgPT0gY29kZW5hbWVdWzBdCiAgICBlbGlmIGNvZGVuYW1lID09ICd4ZW5pYWwnOgogICAgICAgIGVvbF9kYXRhID0gKGRhdGV0aW1lLnN0cnB0aW1lKCcyMDIxLTA0LTIxJywgJyVZLSVtLSVkJyksCiAgICAgICAgICAgICAgICAgICAgZGF0ZXRpbWUuc3RycHRpbWUoJzIwMjQtMDQtMjEnLCAnJVktJW0tJWQnKSkKICAgIGVvbCA9IGVvbF9kYXRhWzBdCiAgICBlb2xfZXNtID0gZW9sX2RhdGFbMV0KCiAgICBhbGxfb3JpZ2lucyA9IHNldCgpCiAgICBvcmlnaW5zX2J5X3BhY2thZ2UgPSB7fQogICAgb2ZmaWNpYWxfbWlycm9ycyA9IG1pcnJvcl9saXN0KCkKCiAgICAjIE4uQi4gb25seSB0aGUgc2VjdXJpdHkgcG9ja2V0IGlzIGNoZWNrZWQgYmVjYXVzZSB0aGlzIHRvb2wgZGlzcGxheXMKICAgICMgaW5mb3JtYXRpb24gYWJvdXQgc2VjdXJpdHkgdXBkYXRlcwogICAgZXNtX3VybCA9IFwKICAgICAgICAnaHR0cHM6Ly8lcy8lcy91YnVudHUvZGlzdHMvJXMtJXMtJXMvbWFpbi9iaW5hcnktJXMvUGFja2FnZXMnCiAgICBwa2dzX2luX2VzbWEgPSB3aGF0c19pbl9lc20oZXNtX3VybCAlCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgKGVzbV9zaXRlLCAnYXBwcycsIGNvZGVuYW1lLCAnYXBwcycsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICdzZWN1cml0eScsIGFyY2gpKQogICAgcGtnc19pbl9lc21pID0gd2hhdHNfaW5fZXNtKGVzbV91cmwgJQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIChlc21fc2l0ZSwgJ2luZnJhJywgY29kZW5hbWUsICdpbmZyYScsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICdzZWN1cml0eScsIGFyY2gpKQoKICAgIGZvciBwa2cgaW4gY2FjaGU6CiAgICAgICAgcGtnbmFtZSA9IHBrZy5uYW1lCgogICAgICAgIGRvd25sb2FkYWJsZSA9IFRydWUKICAgICAgICBpZiBub3QgcGtnLmlzX2luc3RhbGxlZDoKICAgICAgICAgICAgY29udGludWUKICAgICAgICBpZiBub3QgcGtnLmNhbmRpZGF0ZSBvciBub3QgcGtnLmNhbmRpZGF0ZS5kb3dubG9hZGFibGU6CiAgICAgICAgICAgIGRvd25sb2FkYWJsZSA9IEZhbHNlCiAgICAgICAgcGtnX3NpdGVzID0gW10KICAgICAgICBvcmlnaW5zX2J5X3BhY2thZ2VbcGtnbmFtZV0gPSBzZXQoKQoKICAgICAgICBmb3IgdmVyIGluIHBrZy52ZXJzaW9uczoKICAgICAgICAgICAgIyBMb29wIHRocm91Z2ggb3JpZ2lucyBhbmQgc3RvcmUgYWxsIG9mIHRoZW0uIFRoZSBpZGVhIGhlcmUgaXMgdGhhdAogICAgICAgICAgICAjIHdlIGRvbid0IGNhcmUgd2hlcmUgdGhlIGluc3RhbGxlZCBwYWNrYWdlIGNvbWVzIGZyb20sIHByb3ZpZGVkCiAgICAgICAgICAgICMgdGhlcmUgaXMgYXQgbGVhc3Qgb25lIHJlcG9zaXRvcnkgd2UgaWRlbnRpZnkgYXMgYmVpbmcKICAgICAgICAgICAgIyBzZWN1cml0eS1hc3N1cmVkIHVuZGVyIGVpdGhlciBMVFMgb3IgRVNNLgogICAgICAgICAgICBmb3Igb3JpZ2luIGluIHZlci5vcmlnaW5zOgogICAgICAgICAgICAgICAgIyBUT0RPOiBpbiBvcmRlciB0byBoYW5kbGUgRklQUyBhbmQgb3RoZXIgYXJjaGl2ZXMgd2hpY2ggaGF2ZQogICAgICAgICAgICAgICAgIyByb290LWxldmVsIHBhdGggbmFtZXMsIHdlJ2xsIG5lZWQgdG8gbG9vcCBvdmVyIHZlci51cmlzCiAgICAgICAgICAgICAgICAjIGluc3RlYWQKICAgICAgICAgICAgICAgIGlmIG5vdCBvcmlnaW4uc2l0ZToKICAgICAgICAgICAgICAgICAgICBjb250aW51ZQogICAgICAgICAgICAgICAgc2l0ZSA9IHRyaW1fc2l0ZShvcmlnaW4uc2l0ZSkKICAgICAgICAgICAgICAgIGFyY2hpdmUgPSBvcmlnaW4uYXJjaGl2ZQogICAgICAgICAgICAgICAgY29tcG9uZW50ID0gb3JpZ2luLmNvbXBvbmVudAogICAgICAgICAgICAgICAgIyBvcmlnaW4gdGVzdAogICAgICAgICAgICAgICAgb3JpZ2luID0gb3JpZ2luLm9yaWdpbgogICAgICAgICAgICAgICAgb2ZmaWNpYWxfbWlycm9yID0gRmFsc2UKICAgICAgICAgICAgICAgIHRoaXJkcGFydHkgPSBUcnVlCiAgICAgICAgICAgICAgICAjIHRoaXJkcGFydHkgcHJvdmlkZXJzIGxpa2UgZGwuZ29vZ2xlLmNvbSBkb24ndCBzZXQgIk9yaWdpbiIKICAgICAgICAgICAgICAgIGlmIG9yaWdpbiAhPSAiVWJ1bnR1IjoKICAgICAgICAgICAgICAgICAgICB0aGlyZHBhcnR5ID0gRmFsc2UKICAgICAgICAgICAgICAgIGlmIHNpdGUgaW4gb2ZmaWNpYWxfbWlycm9yczoKICAgICAgICAgICAgICAgICAgICBzaXRlID0gIm9mZmljaWFsX21pcnJvciIKICAgICAgICAgICAgICAgIGlmICJNWV9NSVJST1IiIGluIG9zLmVudmlyb246CiAgICAgICAgICAgICAgICAgICAgaWYgc2l0ZSBpbiBvcy5lbnZpcm9uWyJNWV9NSVJST1IiXToKICAgICAgICAgICAgICAgICAgICAgICAgc2l0ZSA9ICJvZmZpY2lhbF9taXJyb3IiCiAgICAgICAgICAgICAgICB0ID0gKHNpdGUsIGFyY2hpdmUsIGNvbXBvbmVudCwgdGhpcmRwYXJ0eSkKICAgICAgICAgICAgICAgIGlmIG5vdCBzaXRlOgogICAgICAgICAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgICAgICAgICBhbGxfb3JpZ2lucy5hZGQodCkKICAgICAgICAgICAgICAgIG9yaWdpbnNfYnlfcGFja2FnZVtwa2duYW1lXS5hZGQodCkKCiAgICAgICAgICAgIGlmIERFQlVHOgogICAgICAgICAgICAgICAgcGtnX3NpdGVzLmFwcGVuZCgiJXMgJXMvJXMiICUKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgKHNpdGUsIGFyY2hpdmUsIGNvbXBvbmVudCkpCgogICAgICAgIHByaW50X2RlYnVnKCJhdmFpbGFibGUgdmVyc2lvbnMgZm9yICVzIiAlIHBrZ25hbWUpCiAgICAgICAgcHJpbnRfZGVidWcoIiwiLmpvaW4ocGtnX3NpdGVzKSkKCiAgICAjIFRoaXMgdHJhY2tzIHN1aXRlcyB3ZSBjYXJlIGFib3V0LiBTYWRseSwgaXQgYXBwZWFycyB0aGF0IHRoZSB3YXkgYXB0CiAgICAjIHN0b3JlcyBvcmlnaW5zIHRydW5jYXRlcyBhd2F5IHRoZSBwYXRoIHRoYXQgY29tZXMgYWZ0ZXIgdGhlCiAgICAjIGRvbWFpbm5hbWUgaW4gdGhlIHNpdGUgcG9ydGlvbiwgb3IgbWF5YmUgSSBhbSBqdXN0IGNsdWVsZXNzLCBidXQKICAgICMgdGhlcmUncyBubyB3YXkgdG8gdGVsbCBGSVBTIGFwYXJ0IGZyb20gRVNNLCBmb3IgaW5zdGFuY2UuCiAgICAjIFNlZSAwMFJFUE9TLnR4dCBmb3IgZXhhbXBsZXMKCiAgICAjIDIwMjAtMDMtMTggdmVyLmZpbGVuYW1lIGhhcyB0aGUgcGF0aCBzbyB3aHkgaXMgdGhhdCBubyBnb29kPwoKICAgICMgVE9ETyBOZWVkIHRvIGhhbmRsZToKICAgICMgICBNQUFTLCBseGQsIGp1anUgUFBBcwogICAgIyAgIG90aGVyIFBQQXMKICAgICMgICBvdGhlciByZXBvcwoKICAgICMgVE9ETyBoYW5kbGUgcGFydG5lci5jLmMKCiAgICAjIG1haW4gYW5kIHJlc3RyaWN0ZWQgZnJvbSByZWxlYXNlLCAtdXBkYXRlcywgLXByb3Bvc2VkLCBvciAtc2VjdXJpdHkKICAgICMgcG9ja2V0cwogICAgc3VpdGVfbWFpbiA9ICgib2ZmaWNpYWxfbWlycm9yIiwgY29kZW5hbWUsICJtYWluIiwgVHJ1ZSkKICAgIHN1aXRlX21haW5fdXBkYXRlcyA9ICgib2ZmaWNpYWxfbWlycm9yIiwgY29kZW5hbWUgKyAiLXVwZGF0ZXMiLAogICAgICAgICAgICAgICAgICAgICAgICAgICJtYWluIiwgVHJ1ZSkKICAgIHN1aXRlX21haW5fc2VjdXJpdHkgPSAoIm9mZmljaWFsX21pcnJvciIsIGNvZGVuYW1lICsgIi1zZWN1cml0eSIsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICJtYWluIiwgVHJ1ZSkKICAgIHN1aXRlX21haW5fcHJvcG9zZWQgPSAoIm9mZmljaWFsX21pcnJvciIsIGNvZGVuYW1lICsgIi1wcm9wb3NlZCIsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICJtYWluIiwgVHJ1ZSkKCiAgICBzdWl0ZV9yZXN0cmljdGVkID0gKCJvZmZpY2lhbF9taXJyb3IiLCBjb2RlbmFtZSwgInJlc3RyaWN0ZWQiLAogICAgICAgICAgICAgICAgICAgICAgICBUcnVlKQogICAgc3VpdGVfcmVzdHJpY3RlZF91cGRhdGVzID0gKCJvZmZpY2lhbF9taXJyb3IiLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvZGVuYW1lICsgIi11cGRhdGVzIiwKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAicmVzdHJpY3RlZCIsIFRydWUpCiAgICBzdWl0ZV9yZXN0cmljdGVkX3NlY3VyaXR5ID0gKCJvZmZpY2lhbF9taXJyb3IiLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb2RlbmFtZSArICItc2VjdXJpdHkiLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAicmVzdHJpY3RlZCIsIFRydWUpCiAgICBzdWl0ZV9yZXN0cmljdGVkX3Byb3Bvc2VkID0gKCJvZmZpY2lhbF9taXJyb3IiLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb2RlbmFtZSArICItcHJvcG9zZWQiLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAicmVzdHJpY3RlZCIsIFRydWUpCgogICAgIyB1bml2ZXJzZSBhbmQgbXVsdGl2ZXJzZSBmcm9tIHJlbGVhc2UsIC11cGRhdGVzLCAtcHJvcG9zZWQsIG9yIC1zZWN1cml0eQogICAgIyBwb2NrZXRzCiAgICBzdWl0ZV91bml2ZXJzZSA9ICgib2ZmaWNpYWxfbWlycm9yIiwgY29kZW5hbWUsICJ1bml2ZXJzZSIsIFRydWUpCiAgICBzdWl0ZV91bml2ZXJzZV91cGRhdGVzID0gKCJvZmZpY2lhbF9taXJyb3IiLCBjb2RlbmFtZSArICItdXBkYXRlcyIsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICJ1bml2ZXJzZSIsIFRydWUpCiAgICBzdWl0ZV91bml2ZXJzZV9zZWN1cml0eSA9ICgib2ZmaWNpYWxfbWlycm9yIiwKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvZGVuYW1lICsgIi1zZWN1cml0eSIsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAidW5pdmVyc2UiLCBUcnVlKQogICAgc3VpdGVfdW5pdmVyc2VfcHJvcG9zZWQgPSAoIm9mZmljaWFsX21pcnJvciIsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb2RlbmFtZSArICItcHJvcG9zZWQiLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgInVuaXZlcnNlIiwgVHJ1ZSkKCiAgICBzdWl0ZV9tdWx0aXZlcnNlID0gKCJvZmZpY2lhbF9taXJyb3IiLCBjb2RlbmFtZSwgIm11bHRpdmVyc2UiLAogICAgICAgICAgICAgICAgICAgICAgICBUcnVlKQogICAgc3VpdGVfbXVsdGl2ZXJzZV91cGRhdGVzID0gKCJvZmZpY2lhbF9taXJyb3IiLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvZGVuYW1lICsgIi11cGRhdGVzIiwKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAibXVsdGl2ZXJzZSIsIFRydWUpCiAgICBzdWl0ZV9tdWx0aXZlcnNlX3NlY3VyaXR5ID0gKCJvZmZpY2lhbF9taXJyb3IiLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb2RlbmFtZSArICItc2VjdXJpdHkiLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAibXVsdGl2ZXJzZSIsIFRydWUpCiAgICBzdWl0ZV9tdWx0aXZlcnNlX3Byb3Bvc2VkID0gKCJvZmZpY2lhbF9taXJyb3IiLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb2RlbmFtZSArICItcHJvcG9zZWQiLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAibXVsdGl2ZXJzZSIsIFRydWUpCgogICAgIyBwYWNrYWdlcyBmcm9tIHRoZSBlc20gcmVzcG9zaXRvcmllcwogICAgIyBJcyB0aGUgT3JpZ2luOiBVYnVudHUgaGVyZT8gTm9wZSBidXQgaXQgZG9lc24ndCBtYXR0ZXIhCiAgICBzdWl0ZV9lc21fbWFpbiA9IChlc21fc2l0ZSwgIiVzLWluZnJhLXVwZGF0ZXMiICUgY29kZW5hbWUsCiAgICAgICAgICAgICAgICAgICAgICAibWFpbiIpCiAgICBzdWl0ZV9lc21fbWFpbl9zZWN1cml0eSA9IChlc21fc2l0ZSwKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICIlcy1pbmZyYS1zZWN1cml0eSIgJSBjb2RlbmFtZSwgIm1haW4iKQogICAgc3VpdGVfZXNtX3VuaXZlcnNlID0gKGVzbV9zaXRlLAogICAgICAgICAgICAgICAgICAgICAgICAgICIlcy1hcHBzLXVwZGF0ZXMiICUgY29kZW5hbWUsICJtYWluIikKICAgIHN1aXRlX2VzbV91bml2ZXJzZV9zZWN1cml0eSA9IChlc21fc2l0ZSwKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAiJXMtYXBwcy1zZWN1cml0eSIgJSBjb2RlbmFtZSwKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAibWFpbiIpCgogICAgbGl2ZXBhdGNoX2VuYWJsZWQgPSBsaXZlcGF0Y2hfaXNfZW5hYmxlZCgpCiAgICBlc21fZW5hYmxlZCA9IGVzbV9pc19lbmFibGVkKCkKICAgIGlzX2VzbV9pbmZyYV91c2VkID0gKHN1aXRlX2VzbV9tYWluIGluIGFsbF9vcmlnaW5zKSBvciBcCiAgICAgICAgICAgICAgICAgICAgICAgIChzdWl0ZV9lc21fbWFpbl9zZWN1cml0eSBpbiBhbGxfb3JpZ2lucykKICAgIGlzX2VzbV9hcHBzX3VzZWQgPSAoc3VpdGVfZXNtX3VuaXZlcnNlIGluIGFsbF9vcmlnaW5zKSBvciBcCiAgICAgICAgICAgICAgICAgICAgICAgKHN1aXRlX2VzbV91bml2ZXJzZV9zZWN1cml0eSBpbiBhbGxfb3JpZ2lucykKCiAgICAjIE5vdyBkbyB0aGUgZmluYWwgbG9vcCB0aHJvdWdoCiAgICBmb3IgcGtnIGluIGNhY2hlOgogICAgICAgIGlmIG5vdCBwa2cuaXNfaW5zdGFsbGVkOgogICAgICAgICAgICBjb250aW51ZQogICAgICAgIGlmIG5vdCBwa2cuY2FuZGlkYXRlIG9yIG5vdCBwa2cuY2FuZGlkYXRlLmRvd25sb2FkYWJsZToKICAgICAgICAgICAgcGtnc3RhdHMucGtnc191bmF2YWlsYWJsZS5hZGQocGtnLm5hbWUpCiAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgcGtnbmFtZSA9IHBrZy5uYW1lCiAgICAgICAgcGtnX29yaWdpbnMgPSBvcmlnaW5zX2J5X3BhY2thZ2VbcGtnbmFtZV0KCiAgICAgICAgIyBUaGlzIHNldCBvZiBpc18qIGJvb2xlYW5zIHRyYWNrcyBzcGVjaWZpYyBzaXR1YXRpb25zIHdlIGNhcmUgYWJvdXQgaW4KICAgICAgICAjIHRoZSBsb2dpYyBiZWxvdzsgZm9yIGluc3RhbmNlLCBpZiB0aGUgcGFja2FnZSBoYXMgYSBtYWluIG9yaWdpbiwgb3IKICAgICAgICAjIGlmIHRoZSBlc20gcmVwb3MgYXJlIGVuYWJsZWQuCgogICAgICAgICMgU29tZSBwYWNrYWdlcyBnZXQgYWRkZWQgaW4gLXVwZGF0ZXMgYW5kIGRvbid0IGV4aXN0IGluIHRoZSByZWxlYXNlCiAgICAgICAgIyBwb2NrZXQgZS5nLiB1YnVudHUtYWR2YW50YWdlLXRvb2xzIGFuZCBsaWJkcm0tdXBkYXRlcy4gVG8gYmUgc2FmZSBhbGwKICAgICAgICAjIHBvY2tldHMgYXJlIGFsbG93ZWQuCiAgICAgICAgaXNfbXJfcGtnX29yaWdpbiA9IChzdWl0ZV9tYWluIGluIHBrZ19vcmlnaW5zKSBvciBcCiAgICAgICAgICAgICAgICAgICAgICAgICAgIChzdWl0ZV9tYWluX3VwZGF0ZXMgaW4gcGtnX29yaWdpbnMpIG9yIFwKICAgICAgICAgICAgICAgICAgICAgICAgICAgKHN1aXRlX21haW5fc2VjdXJpdHkgaW4gcGtnX29yaWdpbnMpIG9yIFwKICAgICAgICAgICAgICAgICAgICAgICAgICAgKHN1aXRlX21haW5fcHJvcG9zZWQgaW4gcGtnX29yaWdpbnMpIG9yIFwKICAgICAgICAgICAgICAgICAgICAgICAgICAgKHN1aXRlX3Jlc3RyaWN0ZWQgaW4gcGtnX29yaWdpbnMpIG9yIFwKICAgICAgICAgICAgICAgICAgICAgICAgICAgKHN1aXRlX3Jlc3RyaWN0ZWRfdXBkYXRlcyBpbiBwa2dfb3JpZ2lucykgb3IgXAogICAgICAgICAgICAgICAgICAgICAgICAgICAoc3VpdGVfcmVzdHJpY3RlZF9zZWN1cml0eSBpbiBwa2dfb3JpZ2lucykgb3IgXAogICAgICAgICAgICAgICAgICAgICAgICAgICAoc3VpdGVfcmVzdHJpY3RlZF9wcm9wb3NlZCBpbiBwa2dfb3JpZ2lucykKICAgICAgICBpc191bV9wa2dfb3JpZ2luID0gKHN1aXRlX3VuaXZlcnNlIGluIHBrZ19vcmlnaW5zKSBvciBcCiAgICAgICAgICAgICAgICAgICAgICAgICAgIChzdWl0ZV91bml2ZXJzZV91cGRhdGVzIGluIHBrZ19vcmlnaW5zKSBvciBcCiAgICAgICAgICAgICAgICAgICAgICAgICAgIChzdWl0ZV91bml2ZXJzZV9zZWN1cml0eSBpbiBwa2dfb3JpZ2lucykgb3IgXAogICAgICAgICAgICAgICAgICAgICAgICAgICAoc3VpdGVfdW5pdmVyc2VfcHJvcG9zZWQgaW4gcGtnX29yaWdpbnMpIG9yIFwKICAgICAgICAgICAgICAgICAgICAgICAgICAgKHN1aXRlX211bHRpdmVyc2UgaW4gcGtnX29yaWdpbnMpIG9yIFwKICAgICAgICAgICAgICAgICAgICAgICAgICAgKHN1aXRlX211bHRpdmVyc2VfdXBkYXRlcyBpbiBwa2dfb3JpZ2lucykgb3IgXAogICAgICAgICAgICAgICAgICAgICAgICAgICAoc3VpdGVfbXVsdGl2ZXJzZV9zZWN1cml0eSBpbiBwa2dfb3JpZ2lucykgb3IgXAogICAgICAgICAgICAgICAgICAgICAgICAgICAoc3VpdGVfbXVsdGl2ZXJzZV9wcm9wb3NlZCBpbiBwa2dfb3JpZ2lucykKCiAgICAgICAgaXNfZXNtX2luZnJhX3BrZ19vcmlnaW4gPSAoc3VpdGVfZXNtX21haW4gaW4gcGtnX29yaWdpbnMpIG9yIFwKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIChzdWl0ZV9lc21fbWFpbl9zZWN1cml0eSBpbiBwa2dfb3JpZ2lucykKICAgICAgICBpc19lc21fYXBwc19wa2dfb3JpZ2luID0gKHN1aXRlX2VzbV91bml2ZXJzZSBpbiBwa2dfb3JpZ2lucykgb3IgXAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAoc3VpdGVfZXNtX3VuaXZlcnNlX3NlY3VyaXR5IGluIHBrZ19vcmlnaW5zKQoKICAgICAgICAjIEEgdGhpcmQgcGFydHkgb25lIHdvbid0IGFwcGVhciBpbiBhbnkgb2YgdGhlIGFib3ZlIG9yaWdpbnMKICAgICAgICBpZiBub3QgaXNfbXJfcGtnX29yaWdpbiBhbmQgbm90IGlzX3VtX3BrZ19vcmlnaW4gXAogICAgICAgICAgICAgICAgYW5kIG5vdCBpc19lc21faW5mcmFfcGtnX29yaWdpbiBhbmQgbm90IGlzX2VzbV9hcHBzX3BrZ19vcmlnaW46CiAgICAgICAgICAgIHBrZ3N0YXRzLnBrZ3NfdGhpcmRwYXJ0eS5hZGQocGtnbmFtZSkKCiAgICAgICAgIyBQcmVwYXJlIHRvIGdvIGNyb3NzLWV5ZWQuIFRoaXMgc2VjdGlvbiBiYXNpY2FsbHkgaG9sZHMgYWxsIHRoZQogICAgICAgICMgY29tcGxleCBsb2dpYyBpbiBkZWNpZGluZyB3aGljaCBidWNrZXRzIGEgcGFja2FnZSBoYXMgdG8gZ28gaW50by4KICAgICAgICAjIFRoZXJlIGlzIGEgbG90IG9mIGNvbXBsZXhpdHkgdGhhdCBlbWVyZ2VzIGZyb20gdGhlIHNpbXBsZSB2YXJpYXRpb25zCiAgICAgICAgIyBpbiBhcmNoaXZlIGFuZCBzdWl0ZSBuYW1pbmcgY29udmVudGlvbnM7IEkndmUgdHJpZWQgdG8gbWFrZSBpdCBhcwogICAgICAgICMgbGVnaWJsZSBhcyBJIGNhbiB3aGlsZSBqZXQtbGFnZ2VkIGJ1dCBpdCdzIHN0aWxsIGhhcmQuIC0tIGtpa28KCiAgICAgICAgaWYgRmFsc2U6ICAjIFRPRE8gcGFja2FnZSBoYXMgRVNNIGZpcHMgb3JpZ2luCiAgICAgICAgICAgICMgVE9ETyBwYWNrYWdlIGhhcyBFU00gZmlwcy11cGRhdGVzIG9yaWdpbjogT0sKICAgICAgICAgICAgIyBJZiB1c2VyIGhhcyBlbmFibGVkIEZJUFMsIGJ1dCBub3QgdXBkYXRlcywgQkFELCBidXQgbmVlZCBzb21lCiAgICAgICAgICAgICMgdGhvdWdodCBvbiBob3cgdG8gZGlzcGxheSBpdCwgYXMgaXQgY2FuJ3QgYmUgcGF0Y2hlZCBhdCBhbGwKICAgICAgICAgICAgcGFzcwogICAgICAgIGVsaWYgaXNfbXJfcGtnX29yaWdpbjoKICAgICAgICAgICAgcGtnc3RhdHMucGtnc19tci5hZGQocGtnbmFtZSkKICAgICAgICBlbGlmIGlzX3VtX3BrZ19vcmlnaW46CiAgICAgICAgICAgIHBrZ3N0YXRzLnBrZ3NfdW0uYWRkKHBrZ25hbWUpCiAgICAgICAgZWxzZToKICAgICAgICAgICAgIyBUT0RPIHByaW50IGluZm9ybWF0aW9uIGFib3V0IHBhY2thZ2VzIGluIHRoaXMgY2F0ZWdvcnkgaWYgaW4KICAgICAgICAgICAgIyBkZWJ1Z2dpbmcgbW9kZQogICAgICAgICAgICBwa2dzdGF0cy5wa2dzX3VuY2F0ZWdvcml6ZWQuYWRkKHBrZ25hbWUpCgogICAgICAgICMgQ2hlY2sgdG8gc2VlIGlmIHRoZSBwYWNrYWdlIGlzIGF2YWlsYWJsZSBpbiBlc20taW5mcmEgb3IgZXNtLWFwcHMKICAgICAgICAjIGFuZCBhZGQgaXQgdG8gdGhlIHJpZ2h0IHBrZ3N0YXRzIGNhdGVnb3J5CiAgICAgICAgIyBOQjogYXBwcyBpcyBmaXJzdCBmb3IgdGVzdGluZyB0aGUgaGVsbG8gcGFja2FnZSB3aGljaCBpcyBib3RoIGluIGVzbWkKICAgICAgICAjIGFuZCBlc21hCiAgICAgICAgaWYgcGtnbmFtZSBpbiBwa2dzX2luX2VzbWE6CiAgICAgICAgICAgIHBrZ3N0YXRzLnBrZ3NfdXBkYXRlZF9pbl9lc21hLmFkZChwa2duYW1lKQogICAgICAgIGVsaWYgcGtnbmFtZSBpbiBwa2dzX2luX2VzbWk6CiAgICAgICAgICAgIHBrZ3N0YXRzLnBrZ3NfdXBkYXRlZF9pbl9lc21pLmFkZChwa2duYW1lKQoKICAgIHRvdGFsX3BhY2thZ2VzID0gKGxlbihwa2dzdGF0cy5wa2dzX21yKSArCiAgICAgICAgICAgICAgICAgICAgICBsZW4ocGtnc3RhdHMucGtnc191bSkgKwogICAgICAgICAgICAgICAgICAgICAgbGVuKHBrZ3N0YXRzLnBrZ3NfdGhpcmRwYXJ0eSkgKwogICAgICAgICAgICAgICAgICAgICAgbGVuKHBrZ3N0YXRzLnBrZ3NfdW5hdmFpbGFibGUpKQogICAgd2lkdGggPSBsZW4oc3RyKHRvdGFsX3BhY2thZ2VzKSkKICAgIHByaW50KCIlcyBwYWNrYWdlcyBpbnN0YWxsZWQsIG9mIHdoaWNoOiIgJQogICAgICAgICAgIns6Pnt3aWR0aH19Ii5mb3JtYXQodG90YWxfcGFja2FnZXMsIHdpZHRoPXdpZHRoKSkKCiAgICAjIGZpbHRlcnMgZmlyc3QgYXMgdGhleSBwcm92aWRlIGxlc3MgaW5mb3JtYXRpb24KICAgIGlmIGFyZ3MudGhpcmRwYXJ0eToKICAgICAgICBpZiBwa2dzdGF0cy5wa2dzX3RoaXJkcGFydHk6CiAgICAgICAgICAgIHBrZ3NfdGhpcmRwYXJ0eSA9IHNvcnRlZChwIGZvciBwIGluIHBrZ3N0YXRzLnBrZ3NfdGhpcmRwYXJ0eSkKICAgICAgICAgICAgcHJpbnRfdGhpcmRwYXJ0eV9jb3VudCgpCiAgICAgICAgICAgIHByaW50X3dyYXBwZWQoJyAnLmpvaW4ocGtnc190aGlyZHBhcnR5KSkKICAgICAgICAgICAgbXNnID0gKCJQYWNrYWdlcyBmcm9tIHRoaXJkIHBhcnRpZXMgYXJlIG5vdCBwcm92aWRlZCBieSB0aGUgIgogICAgICAgICAgICAgICAgICAgIm9mZmljaWFsIFVidW50dSBhcmNoaXZlLCBmb3IgZXhhbXBsZSBwYWNrYWdlcyBmcm9tICIKICAgICAgICAgICAgICAgICAgICJQZXJzb25hbCBQYWNrYWdlIEFyY2hpdmVzIGluIExhdW5jaHBhZC4iKQogICAgICAgICAgICBwcmludCgiIikKICAgICAgICAgICAgcHJpbnRfd3JhcHBlZChtc2cpCiAgICAgICAgICAgIHByaW50KCIiKQogICAgICAgICAgICBwcmludF93cmFwcGVkKCJSdW4gJ2FwdC1jYWNoZSBwb2xpY3kgJXMnIHRvIGxlYXJuIG1vcmUgYWJvdXQgIgogICAgICAgICAgICAgICAgICAgICAgICAgICJ0aGF0IHBhY2thZ2UuIiAlIHBrZ3NfdGhpcmRwYXJ0eVswXSkKICAgICAgICAgICAgc3lzLmV4aXQoMCkKICAgICAgICBlbHNlOgogICAgICAgICAgICBwcmludF93cmFwcGVkKCJZb3UgaGF2ZSBubyBwYWNrYWdlcyBpbnN0YWxsZWQgZnJvbSBhIHRoaXJkIHBhcnR5LiIpCiAgICAgICAgICAgIHN5cy5leGl0KDApCiAgICBpZiBhcmdzLnVuYXZhaWxhYmxlOgogICAgICAgIGlmIHBrZ3N0YXRzLnBrZ3NfdW5hdmFpbGFibGU6CiAgICAgICAgICAgIHBrZ3NfdW5hdmFpbGFibGUgPSBzb3J0ZWQocCBmb3IgcCBpbiBwa2dzdGF0cy5wa2dzX3VuYXZhaWxhYmxlKQogICAgICAgICAgICBwcmludF91bmF2YWlsYWJsZV9jb3VudCgpCiAgICAgICAgICAgIHByaW50X3dyYXBwZWQoJyAnLmpvaW4ocGtnc191bmF2YWlsYWJsZSkpCiAgICAgICAgICAgIG1zZyA9ICgiUGFja2FnZXMgdGhhdCBhcmUgbm90IGF2YWlsYWJsZSBmb3IgZG93bmxvYWQgIgogICAgICAgICAgICAgICAgICAgIm1heSBiZSBsZWZ0IG92ZXIgZnJvbSBhIHByZXZpb3VzIHJlbGVhc2Ugb2YgIgogICAgICAgICAgICAgICAgICAgIlVidW50dSwgbWF5IGhhdmUgYmVlbiBpbnN0YWxsZWQgZGlyZWN0bHkgZnJvbSAiCiAgICAgICAgICAgICAgICAgICAiYSAuZGViIGZpbGUsIG9yIGFyZSBmcm9tIGEgc291cmNlIHdoaWNoIGhhcyAiCiAgICAgICAgICAgICAgICAgICAiYmVlbiBkaXNhYmxlZC4iKQogICAgICAgICAgICBwcmludCgiIikKICAgICAgICAgICAgcHJpbnRfd3JhcHBlZChtc2cpCiAgICAgICAgICAgIHByaW50KCIiKQogICAgICAgICAgICBwcmludF93cmFwcGVkKCJSdW4gJ2FwdC1jYWNoZSBzaG93ICVzJyB0byBsZWFybiBtb3JlIGFib3V0ICIKICAgICAgICAgICAgICAgICAgICAgICAgICAidGhhdCBwYWNrYWdlLiIgJSBwa2dzX3VuYXZhaWxhYmxlWzBdKQogICAgICAgICAgICBzeXMuZXhpdCgwKQogICAgICAgIGVsc2U6CiAgICAgICAgICAgIHByaW50X3dyYXBwZWQoIllvdSBoYXZlIG5vIHBhY2thZ2VzIGluc3RhbGxlZCB0aGF0IGFyZSBubyBsb25nZXIgIgogICAgICAgICAgICAgICAgICAgICAgICAgICJhdmFpbGFibGUuIikKICAgICAgICAgICAgc3lzLmV4aXQoMCkKICAgICMgT25seSBzaG93IExUUyBwYXRjaGVzIGFuZCBleHBpcmF0aW9uIG5vdGljZXMgaWYgdGhlIHJlbGVhc2UgaXMgbm90CiAgICAjIHlldCBleHBpcmVkOyBzaG93aW5nIExUUyBwYXRjaGVzIHdvdWxkIGdpdmUgYSBmYWxzZSBzZW5zZSBvZgogICAgIyBzZWN1cml0eS4KICAgIGlmIG5vdCByZWxlYXNlX2V4cGlyZWQ6CiAgICAgICAgcHJpbnQoIiVzIHJlY2VpdmUgcGFja2FnZSB1cGRhdGVzJXMgdW50aWwgJWQvJWQiICUKICAgICAgICAgICAgICAoIns6Pnt3aWR0aH19Ii5mb3JtYXQobGVuKHBrZ3N0YXRzLnBrZ3NfbXIpLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB3aWR0aD13aWR0aCksCiAgICAgICAgICAgICAgICIgd2l0aCBMVFMiIGlmIGx0cyBlbHNlICIiLAogICAgICAgICAgICAgICBlb2wubW9udGgsIGVvbC55ZWFyKSkKICAgIGVsaWYgcmVsZWFzZV9leHBpcmVkIGFuZCBsdHM6CiAgICAgICAgcHJpbnQoIiVzICVzIHNlY3VyaXR5IHVwZGF0ZXMgd2l0aCBFU00gSW5mcmEgIgogICAgICAgICAgICAgICJ1bnRpbCAlZC8lZCIgJQogICAgICAgICAgICAgICgiezo+e3dpZHRofX0iLmZvcm1hdChsZW4ocGtnc3RhdHMucGtnc19tciksCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHdpZHRoPXdpZHRoKSwKICAgICAgICAgICAgICAgImFyZSByZWNlaXZpbmciIGlmIGVzbV9lbmFibGVkIGVsc2UgImNvdWxkIHJlY2VpdmUiLAogICAgICAgICAgICAgICBlb2xfZXNtLm1vbnRoLCBlb2xfZXNtLnllYXIpKQogICAgaWYgbHRzIGFuZCBwa2dzdGF0cy5wa2dzX3VtOgogICAgICAgIHByaW50KCIlcyAlcyBzZWN1cml0eSB1cGRhdGVzIHdpdGggRVNNIEFwcHMgIgogICAgICAgICAgICAgICJ1bnRpbCAlZC8lZCIgJQogICAgICAgICAgICAgICgiezo+e3dpZHRofX0iLmZvcm1hdChsZW4ocGtnc3RhdHMucGtnc191bSksCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHdpZHRoPXdpZHRoKSwKICAgICAgICAgICAgICAgImFyZSByZWNlaXZpbmciIGlmIGVzbV9lbmFibGVkIGVsc2UgImNvdWxkIHJlY2VpdmUiLAogICAgICAgICAgICAgICBlb2xfZXNtLm1vbnRoLCBlb2xfZXNtLnllYXIpKQogICAgaWYgcGtnc3RhdHMucGtnc190aGlyZHBhcnR5OgogICAgICAgIHByaW50X3RoaXJkcGFydHlfY291bnQoKQogICAgaWYgcGtnc3RhdHMucGtnc191bmF2YWlsYWJsZToKICAgICAgICBwcmludF91bmF2YWlsYWJsZV9jb3VudCgpCiAgICAjIHByaW50IHRoZSBkZXRhaWwgbWVzc2FnZXMgYWZ0ZXIgdGhlIGNvdW50IG9mIHBhY2thZ2VzCiAgICBpZiBwa2dzdGF0cy5wa2dzX3RoaXJkcGFydHk6CiAgICAgICAgbXNnID0gKCJQYWNrYWdlcyBmcm9tIHRoaXJkIHBhcnRpZXMgYXJlIG5vdCBwcm92aWRlZCBieSB0aGUgIgogICAgICAgICAgICAgICAib2ZmaWNpYWwgVWJ1bnR1IGFyY2hpdmUsIGZvciBleGFtcGxlIHBhY2thZ2VzIGZyb20gIgogICAgICAgICAgICAgICAiUGVyc29uYWwgUGFja2FnZSBBcmNoaXZlcyBpbiBMYXVuY2hwYWQuIikKICAgICAgICBwcmludCgiIikKICAgICAgICBwcmludF93cmFwcGVkKG1zZykKICAgICAgICBhY3Rpb24gPSAoIkZvciBtb3JlIGluZm9ybWF0aW9uIG9uIHRoZSBwYWNrYWdlcywgcnVuICIKICAgICAgICAgICAgICAgICAgIid1YnVudHUtc2VjdXJpdHktc3RhdHVzIC0tdGhpcmRwYXJ0eScuIikKICAgICAgICBwcmludF93cmFwcGVkKGFjdGlvbikKICAgIGlmIHBrZ3N0YXRzLnBrZ3NfdW5hdmFpbGFibGU6CiAgICAgICAgbXNnID0gKCJQYWNrYWdlcyB0aGF0IGFyZSBub3QgYXZhaWxhYmxlIGZvciBkb3dubG9hZCAiCiAgICAgICAgICAgICAgICJtYXkgYmUgbGVmdCBvdmVyIGZyb20gYSBwcmV2aW91cyByZWxlYXNlIG9mICIKICAgICAgICAgICAgICAgIlVidW50dSwgbWF5IGhhdmUgYmVlbiBpbnN0YWxsZWQgZGlyZWN0bHkgZnJvbSAiCiAgICAgICAgICAgICAgICJhIC5kZWIgZmlsZSwgb3IgYXJlIGZyb20gYSBzb3VyY2Ugd2hpY2ggaGFzICIKICAgICAgICAgICAgICAgImJlZW4gZGlzYWJsZWQuIikKICAgICAgICBwcmludCgiIikKICAgICAgICBwcmludF93cmFwcGVkKG1zZykKICAgICAgICBhY3Rpb24gPSAoIkZvciBtb3JlIGluZm9ybWF0aW9uIG9uIHRoZSBwYWNrYWdlcywgcnVuICIKICAgICAgICAgICAgICAgICAgIid1YnVudHUtc2VjdXJpdHktc3RhdHVzIC0tdW5hdmFpbGFibGUnLiIpCiAgICAgICAgcHJpbnRfd3JhcHBlZChhY3Rpb24pCiAgICAjIHByaW50IHRoZSBFU00gY2FsbHMgdG8gYWN0aW9uIGxhc3QKICAgIGlmIGx0cyBhbmQgbm90IGVzbV9lbmFibGVkOgogICAgICAgIGlmIHJlbGVhc2VfZXhwaXJlZCBhbmQgcGtnc3RhdHMucGtnc19tcjoKICAgICAgICAgICAgcGtnc191cGRhdGVkX2luX2VzbWkgPSBwa2dzdGF0cy5wa2dzX3VwZGF0ZWRfaW5fZXNtaQogICAgICAgICAgICBwcmludCgiIikKICAgICAgICAgICAgcHJpbnRfd3JhcHBlZChnZXR0ZXh0LmRuZ2V0dGV4dCgidXBkYXRlLW1hbmFnZXIiLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICJFbmFibGUgRXh0ZW5kZWQgU2VjdXJpdHkgIgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICJNYWludGVuYW5jZSAoRVNNIEluZnJhKSB0byAiCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgImdldCAlaSBzZWN1cml0eSB1cGRhdGUgKHNvIGZhcikgIgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICJhbmQgZW5hYmxlIGNvdmVyYWdlIG9mICVpICIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAicGFja2FnZXMuIiwKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAiRW5hYmxlIEV4dGVuZGVkIFNlY3VyaXR5ICIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAiTWFpbnRlbmFuY2UgKEVTTSBJbmZyYSkgdG8gIgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICJnZXQgJWkgc2VjdXJpdHkgdXBkYXRlcyAoc28gZmFyKSAiCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgImFuZCBlbmFibGUgY292ZXJhZ2Ugb2YgJWkgIgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICJwYWNrYWdlcy4iLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGxlbihwa2dzX3VwZGF0ZWRfaW5fZXNtaSkpICUKICAgICAgICAgICAgICAgICAgICAgICAgICAobGVuKHBrZ3NfdXBkYXRlZF9pbl9lc21pKSwKICAgICAgICAgICAgICAgICAgICAgICAgICAgbGVuKHBrZ3N0YXRzLnBrZ3NfbXIpKSkKICAgICAgICAgICAgaWYgbGl2ZXBhdGNoX2VuYWJsZWQ6CiAgICAgICAgICAgICAgICBwcmludCgiXG5FbmFibGUgRVNNIEluZnJhIHdpdGg6IHVhIGVuYWJsZSBlc20taW5mcmEiKQogICAgICAgIGlmIHBrZ3N0YXRzLnBrZ3NfdW06CiAgICAgICAgICAgIHBrZ3NfdXBkYXRlZF9pbl9lc21hID0gcGtnc3RhdHMucGtnc191cGRhdGVkX2luX2VzbWEKICAgICAgICAgICAgcHJpbnQoIiIpCiAgICAgICAgICAgIHByaW50X3dyYXBwZWQoZ2V0dGV4dC5kbmdldHRleHQoInVwZGF0ZS1tYW5hZ2VyIiwKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAiRW5hYmxlIEV4dGVuZGVkIFNlY3VyaXR5ICIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAiTWFpbnRlbmFuY2UgKEVTTSBBcHBzKSB0byAiCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgImdldCAlaSBzZWN1cml0eSB1cGRhdGUgKHNvIGZhcikgIgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICJhbmQgZW5hYmxlIGNvdmVyYWdlIG9mICVpICIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAicGFja2FnZXMuIiwKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAiRW5hYmxlIEV4dGVuZGVkIFNlY3VyaXR5ICIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAiTWFpbnRlbmFuY2UgKEVTTSBBcHBzKSB0byAiCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgImdldCAlaSBzZWN1cml0eSB1cGRhdGVzIChzbyBmYXIpICIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAiYW5kIGVuYWJsZSBjb3ZlcmFnZSBvZiAlaSAiCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgInBhY2thZ2VzLiIsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgbGVuKHBrZ3NfdXBkYXRlZF9pbl9lc21hKSkgJQogICAgICAgICAgICAgICAgICAgICAgICAgIChsZW4ocGtnc191cGRhdGVkX2luX2VzbWEpLAogICAgICAgICAgICAgICAgICAgICAgICAgICBsZW4ocGtnc3RhdHMucGtnc191bSkpKQogICAgICAgICAgICBpZiBsaXZlcGF0Y2hfZW5hYmxlZDoKICAgICAgICAgICAgICAgIHByaW50KCJcbkVuYWJsZSBFU00gQXBwcyB3aXRoOiB1YSBlbmFibGUgZXNtLWFwcHMiKQogICAgaWYgbHRzIGFuZCBub3QgbGl2ZXBhdGNoX2VuYWJsZWQ6CiAgICAgICAgcHJpbnQoIlxuVGhpcyBtYWNoaW5lIGlzIG5vdCBhdHRhY2hlZCB0byBhbiBVYnVudHUgQWR2YW50YWdlICIKICAgICAgICAgICAgICAic3Vic2NyaXB0aW9uLlxuU2VlIGh0dHBzOi8vdWJ1bnR1LmNvbS9hZHZhbnRhZ2UiKQo='
[[ -f /tmp/ubuntu-security-status ]] && { chmod +x /tmp/ubuntu-security-status; } || { echo ${USS_B64}|base64 -d|tee 1>/dev/null /tmp/ubuntu-security-status;chmod +x /tmp/ubuntu-security-status; }
# Create a ubuntu-security-status file
printf "\n\e[2G\e[1mRun ubuntu-security-status\e[0m\n"
if [[ -f /tmp/ubuntu-security-status ]];then
	cp /usr/share/ubuntu-release-upgrader/mirrors.cfg ${REL_DIR}/mirror.cfg
	sed "s|/usr/share/ubuntu-release-upgrader/mirrors.cfg|${REL_DIR}/mirror.cfg|g" -i /tmp/ubuntu-security-status
	printf "\e[2G - \e[38;2;0;160;200mINFO\e[0m: Running ubuntu-security-status\n"
	/tmp/ubuntu-security-status
	# make a more verbose report
	/tmp/ubuntu-security-status --thirdparty|tee 1>/dev/null ${UTIL_DIR}/ubuntu-security-status${OSSA_SUFFX}
	[[ -s ${UTIL_DIR}/ubuntu-security-status${OSSA_SUFFX} ]] && { printf "\e[2G - \e[38;2;0;255;0mSUCCESS\e[0m: Created ubuntu-security-status output file\n"; } || { printf "\e[2G - \e[38;2;255;0;0mERROR\e[0m: Could not create ubuntu-security-status output file\n" ; }
	rm -f 2>/dev/null /tmp/ubuntu-security-status
else
	printf "\e[2G - \e[38;2;0;160;200mINFO\e[0m: Cannot find binary ubuntu-security-status. Skipping\n"
fi

######################
# DOWNLOAD OVAL DATA #
######################

[[ ${OSSA_SCAN} = true ]] && { printf "\n\e[2G\e[1mDownload OVAL Data for CVE scanning\e[0m\n"; } || { printf "\n\e[2G\e[1mDownload OVAL Data for offline CVE scanning\e[0m\n"; }
export SCAN_RELEASE=$(lsb_release -sc)
OVAL_URI="https://people.canonical.com/~ubuntu-security/oval/oci.com.ubuntu.${SCAN_RELEASE}.cve.oval.xml.bz2"
TEST_OVAL=$(curl -slSL --connect-timeout 5 --max-time 20 --retry 5 --retry-delay 1 -w %{http_code} -o /dev/null ${OVAL_URI} 2>&1)
[[ ${TEST_OVAL:(-3)} -eq 200 ]] && { printf "\r\e[2G - \e[38;2;0;160;200mINFO\e[0m: Downloading OVAL data for Ubuntu ${SCAN_RELEASE^}\n";wget --show-progress --progress=bar:noscroll --no-dns-cache -qO- ${OVAL_URI}|bunzip2 -d|tee 1>/dev/null ${OVAL_DIR}/$(basename ${OVAL_URI//.bz2}); }
[[ ${TEST_OVAL:(-3)} -eq 404 ]] && { printf "\e[2G - \e[38;2;0;160;200mINFO\e[0m: OVAL data file for Ubuntu ${SCAN_RELEASE^} does not exist. Skipping\n" ; }
[[ ${TEST_OVAL:(-3)} -eq 200 && -s ${OVAL_DIR}/$(basename ${OVAL_URI//.bz2}) ]] && { printf "\e[2G - \e[38;2;0;255;0mSUCCESS\e[0m: Copied OVAL data for for Ubuntu ${SCAN_RELEASE^} to ${OVAL_DIR}/$(basename ${OVAL_URI//.bz2})\n"; }


####################
# PERFORM CVE SCAN #
####################

if [[ ${OSSA_SCAN} = true ]];then
	printf "\n\e[2G\e[1mPerform online CVE scan\e[0m\n"
	[[ -f ${MFST_DIR}/manifest.classic${OSSA_SUFFX} ]] && { printf "\r\e[2G - \e[38;2;0;160;200mINFO\e[0m: Linking classic manifest to OVAL Data Directroy\n";ln -sf ${MFST_DIR}/manifest.classic${OSSA_SUFFX} ${OVAL_DIR}/${SCAN_RELEASE}.manifest; }
	[[ -f ${OVAL_DIR}/$(basename ${OVAL_URI//.bz2}) && -h ${OVAL_DIR}/${SCAN_RELEASE}.manifest ]] && { printf "\r\e[2G - \e[38;2;0;160;200mINFO\e[0m: Initiating CVE Scan using OVAL data for Ubuntu ${SCAN_RELEASE^}\n"; }
	[[ -f ${OVAL_DIR}/$(basename ${OVAL_URI//.bz2}) && -h ${OVAL_DIR}/${SCAN_RELEASE}.manifest ]] && { oscap oval eval --report ${RPRT_DIR}/oscap-cve-scan-report-$(hostname -s).${SCAN_RELEASE}.html ${OVAL_DIR}/$(basename ${OVAL_URI//.bz2})|awk -vF=0 -vT=0 '{if ($NF=="false") F++} {if ($NF=="true") T++} END {print "  - Common Vulnerabilities Addressed: "F"\n  - Current Vulnerability Exposure: "T}'; }
  [[ -s ${RPRT_DIR}/oscap-cve-scan-report-$(hostname -s).${RELEASE_SCAN}.html ]] && { printf "\e[2G - \e[38;2;0;255;0mSUCCESS\e[0m: OpenSCAP CVE Report is located @ ${RPRT_DIR}/oscap-cve-scan-report-$(hostname -s).${RELEASE_SCAN}.html\n"; }  || { printf "\e[2G - \e[38;2;255;0;0mERROR\e[0m: Encountered issues running OpenSCAP CVE Scan.  Report not available.\n" ; }
fi

######################
# PROCESSES SNAPSHOT #
######################

printf "\n\e[2G\e[1mTake Snapshot of Current Processes (ps -auxwww)\e[0m\n"
printf "\e[2G - \e[38;2;0;160;200mINFO\e[0m: Running ps -auxwww\n"
ps 2>/dev/null auxwwww|tee 1>/dev/null ${UTIL_DIR}/ps.out${OSSA_SUFFX}
[[ -s ${UTIL_DIR}/ps.out${OSSA_SUFFX} ]] && { printf "\e[2G - \e[38;2;0;255;0mSUCCESS\e[0m: Created process snapshot file\n"; } || { printf "\e[2G - \e[38;2;255;0;0mERROR\e[0m: Could not create process snapshot file\n" ; }
PS_PW_LINES=($(grep -onE '[Pp][Aa][Ss][Ss]?(w)| -P ' ${UTIL_DIR}/ps.out${OSSA_SUFFX}|awk -F: '{print $1":"$2}'))
printf "\e[2G - \e[38;2;0;160;200mINFO\e[0m: Checking for embedded credentials in ps output using a simple regex\n"
[[ ${#PS_LINES[@]} -ge 1 ]] && { printf "\e[2G - \e[38;2;255;200;0mWARNING\e[0m: Please review following lines in ${UTIL_DIR}/ps.out${OSSA_SUFFX} for potental password data:\n$(printf '\e[14G%s\n' ${PS_LINES[@]})";echo; } || { printf "\e[2G - \e[38;2;0;255;0mSUCCESS\e[0m: The simple regex did not find password data in ps output, however you should perform a thorough review of ${UTIL_DIR}/ps.out${OSSA_SUFFX}\n";echo; }


####################
# NETSTAT SNAPSHOT #
####################

printf "\n\e[2G\e[1mTake Snapshot of Network Statistics (netstat -an)\e[0m\n"
printf "\e[2G - \e[38;2;0;160;200mINFO\e[0m: Running netstat -an\n"
netstat 2>/dev/null -an|tee 1>/dev/null ${UTIL_DIR}/netstat.out${OSSA_SUFFX}
[[ -s ${UTIL_DIR}/netstat.out${OSSA_SUFFX} ]] && { printf "\e[2G - \e[38;2;0;255;0mSUCCESS\e[0m: Created netstat snapshot file\n"; } || { printf "\e[2G - \e[38;2;255;0;0mERROR\e[0m: Could not create netstat snapshot file\n" ; }

#################
# LSOF SNAPSHOT #
#################

printf "\n\e[2G\e[1mList open files (lsof)\e[0m\n"
printf "\e[2G - \e[38;2;0;160;200mINFO\e[0m: Running lsof\n"
lsof 2>/dev/null|tee 1>/dev/null ${UTIL_DIR}/lsof.out${OSSA_SUFFX}
[[ -s ${UTIL_DIR}/lsof.out${OSSA_SUFFX} ]] && { printf "\e[2G - \e[38;2;0;255;0mSUCCESS\e[0m: Created lsof snapshot file\n"; } || { printf "\e[2G - \e[38;2;255;0;0mERROR\e[0m: Could not create lsof snapshot file\n" ; }


##################
# Create Tarball #
##################

printf "\n\e[2G\e[1mArchiving and Compressing Collected Data\e[0m\n"
[[ -n ${OSSA_PW} ]] && { export TARBALL=/tmp/ossa-datafile.encrypted${OSSA_SUFFX}.tgz; } || { export TARBALL=/tmp/ossa-datafile${OSSA_SUFFX}.tgz; }
if [[ -n ${OSSA_PW} ]];then
	printf "\e[2G - \e[38;2;0;160;200mINFO\e[0m: Encrypting OSSA data files using openssl\n"
	printf "\e[2G - \e[38;2;0;160;200mINFO\e[0m: Password is \"${OSSA_PW}\"\n"
	tar czvf - -C ${OSSA_DIR%/*} ${OSSA_DIR##*/} | openssl enc -e -aes256 -pbkdf2 -pass env:OSSA_PW -out ${TARBALL}
else
	printf "\e[2G - \e[38;2;0;160;200mINFO\e[0m: Archiving and compressing OSSA Datafiles\n"
	printf "\e[2G - \e[38;2;0;160;200mINFO\e[0m: Tarball is not encrytped. \n"
	tar -czf ${TARBALL} -C ${OSSA_DIR%/*} ${OSSA_DIR##*/}
fi
[[ -s ${TARBALL} ]] && { printf "\e[2G - \e[38;2;0;255;0mSUCCESS\e[0m: Created tarball ${TARBALL}\n"; } || { printf "\e[2G - \e[38;2;255;0;0mERROR\e[0m: Could not create tarball ${TARBALL}\n" ; }
printf "\e[2G - \e[38;2;0;160;200mINFO\e[0m: Please download ${TARBALL} to your local machine\n"

############
# CLEAN UP #
############

printf "\n\e[2G\e[1mPerforming Cleanup\e[0m\n"
if [[ ${OSSA_KEEP} = true ]];then
	printf "\e[2G - \e[38;2;0;160;200mINFO\e[0m: Keep option specified. Not removing OSSA Data Directory\n"
else
	printf "\e[2G - \e[38;2;0;160;200mINFO\e[0m: Removing OSSA Data Directory\n"
	cd
	rm -rf ${OSSA_DIR}
  [[ -d ${OSSA_DIR} ]] && { printf "\e[2G - \e[38;2;255;0;0mERROR\e[0m: Failed to delete ${OSSA_DIR}\n" ; } || { printf "\e[2G - \e[38;2;0;255;0mSUCCESS\e[0m: Deleted ${OSSA_DIR}\n"; }
fi


#################
# END OF SCRIPT #
#################

read -t 20 -p "Hit ENTER or wait 20 seconds to clear screen"
tput sgr0; tput cnorm; tput rmcup
echo
# Show elapsed time
printf "\n\e[1mOpen Source Security Assessment completed in $(TZ=UTC date --date now-${NOW} "+%H:%M:%S")\e[0m\n\n"
# Show tarball location
printf "\n\e[2GData collected during the Open Source Security Assessment is located at\n${TARBALL}\e[0m\n\n"
