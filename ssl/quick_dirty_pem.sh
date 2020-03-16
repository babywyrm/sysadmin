#!/bin/bash
##
##
## Quick 'n dirty script to create a pound pem-file
## To be run in the CA directory
##
###   Created on 10 JAN 2016 (?)                                    ###
###   https://github.com/tmschx/bash-sysadmin/blob/master/slpem.sh  ###
##
##############################################
# Check for required argument
CERTIFICATE="${1}"
if [[ -z ${CERTIFICATE} ]]; then
	printf "Script requires a certificate name as argument.\n"
	exit 1
fi

# Set variables and default values
set -u
CA="skyCA"				# Name of the Certificate Authority
DIR_CRT="certs"			# directory containing the certificates
DIR_KEY="private"		# directory containing the private keys
CRT_FILENAME="./${DIR_CRT}/${CERTIFICATE}.crt"		# Input file with certificate
KEY_FILENAME="./${DIR_KEY}/${CERTIFICATE}.key"		# Input file with private key
PEM_FILENAME="./${DIR_KEY}/${CERTIFICATE}.pem"		# Output pem file; put it in the private key directory
CA_CRT_FILENAME="./${DIR_CRT}/${CA}.crt"			# Input file with CA certificate

# Check if this script is run as root, otherwise exit.
if [[ $(/usr/bin/whoami) != root ]]; then
	printf "Must be root to execute this script. Exiting.\n"
	exit 1
fi

# Check if directories exist.
if [[ ! -d ${DIR_CRT} || ! -d ${DIR_KEY} ]]; then
	printf "The '%s' or the '%s' directory does not exist. Exiting.\n" ${DIR_CRT} ${DIR_KEY}
	exit 1
fi

# Add certificate
printf "Getting certificate from %s... " ${CRT_FILENAME}
if [[ -e ${CRT_FILENAME} ]]; then
	openssl x509 -in ${CRT_FILENAME} > ${PEM_FILENAME}
	if [[ ${?} != 0 ]]; then
		printf "error occured. Exiting.\n"
		exit 2
	else
		printf "success: certificate written to %s.\n" ${PEM_FILENAME}
	fi
else
	printf "file does not exist. Deleting %s and exiting.\n" ${PEM_FILENAME}
	rm ${PEM_FILENAME} 2> /dev/null
	exit 1
fi

# Add private key
printf "Getting private key from %s... " ${KEY_FILENAME}
if [[ -e ${KEY_FILENAME} ]]; then
	openssl rsa -in ${KEY_FILENAME} >> ${PEM_FILENAME}
	if [[ ${?} != 0 ]]; then
		printf "error occured. Exiting.\n"
		exit 2
	else
		printf "success: key added to %s.\n" ${PEM_FILENAME}
	fi
else
	printf "file does not exist. Deleting %s and exiting.\n" ${PEM_FILENAME}
	rm ${PEM_FILENAME} 2> /dev/null
	exit 1
fi

# Add CA certificate
printf "Getting CA certificate from %s... " ${CA_CRT_FILENAME}
if [[ -e ${CA_CRT_FILENAME} ]]; then
	openssl x509 -in ${CA_CRT_FILENAME} >> ${PEM_FILENAME}
	if [[ ${?} != 0 ]]; then
		printf "error occured. Exiting.\n"
		exit 2
	else
		printf "success: CA certificate added to %s.\n" ${PEM_FILENAME}
	fi
else
	printf "file does not exist. Deleting %s and exiting.\n" ${PEM_FILENAME}
	rm ${PEM_FILENAME} 2> /dev/null
	exit 1
fi

# Done and exit
exit 0

####
####################################################
