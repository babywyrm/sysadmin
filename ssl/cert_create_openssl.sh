#!/bin/bash
##
## /usr/local/script/slcert.sh
## Create a new signed sertificate using OpenSSL
##
## Created on 12 JAN 2014
## Version 1.1 dated 13 JAN 2014
##

# Set variables and default values
set -u
CERTIFICATE=""			# Certificate name
CRT_FILENAME=""			# Filename for certificate key
KEY_FILENAME=""			# Filename for private key
FILE_CONFIG="openssl.skyCA.cnf" # CA openssl configuration file
CRL_FILENAME="skyCA.crl.pem"	# CA certificate revokation list
CRL_TXTFILE="skyCA.crl.txt"	# CA certificate revokation list in plain text
DIR_SKYCA="/srv/etc/skyCA"	# CA directory
DIR_CURRENT=$(pwd)			# Current directory
F_OPTION=""				# Chosen option (create or revoke)
EXITCODE=0				# Assume everything will go well 

# Define functions
function checktocontinue() {
	# Ask to continue
	read -p "Continue (y/n)? " -n 1 -r
	if [[ "$REPLY" =~ ^[Yy]$ ]]; then
		printf "\n"
	else
		printf "\nYou choose not to continue. Exiting.\n"
		exit 1
	fi
}

# Check if this script is run as root, otherwise exit.
if [[ $(whoami) != root ]]; then
	printf "Must be root to execute this script. Exiting.\n"
	exit 1
fi
# Check for openssl
if [[ ! -x $(which openssl) ]]; then
   printf -- "Cannot execute 'openssl'. Exiting.\n"
   exit 1
fi

# Evaluate given options using getops; set variables accordingly
while getopts ":i:r:d:c:h" opt; do
   case "$opt" in
     i)
       if [[ -z ${F_OPTION} ]]; then
          F_OPTION="I"
          CERTIFICATE="${OPTARG}"
        else
          printf -- "Only one option can be specified. Exiting.\n"
          exit 1
       fi
       ;;
     r)
       if [[ -z ${F_OPTION} ]]; then
          F_OPTION="R"
          CERTIFICATE="${OPTARG}"
        else
          printf -- "Only one option can be specified. Exiting.\n"
          exit 1
       fi
       ;;
     d)
       DIR_SKYCA="${OPTARG}" 
       ;;
     c)
       FILE_CONFIG="${OPTARG}"
       printf -- "Using OpenSSL configuration file %s.\n" ${FILE_CONFIG}
       ;;
     \? | h | :)
       printf -- "Script for issueing and revoking SSL-certificates using OpenSSL.\n"
       printf -- "Usage: %s -i filename | -r filename | -h  [-d directory] [-c config file]\n" "${0##*/}"
       printf -- "   -h   Help: show this help message and exit.\n"
       printf -- "   -i   Issue: create new private key and have SkyCA issue a certificate.\n"
       printf -- "   -r   Revoke: revoke a certificate issued by SkyCA.\n"
       printf -- "   -d   Directory: use 'directory' as working dir instead of %s.\n" ${DIR_SKYCA}
       printf -- "   -c   Config file: use 'config file' as OpenSLL configuration instead of %s.\n" ${FILE_CONFIG} 
       exit 2
       ;;
    :)
       printf -- "Option -%s requires an argument. Exiting.\n" "${OPTARG}"
       exit 1
       ;;
   esac
done

# Change working directory
if [[ -d "${DIR_SKYCA}" ]]; then
   cd ${DIR_SKYCA}
   if [[ ${?} != 0 ]]; then
      printf -- "Could not change working directory to %s. Exiting.\n" ${DIR_SKYCA}
      exit 1
   fi
   printf -- "Working directory set to %s.\n" ${DIR_SKYCA}
 else
   printf -- "Directory %s does not exist. Exiting.\n" ${DIR_SKYCA}
   exit 1
fi

# Set file names
CSR_FILENAME="${CERTIFICATE}.csr"
CRT_FILENAME="${CERTIFICATE}.crt"
KEY_FILENAME="${CERTIFICATE}.key"

# Issue or Revoke?
case ${F_OPTION} in
   I)
     printf -- "==== SSL-certificate %s is about to be issued.\n" "${CERTIFICATE}"
     if [[ -e ${FILE_CONFIG} ]]; then

        # Create certificate signing request and private key
        openssl req -config ${FILE_CONFIG} -new -nodes \
                    -keyout "./private/${KEY_FILENAME}" \
                    -out ${CSR_FILENAME} \
                   -days 3649
        EXITCODE=${?}

        # Sign certificate if all went well
        if [[ ${EXITCODE} == 0 ]]; then
           printf -- " == Certificate signing request and private key created.\n"
           printf -- " == Signing and issueing certificate...\n"
           openssl ca -config ${FILE_CONFIG} \
                      -policy policy_anything \
                      -out "./certs/${CRT_FILENAME}" \
                      -infiles ${CSR_FILENAME}
           EXITCODE=${?}

           # Remove CSR-file if everything succeeded
           if [[ ${EXITCODE} == 0 ]]; then
              printf -- " == Certificate issued. Removing CSR-file %s...\n" ${CSR_FILENAME}
              rm ${CSR_FILENAME}

            else
              printf -- " ** Error occured while siging and issueing CRT-file for %s.\n" ${CERTIFICATE}
           fi

         else
           printf -- " ** Error occured while creating private key and CSR-file for %s. " ${CERTIFICATE}
           printf -- "Certificate not issued.\n"
        fi

      else
        printf -- " ** Configuration file %s does not exist.\n" ${FILE_CONFIG}
        EXITCODE=1
     fi
     ;;

   R)
     printf -- "==== SSL-certificate %s is about to be revoked.\n" "${CERTIFICATE}"
     if [[ -e ${FILE_CONFIG} ]]; then

        # Revoke certificate
        openssl ca -config ${FILE_CONFIG} \
                   -revoke "./certs/${CRT_FILENAME}"
        EXITCODE=${?}

	# Update revokation list
        if [[ ${EXITCODE} == 0 ]]; then
           printf -- " == Certificate revoked.\n"
           printf -- " == Creating new revokation list...\n"
           openssl ca -config ${FILE_CONFIG} \
                      -gencrl \
                      -out "./crl/${CRL_FILENAME}"
           EXITCODE=${?}
           if [[ ${EXITCODE} == 0 ]]; then
               printf -- " == New certificate revokation list created.\n"
               openssl crl -in "./crl/${CRL_FILENAME}" -text > "./crl/${CRL_TXTFILE}"
            else
               printf -- " ** Error occured while creating certificate revokation list.\n"
           fi
         else
           printf -- " ** Error occured while revoking certificate %s. CRL not updated.\n" ${CERTIFICATE}
        fi

      else
        printf -- " ** Configuration file %s does not exist.\n" ${FILE_CONFIG}
        EXITCODE=1
     fi
     ;;

   *)	# Unknown option speficied.
     printf -- " ** Not specified whether to issue or revoke a certificate. Exiting.\n"
     EXITCODE=1
     ;;
esac

# Change back directory to original working dir
if [[ -d "${DIR_CURRENT}" ]]; then
   cd ${DIR_CURRENT}
   if [[ ${?} != 0 ]]; then
      printf -- "Failed changing working directory back to %s. Exiting.\n" ${DIR_CURRENT}
      exit 1
   fi
   printf -- "Working directory changed back to %s.\n" ${DIR_CURRENT}
 else
   printf -- "Cannot change back to %s, because directory does not exist anymore. Exiting.\n" ${DIR_CURRENT}
   exit 1
fi

# Message and exit
if [[ ${EXITCODE} == 0 ]]; then
   printf "All done.\n"
 else
   printf "Finished, but one or more errors occured.\n"
fi
exit ${EXITCODE}

##############################
##
##
