---
decrypt_.yml

```
# this is how you encrypt a file using openssl and aes-256
#   openssl aes-256-cbc -salt -a -e -in <src file> -out <out file> -k <enc salt>

# expects you pass in vars:
#   enc_src_file      -- local location of encrypted src file that will copied to target node
#   enc_src_dest      -- where the decrypted file should be put
#   enc_salt          -- salt used to decrypt
#   enc_file_user     -- user ownership
#   enc_file_group    -- group ownership
#   enc_file_mode     -- mode to apply

# example usage
#  - include: "{{ playbook_dir }}/roles/common/tasks/decrypt.yml"
#    vars:
#      enc_src_file:   "{{ playbook_dir }}/roles/common/files/squid/squid.example.com.crt.enc"
#      enc_src_dest:   "/etc/squid/certs/squid.example.com.crt"
#      enc_salt:       "{{ squid_certs_salt }}"
#      enc_file_user:  "squid"
#      enc_file_group: "squid"
#      enc_file_mode:  "0440"

- name: copy file to target
  copy: src={{ enc_src_file }} dest=/tmp/{{ enc_src_file | basename }}
        owner=root group=root mode=0400
  register: enc_file
  tags: decrypt

- name: check to see if target path exists
  stat: path="{{ enc_src_dest }}"
  register: st_src_dest
  tags: decrypt

- name: decrypt file
  shell: openssl aes-256-cbc -salt -a -d -in /tmp/{{ enc_src_file | basename }} -out {{ enc_src_dest }} -k {{ enc_salt }}
  no_log: True
  when: enc_file.changed or not st_src_dest.stat.exists 
  tags: decrypt

- name: adjust file attributes
  file: path="{{ enc_src_dest }}"
    owner="{{ enc_file_user }}" group="{{ enc_file_group }}"
    mode="{{ enc_file_mode }}"
  tags: decrypt

```
  ################


```
  #!/bin/sh

VAULT_PASSWORD="~/scripting/ansible_vault_pass"

# Die if they fat finger arguments, this program will be run as root
[ $? = 0 ] || die "Error parsing arguments. Use -e to encrypt or -d to decrypt"

while true; do
	case $1 in
		-e)
			echo "Start securing repository data before any commit"

			echo " * Enable vault with password from "$VAULT_PASSWORD
			export ANSIBLE_VAULT_PASSWORD_FILE=$VAULT_PASSWORD

			echo " * Encrypt data files in host_vars with password"
			for FILENAME in $(find host_vars/ -type f  | xargs egrep -l 'pass|token')
			do
				echo "  * Encode file: "$FILENAME
				ansible-vault encrypt $FILENAME
			done	

			echo " * Encrypt data files in group_vars with password"
			for FILENAME in $(find group_vars/ -type f  | xargs egrep -l 'pass|token')
			do
				echo "  * Encode file: "$FILENAME
				ansible-vault encrypt $FILENAME
			done
			exit 0
		;;
		-d)
			echo "Start derypting repository data before any edition"

			echo " * Decrypt vault with password from "$VAULT_PASSWORD
			export ANSIBLE_VAULT_PASSWORD_FILE=$VAULT_PASSWORD

			echo " * Decrypt data files in host_vars with password"
			for FILENAME in $(find host_vars/ -type f  | xargs egrep -l 'ANSIBLE_VAULT')
			do
				echo "  * Decode file: "$FILENAME
				ansible-vault decrypt $FILENAME
			done

			echo " * Decrypt data files in group_vars with password"
			for FILENAME in $(find group_vars/ -type f  | xargs egrep -l 'ANSIBLE_VAULT')
			do
				echo "  * Decode file: "$FILENAME
				ansible-vault decrypt $FILENAME
			done
			exit 0
		;;
		--)                                                                 
            # no more arguments to parse                                
            break                                                       
            ;;
		*)                                                                  
			printf "Unknown option %s\n" "$1"                           
			exit 1                                                      
		;;                                                                  
	esac                                                                        
done


