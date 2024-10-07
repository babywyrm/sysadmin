##
#
https://gist.github.com/tankala/200e9286fde580acdfb38c3f0a737bf2
#
##

AppArmor docker profile corrpuption problem
appArmorDockerProfileCorrpution.md
Due to a file corruption or some reason I started getting below error

AppArmor enabled on system but the docker-default profile could not be loaded: strconv.Atoi: parsing "found": invalid syntax
I followed below steps to fix this problem. Please take backup of AppArmor profiles if you created any before running below commands

sudo rm -rf /etc/apparmor*
sudo apt remove --assume-yes --purge apparmor
sudo apt install apparmor
@padaVVan
padaVVan commented on Aug 9, 2022
Thanks. Its works for me

@ashok-kc
ashok-kc commented on Aug 9, 2022
Cool. Thank you for acknowledging

@baremarco
baremarco commented on Dec 15, 2022
Muchas gracias, tambien me sirvio

@mahendra150
mahendra150 commented on Dec 23, 2022
yes is working.

@keksgauner
keksgauner commented on Feb 14, 2023 • 
Thx it worked

I will write what I had to do
When I did docker-compose up -d as before I got the error

Error response from daemon: failed to create shim task: OCI runtime create failed: runc create failed: unable to start container process: error during container init: unable to apply apparmor profile: apparmor failed to apply profile: write /proc/self/attr/apparmor/exec: no such file or directory: unknown
I thought I would have to update docker to get to docker compose. kinda did it like this (idk if this right)

apt-get remove docker docker-engine docker.io containerd runc
apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
But after that I came to this error

Error response from daemon: AppArmor enabled on system but the docker-default profile could not be loaded: strconv.Atoi: parsing "found": invalid syntax
I have tried to reinstall appamor
(I have done both decide for yourself what is right)

sudo rm -rf /etc/apparmor*
sudo apt install apparmor --reinstall
sudo service apparmor restart
sudo service docker restart
sudo rm -rf /etc/apparmor*
sudo apt remove --assume-yes --purge apparmor
sudo apt install apparmor
Last came this error

Error response from daemon: AppArmor enabled on system but the docker-default profile could not be loaded: running `apparmor_parser apparmor_parser --version` failed with output:
error: exec: "apparmor_parser": executable file not found in $PATH
And in the end that helped

 apt install apparmor-utils
And in the end it works again with docker compose up -d

@xaochuk
xaochuk commented on Feb 16, 2023
Thank you so much, only this helps me.

@jaquelineabreu
jaquelineabreu commented on Feb 16, 2023
Obrigada!!!!

@asc0910
asc0910 commented on Feb 20, 2023
Thanks it worked for me

@ppanon2022
ppanon2022 commented on Apr 16, 2023
The thing is that the files in /etc/apparmor.d come from more than just the apparmor package. There are profile files from packages like isc-dhcp-client, ntp, rsyslog, snapd, tcpdump, and liblxc-common. So what you're doing is wiping out all the MAC security for dhcp-client, ntp, rsyslog, snapd, etc. and weakening O/S security as a result.

@ppanon2022
ppanon2022 commented on Apr 16, 2023
I think https://docs.docker.com/engine/security/apparmor/ provides some indication of the issues with using apparmor and docker.
