
##
#
https://docs.aws.amazon.com/cli/latest/reference/eks/update-kubeconfig.html
#
##



When running following command to update kubernetes config to get connected with EKS cluster then getting this error "'NoneType' object is not iterable"

aws eks update-kubeconfig --region us-east-2 --name <cluster name>
amazon-web-serviceskubernetesamazon-eks
Share
Follow
asked May 9, 2022 at 18:33
Abhishek Jain's user avatar
Abhishek Jain
3,57711 gold badge2424 silver badges2525 bronze badges
Could you post the output of the command with --debug please? – 
sudo
 May 9, 2022 at 18:34
Add a comment
2 Answers
Sorted by:


Do you have an existing k8s config? Running

aws eks update-kubeconfig --region <region> --name <cluster name>

Generates a ~/.kube/config.

If you already have a ~/.kube/config, there could be a conflict between the file to be generated, and the file that already exists that prevents them from being merged.

If you have a ~/.kube/config file, and you aren't actively using it, running

rm ~/.kube/config

and then attempting

aws eks update-kubeconfig --region us-east-2 --name <cluster name>

afterwards will likely solve your issue.

If you are using your ~/.kube/config file, rename it something else so you could use it later, and then run the eks command again.

See a similar issue here: https://github.com/aws/aws-cli/issues/4843
  
  

reset-kube-config.md
Reset Kube Config .sh
A Utility script.

Purpose
Resets your Kube Config (~/.kube/config) to your available clusters according to eksctl get cluster -A

Description
Uses eksctl to rewrite your kubeconfig file, useful if you're constantly tearing down and spinning up clusters and you just need to reset to what's currently available

Makes a backup with the first available number in ~/.kube/config.<SOME_NUMBER>.bak of your kube config before resetting

Line 14 is the core functionality of the script, which grabs eksctl clusters and then writes them to your kubeconfig

eksctl get cluster -A -v 0 | grep -v NAME | xargs -n2 sh -c 'eksctl utils write-kubeconfig -c $1 -r $2' sh
Usage
Run:

curl https://gist.githubusercontent.com/Benbentwo/26361390bb1fb5d7ca9c09adbfdad1d1/raw/reset-kube-config.sh | bash
Alternatively, if you're not a fan of the curl ... | bash (understandably) you can always:

curl -O https://gist.githubusercontent.com/Benbentwo/26361390bb1fb5d7ca9c09adbfdad1d1/raw/reset-kube-config.sh
chmod +x ./reset-kube-config.sh
./reset-kube-config.sh
reset-kube-config.sh

```
#!/bin/bash

eksctl > /dev/null || { echo "No eksctl, is it installed?"; return 1;}

counter=0
while [[ -f ~/.kube/config.${counter}.bak ]]; do
  ((counter++))
done
echo "Creating Backup ~/.kube/config.${counter}.bak"

mv ~/.kube/config ~/.kube/config.${counter}.bak

# All Regions and ignore errored regions (like ap-east-1 & me-south-1)
eksctl get cluster -A -v 0 | grep -v NAME | xargs -n2 sh -c 'eksctl utils write-kubeconfig -c $1 -r $2' sh
# Longer Version with better management of printing below, removed the section because its duplicative, could be useful for other commands.
#eksctl get cluster -A -v 0 | grep -v NAME| awk -F '[ .]' '{maj = $1; min = $2; print maj, min}' | xargs -n2 sh -c 'eksctl utils write-kubeconfig -c $1 -r $2' sh


```



##
##

