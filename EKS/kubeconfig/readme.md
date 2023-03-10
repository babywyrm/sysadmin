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

