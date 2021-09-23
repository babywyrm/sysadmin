#!/bin/sh
## cent7
####################

#######################################
#######################################
set -x
kubeadm reset --force
yum remove -y kubeadm kubectl kubelet kubernetes-cni kube*
yum autoremove -y
[ -e ~/.kube ] && rm -rf ~/.kube
[ -e /etc/kubernetes ] && rm -rf /etc/kubernetes
[ -e /opt/cni ] && rm -rf /opt/cni

########################
##
##
