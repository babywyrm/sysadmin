# update and install ntp
yum update -y
yum install ntp -y
systemctl enable ntpd --now

# Install crictl, for Cri-o, but did not work with k8s 1.10 as of yet.
curl -L -O https://github.com/kubernetes-incubator/cri-tools/releases/download/v1.0.0-beta.0/crictl-v1.0.0-beta.0-linux-amd64.tar.gz
tar xvf crictl-v1.0.0-beta.0-linux-amd64.tar.gz
# mv crictl /usr/local/bin/crictl

cat > /etc/yum.repos.d/virt7-container-common-candidate.repo << EOF
[virt7-container-common-candidate]
name=virt7-container-common-candidate
baseurl=https://cbs.centos.org/repos/virt7-container-common-candidate/x86_64/os/
enabled=1
gpgcheck=0
EOF

# skip cri-o for now, use docker instead
# yum install cri-o -y
# systemctl enable crio --now
yum install docker -y
systemctl enable docker --now

# install k8s
cat < /etc/yum.repos.d/kubernetes.repo
[kubernetes]
name=Kubernetes
baseurl=https://packages.cloud.google.com/yum/repos/kubernetes-el7-\$basearch
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://packages.cloud.google.com/yum/doc/yum-key.gpg https://packages.cloud.google.com/yum/doc/rpm-package-key.gpg
EOF
setenforce 0
yum install -y kubelet kubeadm kubectl nfs-utils
# I needed nfs-utils to mount nfs volumes

# extra kubelet things for cri-o
#cat < /etc/systemd/system/kubelet.service.d/05-kubeadm.conf
#[Service]
#Environment="KUBELET_EXTRA_ARGS=--container-runtime=remote --container-runtime-endpoint=unix:///var/run/crio/crio.sock"
#EOF
#sed -i "s/cgroup-driver=systemd/cgroup-driver=cgroupfs/g" /etc/systemd/system/kubelet.service.d/10-kubeadm.conf
systemctl daemon-reload
systemctl enable kubelet --now

# k8s sysctl settings on CentOS
cat <  /etc/sysctl.d/k8s.conf
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1
EOF
sysctl --system
@vevsatechnologies
