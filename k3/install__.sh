#!/bin/env bash

##
##
## https://gist.githubusercontent.com/diceone/a49cdc4857b02a0f90f1a42ee4ee5eec/raw/b1e3617105090abfb47406352f1b381972b576b6/install-k3s.sh
##
##

set -e
export PATH=/usr/local/bin:/usr/bin:/usr/local/sbin:/usr/sbin

: <<'README'
# Master node install, note this script /should/ be idempotentish. Rerunning to get worker node command output is fine
sudo -E ./install-k3s.sh
# to skip install of rancher
SKIP_RANCHER_INSTALL=true sudo -E ./install-k3s.sh

# Worker node install, note that these commands are echoed with valid values after a master node install
export K3S_HOST=
export K3S_TOKEN=
export SKIP_RANCHER_INSTALL=true
sudo -E ./install-k3s.sh

# To prevent the deploying of the distributed embedded db
export DISABLE_DISTRIBUTED_DB=true
README

# State options
MOUNTPOINT="${MOUNTPOINT:-/data1}"

#RANCHER Install options
RANCHER_LETSENCRYPT_ENVIRONMENT="${RANCHER_LETSENCRYPT_ENVIRONMENT:-staging}"
RANCHER_LETSENCRYPT_EMAIL="${RANCHER_LETSENCRYPT_EMAIL:-you@example.com}"
RANCHER_HOSTNAME="${RANCHER_HOSTNAME:-rancher.example.com}"
RANCHER_TLS_SOURCE="${RANCHER_TLS_SOURCE:-letsEncrypt}"

#Cert manager options
CERT_MANAGER_VERSION=v0.16.1

if (( $EUID != 0 )); then
    echo -e "Script must be ran as root user. See README in script"
    exit 1
fi

if [ -z $K3S_HOST ]
then
  while true; do
      echo -e "!!!!WARNING!!!!\nIf this is /NOT/ the first node in the cluster see in-script readme.\n!!!!WARNING!!!!\n"
      read -p "Proceed with master node install?" yn
      case $yn in
          [Yy]* ) break;;
          [Nn]* ) exit 1;;
          * ) echo "Please answer yes or no.";;
      esac
  done
  if [ -z $DISABLE_DISTRIBUTED_DB ]
  then
    export INSTALL_K3S_EXEC="server --cluster-init"
  fi

else
  echo "Agent install detected."
  if [ -z $K3S_TOKEN ]
  then
    echo "K3S_TOKEN unset, this is required to continue for agent install"
    exit 1
  else
    echo "K3S_TOKEN set, installation continuing"
  fi
  SKIP_RANCHER_INSTALL=true
  export K3S_URL=https://$K3S_HOST:6443

  if [ -z $DISABLE_DISTRIBUTED_DB ]
  then
    export INSTALL_K3S_EXEC="server --server https://$K3S_HOST:6443"
  fi
fi

#This is required to do state migration /before/ service starts
export INSTALL_K3S_SKIP_START=true

if ! [ -z $SKIP_RANCHER_INSTALL ]
then
  export INSTALL_K3S_EXEC="$INSTALL_K3S_EXEC --disable traefik"
fi

if mountpoint -q "$MOUNTPOINT"
then
  echo "$MOUNTPOINT mounted, installation can continue"
  echo "---Installing prereqs"
  yum clean all
  yum install -y iscsi-initiator-utils nfs-utils
  yum install -y container-selinux selinux-policy-base
  rpm -i https://rpm.rancher.io/k3s-selinux-0.1.1-rc1.el7.noarch.rpm || true

  curl -sfL https://get.k3s.io | sh -

  if [ -d "${MOUNTPOINT}"/k3s ]
  then
    echo "---/var/lib/rancher/k3s already migrated, moving on"
  else
    echo "---Migrating /var/lib/rancher/k3s"
    mv /var/lib/rancher/k3s "$MOUNTPOINT"
  fi
  rm -rf /var/lib/rancher/k3s
  ln -s "${MOUNTPOINT}"/k3s /var/lib/rancher/k3s

  if systemctl is-enabled --quiet k3s &>/dev/null
  then
    echo "---(Re)starting k3s service"
    systemctl restart k3s
  else
    echo "---(Re)starting k3s-agent service"
    systemctl restart k3s-agent
  fi

  if [ -d "${MOUNTPOINT}"/k3s/etc ]
  then
    echo "---/etc/rancher already migrated, moving on"
  else
    echo "---Migrating /etc/rancher"
    mv /etc/rancher "${MOUNTPOINT}"/k3s/etc/ || true
    mkdir "${MOUNTPOINT}"/k3s/etc || true
  fi
  rm -rf /etc/rancher
  ln -s "${MOUNTPOINT}"/k3s/etc /etc/rancher

  export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
  if [ -f $KUBECONFIG ]
  then
    if which helm &>/dev/null
    then
      echo "---Helm already installed, moving on"
    else
      curl https://raw.githubusercontent.com/helm/helm/master/scripts/get-helm-3 | bash
    fi

    if [ -z $SKIP_RANCHER_INSTALL ]
    then
      if kubectl get challenges # TODO find better way to detect if all CRDs are deployed
      then
        echo "---Cert manager CRDs deployed"
      else
        kubectl apply --validate=false -f https://github.com/jetstack/cert-manager/releases/download/${CERT_MANAGER_VERSION}/cert-manager.crds.yaml
      fi

      kubectl create namespace cert-manager || true
      helm repo add jetstack https://charts.jetstack.io
      helm repo update
      # TODO add switch to do helm upgrade if already installed
      helm install --wait \
        cert-manager jetstack/cert-manager \
        --namespace cert-manager \
        --version ${CERT_MANAGER_VERSION} || true

      helm repo add rancher-latest https://releases.rancher.com/server-charts/latest
      kubectl create namespace cattle-system || true
      # TODO add switch to do helm upgrade if already installed
      helm install \
        rancher rancher-latest/rancher \
        --namespace cattle-system \
        --set hostname="${RANCHER_HOSTNAME}" \
        --set ingress.tls.source="${RANCHER_TLS_SOURCE}" \
        --set letsEncrypt.environment="${RANCHER_LETSENCRYPT_ENVIRONMENT}" \
        --set letsEncrypt.email="${RANCHER_LETSENCRYPT_EMAIL}" || true
      kubectl -n cattle-system rollout status deploy/rancher
    else
      echo "---Skipping rancher install, moving on"
    fi
  else
    echo "${KUBECONFIG} not present, moving on. Any deployment of cert-manager/rancher will not occur."
  fi
else
  echo "---${MOUNTPOINT} not present, exiting. INSTALLATION FAILED!!!!"
  exit 1
fi

echo "---Install Complete"

if [ -z $K3S_HOST ]
then
  K3S_HOST=$(ifconfig eth0 | grep "inet " | awk '{$1=$1};1' | cut -d " " -f 2)
  K3S_TOKEN=$(cat /var/lib/rancher/k3s/server/node-token)

  echo -e "#!/bin/env bash\n\n#Additional node provisioning script\nexport SKIP_RANCHER_INSTALL=true\nexport K3S_HOST=${K3S_HOST}\nexport K3S_TOKEN=${K3S_TOKEN}\nsudo -E ./install-k3s.sh" | tee provision_agent.sh
  echo -e "^ saved as ~/provision_agent.sh"
  chmod +x provision_agent.sh
fi

##
##
