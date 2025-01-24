#!/bin/bash

##
#####
## https://gist.github.com/taking/9c8cf59bfc6e5a607deae05afc6d00cd
#####
##
# Author by Taking

# (1) K3s Install + Reset
# (2) Istio + Multi Cluster
# (3) Multi Cluster


# Check permission
if ! [ $(id -u) = 0 ]
  then echo "${RED}Please run as root ${NC}"
  exit
fi


get_latest_release() {
  curl --silent "https://api.github.com/repos/$1/releases/latest" | # Get latest release from GitHub api
    grep '"tag_name":' |                                            # Get tag line
    sed -E 's/.*"([^"]+)".*/\1/'                                    # Pluck JSON value
}


RED=`tput setaf 1`
GREEN=`tput setaf 2`
NC=`tput sgr0`

# (임시) Master IP 설정 값
M_IP=192.168.150.194
SERVERPASS="YourP@ss"
istio_ver=$(get_latest_release istio/istio)
istio_sample_addr="https://raw.githubusercontent.com/istio/istio/master/samples"
internal_ip="$(hostname -I | awk {'print $1'})"
instance_public_ip="$(curl ifconfig.me --silent)"

############ k8s check ###############

if [ -f /etc/rancher/k3s/k3s.yaml ]; then
    echo "${RED}--K3s reset check--${NC}"
    
    echo "k3s reset?"
    read -r -p "Are You Sure? [Y/n] " input
    case $input in
        [yY][eE][sS]|[yY])
    		    echo "Yes"
        /usr/local/bin/k3s-uninstall.sh
        rm -f /etc/sysctl.d/k8s.conf
        rm -rf ~/.kube/
        rm -rf ~/cluster1 ~/cluster2 ~/cluster3
        exit 1
		    ;;
        [nN][oO]|[nN])
		    echo "No"
       		    ;;
        *)
	    echo "Invalid input..."
	    exit 1
	    ;;
    esac
fi

echo "${RED}--Kubectx, Kubens Install Check...--${NC}"

if [ -f /usr/bin/kubectx ]; then
    echo "${RED}--kubectx exist...PASS--${NC}"
else
    echo "${RED}--Kubernetetes : kubectx + kubens downloading...--${NC}"
    git clone https://github.com/ahmetb/kubectx
    cp -r kubectx/kube* /usr/bin/
    rm -rf ./kubectx
    kubectx
fi

M_CHECK=false

echo "master config check"
read -r -p "Are You Master? [Y/n] " input
case $input in
    [yY][eE][sS]|[yY])
        echo "Yes"
    M_CHECK=true
    ;;
    [nN][oO]|[nN])
    echo "No"
    M_CHECK=false
          ;;
    *)
  echo "Invalid input..."
  exit 1
  ;;
esac


############ hostname change ###############
# Hostname 으로, 모든 것이 설정됩니다.
echo "${RED}--HOSTNAME CHANGE (IMPORTANT)--${NC}"
read -p "hostname Change is (ex k8s-worker) : " uhost
hostnamectl set-hostname $uhost
echo '[Hostname] Change Success'
echo "${RED}--HOSTNAME CHANGE END--${NC}"


echo "${RED}--K3s INSTALL CHECK--${NC}"
if [ -f /etc/rancher/k3s/k3s.yaml ]; then
    echo "${RED}--K3s INSTALLED...PASS--${NC}"
else
    echo "${RED}--K3s INSTALLING...--${NC}"
    curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="--no-deploy=servicelb --disable traefik --disable local-storage" sh -s - --cluster-cidr=10.240.0.0/16 --service-cidr=10.110.0.0/16 --node-name=$(hostname) --tls-san=$(curl ifconfig.me --silent) --kube-proxy-arg proxy-mode=ipvs

    if [ -f /etc/sysctl.d/k8s.conf ]; then
        echo "${RED}--System initialized...PASS--${NC}"
    else
        echo "${RED}--Kubernetes initializing...--${NC}"
        swapoff -a
        echo 1 > /proc/sys/net/ipv4/ip_forward
        modprobe br_netfilter
        cat <<EOF > /etc/sysctl.d/k8s.conf
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
EOF
        sysctl --system
        systemctl enable --now k3s
        sudo apt install curl wget vim make sshpass -y
    fi

    echo "${RED}--K3s INSTALL SUCCESS...--${NC}"
fi

if [ -f /etc/rancher/k3s/k3s.yaml ]; then
    # all
    kubectl config set-context default --cluster=$(hostname) &&
    kubectl config set-context default --user=$(hostname) &&
    kubectl config rename-context default $(hostname) &&
    sed -i "s/  name: default/  name: $(hostname)/g" /etc/rancher/k3s/k3s.yaml &&
    sed -i "s/- name: default/- name: $(hostname)/g" /etc/rancher/k3s/k3s.yaml &&
    kubectl get nodes

    kubectl -n kube-system create serviceaccount $(hostname) &&
    kubectl create clusterrolebinding $(hostname) \
      --clusterrole=cluster-admin \
      --serviceaccount=kube-system:$(hostname)

    if [ "$internal_ip" = "$instance_public_ip" ]; then
      echo 'pass'
    else
      sed -i "5s/.*/    server\: https\:\/\/${instance_public_ip}:6443/g" /etc/rancher/k3s/k3s.yaml
      cp /etc/rancher/k3s/k3s.yaml ~/.kube/config
    fi

    kubectl config view


    if [ "$M_CHECK" = true ]; then
      echo "Master Check is " $M_CHECK 
      file=~/cluster2
      while [ ! -f "$file" ]
      do
          echo '-- cluster2 config 파일 수신 대기중.. --'
          sleep 5
      done

      if [ -f ~/cluster2 ]; then
          echo '-- cluster2 config 수신 완료 --'
      fi

      file=~/cluster3
      while [ ! -f "$file" ]
      do
          echo '-- cluster3 config 파일 수신 대기중.. --'
          sleep 5
      done

      if [ -f ~/cluster3 ]; then
          echo '-- cluster3 config 수신 완료 --'
      fi

      if [ -f ~/cluster2 -a -f ~/cluster3 ]; then
          echo '-- cluster2, cluster3 config 수신 완료 --'
          cp /etc/rancher/k3s/k3s.yaml ~/cluster1
          KUBECONFIG=~/cluster1:~/cluster2:~/cluster3: kubectl config view --flatten > ~/merge_kubeconfig
          mv ~/merge_kubeconfig /etc/rancher/k3s/k3s.yaml
          cp /etc/rancher/k3s/k3s.yaml ~/.kube/config
          kubectl config view
          kubectx
      fi

    fi

    if [ "$M_CHECK" = false ]; then
      echo "Master Check is " $M_CHECK 
      echo "Master IP is " $M_IP 
      echo '-- master로 config 파일 수신 처리 --'
      sshpass -p $SERVERPASS scp /etc/rancher/k3s/k3s.yaml ubuntu@$M_IP:/home/ubuntu/$(hostname)
    fi
fi

echo service_cidr=$(echo '{"apiVersion":"v1","kind":"Service","metadata":{"name":"tst"},"spec":{"clusterIP":"1.1.1.1","ports":[{"port":443}]}}' | kubectl apply -f - 2>&1 | sed 's/.*valid IPs is //')

echo "metallb installing..."
#read -r -p "What is Your IP : " internal_ip
kubectl apply -f https://raw.githubusercontent.com/metallb/metallb/master/manifests/namespace.yaml
kubectl apply -f https://raw.githubusercontent.com/metallb/metallb/master/manifests/metallb.yaml
kubectl create secret generic -n metallb-system memberlist --from-literal=secretkey='$(openssl rand -base64 128)'
cat <<EOF | kubectl --context $(hostname) apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  namespace: metallb-system
  name: config
data:
  config: |
    address-pools:
    - name: default
      protocol: layer2
      addresses:
      - ${internal_ip}/32
EOF

kubectl describe configmap/config -n metallb-system


echo "${RED}--istio check start--${NC}"


if [ -d ~/istio-${istio_ver} ]; then
    echo "${RED}--Istio exist.. PASS--${NC}"
else
    echo "${RED}--istio downloading...--${NC}"
    cd ~/
    wget https://github.com/istio/istio/releases/download/${istio_ver}/istio-${istio_ver}-linux-amd64.tar.gz
    tar -xvzf istio-${istio_ver}-linux-amd64.tar.gz
    cp -r ~/istio-${istio_ver}/bin/istioctl /usr/local/bin/
    istioctl version
fi

echo "${RED}--istio end--${NC}"

if [ "$M_CHECK" = true ]; then

    CA_DIR=$(mktemp --tmpdir="${TMPDIR:-/tmp}" -d k8s-ca.XXXXX)
    cd $CA_DIR
    # make -f ~/istio-${istio_ver}/tools/certs/Makefile.selfsigned.mk root-ca
    make -f ~/istio-${istio_ver}/tools/certs/Makefile.selfsigned.mk cluster-cacerts

    for cluster in $(kubectx);
    do
    kubectx $cluster;
    echo "cluster: ${cluster} .........\n"
    kubectl create namespace istio-system;
    kubectl --context=$cluster get ns istio-system &&
    kubectl --context=$cluster label ns istio-system topology.istio.io/network=${cluster} --overwrite
    kubectl --context=$cluster get ns --show-labels | grep istio-system
    kubectl --context=$cluster delete secret cacerts -n istio-system
    kubectl --context=$cluster create secret generic cacerts -n istio-system \
        --from-file=$CA_DIR/cluster/ca-cert.pem \
        --from-file=$CA_DIR/cluster/ca-key.pem \
        --from-file=$CA_DIR/cluster/root-cert.pem \
        --from-file=$CA_DIR/cluster/cert-chain.pem;
    echo "End cluster: ${cluster} .........\n"
    done

    for cluster in $(kubectx);
    do
      kubectx $cluster;
      echo "${RED} istio installing on cluster: ${cluster} .........${NC}"
      cat << EOF | istioctl manifest install -y --context ${cluster} -f -
apiVersion: install.istio.io/v1alpha1
kind: IstioOperator
metadata:
  name: gedge-controlplane
  namespace: istio-system
spec:
  revision: ""
  hub: gcr.io/istio-release
  profile: preview
  meshConfig:
    accessLogFile: /dev/stdout
    # enableAutoMtls: true
    enableTracing: true
    defaultConfig:
      tracing:
        sampling: 100
      proxyMetadata:
        # Enable Istio agent to handle DNS requests for known hosts
        # Unknown hosts will automatically be resolved using upstream dns servers in resolv.conf
        # Enable basic DNS proxying
        ISTIO_META_DNS_CAPTURE: "true"
        # Enable automatic address allocation, optional
        ISTIO_META_DNS_AUTO_ALLOCATE: "true"
  values:
    global:
      pilotCertProvider: istiod
      meshID: mesh1
      multiCluster:
        clusterName: ${cluster}
      network: ${cluster}
    #   meshNetworks:
    #     ${cluster}:
    #       endpoints:
    #         - fromRegistry: ${cluster}
    #       gateways:
    #         - registryServiceName: istio-ingressgateway.istio-system.svc.cluster.local
    #           port: 443
  components:
    ingressGateways:
      - name: istio-ingressgateway
        label:
          istio: ingressgateway
          app: istio-ingressgateway
          topology.istio.io/network: ${cluster}
        enabled: true
        k8s:
          env:
            # sni-dnat adds the clusters required for AUTO_PASSTHROUGH mode
            - name: ISTIO_META_ROUTER_MODE
              value: "sni-dnat"
            # traffic through this gateway should be routed inside the network
            - name: ISTIO_META_REQUESTED_NETWORK_VIEW
              value: ${cluster}
          service:
            ports:
              - name: http2
                port: 80
                targetPort: 8080
              - name: https
                port: 443
                targetPort: 8443
              - name: tls
                port: 15443
                targetPort: 15443
              - name: status-port
                port: 15021
                targetPort: 15021
              - name: tls-xds
                port: 15012
                targetPort: 15012
              - name: tls-webhook
                port: 15017
                targetPort: 15017
    pilot:
      k8s:
        env:
          - name: PILOT_SKIP_VALIDATE_TRUST_DOMAIN
            value: "true"
EOF
    kubectl --context=${cluster} -n istio-system \
      rollout status deploy/istio-ingressgateway || break  
    kubectl get pods -n istio-system --context ${cluster}

    istioctl x create-remote-secret \
      --context=cluster2 \
      --name=cluster2 | \
    kubectl --context=cluster1 apply -f -

    sleep 2

    istioctl x create-remote-secret \
      --context=cluster3 \
      --name=cluster3 | \
    kubectl --context=cluster1 apply -f -


    echo "end cluster: ${cluster} .........\n"
done

fi

if [ "$M_CHECK" = true ]; then

  echo "bookinfo example install check"
  read -r -p "install example? [Y/n] " input
  case $input in
      [yY][eE][sS]|[yY])
          echo "Yes"


          echo "istio PeerAuthentication apply: $(hostname) .........\n"
          cat <<EOF | kubectl --context=$(hostname) -n bookinfo apply -f -
apiVersion: "security.istio.io/v1beta1"
kind: "PeerAuthentication"
metadata:
  name: "default"
spec:
  mtls:
    mode: STRICT
EOF

          echo "${RED} istio multi-cluster bookinfo installing...\n${NC}"
          echo "cluster is ${RED}[$(hostname)]\n${NC}...\n"
          kubectl --context $(hostname) create ns bookinfo
          kubectl --context $(hostname) label namespace bookinfo istio-injection=enabled --overwrite
          kubectl --context $(hostname) get namespace -L istio-injection
          kubectl --context $(hostname) apply -n bookinfo -f ${istio_sample_addr}/bookinfo/platform/kube/bookinfo.yaml -l 'service=productpage' 
          kubectl --context $(hostname) apply -n bookinfo -f ${istio_sample_addr}/bookinfo/platform/kube/bookinfo.yaml -l 'account=productpage' 
          kubectl --context $(hostname) apply -n bookinfo -f ${istio_sample_addr}/bookinfo/platform/kube/bookinfo.yaml -l 'app=productpage'
          kubectl --context $(hostname) apply -n bookinfo -f ${istio_sample_addr}/bookinfo/platform/kube/bookinfo.yaml -l 'account'
          echo "${RED} cluster1 bookinfo - productpage - success\n${NC}"


          echo "cluster is ${RED}[cluster2]\n${NC}...\n"
          kubectl --context cluster2 create ns bookinfo
          kubectl --context cluster2 label namespace bookinfo istio-injection=enabled --overwrite
          kubectl --context cluster2 get namespace -L istio-injection
          kubectl --context cluster2 apply -n bookinfo -f ${istio_sample_addr}/bookinfo/platform/kube/bookinfo.yaml -l 'service=details' 
          kubectl --context cluster2 apply -n bookinfo -f ${istio_sample_addr}/bookinfo/platform/kube/bookinfo.yaml -l 'account=details' 
          kubectl --context cluster2 apply -n bookinfo -f ${istio_sample_addr}/bookinfo/platform/kube/bookinfo.yaml -l 'app=details'
          echo "${RED} cluster2 bookinfo - details - success\n${NC}"

          echo "cluster is ${RED}[cluster3]\n${NC}...\n"
          kubectl --context cluster3 create ns bookinfo
          kubectl --context cluster3 label namespace bookinfo istio-injection=enabled --overwrite
          kubectl --context cluster3 get namespace -L istio-injection
          kubectl --context cluster3 apply -n bookinfo -f ${istio_sample_addr}/bookinfo/platform/kube/bookinfo.yaml -l 'service=reviews' 
          kubectl --context cluster3 apply -n bookinfo -f ${istio_sample_addr}/bookinfo/platform/kube/bookinfo.yaml -l 'account=reviews' 
          kubectl --context cluster3 apply -n bookinfo -f ${istio_sample_addr}/bookinfo/platform/kube/bookinfo.yaml -l 'app=reviews'
          kubectl --context cluster3 apply -n bookinfo -f ${istio_sample_addr}/bookinfo/platform/kube/bookinfo.yaml -l 'service=ratings' 
          kubectl --context cluster3 apply -n bookinfo -f ${istio_sample_addr}/bookinfo/platform/kube/bookinfo.yaml -l 'account=ratings' 
          kubectl --context cluster3 apply -n bookinfo -f ${istio_sample_addr}/bookinfo/platform/kube/bookinfo.yaml -l 'app=ratings'
          echo "${RED} cluster3 bookinfo - reviews, ratings - success\n${NC}"




    for cluster in $(kubectx);
    do
      kubectx $cluster;
      echo "${RED} istio gateway install on cluster: ${cluster} .........${NC}"
      cat << EOF | kubectl --context ${cluster} apply -f -
apiVersion: networking.istio.io/v1alpha3
kind: Gateway
metadata:
  name: gedge-gateway
  namespace: bookinfo
spec:
  selector:
    istio: ingressgateway # use istio default controller
  servers:
  - port:
      number: 80
      name: http
      protocol: HTTP
    hosts:
    - "*"
  - port:
      number: 15443
      name: tls
      protocol: tls
    tls:
      mode: AUTO_PASSTHROUGH
    hosts:
    - "*.local"
    - "*.gedge"
EOF
    done

    kubectx $(hostname)

    cat << EOF | kubectl --context $(hostname) apply -f -
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: bookinfo-vs
  namespace: bookinfo
spec:
  hosts:
  - "${instance_public_ip}.nip.io"
  gateways:
  - gedge-gateway
  http:
  - match:
    - uri:
        exact: /productpage
    - uri:
        prefix: /static
    - uri:
        exact: /login
    - uri:
        exact: /logout
    - uri:
        prefix: /api/v1/products
    route:
    - destination:
        host: productpage
        port:
          number: 9080
---
apiVersion: networking.istio.io/v1alpha3
kind: DestinationRule
metadata:
  name: destination-mtls
  namespace: bookinfo
spec:
  host: "*.gedge"
  trafficPolicy:
    tls:
      mode: ISTIO_MUTUAL
  host: "*.local"
  trafficPolicy:
    tls:
      mode: ISTIO_MUTUAL
  host: "*.nip.io"
  trafficPolicy:
    tls:
      mode: ISTIO_MUTUAL
# ---
# apiVersion: networking.istio.io/v1alpha3
# kind: ServiceEntry
# metadata:
#   name: bookinfo-se
#   namespace: bookinfo
# spec:
#   hosts:
#   - "*.local"
#   location: MESH_INTERNAL
#   addresses:
#   - ${internal_ip}
#   ports:
#   - name: http1
#     number: 80
#     protocol: http
#   resolution: DNS
#   endpoints:
#   - address: $(kubectl get --context=cluster1 svc --selector=app=istio-ingressgateway -n istio-system -o jsonpath='{.items[0].status.loadBalancer.ingress[0].ip}')
#     ports:
#       http1: 15443 # Do not change this port value
#   - address: $(kubectl get --context=cluster2 svc --selector=app=istio-ingressgateway -n istio-system -o jsonpath='{.items[0].status.loadBalancer.ingress[0].ip}')
#     ports:
#       http1: 15443 # Do not change this port value
#   - address: $(kubectl get --context=cluster3 svc --selector=app=istio-ingressgateway -n istio-system -o jsonpath='{.items[0].status.loadBalancer.ingress[0].ip}')
#     ports:
#       http1: 15443
EOF


          echo "${RED} bookinfo check ${NC}"
          for cluster in $(kubectx);
          do
            kubectx $cluster;
            echo ".........${cluster} ........."
            kubectl --context $cluster get pod,svc -n bookinfo
            echo "\n"
          done
          echo "${RED} bookinfo check end ${NC}"
          

          echo "${RED} kiali check ${NC}"
          for cluster in $(kubectx);
          do
            kubectx $cluster;
            echo "${RED}kiali, prometheus installing on cluster: $(hostname) .........${NC}"  
            echo ".........${cluster} ........."
            kubectl --context=${cluster} apply -f ${istio_sample_addr}/addons/prometheus.yaml
            sleep 5  
            kubectl --context=${cluster} apply -f ${istio_sample_addr}/addons/kiali.yaml
            sleep 5
            kubectl --context=${cluster} apply -f ${istio_sample_addr}/addons/jaeger.yaml
          done
          echo "${RED} kiali check end ${NC}"

        
          echo "on cluster: $(hostname) .........\n"
          kubectl --context=$(hostname) get pod,svc -n istio-system
          echo "................................................\n"

          until [ $(kubectl --context $(hostname) -n istio-system get pods -o jsonpath='{range .items[*].status.containerStatuses[*]}{.ready}{"\n"}{end}' | grep false -c) -eq 0 ]; do
            echo "$(hostname) cluster - Waiting for all the istio-system pods to become ready"
            kubectl --context $(hostname) -n istio-system get pods
            sleep 2
          done

          kubectl --context=$(hostname) patch svc kiali -n istio-system -p '{"spec": {"type": "NodePort"}}'
          kubectl --context=$(hostname) patch svc tracing -n istio-system -p '{"spec": {"type": "NodePort"}}'

          until [ $(kubectl --context $(hostname) -n bookinfo get pods -o jsonpath='{range .items[*].status.containerStatuses[*]}{.ready}{"\n"}{end}' | grep false -c) -eq 0 ]; do
            echo "$(hostname) cluster - Waiting for all the bookinfo pods to become ready"
            kubectl --context $(hostname) -n bookinfo get pods
            sleep 2
          done
          echo "bookinfo success\n"  

      cat << EOF | kubectl --context $(hostname) -n istio-system apply -f -
apiVersion: networking.istio.io/v1alpha3
kind: Gateway
metadata:
  name: metrics-gateway
spec:
  selector:
    istio: ingressgateway # use istio default controller
  servers:
  - port:
      number: 80
      name: http
      protocol: HTTP
    hosts:
    - "*"
---
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: istio-metrics-vs
spec:
  hosts:
  - "${instance_public_ip}.nip.io"
  gateways:
  - metrics-gateway
  http:
  - match:
    - uri:
        prefix: /kiali
    route:
    - destination:
        host: kiali.istio-system.svc.cluster.local
        port:
          number: 20001
  - match:
    - uri:
        prefix: /jaeger
    route:
    - destination:
        host: tracing.istio-system.svc.cluster.local
        port:
          number: 80
EOF

          kubectl --context=$(hostname) patch svc productpage -n bookinfo -p '{"spec": {"type": "NodePort"}}'

          echo "bookinfo productpage uri is
    - http://$(curl ifconfig.me --silent):$(kubectl --context=$(hostname) get -o jsonpath="{.spec.ports[0].nodePort}" svc productpage -n bookinfo)
    - http://$(curl ifconfig.me --silent).nip.io/productpage
          "

          echo "kiali Webpage uri is
    - http://$(curl ifconfig.me --silent):$(kubectl --context=$(hostname) get -o jsonpath="{.spec.ports[0].nodePort}" svc kiali -n istio-system)
    - http://$(curl ifconfig.me --silent).nip.io/kiali
          "

          echo "jaeger Webpage uri is
    - http://$(curl ifconfig.me --silent):$(kubectl --context=$(hostname) get -o jsonpath="{.spec.ports[0].nodePort}" svc tracing -n istio-system)
    - http://$(curl ifconfig.me --silent).nip.io/jaeger
          "


          echo "${RED} ........script end .........${NC}"  
          
          echo "${RED} ........ productpage curling .........${NC}"  
      for i in $(seq 1 100); do curl -s -o /dev/null "http://$(curl ifconfig.me --silent).nip.io/productpage"; done

      ;;
      [nN][oO]|[nN])
      echo "No"
            ;;
      *)
    echo "Invalid input..."
    exit 1
    ;;
  esac

fi
