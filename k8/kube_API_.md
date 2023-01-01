# Accessing Kubelet API

```bash
curl -sk https://localhost:10250/pods/
```

* If `--anonymous-auth` is turned off, you will see a `401 Unauthorized` response.
* If `--anonymous-auth` is `true` and `--authorization-mode` is `Webhook` you'll see `403 Forbidden` response with message `Forbidden (user=system:anonymous, verb=get, resource=nodes, subresource=proxy)`
* If `--anonymous-auth` is `true` and `--authorization-mode` is `AlwaysAllow` you'll see a list of pods.

## Execing into a pod

```bash
curl -skv -X POST -H "X-Stream-Protocol-Version: v2.channel.k8s.io" -H "X-Stream-Protocol-Version: channel.k8s.io" "https://localhost:10250/exec/<namespace>/<pod name>/<container name>/?command=touch&command=hello_world&input=1&output=1&tty=1"
```
This gives a `302 Found` response on v1.9 but execing into the pod directly shows no evidence of the file being created. On v1.11 there was an `Upgrade request required` response - maybe TLS issue?

## Changing kubelet settings 

Edit `/etc/systemd/system/kubelet.service.d/10-kubeadm.conf`

```bash
sudo systemctl daemon-reload
sudo systemctl restart kubelet.service
```

Or, if the settings are in /var/lib/kubelet/config.yaml, edit the config file and then `sudo systemctl restart kubelet.service`.

#
# https://gist.github.com/gbevan/8a0a786cfc2728cd2998f868b0ff5b72
#


Fix internet access for microk8s pods
etc_iptables.conf
# see https://unrouted.io/2017/08/15/docker-firewall/
*filter
:INPUT ACCEPT [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
:FILTERS - [0:0]
:DOCKER-USER - [0:0]

-F INPUT
-F DOCKER-USER
-F FILTERS

-A INPUT -i lo -j ACCEPT
-A INPUT -p icmp --icmp-type any -j ACCEPT
-A INPUT -j FILTERS

# you may need to change this, replace eno1 with the nic bound to your external ip
-A DOCKER-USER -i eno1 -j FILTERS
-A DOCKER-USER -i cbr0 -j FILTERS

-A FILTERS -m state --state ESTABLISHED,RELATED -j ACCEPT
# open access for dev
-A FILTERS -m state --state NEW -s 0.0.0.0/0 -j ACCEPT

# you might want more restructive permissions
#-A FILTERS -m state --state NEW -s 192.168.0.0/24 -j ACCEPT
#-A FILTERS -m state --state NEW -m tcp -p tcp --dport 22 -j ACCEPT
#-A FILTERS -m state --state NEW -m tcp -p tcp --dport 23 -j ACCEPT
#-A FILTERS -m state --state NEW -m tcp -p tcp --dport 80 -j ACCEPT
#-A FILTERS -m state --state NEW -m tcp -p tcp --dport 443 -j ACCEPT

# Log&Reject everything else
-A FILTERS -j LOG --log-prefix "IPTables-Dropped: "
-A FILTERS -j REJECT --reject-with icmp-host-prohibited

COMMIT
etc_systemd_system_iptables.service
# see https://unrouted.io/2017/08/15/docker-firewall/

[Unit]
Description=Restore iptables firewall rules
Before=network-pre.target

[Service]
Type=oneshot
ExecStart=/sbin/iptables-restore -n /etc/iptables.conf

[Install]
WantedBy=multi-user.target


#
##
##
#

## Resources
  * https://kubernetes.io/docs/tasks/administer-cluster/access-cluster-api/
  * https://thenewstack.io/taking-kubernetes-api-spin/ <-- This is just in case.

## Main Stuff
There are two ways you can talk to the KUBE API.

### Kube-proxy
Start a kube proxy server which will act as a reverse proxy for the client.
```
kubectl proxy --port <PORT_NUMBER> &
curl -s http://localhost:<PORT_NUMBER>/
curl -s http://localhost:<PORT_NUMBER>/api/v1/nodes | jq '.items[].metadata.labels'
```

### Direct KUBE API
Get token and URL from cluster and directly talk to Kube API.

**Note:** *Unless you figure out a way to get the call to use root certificates from the system, you will not be able to access privileged data. Best to stick to option #1.*
```
APISERVER=$(kubectl config view | grep server | cut -f 2- -d ":" | tr -d " ")
TOKEN=$(kubectl describe secret $(kubectl get secrets | grep default | cut -f1 -d ' ') | grep -E '^token' | cut -f2 -d':' | tr -d '\t')
curl $APISERVER/api --header "Authorization: Bearer $TOKEN" --insecure
```

