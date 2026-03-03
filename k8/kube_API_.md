### 1. Modern Kubelet API Interaction (Port 10250)
Modern clusters (EKS 1.24+) generally disable anonymous auth by default.

**Testing Auth Status:**
```bash
# Check if anonymous auth is enabled
curl -skI https://localhost:10250/pods/

# 401 Unauthorized = Anonymous disabled (Standard/Secure)
# 403 Forbidden = Anonymous enabled, but RBAC blocks listing (Common)
# 200 OK = Critical misconfiguration (AlwaysAllow)
```

**Executing via Kubelet (Directly on Node):**
In 2026, `curl` requires a SPDY or WebSocket upgrade header to handle the stream correctly. Simple `touch` commands via `GET/POST` often fail because the Kubelet expects an **"Upgrade"** to a bi-directional stream.

```bash
# Using a tool like 'wscat' or 'websocat' is now the standard for direct Kubelet exec
websocat -kn1 --header "Authorization: Bearer $(cat /var/lib/kubelet/pki/kubelet-client.crt)" \
"wss://localhost:10250/exec/<ns>/<pod>/<container>?command=id&input=1&output=1&tty=1"
```

---

### 2. Modifying Kubelet Config (Modern Way)
Systemd drop-in files are still used, but the core configuration has moved to a versioned YAML file.

**Path:** `/var/lib/kubelet/config.yaml`
```bash
# 1. Edit the YAML directly for permanent changes
sudo vi /var/lib/kubelet/config.yaml

# 2. To change flags (e.g., enable/disable auth), check drop-ins:
# Look for 'EnvironmentFile' in the output of:
systemctl cat kubelet

# 3. Reload and Restart
sudo systemctl daemon-reload && sudo systemctl restart kubelet
```

---

### 3. Iptables Persistence (2026 Refactor)
Legacy `iptables-restore` is being replaced by `nftables` in many distros (Ubuntu 24.04+), but `iptables-nft` remains the K8s standard. We now use **DOCKER-USER** chain as it survives Docker restarts.

**File:** `/etc/iptables.rules`
```text
*filter
:INPUT ACCEPT [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
:DOCKER-USER - [0:0]

# Allow established traffic
-A DOCKER-USER -m state --state RELATED,ESTABLISHED -j ACCEPT

# Allow internal Pod-to-Pod traffic (example CIDR)
-A DOCKER-USER -s 10.244.0.0/16 -j ACCEPT

# Block external access to Kubelet and NodePorts from outside the VPC
-A DOCKER-USER -i eno1 -p tcp --match multiport --dports 10250,30000:32767 -j DROP

# Log drops (Rate limited to prevent disk filling)
-A DOCKER-USER -m limit --limit 5/min -j LOG --log-prefix "K8S-BLOCK: "
-A DOCKER-USER -j RETURN
COMMIT
```

**Systemd Service:** `/etc/systemd/system/iptables-restore.service`
```ini
[Unit]
Description=Restore Iptables Rules
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
ExecStart=/sbin/iptables-restore /etc/iptables.rules
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
```

---

### 4. Talking to Kube API (The 2026 Way)
Kubernetes **no longer creates ServiceAccount tokens** as Secrets automatically. You must use the `TokenRequest` API or fetch the projected volume token.

#### Method A: The Temporary Proxy (Standard Dev)
```bash
# Bind to all interfaces (Careful!)
kubectl proxy --address='0.0.0.0' --accept-hosts='^*$' &
```

#### Method B: Direct API Access (The Red Team / Admin Way)
Since 1.24+, tokens aren't in `kubectl get secrets`. Use this one-liner:

```bash
# 1. Define APISERVER
APISERVER=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')

# 2. Create an ephemeral Token (Valid for 1 hour)
TOKEN=$(kubectl create token default)

# 3. Access API
curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/namespaces/default/pods"
```

#### Method C: Accessing from *Inside* a Pod
If you've compromised a pod, the token is at `/var/run/secrets/kubernetes.io/serviceaccount/token`.

```bash
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
CACERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt

# Query using the internal CA for 0 SSL warnings
curl --cacert $CACERT -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api/v1/pods
```

---

### 5. Bonus: Discovery (IMDSv2)
If you are on an EKS node, you often need to bypass IMDSv2 (Session Tokens) to get the Node's IAM Role.

```bash
# 1. Get Session Token
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")

# 2. Use Token to get IAM Credentials
ROLE_NAME=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" -s http://169.254.169.254/latest/meta-data/iam/security-credentials/)
curl -H "X-aws-ec2-metadata-token: $TOKEN" -s http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE_NAME
```



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

