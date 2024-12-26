
##
#
https://medium.com/@achanandhi.m/install-k3s-on-a-remote-machine-using-k3sup-756bbfb09ed4
#
https://nerc-project.github.io/nerc-docs/other-tools/kubernetes/k3s/k3s-using-k3sup/
#
https://github.com/alexellis/k3sup
#
##

k3sup 🚀 (said 'ketchup')

k3sup logo

k3sup is a light-weight utility to get from zero to KUBECONFIG with k3s on any local or remote VM. All you need is ssh access and the k3sup binary to get kubectl access immediately.

The tool is written in Go and is cross-compiled for Linux, Windows, MacOS and even on Raspberry Pi.

How do you say it? Ketchup, as in tomato.

Sponsor this License: MIT build Github All Releases
Contents:

    k3sup 🚀 (said 'ketchup')
        Contents:
        What's this for? 💻
        Do you love k3sup?
            Uses
            Bootstrapping Kubernetes
        Download k3sup (tl;dr)
            A note for Windows users
        Demo 📼
        Usage ✅
        Pre-requisites for k3sup servers and agents
            👑 Setup a Kubernetes server with k3sup
            Checking if a cluster is ready
            Merging clusters into your KUBECONFIG
            😸 Join some agents to your Kubernetes server
            Use your hardware authentication / 2FA or SSH Agent
            K3sup plan for automation
            Create a multi-master (HA) setup with external SQL
            Create a multi-master (HA) setup with embedded etcd
            👨‍💻 Micro-tutorial for Raspberry Pi (2, 3, or 4) 🥧
        Caveats on security
        Contributing
            Blog posts & tweets
            Contributing via GitHub
            License
        📢 What are people saying about k3sup?
        Similar tools & glossary
        Troubleshooting and support
            Maybe the problem is with K3s?
            Common issues
            Support and k3sup for commercial use
            Getting access to your KUBECONFIG
            Smart cards and 2FA
            Misc note on iptables

What's this for? 💻

This tool uses ssh to install k3s to a remote Linux host. You can also use it to join existing Linux hosts into a k3s cluster as agents. First, k3s is installed using the utility script from Rancher, along with a flag for your host's public IP so that TLS works properly. The kubeconfig file on the server is then fetched and updated so that you can connect from your laptop using kubectl.

You may wonder why a tool like this needs to exist when you can do this sort of thing with bash.

k3sup was developed to automate what can be a very manual and confusing process for many developers, who are already short on time. Once you've provisioned a VM with your favourite tooling, k3sup means you are only 60 seconds away from running kubectl get pods on your own computer. If you are a local computer, you can bypass SSH with k3sup install --local
Do you use k3sup?

k3sup was created by Alex Ellis - the founder of OpenFaaS ® & inlets.
Sponsor this project

Want to see continued development? Sponsor alexellis on GitHub
Uses

    Bootstrap Kubernetes with k3s onto any VM with k3sup install - either manually, during CI or through cloud-init
    Get from zero to kubectl with k3s on Raspberry Pi (RPi), VMs, AWS EC2, Packet bare-metal, DigitalOcean, Civo, Scaleway, and others
    Build a HA, multi-master (server) cluster
    Fetch the KUBECONFIG from an existing k3s cluster
    Join nodes into an existing k3s cluster with k3sup join

Bootstrapping Kubernetes

Conceptual architecture Conceptual architecture, showing k3sup running locally against any VM such as AWS EC2 or a VPS such as DigitalOcean.
Download k3sup (tl;dr)

k3sup is distributed as a static Go binary. You can use the installer on MacOS and Linux, or visit the Releases page to download the executable for Windows.

curl -sLS https://get.k3sup.dev | sh
sudo install k3sup /usr/local/bin/

k3sup --help

A note for Windows users

Windows users can use k3sup install and k3sup join with a normal "Windows command prompt".
Demo 📼

In the demo I install Kubernetes (k3s) onto two separate machines and get my kubeconfig downloaded to my laptop each time in around one minute.

    Ubuntu 18.04 VM created on DigitalOcean with ssh key copied automatically
    Raspberry Pi 4 with my ssh key copied over via ssh-copy-id

Watch the demo:

asciicast
Usage ✅

The k3sup tool is a client application which you can run on your own computer. It uses SSH to connect to remote servers and creates a local KUBECONFIG file on your disk. Binaries are provided for MacOS, Windows, and Linux (including ARM).
Pre-requisites for k3sup servers and agents

Some Linux hosts are configured to allow sudo to run without having to repeat your password. For those which are not already configured that way, you'll need to make the following changes if you wish to use k3sup:

# sudo visudo

# Then add to the bottom of the file
# replace "alex" with your username i.e. "ubuntu"
alex ALL=(ALL) NOPASSWD: ALL

In most circumstances, cloud images for Ubuntu and other distributions will not require this step.

As an alternative, if you only need a single server you can log in interactively and run k3sup install --local instead of using SSH.
👑 Setup a Kubernetes server with k3sup

You can setup a server and stop here, or go on to use the join command to add some "agents" aka nodes or workers into the cluster to expand its compute capacity.

Provision a new VM running a compatible operating system such as Ubuntu, Debian, Raspbian, or something else. Make sure that you opt-in to copy your registered SSH keys over to the new VM or host automatically.

    Note: You can copy ssh keys to a remote VM with ssh-copy-id user@IP.

Imagine the IP was 192.168.0.1 and the username was ubuntu, then you would run this:

    Run k3sup:

export IP=192.168.0.1
k3sup install --ip $IP --user ubuntu

# Or use a hostname and SSH key for EC2
export HOST="ec2-3-250-131-77.eu-west-1.compute.amazonaws.com"
k3sup install --host $HOST --user ubuntu \
  --ssh-key $HOME/ec2-key.pem

Other options for install:

    --cluster - start this server in clustering mode using embedded etcd (embedded HA)
    --skip-install - if you already have k3s installed, you can just run this command to get the kubeconfig
    --ssh-key - specify a specific path for the SSH key for remote login
    --local - Perform a local install without using ssh
    --local-path - default is ./kubeconfig - set the file where you want to save your cluster's kubeconfig. By default this file will be overwritten.
    --merge - Merge config into existing file instead of overwriting (e.g. to add config to the default kubectl config, use --local-path ~/.kube/config --merge).
    --context - default is default - set the name of the kubeconfig context.
    --ssh-port - default is 22, but you can specify an alternative port i.e. 2222
    --no-extras - disable "servicelb" and "traefik"
    --k3s-extra-args - Optional extra arguments to pass to k3s installer, wrapped in quotes, i.e. --k3s-extra-args '--disable traefik' or --k3s-extra-args '--docker'. For multiple args combine then within single quotes --k3s-extra-args '--disable traefik --docker'.
    --k3s-version - set the specific version of k3s, i.e. v1.21.1
    --k3s-channel - set a specific version of k3s based upon a channel i.e. stable

    --ipsec - Enforces the optional extra argument for k3s: --flannel-backend option: ipsec

    --print-command - Prints out the command, sent over SSH to the remote computer
    --datastore - used to pass a SQL connection-string to the --datastore-endpoint flag of k3s. You must use the format required by k3s in the Rancher docs.

See even more install options by running k3sup install --help.

    Now try the access:

export KUBECONFIG=`pwd`/kubeconfig
kubectl get node

Note that you should always use pwd/ so that a full path is set, and you can change directory if you wish.
Checking if a cluster is ready

There are various ways to confirm whether a cluster is ready to use.

K3sup runs the "kubectl get nodes" command using a KUBECONFIG file, and looks for the "Ready" status on each node, including agents/workers.

Install K3s directly on the node and then check if it's ready:

k3sup install \
  --local \
  --context localk3s

k3sup ready \
  --context localk3s \
  --kubeconfig ./kubeconfig

Check a remote server saved to a local file:

k3sup install \
  --ip 192.168.0.101 \
  --user pi

k3sup ready \
  --context default \
  --kubeconfig ./kubeconfig

Check a merged context in your default KUBECONFIG:

k3sup install \
  --ip 192.168.0.101 \
  --user pi \
  --context pik3s \
  --merge \
  --local-path $HOME/.kube/config

# $HOME/.kube/config is a default for kubeconfig
k3sup ready --context pik3s

Merging clusters into your KUBECONFIG

You can also merge the remote config into your main KUBECONFIG file $HOME/.kube/config, then use kubectl config get-contexts or kubectx to manage it.

The default "context" name for the remote k3s cluster is default, however you can override this as below.

For example:

k3sup install \
  --ip $IP \
  --user $USER \
  --merge \
  --local-path $HOME/.kube/config \
  --context my-k3s

Here we set a context of my-k3s and also merge into our main local KUBECONFIG file, so we could run kubectl config use-context my-k3s or kubectx my-k3s.
😸 Join some agents to your Kubernetes server

Let's say that you have a server, and have already run the following:

export SERVER_IP=192.168.0.100
export USER=root

k3sup install --ip $SERVER_IP --user $USER

Next join one or more agents to the cluster:

export AGENT_IP=192.168.0.101

export SERVER_IP=192.168.0.100
export USER=root

k3sup join --ip $AGENT_IP --server-ip $SERVER_IP --user $USER

Please note that if you are using different usernames for SSH'ing to the agent and the server that you must provide the username for the server via the --server-user parameter.

That's all, so with the above command you can have a two-node cluster up and running, whether that's using VMs on-premises, using Raspberry Pis, 64-bit ARM or even cloud VMs on EC2.
Use your hardware authentication / 2FA or SSH Agent

You may wish to use the ssh-agent utility if:

    Your SSH key is protected by a password, and you don't want to type it in for each k3sup command
    You use a hardware authentication device key like a Yubico YubiKey to authenticate SSH sessions

Run the following to set SSH_AUTH_SOCK:

$ eval $(ssh-agent)
Agent pid 2641757

Optionally, if your key is encrypted, run: ssh-add ~/.ssh/id_rsa

Now run any k3sup command, and your SSH key will be requested from the ssh-agent instead of from the usual location.

You can also specify an SSH key with --ssh-key if you want to use a specific key-pair.
K3sup plan for automation

A new command was added to k3sup to help with automating large amounts of nodes.

k3sup plan reads a JSON input file containing hosts, and will generate an installation command for a number of servers and agents.

Example input file:

[
  {
    "hostname": "node-a-1",
    "ip": "192.168.129.138"
  },
  {
    "hostname": "node-a-2",
    "ip": "192.168.129.128"
  },
  {
    "hostname": "node-a-3",
    "ip": "192.168.129.131"
  },
  {
    "hostname": "node-a-4",
    "ip": "192.168.129.130"
  },
  {
    "hostname": "node-a-5",
    "ip": "192.168.129.127"
  }
]

The following will create 1x primary server, with 2x additional servers within a HA etcd cluster, the last two nodes will be added as agents:

k3sup plan \
  devices.json \
  --user ubuntu \
  --servers 3 \
  --server-k3s-extra-args "--disable traefik" \
  --background > bootstrap.sh

Then make the file executable and run it:

chmod +x bootstrap.sh
./bootstrap.sh

Watch a demo with dozens of Firecracker VMs: Testing Kubernetes at Scale with bare-metal

The initial version of k3sup plan has a reduced set of flags. Flags such as --k3s-version and --datastore are not available, but feel free to propose an issue with what you need.
Create a multi-master (HA) setup with external SQL

The easiest way to test out k3s' multi-master (HA) mode with external storage, is to set up a Mysql server using DigitalOcean's managed service.

    Get the connection string from your DigitalOcean dashboard, and adapt it

Before:

mysql://doadmin:80624d3936dfc8d2e80593@db-mysql-lon1-90578-do-user-6456202-0.a.db.ondigitalocean.com:25060/defaultdb?ssl-mode=REQUIRED

After:

mysql://doadmin:80624d3936dfc8d2e80593@tcp(db-mysql-lon1-90578-do-user-6456202-0.a.db.ondigitalocean.com:25060)/defaultdb

Note that we've removed ?ssl-mode=REQUIRED and wrapped the host/port in tcp().

export DATASTORE="mysql://doadmin:80624d3936dfc8d2e80593@tcp(db-mysql-lon1-90578-do-user-6456202-0.a.db.ondigitalocean.com:25060)/defaultdb

You can prefix this command with   two spaces, to prevent it being cached in your bash history.

Generate a token used to encrypt data (If you already have a running node this can be retrieved by logging into a running node and looking in /var/lib/rancher/k3s/server/token)

# Best option for a token:
export TOKEN=$(openssl rand -base64 64)

# Fallback for no openssl, on a Linux host:
export TOKEN=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 64)

# Failing that, then try:
export TOKEN=$(head -c 64 /dev/urandom|shasum| cut -d - -f 1)

    Create three VMs

Imagine we have the following three VMs, two will be servers, and one will be an agent.

export SERVER1=104.248.135.109
export SERVER2=104.248.25.221
export AGENT1=104.248.137.25

    Install the first server

k3sup install --user root --ip $SERVER1 --datastore="${DATASTORE}" --token=${TOKEN}

    Install the second server

k3sup install --user root --ip $SERVER2 --datastore="${DATASTORE}" --token=${TOKEN}

    Join the first agent

You can join the agent to either server, the datastore is not required for this step.

k3sup join --user root --server-ip $SERVER1 --ip $AGENT1

Please note that if you are using different usernames for SSH'ing to the agent and the server that you must provide the username for the server via the --server-user parameter.

    Additional steps

If you run kubectl get node, you'll now see two masters/servers and one agent, however, we joined the agent to the first server. If the first server goes down, the agent will effectively also go offline.

kubectl get node

NAME              STATUS                        ROLES    AGE     VERSION
k3sup-1           Ready                         master   73s     v1.19.6+k3s1
k3sup-2           Ready                         master   2m31s   v1.19.6+k3s1
k3sup-3           Ready                         <none>   14s     v1.19.6+k3s1

There are two ways to prevent a dependency on the IP address of any one host. The first is to create a TCP load-balancer in the cloud of your choice, the second is for you to create a DNS round-robbin record, which contains all of the IPs of your servers.

In your DigitalOcean dashboard, go to the Networking menu and click "Load Balancer", create one in the same region as your Droplets and SQL server. Select your two Droplets, i.e. 104.248.34.61 and 142.93.175.203, and use TCP with port 6443.

If you want to run k3sup join against the IP of the LB, then you should also add TCP port 22

Make sure that the health-check setting is also set to TCP and port 6443. Wait to get your IP, mine was: 174.138.101.83

Save the LB into an environment variable:

export LB=174.138.101.83

Now use ssh to log into both of your servers, and edit their config files at /etc/systemd/system/k3s.service, update the lines --tls-san and the following address, to that of your LB:

ExecStart=/usr/local/bin/k3s \
    server \
        '--tls-san' \
        '104.248.135.109' \

Becomes:

ExecStart=/usr/local/bin/k3s \
    server \
        '--tls-san' \
        '174.138.101.83' \

Now run:

sudo systemctl daemon-reload && \
  sudo systemctl restart k3s-agent

And repeat these steps on the other server.

You can update the agent manually, via ssh and edit /etc/systemd/system/k3s-agent.service.env on the host, or use k3sup join again, but only if you added port 22 to your LB:

k3sup join --user root --server-ip $LB --ip $AGENT1

Finally, regenerate your KUBECONFIG file with the LB's IP, instead of one of the servers:

k3sup install --skip-install --ip $LB

Log into the first server, and stop k3s sudo systemctl stop k3s, then check that kubectl still functions as expected:

export KUBECONFIG=`pwd`/kubeconfig
kubectl get node -o wide

NAME              STATUS                        ROLES    AGE   VERSION
k3sup-1           NotReady                      master   23m   v1.19.6+k3s1
k3sup-2           Ready                         master   25m   v1.19.6+k3s1
k3sup-3           Ready                         <none>   22m   v1.19.6+k3s1

You've just simulated a failure of one of your masters/servers, and you can still access kubectl. Congratulations on building a resilient k3s cluster.
Create a multi-master (HA) setup with embedded etcd

In k3s v1.19.5+k3s1 a HA multi-master (multi-server in k3s terminology) configuration is available called "embedded etcd". A quorum of servers will be required, which means having an odd number of nodes and least three. See more

    Initialize the cluster with the first server

Note the --cluster flag

export SERVER_IP=192.168.0.100
export USER=root

k3sup install \
  --ip $SERVER_IP \
  --user $USER \
  --cluster \
  --k3s-version v1.19.1+k3s1

    Join each additional server

    Note the new --server flag

export USER=root
export SERVER_IP=192.168.0.100
export NEXT_SERVER_IP=192.168.0.101

k3sup join \
  --ip $NEXT_SERVER_IP \
  --user $USER \
  --server-user $USER \
  --server-ip $SERVER_IP \
  --server \
  --k3s-version v1.19.1+k3s1

Now check kubectl get node:

kubectl get node
NAME              STATUS   ROLES    AGE     VERSION
paprika-gregory   Ready    master   8m27s   v1.19.2-k3s
cave-sensor       Ready    master   27m     v1.19.2-k3s

If you used --no-extras on the initial installation you will also need to provide it on each join:

export USER=root
export SERVER_IP=192.168.0.100
export NEXT_SERVER_IP=192.168.0.101

k3sup join \
  --ip $NEXT_SERVER_IP \
  --user $USER \
  --server-user $USER \
  --server-ip $SERVER_IP \
  --server \
  --no-extras \
  --k3s-version v1.19.1+k3s1

👨‍💻 Micro-tutorial for Raspberry Pi (2, 3, or 4) 🥧

In a few moments you will have Kubernetes up and running on your Raspberry Pi 2, 3 or 4. Stand by for the fastest possible install. At the end you will have a KUBECONFIG file on your local computer that you can use to access your cluster remotely.

Conceptual architecture, showing k3sup running locally against bare-metal ARM devices.

    Download etcher.io for your OS

    Flash an SD card using Raspbian Lite

    Enable SSH by creating an empty file named ssh in the boot partition

    Generate an ssh-key if you don't already have one with ssh-keygen (hit enter to all questions)

    Find the RPi IP with ping -c raspberrypi.local, then set export SERVER_IP="" with the IP

    Enable container features in the kernel, by editing /boot/cmdline.txt (or /boot/firmware/cmdline.txt on Ubuntu)

    Add the following to the end of the line:  cgroup_enable=cpuset cgroup_memory=1 cgroup_enable=memory

    Copy over your ssh key with: ssh-copy-id pi@raspberrypi.local

    Run k3sup install --ip $SERVER_IP --user pi

    Point at the config file and get the status of the node:

export KUBECONFIG=`pwd`/kubeconfig
kubectl get node -o wide

You now have kubectl access from your laptop to your Raspberry Pi running k3s.

If you want to join some nodes, run export IP="" for each additional RPi, followed by:

    k3sup join --ip $IP --server-ip $SERVER_IP --user pi

    Remember all these commands are run from your computer, not the RPi.

Now where next? I would recommend my detailed tutorial where I spend time looking at how to flash the SD card, deploy k3s, deploy OpenFaaS (for some useful microservices), and then get incoming HTTP traffic.

Try it now: Will it cluster? K3s on Raspbian
Caveats on security

If you are using public cloud, then make sure you see the notes from the Rancher team on setting up a Firewall or Security Group.

k3s docs: k3s configuration / open ports
Contributing
Blog posts & tweets

Blogs posts, tutorials, and Tweets about k3sup (#k3sup) are appreciated. Please send a PR to the README.md file to add yours.
Contributing via GitHub

Before contributing code, please see the CONTRIBUTING guide. Note that k3sup uses the same guide arkade

Both Issues and PRs have their own templates. Please fill out the whole template.

All commits must be signed-off as part of the Developer Certificate of Origin (DCO)
License

MIT
📢 What are people saying about k3sup?

    Five years of Raspberry Pi clusters - raspberrypi.org

    Multi-master HA Kubernetes in < 5 minutes by Alex Ellis

    Kubernetes Homelab with Raspberry Pi and k3sup

    Building a Kubernetes cluster on Raspberry Pi running Ubuntu server by Jakub Czapliński

    Multi-node Kubernetes on Civo in 5 minutes flat with k3sup! - Civo Learn guide

    Zero to k3s Kubeconfig in seconds on AWS EC2 with k3sup by Saiyam Pathak

    Create a 3-node k3s cluster with k3sup & DigitalOcean

    Cheap k3s cluster using Amazon Lightsail

    k3sup mentioned on Kubernetes Podcast episode 67 by Craig Box & Adam Glick

    Scheduling Kubernetes workloads to Raspberry Pi using Inlets and Crossplane by Daniel Mangum
        Also checkout the live demo

    Blog post by Ruan Bekker:

        Provision k3s to all the places with a awesome utility called "k3sup" by @alexellisuk. Definitely worth checking it out, its epic!

    Provision k3s on the fly with k3sup

    Dave Cadwallader (@geek_dave):

        Alex - Thanks so much for all the effort you put into your tools and tutorials. My rpi homelab has been a valuable learning playground for CNCF tech thanks to you!

    k3sup in KubeWeekly #181

    Will it cluster? K3s on Raspbian

    Kubernetes the Easy Way with k3sup – Cisco DevOps Series

    Trying tiny k3s on Google Cloud with k3sup by Stark & Wayne

    Setting up a Raspberry Pi Kubernetes Cluster with Blinkt! Strips that Show Number of Pods per Node

    From Zero to Kubernetes Dashboard within Minutes with k3sup and Kontena Lens - by Lauri Nevala

    BYOK - Build your Own Kubernetes Cluster with Raspberry Pis, k3s, and k3sup by Michael Irwin

    Run Kubernetes On Your Machine with k3sup by Luc Juggery

    Trying out k3sup by Geert Baeke

    Creating your first Kubernetes cluster with k3sup by Daniel Persson

    My 2019 In Review - Hello Open Source by Alistair Hey

    Kubernetes 104: Create a 2-node k3s cluster with k3sup by Ahmed Abelsamad

    My home Kubernetes cluster driven by GitOps and k3sup - by Devin Buhl

    Raspberry Pi: From 0 to k3s cluster in 5 min with k3sup and Ansible - by Pablo Caderno

    Kubernetes: from Zero to Hero with Kompose, Minikube, k3sup and Helm by Leon Klingele, Alexander Merker & Florian Wintel

    Deploying a highly-available K3s with k3sup by Dmitriy Akulov

    Multi-master HA Kubernetes using K3Sup on Windows10/Server 2019 by Aaron Holt

    Ansible Role: k3sup by Ivan Vandot

    HashiCorp Vault on K3s on RPi4 by Colin McCarthy

    Raspberry Pi Cluster Part 2: ToDo API running on Kubernetes with k3s by Dino Fizzotti

    Cloud Native Tools for Developers Webinar Recap by Alex Ellis & Alistair Hey

    Unobtrusive local development with kubernetes, k3s, traefik2 by Vyacheslav

    Cómo desplegar un clúster de Kubernetes en 60 segundos con k3sup by Ignacio Van Droogenbroeck

    Raspberry Kubernetes cluster for my homlab with k3sup by Nicola Ballotta

    k3sup On MacOS Catalina by John Doyle

    Provision k3s on Google Cloud with Terraform and k3sup — Nimble by Carlos Herrera

    K3s: Edge Kubernetes by James Governor

    OpenStack sur LXD avec Juju et k3sup dans phoenixNAP

    Creating a k3s Cluster with k3sup & Multipass 💻☸️ by Tom Watt

    How I’ve set up my highly-available Kubernetes cluster by JJ Macalinao

    Creating a K3S Raspberry PI Cluster with K3Sup to fire up nightscout with MongoDB

    Kubernetes Cluster with Rancher on Windows using K3s by Adyanth H

    k3s in LXC on Proxmox with k3sup by Todd Edwards

Checkout the Announcement tweet
Similar tools & glossary

Glossary:

    Kubernetes: master/slave
    k3s: server/agent

Related tools:

    k3s - Kubernetes as installed by k3sup. k3s is a compliant, light-weight, multi-architecture distribution of Kubernetes. It can be used to run Kubernetes locally or remotely for development, or in edge locations.
    k3d - this tool runs a Docker container on your local laptop with k3s inside
    kind - kind can run a Kubernetes cluster within a Docker container for local development. k3s is also suitable for this purpose through k3d. KinD is not suitable for running a remote cluster for development.
    kubeadm - a tool to create fully-loaded, production-ready Kubernetes clusters with or without high-availability (HA). Tends to be heavier-weight and slower than k3s. It is aimed at cloud VMs or bare-metal computers which means it doesn't always work well with low-powered ARM devices.
    k3v - "virtual kubernetes" - a very early PoC from the author of k3s aiming to slice up a single cluster for multiple tenants
    k3sup-multipass - a helper to launch single node k3s cluster with one command using a multipass VM and optionally proxy the ingress to localhost for easier development.

Troubleshooting and support
Maybe the problem is with K3s?

If you're having issues, it's likely that this is a problem with K3s, and not with k3sup. How do we know that? K3sup is a very mature project and has a few use-cases that it generally performs very well.

Rancher provides support for K3s on their Slack in the #k3s channel. This should be your first port of call. Your second port of call is to raise an issue with the K3s maintainers in the K3s repo

Do you want to install a specific version of K3s? See k3sup install --help and the --k3s-version and --k3s-channel flags.

Is your system ready to run Kubernetes? K3s requires certain Kernel modules to be available, run k3s check-config and check the output. Alex tests K3sup with Raspberry Pi OS and Ubuntu LTS on a regular basis.
Common issues

The most common problem is that you missed a step, fortunately it's relatively easy to get the logs from the K3s service and it should tell you what's wrong.

    For the Raspberry Pi you probably haven't updated cmdline.txt to enable cgroups for CPU and memory. Update it as per the instructions in this file.

    You ran kubectl on a node. Don't do this. k3sup copies the file to your local workstation. Don't log into agents or servers other than to check logs / upgrade the system.

    sudo: a terminal is required to read the password - setup password-less sudo on your hosts, see also:Pre-requisites for k3sup agents and servers

    You want to install directly on a server, without using SSH. See also: k3sup install --local which doesn't use SSH, but executes the commands directly on a host.

    K3s server didn't start. Log in and run sudo systemctl status k3s or sudo journalctl -u k3s to see the logs for the service.

    The K3s agent didn't start. Log in and run sudo systemctl status k3s-agent

    You tried to remove and re-add a server in an etcd cluster and it failed. This is a known issue, see the K3s issue tracker.

    You tried to use an unsupported version of a database for HA. See this list from Rancher

    Your tried to join a node to the cluster and got an error "ssh: handshake failed". This is probably one of three possibilities:
        You did not run ssh-copy-id. Try to run it and check if you can log in to the server and the new node without a password prompt using regular ssh.
        You have an RSA public key. There is an underlying issue in a Go library which is referred here. Please provide the additional parameter --ssh-key ~/.ssh/id_rsa (or wherever your private key lives) until the issue is resolved.
        You are using different usernames for SSH'ing to the server and the node to be added. In that case, playe provide the username for the server via the --server-user parameter.

    Your .ssh/config file isn't being used by K3sup. K3sup does not use the config file used by the ssh command-line, but instead uses CLI flags, run k3sup install/join --help to learn which are supported.

    Note: Passing --no-deploy to --k3s-extra-args was deprecated by the K3s installer in K3s 1.17. Use --disable instead or --no-extras.

Getting access to your KUBECONFIG

You may have run into an issue where sudo access is required for kubectl access.

You should not run kubectl on your server or agent nodes. k3sup is designed to rewrite and/or merge your cluster's config to your local KUBECONFIG file. You should run kubectl on your laptop / client machine.

If you've lost your kubeconfig, you can use k3sup install --skip-install. See also the various flags for merging and setting a context name.
Smart cards and 2FA

    Warning: issues requesting support for smart cards / 2FA will be closed immediately. The feature has been proven to work, and is provided as-is.

You can use a smart card or 2FA security key such as a Yubikey. You must have your ssh-agent configured correctly, at that point k3sup will defer to the agent to make connections on MacOS and Linux. Find out more
Misc note on iptables

    Note added by Eduardo Minguez Perez

Currently there is an issue in k3s involving iptables >= 1.8 that can affect the network communication. See the k3s issue and the corresponding kubernetes one for more information and workarounds. The issue has been observed in Debian Buster but it can affect other distributions as well
