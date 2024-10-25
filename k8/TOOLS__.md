
##
#
https://gist.github.com/yokawasa/26306126fe893285770c1c94c1571be8
#
##

# Kubernetes Tools

<!-- TOC -->

- [Kubernetes Tools](#kubernetes-tools)
    - [Links](#links)
    - [kubectx](#kubectx)
    - [stern](#stern)
    - [kubefwd](#kubefwd)
    - [kubespy](#kubespy)
    - [hadolint](#hadolint)

<!-- /TOC -->

## Links
- iterm2 / oh-my-zsh (theme: tangodark | [palenight](https://github.com/JonathanSpeek/palenight-iterm2))
- kubectl tab completion (`source <(kubectl completion zsh)`)
- VSCode + [GitLens](https://marketplace.visualstudio.com/items?itemName=eamodio.gitlens) | [moonlight](https://marketplace.visualstudio.com/items?itemName=atomiks.moonlight) | [YAML](https://marketplace.visualstudio.com/items?itemName=redhat.vscode-yaml) |  
- skaffold
- kubectl plugins
  - [kube-capacity](https://github.com/robscott/kube-capacity)
  - [kubectl-plugin-ssh-jump](https://github.com/yokawasa/kubectl-plugin-ssh-jump)
  - [kubectl-fzf](https://github.com/bonnefoa/kubectl-fzf)

## kubectx
[kubectx](https://github.com/ahmetb/kubectx) is a commandline tool that allow you to switch between clusters and namespaces in kubectl easily & smoothly

```sh
# installation (Mac)
$ brew install kubectx

# how to switch contexts
$ kubectx [tab]
 <cluster1> <cluster2> <cluster3> ...
```

## stern
[stern](https://github.com/wercker/stern) is a commandline for multi pod and container log tailing for Kubernetes

```
# installation on MacOS
$ brew install stern

# Usage
## tail <podname> in namespace
## stern <podname> -n <namespace>
$ stern samplepod

+ samplepod-684ccd679f-nl252 › sample-pod-demo
samplepod-684ccd679f-nl252 sample-pod-demo o36e6ivtni@8ae3fca5-9b5c-471b-99d8-0eeb567c6acb
samplepod-684ccd679f-nl252 sample-pod-demo ===== table list =====
samplepod-684ccd679f-nl252 sample-pod-demo ('test',)
samplepod-684ccd679f-nl252 sample-pod-demo ===== Records =====
samplepod-684ccd679f-nl252 sample-pod-demo Id: 1 Content: hoge
samplepod-684ccd679f-nl252 sample-pod-demo Id: 2 Content: foo
samplepod-684ccd679f-nl252 sample-pod-demo Id: 3 Content: bar
```

## kubefwd
[kubefwd](https://github.com/txn2/kubefwd) is a command line utility built to port forward some or all pods within a Kubernetes namespace.

Installation on Mac
```sh
$ brew install txn2/tap/kubefwd
```

For other platform, use docker like this:
```sh
$ docker run -it --rm --privileged --name the-project \
    -v "$(echo $HOME)/.kube/":/root/.kube/ \
    txn2/kubefwd services -n the-project

$ docker exec the-project curl -s <target>
```

Here is how to use:
```sh
# For all services for default namespace
sudo kubefwd services
# For all services for a specific namespace
sudo kubefwd services -n <namespace>


 _          _           __             _
| | ___   _| |__   ___ / _|_      ____| |
| |/ / | | | '_ \ / _ \ |_\ \ /\ / / _  |
|   <| |_| | |_) |  __/  _|\ V  V / (_| |
|_|\_\\__,_|_.__/ \___|_|   \_/\_/ \__,_|

Press [Ctrl-C] to stop forwarding.
Loading hosts file /etc/hosts
Original hosts backup already exists at /etc/hosts.original
Forwarding local 127.1.27.1:443 as kubernetes:443 to pod mytimeds-m7sn9:443
Forwarding local 127.1.27.2:80 as party-clippy:80 to pod party-clippy-dc7448885-fbzj4:8080
```

Then, access party-clippy

```sh
curl party-clippy:80
```


## kubespy
kubespy is a commandline tool for observing Kubernetes resources in real time
- https://github.com/pulumi/kubespy

Here is a way to install kubespy
```sh
# install binary (`go install` didn't work on my env for some reason)

$ wget https://github.com/pulumi/kubespy/releases/download/v0.4.0/kubespy-darwin-368.tar.gz
$ tar zxvf kubespy-darwin-368.tar.gz
$ cp -p releases/kubespy-darwin-386/kubespy $PATH/
$ kubespy

Spy on your Kubernetes resources

Usage:
  kubespy [command]

Available Commands:
  changes     Displays changes made to a Kubernetes resource in real time. Emitted as JSON diffs
  help        Help about any command
  status      Displays changes to a Kubernetes resources's status in real time. Emitted as JSON diffs
  trace       Traces status of complex API objects
  version     Displays version information for this tool

Flags:
  -h, --help   help for kubespy

Use "kubespy [command] --help" for more information about a command.
```

## hadolint
[hadolint](https://github.com/hadolint/hadolint) is a smarter Dockerfile linter that helps you build best practice Docker images.

How to install
```sh
# Directly download binary
$ curl -L -O https://github.com/hadolint/hadolint/releases/download/v1.15.0/hadolint-Darwin-x86_64
$ ln -s hadolint-Darwin-x86_64 hadolint

# Install with brew on Mac
$ brew install hadolint

# Use docker container
$ docker pull hadolint/hadolint
```

How to Use 
```sh
$ cd azure-container-labs/apps/vote/azure-vote
# hadolint <Dockerfile>
$ hadolint Dockerfile

Dockerfile:3 DL3008 Pin versions in apt get install. Instead of `apt-get install <package>` use `apt-get install <package>=<version>`
Dockerfile:3 DL3009 Delete the apt-get lists after installing something
Dockerfile:3 DL3013 Pin versions in pip. Instead of `pip install <package>` use `pip install <package>==<version>`
Dockerfile:3 DL3015 Avoid additional packages by specifying `--no-install-recommends`
Dockerfile:7 DL3020 Use COPY instead of ADD for files and folders
```
For more detail, see [hadolint/hadolint](https://github.com/hadolint/hadolint)  
