
# GitHub Actions with M1 macOS Runners and Self-Hosting via Kubernetes

This guide consolidates and improves the process of running GitHub Actions on M1 (Apple Silicon) macOS runners or self-hosted runners via Kubernetes, Vagrant, or UTM/QEMU. 

It covers both GitHub-hosted and self-hosted runner configurations.

---

## ✨ GitHub-Hosted M1 macOS Runners

### Availability

* As of **January 30, 2024**, M1 macOS runners are available for public open-source usage.
* Refer to official changelogs:

  * [2023-10-02 Beta](https://github.blog/changelog/2023-10-02-github-actions-apple-silicon-m1-macos-runners-are-now-available-in-public-beta/)
  * [2024-01-30 GA for OSS](https://github.blog/changelog/2024-01-30-github-actions-introducing-the-new-m1-macos-runner-available-to-open-source/)

### How to Use

Update your workflow YAML:

```yaml
runs-on: macos-14
```

> Note: `macos-12` and `macos-13` are Intel-based; use `macos-14` for Apple Silicon.

To verify architecture:

```yaml
- run: uname -m  # should return 'arm64'
```

If using Node.js, consider pinning your Node version with `actions/setup-node` and use the `architecture` flag:

```yaml
- uses: actions/setup-node@v4
  with:
    node-version: 18
    architecture: arm64
```

---

## 🯠 Self-Hosted Apple Silicon Runner

### Install Homebrew and QEMU

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
brew install qemu
```

### Build the Runner

```bash
export COMPlus_ReadyToRun=0
git clone https://github.com/hkratz/gha-runner-osx-arm64.git -b macos-arm64
cd gha-runner-osx-arm64/src/
./dev.sh layout
cd ../_layout/
./config.sh --url https://github.com/your/repo --token YOUR_TOKEN
```

---

## 🌎 Virtualized x86\_64 GitHub Runner on Apple Silicon

### Convert .OVA to .qcow2 for UTM

```bash
tar -xvf your_image.ova
qemu-img convert -O qcow2 your_image.vmdk your_image.qcow2
```

### Create UTM VM

1. Open UTM
2. Click "+" > "Start from Scratch"
3. Under Drives tab: Import the `.qcow2` file
4. In "System" tab > Advanced: Uncheck UEFI boot if needed
5. Set performance:

   * RAM: ≥ 6GB
   * Cores: 6
   * Enable multicore
6. Save and start the VM

---

## 🚀 Kubernetes-based GitHub Actions Runner

### Vagrant Setup (Optional)

```ruby
Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/jammy64"
  config.vm.provider "virtualbox" do |vb|
    vb.memory = 2048
  end
  config.vm.provision :docker
end
```

```bash
vagrant up
vagrant ssh
```

### Install Minikube + kubectl

```bash
curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
sudo install minikube-linux-amd64 /usr/local/bin/minikube
minikube start

curl -LO "https://dl.k8s.io/release/$(curl -Ls https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
```

### Install cert-manager

```bash
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.8.0/cert-manager.yaml
```

### Install Actions Runner Controller

```bash
kubectl create -f https://github.com/actions-runner-controller/actions-runner-controller/releases/download/v0.22.2/actions-runner-controller.yaml

kubectl delete validatingwebhookconfiguration validating-webhook-configuration
kubectl delete mutatingwebhookconfiguration mutating-webhook-configuration
```

### Add GitHub Token

```bash
export GITHUB_TOKEN=ghp_XXXXXXXX
kubectl create secret generic controller-manager \
  -n actions-runner-system \
  --from-literal=github_token=${GITHUB_TOKEN}
```

### Runner Configuration (Single Repo)

```yaml
# runner.yaml
apiVersion: actions.summerwind.dev/v1alpha1
kind: Runner
metadata:
  name: example-runner
spec:
  repository: kyanny/test
  env: []
```

```bash
kubectl apply -f runner.yaml
```

If stuck in `NotReady 1/2`, prefer RunnerDeployment:

### Runner Deployment Example

```yaml
# runnerdeployment.yaml
apiVersion: actions.summerwind.dev/v1alpha1
kind: RunnerDeployment
metadata:
  name: example-runnerdeploy
spec:
  replicas: 2
  template:
    spec:
      repository: kyanny/test
      env: []
```

```bash
kubectl apply -f runnerdeployment.yaml
kubectl get pod -A
```

---

## References

* [hkratz/gha-runner-osx-arm64#2](https://github.com/hkratz/gha-runner-osx-arm64/issues/2)
* [dotnet/runtime#64103](https://github.com/dotnet/runtime/issues/64103)
* [GitHub Community Discussion #48854](https://github.com/orgs/community/discussions/48854)
* [Tadhg Boyle’s Gist for M1 UTM](https://gist.github.com/tadhgboyle/a0c859b7d7c0a258593dc00cdc5006cc)

---

For production use, prefer GitHub-hosted M1 runners with `macos-14`, or deploy self-hosted runners via Kubernetes + ARC for full control.





##
##

https://github.blog/changelog/2023-10-02-github-actions-apple-silicon-m1-macos-runners-are-now-available-in-public-beta/

https://github.blog/changelog/2024-01-30-github-actions-introducing-the-new-m1-macos-runner-available-to-open-source/



https://github.com/hkratz/gha-runner-osx-arm64/pull/2
https://github.com/dotnet/runtime/issues/64103
```
export COMPlus_ReadyToRun=0
git clone https://github.com/hkratz/gha-runner-osx-arm64.git -b macos-arm64
cd gha-runner-osx-arm64/src/
./dev.sh layout
cd ../_layout/
./config.sh --url  {repo-url} --token AA... # use your repo URL and your runner registration token
```




https://gist.github.com/tadhgboyle/a0c859b7d7c0a258593dc00cdc5006cc




    install homebrew if you have not already
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

    install qemu
        brew install qemu

    extract the .ova file
        tar -xvf /path/to/ova

    convert the .ova file to a .qcow2 file
        qemu-img convert -O qcow2 /path/to/vdmk /path/to/output/qcow2
        make sure you have the .qcow2 extension in the output path
        there is no output until the processing is complete. it might take up to 5 minutes

    download utm

    make a new virtual machine in utm
        click the + icon on the top menu and then "start from scratch"
        go to the "drives" tab and click "import drive", then select the .qcow2 we just made
        in some cases you might have to disable uefi booting
            click on "system", then "advanced settings", and then unselect "uefi booting"
        by default, preformance is awful. to fix this you should give at least 6gb of RAM, 6 cores and enable mulicore mode
        click "save"

    start the virtual machine and enjoy x86_64 emulation on your m1 mac!
    ```



     How to run on M1 Mac runners? #48854


```
```


# https://github.com/orgs/community/discussions/48854

     
Closed Unanswered
jsoneaday asked this question in Actions
jsoneaday
Mar 1, 2023
Select Topic Area

Question
Body

I am running some actions that have build steps using node-gyp. Node-gyp can build as x86_64 or arm64, but on my runner it is building as x86_64. My runner uses runs-on: macos-12. When I build the same project with the same settings on my M1 dev machine it builds as arm64.

How can I use a MacOS runner image that is M1 compatible?
Replies: 2 comments · 2 replies

jsoref
Mar 6, 2023

You'll probably need to install node yourself, the default appears to be x86_64: actions/setup-node#462

Try using brew?
2 replies
@cbackas
cbackas
Apr 11, 2023

@jsoref I'm confused, macos-12 isn't an ARM runner so what would it matter how you try to install node?

How do you actually tell it to use an M1 runner? The github roadmap was updated yesterday to imply that M1 runners are in public beta and all you need to do is update your runs-on: but it doesn't say what to set it to and I can't find it otherwise.
@jsoref
jsoref
Apr 11, 2023

So, the short of it is that at the time you could have self-hosted on an m1, but then you'd have to tell something you want to install the arm version (e.g. brew).

As for using the m1 runners from github, I'm sure they'll post a blog entry explaining how to select them.
github-actions[bot]
bot
May 9, 2024

🕒 Discussion Activity Reminder 🕒

This Discussion has been labeled as dormant by an automated system for having no activity in the last 60 days. Please consider one the following actions:

1️⃣ Close as Out of Date: If the topic is no longer relevant, close the Discussion as out of date at the bottom of the page.

2️⃣ Provide More Information: Share additional details or context — or let the community know if you've found a solution on your own.

3️⃣ Mark a Reply as Answer: If your question has been answered by a reply, mark the most helpful reply as the solution.

Note: This dormant notification will only apply to Discussions with the Question label. To learn more, see our recent announcement.

Thank you for helping bring this Discussion to a resolution! 💬





- Docker on Vagrant
# minikube for Kubernetes cluster

### Vagrant

- Vagrantfile
  - Memory: more than 2048 RAM
  - [Docker - Provisioning | Vagrant by HashiCorp](https://www.vagrantup.com/docs/provisioning/docker) to install Docker

```
Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/jammy64"
  config.vm.provider "virtualbox" do |vb|
    vb.memory = 2048
  end
  config.vm.provision :docker
end
```

- Log in to the VM

```
vagrant up
vagrant ssh
```

### minikube && kubectl

[minikube start | minikube](https://minikube.sigs.k8s.io/docs/start/)

```
curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
sudo install minikube-linux-amd64 /usr/local/bin/minikube

minikube start
```

[Install and Set Up kubectl on Linux | Kubernetes](https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/)

```
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl

kubectl version --client
kubectl cluster-info
```

### cert-manager

[Installation - cert-manager Documentation](https://cert-manager.io/docs/installation/#default-static-install)

```
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.8.0/cert-manager.yaml
```

### actions-runner-controller

https://github.com/actions-runner-controller/actions-runner-controller#installation

- Change version (e.g. `v0.22.2`)
- `kubectl apply` fail, use `kubectl create` [ref](https://github.com/actions-runner-controller/actions-runner-controller/issues/1317#issuecomment-1092303292)

```
kubectl create -f https://github.com/actions-runner-controller/actions-runner-controller/releases/download/v0.22.2/actions-runner-controller.yaml
```

- https://github.com/actions-runner-controller/actions-runner-controller/issues/1159#issuecomment-1054018605
- https://github.com/actions-runner-controller/actions-runner-controller/issues/335#issuecomment-796324357
  - I don't know why :P

```
kubectl delete validatingwebhookconfiguration validating-webhook-configuration
kubectl delete mutatingwebhookconfiguration mutating-webhook-configuration
```

- Personal access token

```
export GITHUB_TOKEN=ghp_XXXXXXXX
kubectl create secret generic controller-manager \
    -n actions-runner-system \
    --from-literal=github_token=${GITHUB_TOKEN}
```

### Single repository runner

- runner.yaml

```
# runner.yaml
apiVersion: actions.summerwind.dev/v1alpha1
kind: Runner
metadata:
  name: example-runner
spec:
  repository: kyanny/test
  env: []
```

```
kubectl apply -f runner.yaml
```

```
kubectl get pod -A
```

- Unfortunately, after running job, `example-runner` pod got stuck in `NotReady 1/2` forever. Delete it and use `RunnerDeployments`.

```
kubectl delete -f runner.yaml
```

### RunnerDeployments

- runnerdeployment.yaml

```
# runnerdeployment.yaml
apiVersion: actions.summerwind.dev/v1alpha1
kind: RunnerDeployment
metadata:
  name: example-runnerdeploy
spec:
  replicas: 2
  template:
    spec:
      repository: kyanny/test
      env: []
```

```
kubectl apply -f runnerdeployment.yaml
```

```
kubectl get pod -A
