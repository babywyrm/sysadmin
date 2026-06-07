# DevContainer with Podman on Fedora on lima

## Environment

- macOS: `Big Sur v11.5.2`
- VS Code: Version: `v1.60.0`
- Remote - Containers: `v0.194.0`
- [lima](https://github.com/lima-vm/lima): `v0.6.3`

## 1. Install Podman and lima

Install using the Homebrew package.
```
brew install podman lima
```

Check command.
```
$ podman --version
podman version 3.3.1
$ lima --version
limactl version 0.6.3
```

## 2. Run "fedora" instance on lima

Clone the lima GitHub repo and start lima with the `fedora.yml`.
```
git clone https://github.com/lima-vm/lima.git
limactl start lima/examples/fedora.yaml
```

Enter `Proceed with the default configuration`.
```
? Creating an instance "fedora"  [Use arrows to move, type to filter]
> Proceed with the default configuration
  Open an editor to override the configuration
  Exit
```
After entering, the instance setup will start.

## 3. Setup build environment

SSH into the Fedora VM.
```
ssh-keygen -R [localhost]:60024
ssh -i ~/.lima/_config/user -o USER=$(whoami) -o StrictHostKeyChecking=no localhost -p 60024
```

Install the required packages, following the "Building from scratch" instructions in the [Podman Installation Instructions](https://podman.io/getting-started/installation).

(In the Fedora VM)
```
sudo dnf install -y \
  btrfs-progs-devel \
  conmon \
  containernetworking-plugins \
  containers-common \
  crun \
  device-mapper-devel \
  git \
  glib2-devel \
  glibc-devel \
  glibc-static \
  go \
  golang-github-cpuguy83-md2man \
  gpgme-devel \
  iptables \
  libassuan-devel \
  libgpg-error-devel \
  libseccomp-devel \
  libselinux-devel \
  make \
  pkgconfig
```

## 4. Setup golang and make (In the Fedora VM)

I referred to the following for instructions on how to set up golang.
https://github.com/dc25/buildPodman/blob/main/build.sh

```
export GOPATH=~/go
export GOCACHE="$(mktemp -d)"
export PATH=$GOPATH/bin:$PATH

mkdir -p $GOPATH
chmod -R 777 $GOPATH > /dev/null 2>&1
rm -rf $GOPATH > /dev/null 2>&1
if [[ -e $GOPATH ]] ; then
    echo unable to remove $GOPTATH
    exit 1
fi
mkdir -p $GOPATH

go get golang.org/x/tools/cmd/goimports
```

Clone the Podman GitHub repo and make/make install.
```
git clone https://github.com/containers/podman/
cd podman
make BUILDTAGS="selinux seccomp"
sudo make install PREFIX=/usr
```

Activate and start the `podman.socket` service.
```
systemctl --user enable --now podman.socket
```

Check Podman command.
```
$ podman -r --url unix:/run/user/${UID}/podman/podman.sock version
Client:
Version:      4.0.0-dev
API Version:  4.0.0-dev
Go Version:   go1.16.6
Git Commit:   e6046224ea88cad9286303456562b4a24ad9cf9b
Built:        Fri Sep 10 15:57:38 2021
OS/Arch:      linux/amd64

Server:
Version:      4.0.0-dev
API Version:  4.0.0-dev
Go Version:   go1.16.6
Git Commit:   e6046224ea88cad9286303456562b4a24ad9cf9b
Built:        Fri Sep 10 15:57:38 2021
OS/Arch:      linux/amd64
```

## 5. Setup Podman remote connection on macOS

Configure Podman remote via SSH connection to Fedora VM.
```
podman system connection add lima --identity ~/.lima/_config/user ssh://$(whoami)@localhost:60024
podman system connection default lima
```

Check connection into the Fedora VM via Podman command.
```
$ podman version
Client:
Version:      3.3.1
API Version:  3.3.1
Go Version:   go1.17
Built:        Tue Aug 31 04:15:26 2021
OS/Arch:      darwin/amd64

Server:
Version:      4.0.0-dev
API Version:  4.0.0-dev
Go Version:   go1.16.6
Git Commit:   e6046224ea88cad9286303456562b4a24ad9cf9b
Built:        Sat Sep 11 00:57:38 2021
OS/Arch:      linux/amd64
```

## 6. Run and Attach to container

Start the container and keep it running.
```
podman run -d --name ubi ubi8 sleep inf
```

Launch the VS code and settings for Remote-Containers.
Set `podman` to `Docker Path`.

<img width="1552" alt="Screen Shot 2021-09-11 at 2 24 10" src="https://user-images.githubusercontent.com/54387703/132893679-8a8e5f5e-8b09-40bb-8526-7b3e3c5edea1.png">

<img width="1552" alt="Screen Shot 2021-09-11 at 2 28 15" src="https://user-images.githubusercontent.com/54387703/132893740-f8ef7290-789b-4121-bb06-8642ec64b44e.png">

Attach the pre-launched container.

<img width="1435" alt="Screen Shot 2021-09-11 at 1 59 55" src="https://user-images.githubusercontent.com/54387703/132893875-88fdb8ee-a1ea-43bd-8e8f-cc0e0dda253f.png">

<img width="1552" alt="Screen Shot 2021-09-11 at 2 03 59" src="https://user-images.githubusercontent.com/54387703/132893965-1cf86837-d153-40c8-aaac-d9524fd309f1.png">

<img width="1552" alt="Screen Shot 2021-09-11 at 2 04 24" src="https://user-images.githubusercontent.com/54387703/132893995-5e8f1e3f-32bc-4df6-ac27-97067fa3e783.png">

## Restrictions

You cannot use `Try a Sample` because Podman's remote connection does not support volume mounts. You will need to rewrite the mount path in the Fedora VM or take other measures.
