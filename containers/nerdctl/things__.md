

1. Install Nerdctl
Prerequisites:
Make sure k3s is installed and running on your system.
Install containerd (already included with k3s).
Steps:
Download Nerdctl:

```
VERSION="1.6.0" # Replace with the latest version
curl -sL "https://github.com/containerd/nerdctl/releases/download/v${VERSION}/nerdctl-${VERSION}-linux-amd64.tar.gz" | sudo tar -xz -C /usr/local/bin/
```

Verify Installation:

```
nerdctl --version
```

2. Install BuildKit
BuildKit is a next-generation builder for container images.

Enable BuildKit:

Set an environment variable to enable BuildKit:

```
export DOCKER_BUILDKIT=1
```
Add it to your shell configuration (~/.bashrc or ~/.zshrc) to make it permanent:
```
echo 'export DOCKER_BUILDKIT=1' >> ~/.bashrc
source ~/.bashrc
```

Verify BuildKit:

```
nerdctl build --help
```


3. Link Nerdctl to k3s Containerd Socket
To avoid specifying the containerd socket manually each time:

Find the k3s Containerd Socket:

```
ls /run/k3s/containerd/containerd.sock
```


Create a Symbolic Link for Nerdctl:

```
sudo mkdir -p /etc/nerdctl
echo 'export CONTAINERD_ADDRESS=/run/k3s/containerd/containerd.sock' | sudo tee /etc/nerdctl/config
```


Set Environment Variable:

Add to your shell configuration:
```
echo 'export CONTAINERD_ADDRESS=/run/k3s/containerd/containerd.sock' >> ~/.bashrc
source ~/.bashrc
```

Test the Connection:

```
nerdctl info
```

If configured correctly, it should display containerd details for k3s.

4. Using Nerdctl
Pull Images:
```
nerdctl pull nginx:latest
```

List Images:

```
nerdctl images
```

Run Containers:

```
nerdctl run -d --name my-nginx -p 8080:80 nginx:latest
```

View Running Containers:
```
nerdctl ps
```

Stop and Remove Containers:
```
nerdctl stop my-nginx
nerdctl rm my-nginx
```

Push Images:
```
nerdctl push your-registry/your-image:tag
```

5. Building Images with BuildKit
Build an Image:
```
nerdctl build -t my-app:latest .
```

Use a BuildKit Configuration File:
Create a file named buildkit.toml for advanced BuildKit configurations. 

Example:

```
[worker.oci]
enabled = true
```

Run BuildKit with the config:

```
nerdctl build --buildkit-config buildkit.toml -t my-app:latest .
```

6. Debugging Nerdctl and BuildKit
Check Logs:

```
journalctl -u containerd
```

List Containers:
```
nerdctl ps -a

```

Troubleshooting:
If the containerd socket is not detected, ensure CONTAINERD_ADDRESS points to /run/k3s/containerd/containerd.sock.
Verify permissions:

```
sudo chmod 660 /run/k3s/containerd/containerd.sock
```

7. Automating k3s and Nerdctl Integration
To ensure Nerdctl always works with k3s's containerd socket, add this to /etc/profile.d/nerdctl.sh:

```
#!/bin/bash
export CONTAINERD_ADDRESS=/run/k3s/containerd/containerd.sock
export DOCKER_BUILDKIT=1
```

Make the script executable:

```
sudo chmod +x /etc/profile.d/nerdctl.sh
```

8. Uninstalling Nerdctl
To remove Nerdctl:
```
sudo rm /usr/local/bin/nerdctl
sudo rm -rf /etc/nerdctl

```


##
##
##


```
   86  nerdctl --address /run/k3s/containerd/containerd.sock images
   88  nerdctl --address /run/k3s/containerd/containerd.sock build -t legacy-oauth:latest .
   95  nerdctl --address /run/k3s/containerd/containerd.sock build -t legacy-oauth:latest .
   98  nerdctl --address /run/k3s/containerd/containerd.sock build -t legacy-oauth:latest .
  102  nerdctl --address /run/k3s/containerd/containerd.sock   --buildkit-host unix:///run/buildkit/buildkitd.sock   build -t legacy-oauth:latest .
  103  nerdctl --address /run/k3s/containerd/containerd.sock images
  109  nerdctl --address /run/k3s/containerd/containerd.sock rmi legacy-oauth:latest
  110  nerdctl --address /run/k3s/containerd/containerd.sock images
  111  nerdctl --address /run/k3s/containerd/containerd.sock build -t legacy-oauth:latest .
  118  nerdctl --address /run/k3s/containerd/containerd.sock build -t legacy-oauth:latest .
  138  nerdctl --address /run/k3s/containerd/containerd.sock build -t legacy-oauth:latest .
  146  nerdctl --address /run/k3s/containerd/containerd.sock build --progress=plain .
  147  nerdctl --address /run/k3s/containerd/containerd.sock build --no-cache -t legacy-oauth:latest .
  152  nerdctl --address /run/k3s/containerd/containerd.sock build --no-cache -t legacy-oauth:latest .
  159  nerdctl images
  163  nerdctl --address /run/k3s/containerd/containerd.sock build --no-cache -t legacy-oauth:latest .
  168  nerdctl --address /run/k3s/containerd/containerd.sock build --no-cache -t legacy-oauth:latest .
  195  nerdctl --address /run/k3s/containerd/containerd.sock build --no-cache -t legacy-oauth:latest .
  198  nerdctl --address /run/k3s/containerd/containerd.sock build --no-cache -t legacy-oauth:latest .
  203  nerdctl images
  208  nerdctl --address /run/k3s/containerd/containerd.sock build --no-cache -t legacy-oauth:latest .
  213  nerdctl images
  220  nerdctl --address /run/k3s/containerd/containerd.sock images
  285  nerdctl --address /run/k3s/containerd/containerd.sock images
  314  history | grep nerdctl
  315  nerdctl --address /run/k3s/containerd/containerd.sock images
  316  nerdctl --address /run/k3s/containerd/containerd.sock   tag legacy-oauth:latest legacy-oauth:stable
  318  nerdctl --address /run/k3s/containerd/containerd.sock images
  320  nerdctl --namespace default tag legacy-oauth:stable k8s.io/legacy-oauth:stable
  322  nerdctl --address /run/k3s/containerd/containerd.sock  --namespace default tag legacy-oauth:stable k8s.io/legacy-oauth:stable
  324  nerdctl images
  327  nerdctl --namespace default tag legacy-oauth:stable k8s.io/legacy-oauth:stable
  328  nerdctl --namespace k8s.io images
  329  nerdctl --address /run/k3s/containerd/containerd.sock  nerdctl --namespace k8s.io images
  330  nerdctl --address /run/k3s/containerd/containerd.sock --namespace k8s.io images
  331  nerdctl --address /run/k3s/containerd/containerd.sock save -o legacy-oauth.tar legacy-oauth:stable

```
