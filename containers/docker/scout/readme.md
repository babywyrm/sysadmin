# Docker Scout CLI notes

**1. Analyze local files**
- _Get an at-a-glance vulnerability summary of the source code in the current working directory_

  ```
  docker scout quickview fs://.
  ```

- _View the details of vulnerabilities found in your local source code_

  ```
  docker scout cves --details --only-severity high fs://.
  ```

- _Compare the analysis of source code on your local filesystem with the analysis of a container image_

  ```
  docker scout compare fs://. --to docker/scout-cli:latest --ignore-unchanged
  ```
  
  For example,
  
  ```
  # Compare 2 alpine images
  docker scout compare --to alpine:latest alpine:3.12
  
  # Compare an image to the latest tag
  docker scout compare --to namespace/repo:latest namespace/repo:v1.2.0-pre

  # Ignore base images
  docker scout compare --ignore-base --to namespace/repo:latest namespace/repo:v1.2.0-pre

  # Generate a markdown output
  docker scout compare --format markdown --to namespace/repo:latest namespace/repo:v1.2.0-pre

  # Compare maven packages only and display critical vulnerabilities in them
  docker scout compare --only-package-type maven --only-severity critical --to namespace/repo:latest namespace/repo:v1.2.0-pre
  ```

**2. Compare two images and displays the differences**

```
docker scout compare
```

**3. Display the CVEs identified for any software artifacts in the image**

```
docker scout cves
```

For example,

```
docker scout cves nginx:latest
```

**4. Display a quick overview of an image**
  
```
docker scout quickview
```

For example,

```
docker scout quickview nginx:latest
```

**5. Display all available base image updates and remediation recommendations.**

```
docker scout recommendations
```

For example,

```
docker scout recommendations nginx:latest
```


##
#
https://github.com/felipecruz91/skout
#
##

With skout, you can get a bird's eye view of the number of Common Vulnerabilities and Exposures (CVEs) detected in the container images running on your Kubernetes cluster, all thanks to Docker Scout.

overview

Note

skout uses Docker Scout which is an early access product at the time of writing.

Recommended requirements
It's highly recommended to have Docker Desktop 4.17 or higher as skout will be using the docker scout CLI plugin that is shipped with that version of Docker Desktop.

However, if Docker Desktop is not present or the version is lower than 4.17, will be using the image docker/scout-cli to analyze the images running in the Kubernetes cluster. Note that the analysis will take longer as we'll be running docker scout in a container instead of using the CLI that comes with Docker Desktop 4.17 or higher. If that's the case, make sure to provide DOCKER_SCOUT_HUB_USER and DOCKER_SCOUT_HUB_PASSWORD as environment variables to provide such values within the container where docker scout runs.

Getting started
If you don't have a Kubernetes cluster, you can enable the one that comes with Docker Desktop or create quickly one with KinD: kind create cluster.

Go to the releases page and download the skout binary for your platform, for instance:
```

curl -LsO https://github.com/felipecruz91/skout/releases/download/0.0.3/skout_0.0.3_darwin_amd64.tar.gz
tar -xvzf skout_0.0.3_darwin_amd64.tar.gz
sudo mv skout /usr/local/bin/skout
Detect vulnerabilities across all the namespaces
skout 
Detect vulnerabilities in the default namespace
skout --namespace default
Passing options to the analysis
You can specify in skout the options defined in docker scout cves -h to customize the report, for instance:

skout --namespace default --ignore-base --only-fixed
How does it work?
skout is a CLI built in Go that connects to a Kubernetes cluster by using a kubeconfig file (default ~/.kube/config). Use the -kubeconfig flag to specify a different location of the kubeconfig file if required.
```

It uses the Kubernetes Go SDK to retrieve the list of container images that are running in the cluster (or in a given namespace if -namespace is set). Then, it runs docker scout on every image to find out the number of vulnerabilities (critical, high, medium and low). Finally, skout displays the vulnerability information in a table format for easy viewing and analysis.

Why could this be useful?
Ideally, you would do image vulnerability scanning as part of your CI/CD pipeline to prevent container images being deployed to your Kubernetes cluster according to a customizable threshold. An image may have 0 CVEs when it's first deployed to your cluster, however, new CVEs can surface over time and long-lived workloads that are not updated/patched regularly will become vulnerable eventually.

With skout you can get a feel of how good or bad your Kubernetes cluster's workloads perform in terms of number of CVEs at runtime. This can help users identify any security issues in their Kubernetes cluster, such as what images have the most vulnerabilities, and take appropriate actions to mitigate them with docker scout eventually.
