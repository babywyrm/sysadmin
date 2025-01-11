
##
#
https://earthly.dev/blog/nerdctl/
#
https://medium.com/@pirocheto/installation-guide-for-migrating-from-docker-to-containerd-nerdctl-0847e30d608c
#
https://github.com/containerd/nerdctl/blob/main/docs/command-reference.md
##

Damaso Sanoja %
Damaso Sanoja
The article examines nerdctl’s container management features. Earthly provides reproducible and parallel build capabilities for your container builds. Learn more about Earthly.

Kubernetes’ support for container runtimes other than Docker Engine has spurred the development of new and more advanced Docker-compatible command line tools. One of the most promising is nerdctl.

nerdctl is an open source command line tool for containerd that is revolutionizing the developer space thanks to features like rootless mode, container image lazy pulling, image encryption and signing, IPFS-based P2P image distribution, and Docker Compose compatibility.

In this article, you’ll experiment with nerdctl to learn more about its powerful features and why you need them.

Setting Up nerdctl
Before setting up nerdctl, you need to know that it’s available in two versions: minimal and full. The main difference is that the full version includes dependencies such as CNI plugins (required for nerdctl run) and BuildKit (which is required for nerdctl build), as well as RootlessKit and slirp4netns (which are required for rootless mode). The minimum version requires that you install these dependencies manually to activate these functionalities/commands.

At the end of the day, both versions share the same core features, so the choice of which to install will depend largely on whether or not you’ll use the features mentioned above.

To install nerdctl, you can download the nerdctl binaries for Windows, FreeBSD, and Linux (AMD64/ARM/ARM64/PPC/S390) from the releases page. Keep in mind that the full version is only available for Linux (AMD64/ARM64).

Alternatively, you can install nerdctl on Linux using Homebrew by running the following command:

>_brew install nerdctl
If your system runs macOS, you can install nerdctl in two ways. You can run nerdctl on top of Lima-based Linux VMs:

>_brew install lima
limactl start
And then run nerdctl commands:

>_nerdctl {...}
Or, you can install Rancher Desktop since it comes with nerdctl installed by default. The same is true if you use Windows or Linux, since Rancher Desktop is available for those architectures as well.

Once nerdctl is running on your system, you can start exploring the features that make it so special.

Rootless Mode
One of the most notable features of nerdctl is its ability to run rootless containers. The so-called rootless mode is a security-oriented feature that facilitates the execution of containers without requiring superuser or root privileges.

Why You Need It
The rootless mode in nerdctl enhances the security posture of your containerized environment by minimizing the risk of privilege escalation attacks. Additionally, it supports a multitenant system by allowing nonprivileged users to run their containerized applications independently.

Rootless mode is integral to nerdctl, and it’s the preferred way to use it since it strikes a balance between security and user autonomy, fostering an environment that is both safe and productive.

Rootless Mode in Action
To enable rootless containers, you need to set up containerd by executing this command:

>_containerd-rootless-setuptool.sh install
The output will look like this:
```
Output...
[INFO] Installed "containerd.service" successfully.
[INFO] To control "containerd.service", run: `systemctl --user 
(start|stop|restart) containerd.service`
[INFO] To run "containerd.service" on system startup automatically, 
run: `sudo loginctl enable-linger damaso`
[INFO] --------------------------------------------------------------
[INFO] Use `nerdctl` to connect to the rootless containerd.
[INFO] You do NOT need to specify $CONTAINERD_ADDRESS explicitly.
```


Once installed, nerdctl runs in rootless mode by default. You can test it by deploying a sample container, like Nginx:

>_nerdctl run -d -p 8080:80 --name nginx nginx:alpine
Another notable feature of nerdctl is its flexibility to build containers either using OCI or containerd backends.

BuildKit Support
BuildKit is a modern, open source toolkit for building container images efficiently and securely. It’s an integral part of Docker and is designed to provide a robust backend for all types of container image builds. As you’ll see shortly, nerdctl supports two BuildKit backends: containerd worker and OCI worker.

Why You Need It
BuildKit’s key features include concurrent, cache-efficient, and Dockerfile-agnostic builds. It also supports advanced features like exporting build results and importing build caches from remote locations.

BuildKit is important because it can handle various building needs and tasks, making container image creation faster and more secure. This, in turn, improves the overall efficiency of developing containerized applications.

BuildKit in Action
As mentioned, you can use two backends for BuildKit. In the documentation, you can find detailed instructions on how to set up each of them. Keep in mind that if you choose OCI worker, you won’t be able to access images managed by containerd; instead, you’d have to choose containerd worker.

Once installed, you can use nerdctl build to build a Docker image using syntax similar to the Docker CLI. For instance, here’s an example of how you can use BuildKit in nerdctl to build a Docker image (assuming that you have a Dockerfile in your current directory):

>_nerdctl build -t your_image_name .
While nerdctl has the ability to offer compatibility with the OCI Image specification, there are still some limitations, especially when it comes to Docker Compose support.

nerdctl Compatibility With Docker Compose
nerdctl compose is a command that lets developers define and control applications that use multiple containers, just like they would using docker compose.

However, keep in mind that even though nerdctl compose implements the Docker Compose V3 specification, some YAML fields have not been implemented.

Why You Need It
Despite the limitations, the nerdctl compose command’s alignment with Docker Compose enables developers to use existing Docker Compose files without having to learn new syntax or workflows. This promotes a seamless transition from Docker to nerdctl.

nerdctl compose in Action
The biggest advantage of nerdctl compose is that you can use it in the same way as docker compose, like this:

>_nerdctl compose up -d
nerdctl compose down
You’ve already learned that nerdctl offers similar functionality to the Docker CLI. But now it’s time to review some cutting-edge features that separate it from other tools, such as the ability to lazy pull images to speed up container startup time.

Lazy Pulling
Lazy pulling is an advanced feature that allows you to run a container in a fraction of the normal time by pulling only the necessary parts of the runtime from the registry. In other words, instead of waiting for the entire image to be downloaded locally, lazy pulling allows you to start the container by performing a partial download.

nerdctl supports lazy pulling container images using either Stargz, Nydus, or OverlayBD snapshotter plugins, which is another sign of its flexibility.

Why You Need It
According to the HelloBench container startup latency benchmark, pulling packages accounts for seventy-six percent of container start time. That means lazy pulling can significantly speed up the start-up time of containers, a feature that is particularly useful in large-scale deployments involving hundreds of containers and real-time applications.

Lazy Pulling in Action
If you want to try lazy pulling using the eStargz format, you’ll have to install Stargz Snapshotter and Stargz Store.

Then, you can start running containers using lazy pulling, like this:

>_nerdctl --snapshotter=stargz run --rm \
ghcr.io/stargz-containers/python:3.7-esgz python3 \
-c'print("hello lazy-pulling")'
As you can see, the --snapshotter flag is used to specify which snapshotter you’ll use for lazy pulling. To find out more about the containerd Stargz Snapshotter plugin, check out the official documentation.

While lazy pulling is a fantastic feature, it’s not the only way to improve the cold-start performance of your containers. Another alternative is to use P2P image distribution.

P2P Image Distribution
The idea of using the peer-to-peer (P2P) networking model to distribute container images (and therefore not depend on a “slow” central repository) is not new. In 2019, Uber introduced Kraken, an open source P2P Docker registry, which was an important step in that direction.

However, containerd developers chose a different path by adding experimental support to nerdctl for distributing images using the InterPlanetary File System (IPFS) instead. In large part, this is because IPFS is a versatile open source P2P sharing protocol—designed from the ground up to organize and distribute data—that provides full support for the OCI Image specification and key nerdctl features such as image encryption and lazy pulling.

Why You Need It
The reasoning behind using IPFS-based P2P image distribution with nerdctl is the same as with lazy pulling. Downloading container images is time-consuming, so implementing peer-to-peer techniques makes a lot of sense.

When you think about a large-scale Kubernetes cluster, one of the biggest bottlenecks is the image repository. If you use P2P image distribution, you can distribute images within the cluster, saving bandwidth and improving the cold-start performance of the containers.

P2P in Action
To start distributing images using IPFS, you need to install the corresponding daemon:

>_containerd-rootless-setuptool.sh -- install-ipfs --init
Then, you can use nerdctl to push images to IPFS by running the following:

>_nerdctl push ipfs://<IMAGE_NAME>
The output should look like this:

>_INFO[0000] pushing image "<IMAGE_NAME>" to IPFS
INFO[0000] ensuring image contents
bafkreicq4dg6nkef5ju422ptedcwfz6kcvpvvhuqeykfrwq5krazf3muze
In this code, the last line is the content identifier (CID), an IPFS address that points to the image. That’s the value you’ll use for other operations such as pulling or running images:

>_
nerdctl pull ipfs://bafkreicq4dg6nkef5ju422ptedcwfz6kcvpvvhuqeykfrwq5krazf3muze
nerdctl run ipfs://bafkreicq4dg6nkef5ju422ptedcwfz6kcvpvvhuqeykfrwq5krazf3muze
Additionally, the command nerdctl push ipfs:// configures OCI images for IPFS automatically, which is an advantage since you can share images using IPFS-agnostic tools. For instance, you can run nerdctl ipfs registry to enable a read-only IPFS localhost registry accessible via localhost:5050/ipfs/<CID> that can be used by Kubernetes, BuildKit, and even Docker.

Image Encryption
When it comes to security, nerdctl supports encryption and decryption of container images using imgcrypt, which is essentially a library that uses OCIcrypt to encrypt image layers. Protecting image layers using these libraries is relatively trivial, as it only requires creating a key pair using OpenSSL and storing them in /etc/containerd/ocicrypt/keys.

Why You Need It
Although nerdctl image encrypt only encrypts image layers and not container environmental variables or cmd commands, this functionality is essential to protect against unauthorized access to images. For an in-depth discussion on how to protect container images, check out this resource discussing encrypted container images for container image security at rest. For the purposes of this article, the important thing to remember is that nerdctl allows you to seamlessly encrypt and decrypt images.

Image Encryption in Action
The good news is that you don’t need to install additional plugins to take advantage of OCIcrypt or imgcrypt with nerdctl.

Assuming you’ve stored your private and public keys in /etc/containerd/ocicrypt/keys (or ~/.config/containerd/ocicrypt/keys for rootless mode), you can encrypt an image using a command like this:

>_nerdctl image encrypt --recipient=jwe:mypubkey.pem \
--platform=linux/amd64,linux/arm64 foo example.com/foo:encrypted
Or, you can decrypt an image using the following command:

>_nerdctl pull --unpack=false example.com/foo:encrypted
nerdctl image decrypt --key=mykey.pem example.com/foo:encrypted foo:decrypted
For added convenience, nerdctl allows you to run encrypted images without adding additional flags:

>_nerdctl run example.com/encrypted-image
Again, this requires your local machine to have the public/private keys in the appropriate location.

