# Container security notes

## Internet references

### Kernel and architecture
    
- namespaces - overview of Linux namespaces
http://man7.org/linux/man-pages/man7/namespaces.7.html

- mount_namespaces - overview of Linux mount namespaces
http://man7.org/linux/man-pages/man7/mount_namespaces.7.html

- Major and Minor (device) Numbers
http://www.makelinux.net/ldd3/chp-3-sect-2

- cgroups - Linux control groups
http://man7.org/linux/man-pages/man7/cgroups.7.html

- How to find namespaces in a Linux system
http://www.opencloudblog.com/?p=251

- Anatomy of a Container: Namespaces, cgroups & Some Filesystem Magic - LinuxCon
https://www.slideshare.net/jpetazzo/anatomy-of-a-container-namespaces-cgroups-some-filesystem-magic-linuxcon

- Vulnerability Exploitation In Docker Container Environments
https://www.blackhat.com/docs/eu-15/materials/eu-15-Bettini-Vulnerability-Exploitation-In-Docker-Container-Environments.pdf

- This is the authoritative documentation on the design, interface and conventions of cgroup v2:
https://www.kernel.org/doc/Documentation/cgroup-v2.txt


### Escaping

- False Boundaries and Arbitrary Code Execution
https://forums.grsecurity.net/viewtopic.php?f=7&t=2522

- Container escape through open_by_handle_at (shocker exploit)
https://lists.linuxcontainers.org/pipermail/lxc-devel/2014-June/009547.html
https://github.com/gabrtv/shocker/blob/master/shocker.c

- Chw00t: How to break out from various chroot solutions
https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf

- Is it possible to escalate privileges and escaping from a Docker container? (security.stackexchange.com)
https://security.stackexchange.com/questions/152978/is-it-possible-to-escalate-privileges-and-escaping-from-a-docker-container

- Abusing Privileged and Unprivileged Linux Containers 
https://www.nccgroup.trust/globalassets/our-research/us/whitepapers/2016/june/container_whitepaper.pdf

- An Empirical Study into the Security Exposure to Hosts of Hostile Virtualized Environments
http://taviso.decsystem.org/virtsec.pdf

- Docker & Security - Florian Barth, Matthias Luft
https://www.ernw.de/download/ERNW_Stocard_Docker-Devops-Security_fbarth-mluft.pdf


### Docker

- My DockerCon 2014 talk: Thoughts on interoperable containers
https://fabiokung.com/2014/06/11/my-dockercon-2014-talk/

- Building a Secure App with Docker - Ying Li and David Lawrence, Docker
https://www.slideshare.net/Docker/building-a-secure-app-with-docker-ying-li-and-david-lawrence-docker
https://www.youtube.com/watch?v=tjxkxVI_PVU

- Docker Daemon tuning and JSON file configuration 
https://sandro-keil.de/blog/2017/01/23/docker-daemon-tuning-and-json-file-configuration/

### Kubernetes
- Apparmor
https://kubernetes.io/docs/tutorials/clusters/apparmor/#upgrading-to-kubernetes-v14-with-apparmor

- Security Best Practices
http://blog.kubernetes.io/2016/08/security-best-practices-kubernetes-deployment.html

- PodSecurityPolicy
https://kubernetes.io/docs/api-reference/v1.6/#podsecuritypolicyspec-v1beta1-extensions


### Hardening & Security

- Security In-Depth for Linux Software - Preventing and Mitigating Security Bugs
https://www.cr0.org/paper/jt-ce-sid_linux.pdf

- Security Best Practices for Kubernetes Deployment
http://blog.kubernetes.io/2016/08/security-best-practices-kubernetes-deployment.html

- Understanding and Hardening Linux Containers
https://www.nccgroup.trust/globalassets/our-research/us/whitepapers/2016/april/ncc_group_understanding_hardening_linux_containers-1-1.pdf

- DEF CON 23 - Aaron Grattafiori - Linux Containers: Future or Fantasy? - 101 Track
https://www.youtube.com/watch?v=iN6QbszB1R8

- Linux Containers (LXC), Docker, and Security
https://www.slideshare.net/jpetazzo/linux-containers-lxc-docker-and-security/2-OutlineFear_Uncertainty_and_Doubtand_the

- The Golden Ticket- Docker and High Security Microservices - Black Belt Track
https://www.youtube.com/watch?v=346WmxQ5xtk
http://www.slideshare.net/Docker/the-golden-ticket-docker-and-high-security-microservices-by-aaron-grattafiori

- Security Lab: Seccomp
http://training.play-with-docker.com/security-seccomp/

- How to Run a More Secure Non-Root User Container:
http://www.projectatomic.io/blog/2016/01/how-to-run-a-more-secure-non-root-user-container/


### Tools

- The Docker Bench for Security is a script that checks for dozens of common best-practices around deploying Docker containers in production. 
https://github.com/docker/dockerbench-security

- Clair - Vulnerability Static Analysis for Containers
https://github.com/coreos/clair

- AppArmor profile generator for docker containers. Basically a better AppArmor profile, than creating one by hand, because who would ever do that.
https://github.com/jessfraz/bane
