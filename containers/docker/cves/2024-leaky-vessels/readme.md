CVE-2024-21626

##
#
https://snyk.io/blog/leaky-vessels-docker-runc-container-breakout-vulnerabilities/
#
https://learn.snyk.io/lesson/cve-2024-21626-runc-process-cwd-container-breakout/
#
https://github.com/snyk/leaky-vessels-dynamic-detector
#
https://docs.avisi.cloud/blog/2024/02/02/kubernetes-security-release-cve-2024-21626/
#
##




runc process.cwd Container breakout vulnerability
Looking at Leaky Vessels CVE-2024-21626
General
Container breakout vulnerability: the basics
What is container breakout vulnerability (CVE-2024-21626)?
Containers are ideally sandboxed instances that are isolated from the underlying host. A "container breakout" vulnerability is one in which an attacker is able to gain unauthorized access to the host operating system from within the container and, in some cases, can allow a user to access sensitive data (credentials, customer info, etc.), modify the system, and launch further attacks, especially when the access gained is with superuser privileges.

About this lesson
In this lesson, we will look at a very specific container breakout vulnerability. A malicious Dockerfile, inherited Docker image (e.g FROM malicious), or Docker image, when built with ‘docker build’ or run with docker run respectively, can break out of the container environment to the host environment in most cases to achieve full root command execution on the host.

This container breakout vulnerability is severe and has the potential to cause damage to any underlying host infrastructure that is building containers.

This issue has been assigned the CVE-2024-21626.

FUN FACT
Discovered by Snyk
Snyk security researcher Rory McNamara, with the Snyk Security Labs team, identified four vulnerabilities — dubbed "Leaky Vessels" — in core container infrastructure components that allow container escapes. An attacker could use these container escapes to gain unauthorized access to the underlying host operating system from within the container.


Container breakout vulnerability in action
You can setup a vulnerable docker file with the below content. It specifies the WORKDIR to /proc/self/fd/7. It will reveal the content from /etc/shadow file
```
FROM alpine
WORKDIR /proc/self/fd/7
RUN cd ../../../../../../ && grep demouser etc/shadow && touch SUCCESSFUL_EXPLOIT
```

Check out the video to see it in action.


Breaking out of the container!
Container breakout via docker build. What you see here is the exploitation of docker build to break out of the container and access the host filesystem via an arbitrary read (in this example, the host’s /etc/shadow file) and write (in this example, the creation of a DOCKER_BUILD_BREAKOUT file).

Container breakout Demo 1

Next, let's look at a container breakout via docker run. What you see here showcases how running a malicious Docker image based on the same vulnerability can similarly result in the breakout of the Docker container to the host OS.

Container breakout demo 2

Impacts of Container Breakout Vulnerability
This vulnerability depends on a malicious container running or building within a vulnerable infrastructure. Due to the nature of this vulnerability, detection is difficult and requires runtime for the most accurate detection. As our existing Snyk products don’t operate on the application runtime, we built two tools to make detecting this vulnerability feasible.

Container Breakout Vulnerability under the hood
Let’s take a deeper look at what happened. The vulnerability occurs due to the order of operations when applying the WORKDIR directive defined in the Dockerfile. WORKDIR defines the initial working directory of all processes created by the Dockerfile, such as those executed at build-time using the RUN directive and those executed at run-time using the CMD or ENTRYPOINT directives.

The provided directory is entered using chdir before specific privileged host directory file descriptors have been closed. It is possible to specify one of these privileged file descriptors via the /proc/self/fd/ directory as the argument to chdir, which causes the privileged file descriptor to remain accessible even after the file descriptor itself is closed during normal operations, prior to handoff to the Dockerfile defined command, either at build or runtime.

When performing the chdir for either a build-time RUN command, or a run-time CMD (or equivalent) based on the specified WORKDIR argument, the chdir happens by path before the various privileged directory file descriptors are closed by the parent process.

A WORKDIR path can use these open file descriptors to chdir into a host directory, which can later be traversed out of to gain access to the host filesystem with the privileges of the Docker Engine. From here it is possible to break out of either the build-time or run-time environment to achieve full host compromise.

Scan your code & stay secure with Snyk - for FREE!
Did you know you can use Snyk for free to verify that your code
doesn't include this or other vulnerabilities?

Container breakout vulnerability mitigation
Because these vulnerabilities affect widely used low-level container engine components and container build tools, Snyk strongly recommends that users check for updates from container build and runtime vendors, including Docker, Kubernetes vendors, cloud container services, and open source communities. You should upgrade systems running container engines and container build tools as soon as fixes are released by your providers.

Install runc patch
We recommend that you take swift action by following the guidance provided in the runc advisory. The release of runc version 1.1.12 incorporates critical patches to address this security vulnerability. Additionally, it is crucial to update technologies bundling runc to their respective patched versions. 1 bug needs a runc update, the other 3 need a buildkit update.

Identify risks leveraging our runtime detection tools
To assist you in identifying potential risks, we have released two open-source tools to serve as reference implementations to help the community identify attempts to exploit these four vulnerabilities.

The Snyk team that recently joined us from Helios has built a runtime detection tool, leaky-vessels-dynamic-detector, for detecting these vulnerabilities based on full-stack runtime data collection technology. This standalone tool, released under the Apache-2.0 license, provides a reference implementation for detecting the vulnerabilities as they are executed.

The second tool is a static analysis program, leaky-vessels-static-detector, also released under the Apache-2.0 license, that scans Dockerfiles and image layers to detect commands that appear to be trying to exploit the vulnerabilities

Update container infrastructure
While updating your container infrastructure is our primary recommendation, we understand that immediate updates may not always be feasible. In such cases, our runtime detection tool can help you evaluate your risk and exposure in the near term. We strongly advise reaching out to your container infrastructure provider to confirm the status of their patched infrastructure.

Remediation should be done at the infrastructure and code tooling level. If applicable, look for announcements or releases from the provider or vendor of your container build and orchestration systems. You will likely need to update your Docker daemons and Kubernetes deployments and any container build tools you use in CI/CD pipelines, on build servers, and on your developers' workstations. It’s also important to screen existing containers using tools like the ones Snyk built to determine if your orchestration nodes or build infrastructure have already been impacted.

Keep learning
To learn more about the vulnerability, check out some other great content:

Leaky Vessels Container Breakout Vulnerabilities blog post
runc process.cwd & leaked fds container breakout (CVE-2024-21626)
Buildkit Mount Cache Race (CVE-2024-23651)
Buildkit GRPC SecurityMode Privilege Check (CVE-2024-23653)
Buildkit Build-time Container Teardown Arbitrary Delete (CVE-2024-23652)


Leaky Vessels: Docker and runc container breakout vulnerabilities (January 2024)
Written by:
Jamie Smith
January 31, 2024

8 mins read
Notes on Leaky Vessels
We will continue to update this blog with any key updates, including updates on the disclosure of any new related vulnerabilities. This blog includes links to detailed blogs on each of the disclosed vulnerabilities, as well as two open source tools to aid in exploit detection.

Snyk security researcher Rory McNamara, with the Snyk Security Labs team, identified four vulnerabilities — dubbed "Leaky Vessels" — in core container infrastructure components that allow container escapes. An attacker could use these container escapes to gain unauthorized access to the underlying host operating system from within the container. Once an attacker gains access to the underlying host operating system, they could potentially access whatever data was on the system, including sensitive data (credentials, customer info, etc.), and launch further attacks. Upon discovery and verification, the Security Labs team initiated the process for responsible disclosure of the vulnerabilities, starting by notifying Docker, who, after review, forwarded one of the vulnerabilities to the open source runc security group. The disclosure timeline is below. 

Because these vulnerabilities affect widely used low-level container engine components and container build tools, Snyk strongly recommends that users check for updates from container build and runtime vendors, including Docker, Kubernetes vendors, cloud container services, and open source communities. You should upgrade systems running container engines and container build tools as soon as fixes are released by your providers.

About the vulnerabilities
On January 31, 2024, the maintainers of runc, a CLI tool for spawning and running containers on Linux, announced a vulnerability (CVE-2024-21626) that allows for an order-of-operations container breakout centered around the WORKDIR command. Exploitation of this vulnerability can result in container escape to the underlying host operating system. This could occur by running a malicious image or by building a container image using a malicious Dockerfile or upstream image (i.e. when using FROM). The patched version, runc 1.1.12, was released on January 31, 2024, at around 3:00 PM EST, per the maintainers.

You can read more details about the vulnerability in this high-level blog, which outlines the runc vulnerability itself. In addition, Rory and the Snyk Labs team identified three other container escape vulnerabilities for a total of four vulnerabilities, listed below, with links to the corresponding CVEs and overview blogs:

CVE-2024-21626: runc process.cwd & leaked fds container breakout

CVE-2024-23651: Buildkit Mount Cache Race

CVE-2024-23653: Buildkit GRPC SecurityMode Privilege Check

CVE-2024-23652: Buildkit Build-time Container Teardown Arbitrary Delete

Tools available from Snyk to help detect these vulnerabilities
These vulnerabilities affect underlying container infrastructure and build tools rather than container images. Snyk Container is designed to help developers eliminate vulnerabilities in their container images, and so these vulnerabilities are outside the scope of what Snyk's products are currently designed to evaluate. However, Snyk developed two open source tools that serve as reference implementations for detecting exploit attempts. Please note that these tools are not covered under Snyk Support, but rather as examples for the community. 

Runtime exploit detection (leaky-vessels-runtime-detector)
The new Helios team at Snyk has built a runtime detection tool for this vulnerability, which can be found at leaky-vessels-runtime-detector, released under the Apache-2.0 license. This standalone tool, released under the Apache-2.0 license, provides a reference implementation for detecting the vulnerabilities as they are executed. The tool ties eBPF hooks to kernel- and user-level functions and to a package detector. This allows them to report invocations of container build and running containers if they match any patterns that indicate a possible exploitation attempt. Note that not all Linux distributions or versions support eBPF, and it's unlikely that customers would be able to leverage it on cloud service providers.

Static container command detection (leaky-vessels-static-detector)
The second tool is a static analysis program, leaky-vessels-static-detector, also released under the Apache-2.0 license, that scans Dockerfiles and image layers to detect commands that appear to be trying to exploit the vulnerabilities. The tool provides JSON-format output that indicates if it has detected any questionable commands. It's important to note that each hit will need to be manually inspected to determine if they are indeed exploits as opposed to legitimate usage of container build commands.

We are releasing these two tools as open source to provide the community with reference implementations for detecting potential exploit attempts. The runtime tool is likely to provide a higher level of confidence in findings than the static tool. However, given the nature of the exploits and the build commands, both tools will likely have some false negative and false positive results. The community can use the tools as examples to create their own tools, or run the tools in their environments. It's important to note that these tools neither fix the vulnerabilities nor block their exploitation, however, the tools will help to identify risk areas. The most prudent path is for customers to update impacted container orchestration platforms as patches become available. 

Are there any active exploits?
The Snyk team has performed ad hoc checks of Dockerfiles from public registries based on the images we see being used most frequently. This is not exhaustive, but in our research, we did not find evidence suggesting that these vulnerabilities have been exploited. Snyk recommends that you continue monitoring your own environment and check your containers until patches are made available and deployed. Given the nature of the issues, Snyk has created two open source tools, outlined above, a dynamic tool to help demonstrate the detection of the actions from the vulnerabilities at runtime, and a static tool to scan images and Dockerfiles to serve as an indicator of potential exploit.

How to prepare for remediation
Remediation should be done at the infrastructure and code tooling level. Look for announcements or releases, if applicable, from the provider or vendor of your container build and orchestration systems.  You will likely need to update your Docker daemons and Kubernetes deployments, as well as any container build tools that you use in CI/CD pipelines, on build servers, and on your developers' workstations. It’s also important to screen existing containers using tools like the ones Snyk built to determine if your orchestration nodes or build infrastructure have already been impacted.

Here are some updates that we've collected from widely used tools and services:

Date

Entity

Information

31-Jan-2024

Maintainers of runc

Released 1.1.12 addressing relevant vulnerabilities

31-Jan-2024

Snyk

Released the reference implementations leaky-vessels-dynamic-detector and leaky-vessels-static-detector to the community to identify potentially questionable containers and images

31-Jan-2024

containerd

Released version 1.6.28

31-Jan-2024

Docker

Docker released buildkit 0.12.5 and moby 25.0.2 and 24.0.9

31-Jan-2024

GCP

Released an update to runc 1.1.12

31-Jan-2024

Ubuntu

Released an update to runc 1.1.12

31-Jan-2024

AWS

Released an update to runc 1.1.12

Anatomy of a disclosure
The timeline for vulnerabilities can be complex, especially when there are multiple entities involved. It's imperative that the disclosures are handled responsibly so bad actors don’t learn of them before fixes are readily available. 

In this case, the vulnerabilities were initially discovered two months ago. At that point, Snyk began the process for responsible disclosure. Here's a timeline of some key milestones in the process.

Timeframe

Item

Week of 20-Nov-2023

Rory McNamara initially discovered the vulnerabilities. He began the internal verification process and additional research to validate findings and build POC exploits.

11-Dec-2023

Initial disclosure sent to Docker with all vulnerabilities, and Docker ACKed the same day.

12-Dec-2023

Snyk received a request from Docker to forward the WORKDIR vulnerability to runc, as it was deemed their responsibility.

13-Dec-2023

Rory was added as a Github Security Advisory (GHSA) collaborator for the Arbitrary Delete and grpc Docker/Buildkit vulns (both initially opened 11-Dec-2023).

19-Dec-2023

Rory was added as GHSA collaborator to WORKDIR by runc (initially opened 11-Dec-2023).

20-Dec-2023

Rory was added as GHSA collaborator for the cache race vulnerability.

02-Jan-2024

runc CVE assigned (Github CNA).

17-Jan-2024

runc sends an announcement to their security mailing list including the patches & embargo date of 31-Jan-2024.

24-Jan-2024

Docker vulnerabilities CVEs assigned (GitHub CNA).

31-Jan-2024

All four "Leaky Vessels" vulnerabilities announced publicly.

31-Jan-2024

Runc released version 1.1.12 which fixes the vulnerabilities.

31-Jan-2024

Snyk released the reference implementations leaky-vessels-dynamic-detector and leaky-vessels-static-detector to the community to identify potentially questionable containers and images.

Each step along the way involves collaboration within and between organizations — not only commercial organizations, but often the teams that maintain the components, which are often made up of a cross-section of the community.

About Snyk's Security Labs team
Snyk's Security Labs team has helped to responsibly disclose over 3,200 vulnerabilities in key packages across a variety of ecosystems. We work closely with open source package maintainers in order to ensure all vulnerabilities are responsibly and efficiently addressed. Our security expertise is one of the reasons that Snyk is trusted by so many big names across the security industry. If you find what you think is a vulnerability and don't know how to proceed to responsibly disclose it, fill out this form and our teams can help.

Was Snyk impacted?
For information about how Snyk addresses vulnerabilities in our own environment, visit the Snyk Trust Portal.

Summary
We will update this blog as we learn more, and we'll be holding a webinar Tuesday, February 6 at 11 AM ET for Leaky Vessels Container Breakout Vulnerabilities - What You Need to Know. Snyk technical experts will provide an in-depth technical review of one of the Leaky Vessels vulnerabilities, what caused it, how it can be exploited, and, most importantly, how it can be mitigated through upgrades and monitoring.

We encourage you to reach out with any questions you have about the vulnerabilities. For the open source tools, create a GitHub ticket on the respective tools (dynamic-detector and static-detector) or reach out on the Snyk community Discord. 

For more information, about Leaky Vessels, check out:

Leaky Vessels — runc Vulnerability Explained (YouTube)

Leaky Vessels deep dive: Escaping from Docker one syscall at a time (blog)

Hands-on lesson: runc process.cwd Container breakout vulnerability (Snyk Learn)

This article is provided for informational purposes only. Snyk is not responsible for any errors or omissions, or for the results obtained from the use of this information.

Change log
January 31, 2024, 3 p.m. ET: Initial release

January 31, 2024, 6 p.m. ET: Added CVE URLs; added updates from AWS, containerd, GCP, Docker, and Ubuntu

Feb 7, 2024, 1 p.m. ET: YouTube video and deep dive links added to Summary section

Feb 8, 2024, 10 a.m. ET: Snyk Learn lesson added to Summary section
