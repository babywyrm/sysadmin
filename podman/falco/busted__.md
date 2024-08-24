
##
#
https://github.com/falcosecurity/falco/issues/1912
#
No support for Podman container activity capturing by container.id #1115 
#
##





Hello,

I come from an issue over at the Sysdig repository where I was advised to open up an issue here: draios/sysdig#385 (comment)

The problem is that Podman container activities still do not seem to be recognized by Sysdig when for example filtering by container.id=<container id>. Since - at least as far as I understand - Sysdig and Falco use the same engine to detect such activities and I am more familiar with Sysdig, I'll write down my Sysdig version.
If there is anything I should also test using Falco, please feel free to tell me.

This problem occurs whether I run a Podman container with crun or runc and I tested it on two different systems with different software versions/systems (see below for version details).
On Ubuntu 22.04.2 LTS and with the according software versions, no containers are recognized by sysdig -c lscontainers and no activity captured by sysdig evt.type=execve and container.id=<container-id>. Leaving out the container.id filter, execve activity from inside the container is captured.
On Rocky Linux 8.8 and with the according software versions, a Podman container run with runc is recognized by sysdig -c lscontainers as container type Docker and with the right container ID. Container image and name are blank. Unfortunately it is not recognized anymore when run with crun and again no activity is captured by sysdig evt.type=execve and container.id=<container-id>. Leaving out the container.id filter, execve activity from inside the container is captured.

Ubuntu 22.04.2 LTS:

$ cat /etc/os-release
PRETTY_NAME="Ubuntu 22.04.2 LTS"

$ sysdig --version
sysdig version 0.27.1

$ podman --version
podman version 3.4.4

$ runc --version
runc version 1.1.4-0ubuntu1~22.04.3
spec: 1.0.2-dev
go: go1.18.1
libseccomp: 2.5.3

$ crun --version
crun version 0.17
commit: 0e9229ae34caaebcb86f1fde18de3acaf18c6d9a
spec: 1.0.0
+SYSTEMD +SELINUX +APPARMOR +CAP +SECCOMP +EBPF +YAJL

Rocky Linux 8.8:

$ cat /etc/os-release
PRETTY_NAME="Rocky Linux 8.8 (Green Obsidian)"

$ sysdig --version
sysdig version 0.31.5

$ podman --version
podman version 4.4.1

$ runc --version
runc version 1.1.4
spec: 1.0.2-dev
go: go1.19.4
libseccomp: 2.5.2

$ crun --version
crun version 1.8.4
commit: 5a8fa99a5e41facba2eda4af12fa26313918805b
rundir: /run/user/1000/crun
spec: 1.0.0
+SYSTEMD +SELINUX +APPARMOR +CAP +SECCOMP +EBPF +CRIU +YAJL

Are Podman containers generally not supported or am I missing something out in my setup? The issue at draios/sysdig#385 - where I originally come from - also does not seem to be fully resolved,

Thank you in advance for any hint towards a solution or a clarification regarding the support for Podman containers :)


##
##


Skip to content
Navigation Menu

    Pricing

Sign in
Sign up
falcosecurity /
falco
Public

Code
Issues 93
Pull requests 12
Discussions
Actions
Projects 1
Security 7

    Insights

Falco 0.31 cannot record the use of shell in container (podman rootless) #1912
Closed
patrickdung opened this issue Feb 23, 2022 · 6 comments
Comments
@patrickdung
patrickdung commented Feb 23, 2022

Describe the bug

Falco 0.31 cannot record the use of shell in containers (podman rootless)

How to reproduce it

This is the related rule

- rule: Terminal shell in container
  desc: A shell was used as the entrypoint/exec point into a container with an attached terminal.
  condition: >
    spawned_process and container
    and shell_procs and proc.tty != 0
    and container_entrypoint
    and not user_expected_terminal_shell_in_container_conditions
  output: "[%evt.time][%container.id] [%container.name]"
  priority: NOTICE
  tags: [container, shell, mitre_execution]

Expected behaviour

There should be log entry when Podman execute a shell shell in a container.

Screenshots

Environment

    Falco version:

Falco version: 0.31.0
Driver version: 319368f1ad778691164d33d59945e00c5752cd27

    System info:

Wed Feb 23 15:58:27 2022: Falco version 0.31.0 (driver version 319368f1ad778691164d33d59945e00c5752cd27)
Wed Feb 23 15:58:27 2022: Falco initialized with configuration file /etc/falco/falco.yaml
Wed Feb 23 15:58:27 2022: Loading rules from file /etc/falco/falco_rules.yaml:
Wed Feb 23 15:58:28 2022: Loading rules from file /etc/falco/falco_rules.local.yaml:
Wed Feb 23 15:58:28 2022: Loading rules from file /etc/falco/k8s_audit_rules.yaml:
Wed Feb 23 15:58:28 2022: Loading rules from file /etc/falco/rules.d/local.yaml:
{
  "machine": "x86_64",
  "nodename": "[REDACTED]",
  "release": "5.16.7-200.fc35.x86_64",
  "sysname": "Linux",
  "version": "#1 SMP PREEMPT Sun Feb 6 19:53:54 UTC 2022"
}

    Cloud provider or hardware configuration:
    OS: Fedora 35, Falco is using BPF not kernel module

    Kernel:

    Installation method:

RPM

Additional context

The shell is executed in the pod by running:
podman exec -it container1 /bin/bash
@patrickdung patrickdung added the kind/bug label Feb 23, 2022
@FedeDP
Contributor
FedeDP commented Mar 2, 2022

Hi! Thanks for opening this issue!
I can confirm the bug: podman as user is not correctly detected by Falco.
I opened a PR to fix this: falcosecurity/libs#236
@FedeDP FedeDP mentioned this issue Mar 3, 2022
fix(userspace/libsinsp): fixed podman as user detection falcosecurity/libs#236
Merged
@FedeDP
Contributor
FedeDP commented Mar 3, 2022

The fix has been merged and will be released in Falco 0.31.1 in the next couple of weeks ;)
@FedeDP
Contributor
FedeDP commented Mar 17, 2022

The fix is now released as part of Falco 0.31.1! Care to test?
@patrickdung
Author
patrickdung commented Mar 17, 2022

It should be ok:

It is triggered by podman exec:

16:30:00.648040656: Notice [16:30:00.648040656][2a91b1303d4c] [container-recon]

@FedeDP
Contributor
FedeDP commented Mar 17, 2022

We can close it then :)
Thanks man!
@jasondellaluce
Contributor
jasondellaluce commented Jun 6, 2022

Closing this as this seems to be fixed by falcosecurity/libs#236 since Falco 0.31.1.
@jasondellaluce jasondellaluce closed this as completed Jun 6, 2022
to join this conversation on GitHub. Already have an account? Sign in to comment
Assignees
No one assigned
Labels
kind/bug
Projects
None yet
Milestone
No milestone
Development

No branches or pull requests
3 participants
@FedeDP
@jasondellaluce
@patrickdung
Footer
© 2024 GitHub, Inc.
Footer navigation

    Terms
    Privacy
    Security
    Status
    Docs
    Contact

falcosecurity/libs on Mar 2, 2022
fix(userspace/libsinsp): fixed podman as user detection #236

What type of PR is this? Uncomment one (or more) /kind <> lines: /kind bug /kind c…
master ← fix_podman_as_user
kind/bug release-note dco-signoff: yes + more
Press escape to close this hovercard
