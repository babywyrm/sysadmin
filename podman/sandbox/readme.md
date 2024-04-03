
##
#
https://github.com/ultrafunkamsterdam/undetected-chromedriver
#
https://chromium.googlesource.com/chromium/src/+/main/docs/linux/sandboxing.md
##


Linux Sandboxing
Chromium uses a multiprocess model, which allows to give different privileges and restrictions to different parts of the browser. For instance, we want renderers to run with a limited set of privileges since they process untrusted input and are likely to be compromised. Renderers will use an IPC mechanism to request access to resource from a more privileged (browser process). You can find more about this general design here.

We use different sandboxing techniques on Linux and Chrome OS, in combination, to achieve a good level of sandboxing. You can see which sandboxes are currently engaged by looking at chrome://sandbox (renderer processes) and chrome://gpu (gpu process).

We have a two layers approach:

Layer-1 (also called the “semantics” layer) prevents access to most resources from a process where it's engaged. The setuid sandbox is used for this.
Layer-2 (also called “attack surface reduction” layer) restricts access from a process to the attack surface of the kernel. Seccomp-BPF is used for this.
You can disable all sandboxing (for testing) with --no-sandbox.

Layered approach
One notable difficulty with seccomp-bpf is that filtering at the system call interface provides difficult to understand semantics. One crucial aspect is that if a process A runs under seccomp-bpf, we need to guarantee that it cannot affect the integrity of process B running under a different seccomp-bpf policy (which would be a sandbox escape). Besides the obvious system calls such as ptrace() or process_vm_writev(), there are multiple subtle issues, such as using open() on /proc entries.

Our layer-1 guarantees the integrity of processes running under different seccomp-bpf policies. In addition, it allows restricting access to the network, something that is difficult to perform at the layer-2.

Sandbox types summary
Name	Layer and process	Linux flavors where available	State
Setuid sandbox	Layer-1 in Zygote processes (renderers, PPAPI, NaCl, some utility processes)	Linux distributions and Chrome OS	Enabled by default (old kernels) and maintained
User namespaces sandbox	Modern alternative to the setuid sandbox. Layer-1 in Zygote processes (renderers, PPAPI, NaCl, some utility processes)	Linux distributions and Chrome OS (kernel >= 3.8)	Enabled by default (modern kernels) and actively developed
Seccomp-BPF	Layer-2 in some Zygote processes (renderers, PPAPI, NaCl), Layer-1 + Layer-2 in GPU process	Linux kernel >= 3.5, Chrome OS and Ubuntu	Enabled by default and actively developed
Seccomp-legacy	Layer-2 in renderers	All	Deprecated
SELinux	Layer-1 in Zygote processes (renderers, PPAPI)	SELinux distributions	Deprecated
AppArmor	Outer layer-1 in Zygote processes (renderers, PPAPI)	Not used	Deprecated
The setuid sandbox
Also called SUID sandbox, our main layer-1 sandbox.

A SUID binary that will create a new network and PID namespace, as well as chroot() the process to an empty directory on request.

To disable it, use --disable-setuid-sandbox. (Do not remove the binary or unset CHROME_DEVEL_SANDBOX, it is not supported).

Main page: LinuxSUIDSandbox

User namespaces sandbox
The namespace sandbox aims to replace the setuid sandbox. It has the advantage of not requiring a setuid binary. It's based on (unprivileged) user namespaces in the Linux kernel. It generally requires a kernel >= 3.10, although it may work with 3.8 if certain patches are backported.

Starting with M-43, if the kernel supports it, unprivileged namespaces are used instead of the setuid sandbox. Starting with M-44, certain processes run in their own PID namespace, which isolates them better.

The seccomp-bpf sandbox
Also called seccomp-filters sandbox.

Our main layer-2 sandbox, designed to shelter the kernel from malicious code executing in userland.

Also used as layer-1 in the GPU process. A BPF compiler will compile a process-specific program to filter system calls and send it to the kernel. The kernel will interpret this program for each system call and allow or disallow the call.

To help with sandboxing of existing code, the kernel can also synchronously raise a SIGSYS signal. This allows user-land to perform actions such as “log and return errno”, emulate the system call or broker-out the system call (perform a remote system call via IPC). Implementing this requires a low-level async-signal safe IPC facility.

seccomp-bpf is supported since Linux 3.5, but is also back-ported on Ubuntu 12.04 and is always available on Chrome OS. See this page for more information.

See this blog post announcing Chrome support. Or this one for a more technical overview.

This sandbox can be disabled with --disable-seccomp-filter-sandbox.

The seccomp sandbox
Also called seccomp-legacy. An obsolete layer-1 sandbox, then available as an optional layer-2 sandbox.

Deprecated by seccomp-bpf and removed from the Chromium code base. It still exists as a separate project here.

See:

http://www.imperialviolet.org/2009/08/26/seccomp.html
http://lwn.net/Articles/346902/
https://code.google.com/p/seccompsandbox/
SELinux
Deprecated. Was designed to be used instead of the SUID sandbox.

Old information for archival purposes:

One can build Chromium with selinux=1 and the Zygote (which starts the renderers and PPAPI processes) will do a dynamic transition. audit2allow will quickly build a usable module.

Available since r26257, more information in this blog post (grep for ‘dynamic’ since dynamic transitions are a little obscure in SELinux)

Developing and debugging with sandboxing
Sandboxing can make developing harder, see:

this page for the setuid sandbox
this page for triggering crashes
this page for debugging tricks
See also
LinuxSandboxIPC
How Chromium's Linux sandbox affects Native Client
