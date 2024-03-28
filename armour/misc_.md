```
#include <tunables/global>


profile docker-default flags=(attach_disconnected,mediate_deleted) {

  #include <abstractions/base>


  network,
  capability,
  file,
  umount,


  signal (receive) peer=unconfined
,

  signal (send,receive) peer=docker-default,


  deny @{PROC}/* w,   # deny write for all files directly in /proc (not in a subdir)
  # deny write to files not in /proc/<number>/** or /proc/sys/**
  deny @{PROC}/{[^1-9],[^1-9][^0-9],[^1-9s][^0-9y][^0-9s],[^1-9][^0-9][^0-9][^0-9]*}/** w,
  deny @{PROC}/sys/[^k]** w,  # deny /proc/sys except /proc/sys/k* (effectively /proc/sys/kernel)
  deny @{PROC}/sys/kernel/{?,??,[^s][^h][^m]**} w,  # deny everything except shm* in /proc/sys/kernel/
  deny @{PROC}/sysrq-trigger rwklx,
  deny @{PROC}/kcore rwklx,

  deny mount,

  deny /sys/[^f]*/** wklx,
  deny /sys/f[^s]*/** wklx,
  deny /sys/fs/[^c]*/** wklx,
  deny /sys/fs/c[^g]*/** wklx,
  deny /sys/fs/cg[^r]*/** wklx,
  deny /sys/firmware/** rwklx,
  deny /sys/kernel/security/** rwklx,


  # suppress ptrace denials when using 'docker ps' or using 'ps' inside a container
  ptrace (trace,read) peer=docker-default,

}

##
##

sudo apt-get install apparmor-utils

#view the current status of apparmor
sudo apparmor_status
sudo aa-status

#AppArmor profiles 
/etc/apparmor.d/
#clear the profiles cache
/etc/init.d/apparmor stop
#unload the profile
/etc/init.d/apparmor teardown
 
#enable complain mode for dhclient
sudo aa-complain /sbin/dhclient
sudo aa-enforce /sbin/dhclient
sudo aa-status


sudo docker run --rm -i --security-opt apparmor=unconfined debian:jessie bash -i &
$ ps -ef | grep bash
root     25643 25628  0 11:11 ?        00:00:00 bash -i
#indicates the process (pid 25643)
$ cat /proc/25643/attr/current
unconfined

sudo docker run --rm -i --security-opt apparmor=docker-default debian:jessie bash -i &
$ ps -ef | grep bash 
#indicates the process (pid 5138)
$ cat /proc/5138/attr/current

docker run --rm -it --security-opt apparmor=docker-default hello-world
#Run without the default seccomp profile
docker run --rm -it --security-opt seccomp=unconfined debian:jessie \
    unshare --map-root-user --user sh -c whoami
```
##
##
https://gist.github.com/vitzli/ed63308a6bddf259d6f8
##
##
```
#include <tunables/global>

/usr/local/bin/ipfs {
  #include <abstractions/base>

  /dev/tty r,
  /home/*/.ipfs/** rwk,
  /proc/sys/kernel/hostname r,
  /proc/sys/net/core/somaxconn r,
  /usr/local/bin/ipfs mr,
  
  /home/*/download/ rw,
  /home/*/download/** rw,
  /srv/repos/ r,
  /srv/repos/** r,
  /srv/torrent/ r,
  /srv/torrent/** r,
}
