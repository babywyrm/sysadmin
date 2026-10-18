```
docker run --rm \
  --read-only \
  --tmpfs /tmp:rw,size=100m,mode=1777 \
  -v $(pwd)/har:/har:rw \
  --security-opt seccomp=./seccomp-profile.json \
  --security-opt apparmor=./apparmor-profile \
  -p 3000:3000 \
  playpen-sandbox
```



# Explanation

--read-only
Mounts the container’s root filesystem as read‑only. This helps prevent any unauthorized writes to the container's filesystem.


--tmpfs /tmp:rw,size=100m,mode=1777
Mounts a temporary filesystem at /tmp (100 MB in size, with mode 1777) so that applications (like Chrome/Selenium) that need to write temporary data can do so. (You can adjust the size as needed.)


-v $(pwd)/har:/har:rw
Mounts your host’s har directory (make sure it exists) to /har inside the container as read‑write. This is where your application will write the HAR logs.


--security-opt seccomp=./seccomp-profile.json
Applies a custom seccomp profile (stored in seccomp-profile.json in your current directory) to restrict the syscalls that the container can make.


--security-opt apparmor=./apparmor-profile
Applies a custom AppArmor profile (stored in apparmor-profile in your current directory) to further confine the container’s permissions.


-p 3000:3000
Exposes port 3000 on the host and maps it to port 3000 in the container.
