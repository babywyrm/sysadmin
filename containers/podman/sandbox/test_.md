
```
podman run \
  --security-opt label=type:container_runtime_t \
  --security-opt label=disable \
  --security-opt apparmor=chromium_profile \
  --security-opt apparmor=node_profile \
  --mount type=bind,source=/path/to/immutable_dir,target=/chromium,readonly \
  --mount type=bind,source=/path/to/writable_dir,target=/workdir,noexec \
  --cap-drop all \
  --read-only \
  -d your-image

  ```
In this command:

```
--security-opt label=type:container_runtime_t: Sets the SELinux type for the container to container_runtime_t.
--security-opt label=disable: Disables the SELinux label confinement for the container.
--security-opt apparmor=chromium_profile: Applies the AppArmor profile chromium_profile to the container.
--security-opt apparmor=node_profile: Applies the AppArmor profile node_profile to the container.
--mount type=bind,source=/path/to/immutable_dir,target=/chromium,readonly: Mounts the directory containing ChromeDriver and Chromium executables as read-only into the container.
--mount type=bind,source=/path/to/writable_dir,target=/workdir,noexec: Mounts the writable directory for Chrome sessions with the noexec option, preventing execution of binaries within.
--cap-drop all: Drops all Linux capabilities from the container.
--read-only: Mounts the container's root filesystem as read-only.
-d: Detaches the container and runs it in the background.
your-image: Specifies the image to run the container from.

```
Writable Workdir with noexec:

The noexec option prevents the execution of binaries within the workdir.
Users can write files to the workdir, but if they attempt to execute any binaries stored there, the execution will be denied.

##
##
```
podman run --security-opt label=type:container_runtime_t \
           --security-opt label=disable \
           --security-opt apparmor=chromium_profile \
           --mount type=bind,source=/path/to/immutable_dir,target=/chromium,readonly \
           -d your-chromium-image
```
Step 3: Create a Writable Directory without Executable Permissions for Chrome Workdir:

Create a writable directory (/path/to/writable_dir) to be used as the workdir for Chrome sessions.
Step 4: Launch Node Container with Workdir Mounted:

```
podman run --security-opt label=type:container_runtime_t \
           --security-opt label=disable \
           --security-opt apparmor=node_profile \
           --mount type=bind,source=/path/to/writable_dir,target=/workdir \
           -d your-node-image
```
           

Sandboxing Controls:

AppArmor and SELinux profiles enforce additional restrictions on the container's behavior.
They define rules specifying which actions the container is allowed to perform, including restricting access to system resources and preventing certain operations.

