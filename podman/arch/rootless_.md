# Setting up podman rootless containers on Arch Linux

##
#
https://gist.github.com/rbellamy/60f8d9ed150ff800b4d598757fef2876
#
##

[Podman](https://podman.io/) is a container engine that is similar to and fully compatible with Docker that has the peculiarity of not requiring a daemon to run and to allow for rootless containers, which are often deemed safer than privileged containers running as root. Podman is a drop-in replacement for Docker that even supports the same syntax and it has good support from Red Hat.

However, running podman rootless containers on Arch Linux may not be obvious, so I'm writing the instructions I have used to achieve that here.

Podman works using control groups and users from which said containers need to be launched need to be assigned an appropriate range of subordinate user and group IDs. On Arch Linux, these files are not present and they need to be created.

From a root shell:

```bash
touch /etc/subuid
touch /etc/subgid
```

This will create two empty files called `subuid` and `subgid` under the `/etc` folder. `subuid` holds a list of users and the subordinate user IDs assigned to them, while `subgid` does the analogue thing with subordinate group IDs.

Next, always within a root shell, use `usermod` to assign a suitable range of subordinate users and groups to your username:

```bash
usermod --add-subuids 100000-150000 --add-subgids 100000-150000 username
```

Make sure the contents of those two files were updated (this doesn't necessarily need to be done from a root shell):

```bash
username@hostname > cat /etc/subuid
username:100000:50001
username@hostname > cat /etc/subgid
username:100000:50001
```

To finalize the change, pop up a shell from the user from which you want to run a container and

```bash
podman system migrate
```

After you've done this, you're done: rootless containers will work great on Arch Linux.
