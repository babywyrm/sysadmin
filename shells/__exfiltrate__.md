# File Transfer Methods from a Kubernetes Pod  ( ..Beta Edition.. )

Below are several techniques to copy files out of a Kubernetes container, from easiest (if you have `kubectl` access) to more “primitive” approaches when you only have a plain shell.

---

## 1. kubectl cp

**Prerequisite**: `kubectl` configured and you have `get`, `pods` and `exec` permissions.

```bash
# Syntax:
kubectl cp <namespace>/<pod>:/remote/path/to/file /local/path/to/file

# Example:
kubectl cp my-namespace/my-pod:/app/secret/data.bin ./data.bin
```

---

## 2. Base64 + Copy-Paste

**Prerequisite**: `base64` binary in the container.

1. **In the pod**:
   ```bash
   base64 /path/to/remote.file
   ```
2. **On your workstation**:  
   • Copy the entire Base64 blob into `file.b64`.  
   • Decode locally:
   ```bash
   base64 -d file.b64 > remote.file
   ```

---

## 2b. Python + Base64 (no `base64` tool)

**Prerequisite**: Python3 in the container.

1. **In the pod**:
   ```bash
   python3 - <<'EOF'
   import base64
   data = open("/path/to/remote.file","rb").read()
   print(base64.b64encode(data).decode())
   EOF
   ```
2. **On your workstation**:  
   • Copy the printed Base64 blob into `file.b64`.  
   • Decode:
   ```bash
   base64 -d file.b64 > remote.file
   ```

---

## 3. Python HTTP Server

**Prerequisite**: Python3 in the container; port forwarded or routable.

1. **In the pod**:
   ```bash
   cd /path/to/dir
   python3 -m http.server 8000
   ```
2. **On your host**:
   ```bash
   # If pod-IP is reachable:
   curl http://<pod-ip>:8000/remote.file -o remote.file

   # Or port-forward:
   kubectl port-forward pod/<pod-name> 8000:8000
   curl http://localhost:8000/remote.file -o remote.file
   ```

---

## 4. Netcat Transfer

**Prerequisite**: `nc` or `netcat` in both pod and host.

1. **On your host**:
   ```bash
   nc -lvp 9001 > remote.file
   ```
2. **In the pod**:
   ```bash
   nc <host-ip> 9001 < /path/to/remote.file
   ```

---

## 5. SCP over SSH

**Prerequisite**: SSH server running in container; valid credentials or key.

```bash
scp user@pod-ip:/path/to/remote.file ./remote.file
```

---

## 6. Tar + Base64 Chunking

**Prerequisite**: `tar` and `base64` in container.

1. **In the pod**:
   ```bash
   tar cf - /path/to/dir | base64
   ```
2. **On your host**:
   • Save output to `archive.b64`.  
   • Decode & extract:
   ```bash
   base64 -d archive.b64 | tar xf -
   ```

---

## 7. SSRF or Web-App Proxy

**Prerequisite**: The app provides an HTTP proxy endpoint.

```bash
curl -X POST http://app.example.com/proxy \
  -H "Content-Type: application/json" \
  -d '{"url":"http://127.0.0.1:8080/path/to/file"}'
```

---

## 8. Manual Deletion & Rolling Restart

**Prerequisite**: You can run K8s API calls from inside the pod (patch/rollout).

1. **Delete the running pod** to free up RWO PVC and hostPort:
   ```bash
   kubectl delete pod -n myns -l app=myapp
   ```
2. **Wait** for the new pod to spawn (with PVC mounted) then use any of the above methods.

---

