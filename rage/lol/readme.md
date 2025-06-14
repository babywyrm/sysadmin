# 🔐 Secure SSH Key Rotation & Obfuscation Script

This script securely generates **ED25519 SSH key pairs** for both a non-root service account and the root user, then **encrypts the private keys using [Rage](https://github.com/str4d/rage)**. 

The obfuscated keys are safely stored on disk, and the root key is also base64-encoded and injected into a Kubernetes Secret for safe failsafe recovery.

---

## ✅ Features

- Generates new SSH key pairs (ED25519)
- Obfuscates private keys using Rage with a trusted identity
- Stores obfuscated keys in a safe location
- Injects root’s obfuscated key into a Kubernetes Secret
- Supports optional:
  - `--dry-run`: Simulate actions
  - `--backup`: Backup existing keys before overwriting
  - `--rollback`: Automatically restore backups if a failure occurs
  - `--verbose`: Show each command being run

---

## 📁 Key Locations

| User        | Key Path                              | Obfuscated Path                             |
|-------------|----------------------------------------|---------------------------------------------|
| `serviceuser` | `/home/serviceuser/.ssh/id_ed25519`   | `/srv/secure/obfuscated/id_ed25519_serviceuser.rage` |
| `adminuser`   | `/root/.ssh/id_ed25519`               | `/srv/secure/obfuscated/id_ed25519_adminuser.rage`   |

The original Rage identity used for encryption is expected to exist at:

```bash
/srv/secure/identity/id_ed25519

Absolutely! Here's the full `README.md` content in one clean Markdown block, ready to copy into your GitHub repo:

---

```markdown
# 🔐 Secure SSH Key Rotation & Obfuscation Script

This script securely generates **ED25519 SSH key pairs** for both a non-root service account and the root user, then **encrypts the private keys using [Rage](https://github.com/str4d/rage)**. The obfuscated keys are safely stored on disk, and the root key is also base64-encoded and injected into a Kubernetes Secret for safe failsafe recovery.

---

## ✅ Features

- Generates new SSH key pairs (ED25519)
- Obfuscates private keys using Rage with a trusted identity
- Stores obfuscated keys in a secure directory
- Injects root’s obfuscated key into a Kubernetes Secret
- Supports optional flags:
  - `--dry-run`: Simulate all actions without modifying anything
  - `--backup`: Save timestamped backups of existing SSH key files
  - `--rollback`: Automatically revert to last known good key state if a failure occurs
  - `--verbose`: Print each command being executed (debugging aid)

---

## 📁 Key Locations

| User        | SSH Key Path                           | Obfuscated Key Path                                       |
|-------------|----------------------------------------|-----------------------------------------------------------|
| `serviceuser` | `/home/serviceuser/.ssh/id_ed25519`   | `/srv/secure/obfuscated/id_ed25519_serviceuser.rage`     |
| `adminuser`   | `/root/.ssh/id_ed25519`               | `/srv/secure/obfuscated/id_ed25519_adminuser.rage`       |

The Rage identity used to encrypt these keys must exist at:

```

/srv/secure/identity/id\_ed25519

```

---
```
## 🛡 Kubernetes Secret

The script securely stores the **adminuser’s encrypted private key** in a Kubernetes secret:

- **Secret Name**: `admin-failsafe`
- **Namespace**: `infra`
- **Key**: `key` (contains the base64-encoded Rage-encrypted private key)

### 🔓 To decrypt the stored key later:

```bash
kubectl -n infra get secret admin-failsafe -o jsonpath="{.data.key}" | base64 -d > /tmp/admin_key.rage
rage --decrypt -i /srv/secure/identity/id_ed25519 -o /tmp/id_ed25519.adminuser /tmp/admin_key.rage
````

---

## 🧪 Usage

```bash
chmod +x generate_keys.sh
sudo ./generate_keys.sh [options]
```

### Options

| Flag         | Description                                            |
| ------------ | ------------------------------------------------------ |
| `--dry-run`  | Show what actions would occur without applying them    |
| `--backup`   | Backup any existing key files with a timestamp         |
| `--rollback` | Automatically restore previous keys if something fails |
| `--verbose`  | Print each command being executed                      |

---

## 🛠 Requirements

* [`rage`](https://github.com/str4d/rage) installed and available in `PATH`
* `kubectl` with access to the correct Kubernetes cluster/namespace
* Script must be run as root (to modify `/root/.ssh`)

---

## 📋 Example

```bash
sudo ./generate_keys.sh --backup --verbose
```

This will:

* Back up current keys
* Generate new ED25519 keys
* Encrypt the private keys using Rage
* Inject the obfuscated admin key into Kubernetes as a secret

---

## ⚠️ Warning

This script **overwrites existing SSH keys** unless `--backup` is used. Always keep the Rage identity key (`/srv/secure/identity/id_ed25519`) safe, as it is required to decrypt any obfuscated private keys.

---

## 💡 Use Cases

* Kubernetes-based infrastructure with secure key rotation policies
* Automated provisioning pipelines with break-glass SSH access
* Secure CI/CD or cluster bootstrap workflows
* Any situation requiring safe delivery or storage of private keys

---

## 📄 License

MIT — provided as-is for secure infrastructure automation. Use at your own risk.

```

