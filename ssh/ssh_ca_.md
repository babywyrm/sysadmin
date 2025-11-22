

# 🔐 2025 Edition: Vault-Signed SSH CA Workflow (Modernized)

## Overview

This guide demonstrates setting up **HashiCorp Vault as an SSH Certificate Authority (CA)** to sign **short-lived SSH certificates** for user access.  
This is a zero-standing-credentials architecture — no persistent authorized keys on servers; Vault issues certificates dynamically.

You’ll:

1. Configure Vault’s SSH CA secrets engine  
2. Register trust on target SSH servers  
3. Obtain signed SSH certs from Vault  
4. Perform ephemeral logins with automatic expiration

---

## 🧱 Prerequisites

| Component    | Description |
|---------------|-------------|
| **Vault Server** | v1.16+ (supports OpenSSH ed25519 CA, native OIDC auth) |
| **SSH Server** | OpenSSH 9.7+ on Linux |
| **Client** | Linux/macOS with `vault`, `jq`, and `openssh` tools |

Systems must have network reachability:
```
VAULT_SERVER → https://vault.internal:8200
SSH_SERVER   → your bastion or host
CLIENT       → user workstation
```

---

## 🚀 1. Vault Server Setup

### VAULT-01: Environment Configuration

```bash
export VAULT_ADDR="https://vault.internal:8200"
vault login
vault status
```

Confirm token validity:
```bash
vault token lookup
```

---

## 🏗️ 2. Configure Vault SSH CA

### VAULT-02A: Enable SSH CA Secrets Engine

Enable the SSH secrets engine at a custom path:

```bash
vault secrets enable -path=ssh-client-signer ssh
vault write ssh-client-signer/config/ca generate_signing_key=true
vault read -field=public_key ssh-client-signer/config/ca > trusted-user-ca-keys.pem
```

Optionally, use your own keypair:
```bash
vault write ssh-client-signer/config/ca private_key=@my_ca ed25519_public_key=@my_ca.pub
```

---

### VAULT-02B: Create Vault Policies and Roles

Create a **policy file** `user-policy.hcl`:

```hcl
path "ssh-client-signer/sign/clientrole" {
  capabilities = ["create", "update"]
}

path "ssh-client-signer/config/ca" {
  capabilities = ["read"]
}
```

Apply it:

```bash
vault policy write user-policy user-policy.hcl
```

Enable OIDC (preferred in 2025) or fallback to userpass:
```bash
# Preferred (OIDC)
vault auth enable oidc
# Legacy (userpass)
vault auth enable userpass
vault write auth/userpass/users/ubuntu password='changeme' policies=user-policy
```

---

### VAULT-02C: Create Client Role

`signer-clientrole.json`:
```json
{
  "allow_user_certificates": true,
  "allowed_users": "*",
  "default_extensions": {
    "permit-pty": ""
  },
  "key_type": "ca",
  "default_user": "ubuntu",
  "ttl": "15m"
}
```

Apply it:
```bash
vault write ssh-client-signer/roles/clientrole @signer-clientrole.json
```

---

## 🖥️ 3. SSH Server Configuration

### SSH-01A: Establish CA Trust

Copy the Vault CA’s public key:

```bash
scp trusted-user-ca-keys.pem root@<ssh-server>:/etc/ssh/
```

Edit `/etc/ssh/sshd_config`:
```text
TrustedUserCAKeys /etc/ssh/trusted-user-ca-keys.pem
PubkeyAuthentication yes
AuthorizedPrincipalsFile none
```

Restart SSH:
```bash
sudo systemctl restart sshd
```

---

## 💻 4. Client Workflow

### CLIENT-01A: Generate and Sign Key

Create ephemeral keypair:
```bash
SSH_USER=$(whoami)
SSH_SERVER="ssh.example.internal"
VAULT_ADDR="https://vault.internal:8200"

mkdir -p ~/.ssh
ssh-keygen -t ed25519 -N "" -C "${SSH_USER}" -f ~/.ssh/id_ed25519_${SSH_USER}
```

Authenticate and fetch token:
```bash
VAULT_TOKEN=$(vault login -method=userpass username=${SSH_USER} password='changeme' -format=json | jq -r .auth.client_token)
```

Sign your public key:
```bash
vault write -field=signed_key ssh-client-signer/sign/clientrole \
  public_key=@~/.ssh/id_ed25519_${SSH_USER}.pub valid_principals="${SSH_USER}" \
  > ~/.ssh/id_ed25519_${SSH_USER}-cert.pub
```

---

### CLIENT-01B: Connect Using the Signed Certificate

```bash
ssh -i ~/.ssh/id_ed25519_${SSH_USER} -i ~/.ssh/id_ed25519_${SSH_USER}-cert.pub ${SSH_USER}@${SSH_SERVER}
```

If the TTL expires (default 15 minutes), the cert becomes invalid automatically.

---

## ⏱️ 5. Short TTL Enforcements

To strengthen ephemeral use, modify TTL dynamically:

```bash
vault write ssh-client-signer/roles/clientrole \
  ttl=2m0s max_ttl=5m0s
```

Then regenerate your keypair and cert; the cert will expire in 2 minutes.

---

## ⚙️ 6. Automation Function

Save this in your `~/.bashrc` or `~/.zshrc` for single-command cert-based SSH logins:

```bash
ssh_vault() {
  set -euo pipefail
  SSH_USER="${1:-$(whoami)}"
  VAULT_ADDR="${VAULT_ADDR:-https://vault.internal:8200}"
  SSH_SERVER="${2:-ssh.example.internal}"

  KEY_PATH="$HOME/.ssh/id_ed25519_${SSH_USER}"
  rm -f "${KEY_PATH}"*

  ssh-keygen -t ed25519 -N "" -C "${SSH_USER}" -f "${KEY_PATH}"
  VAULT_TOKEN=$(vault login -method=userpass username=${SSH_USER} password='changeme' -format=json | jq -r .auth.client_token)
  vault write -field=signed_key ssh-client-signer/sign/clientrole public_key=@${KEY_PATH}.pub valid_principals="${SSH_USER}" > ${KEY_PATH}-cert.pub

  chmod 600 ${KEY_PATH}*
  echo "Connecting with Vault-issued certificate..."
  ssh -i "${KEY_PATH}" -i "${KEY_PATH}-cert.pub" "${SSH_USER}@${SSH_SERVER}"
}
```

Usage:
```bash
ssh_vault ubuntu bastion.internal
```

---

# 🧩 Appendix

#### signer-clientrole.json
```json
{
  "allow_user_certificates": true,
  "allowed_users": "*",
  "default_extensions": {
    "permit-pty": ""
  },
  "key_type": "ca",
  "default_user": "ubuntu",
  "ttl": "15m",
  "max_ttl": "30m"
}
```

#### user-policy.hcl
```hcl
path "ssh-client-signer/sign/*" {
  capabilities = ["create", "update"]
}

path "ssh-client-signer/config/ca" {
  capabilities = ["read"]
}
```

---

## 🔒 Modern Security Improvements (2025)

| Area | Modern Practice |
|------|----------------|
| **CA key type** | Use `ed25519` instead of RSA |
| **Auth method** | Replace `userpass` with OIDC / JWT |
| **TTL management** | Use short-lived certs (`1–15 min`) via role TTL |
| **Auditing** | Enable Vault audit logs to track issued certs |
| **Revocation** | Use constrained roles — no revoke for short TTLs |
| **Automation** | Integrate into DevOps pipelines (e.g., GitHub Actions using JWT auth) |

##
##

# SSH CA use-case with Vault

##
#
https://gist.github.com/kawsark/587f40541881cea58fbaaf07bb82b1be
#
##

In this scenario we are going to set up Vault to sign SSH keys using an internal CA. We will configure the SSH secrets engine and create a CA within Vault. We will then configure an SSH server to trust the CA key we just created. Finally we will attempt to SSH using a private key, and a public key signed by Vault SSH CA.

## Prerequisites

* This guide assumes you have already provisioned a Vault server, SSH host using OpenSSH server, and a SSH client machine.
* The client system must be able to reach the Vault server and the OpenSSH server.
* We will refer to these systems respectively as:
  * VAULT_SERVER
  * SSH_SERVER
  * CLIENT

### VAULT-01 - Vault Server Setup:
```
export VAULT_ADDR="http://vault_server:8200"
export VAULT_TOKEN="root_or_admin_token"
vault status
vault token status
```

### VAULT-02 - SSH-CA setup:

#### VAULT-02A Enable and configure the SSH CA secrets engine:
- Enable the SSH secrets engine and mount it in an arbitrary path. This path will be used to sign Client SSH keys.
- Generate new keys in that path. You can also import keys from your existing PKI, or a Vault PKI engine.
- Create the trusted user CA Keys and update SSH server.
```
vault secrets enable -path=ssh-client-signer ssh
vault write ssh-client-signer/config/ca generate_signing_key=true
vault read -field=public_key ssh-client-signer/config/ca > trusted-user-ca-keys.pem
```

#### VAULT-02B Define users and policies for Vault:
- Add role to Vault: Allow client to access paths at Vault server endpoint.
  * This says that whichever entity has this policy attached to it will be able to 'create' and 'update' to the API path `/ssh-client-signer/sign/clientrole`, which is the path used to sign a key with the SSH CA options `clientrole`
```
vi user-policy.hcl
vault policy write user user-policy.hcl
```

- Also 2 new users using user and password authentication method. The actual authentication can be sourced from an existing identity source such as LDAP, Git etc.
```
vault auth enable userpass
vault write auth/userpass/users/ubuntu password=test policies=user
vault write auth/userpass/users/ec2-user password=test policies=user
vault write auth/userpass/users/$(whoami) password=test policies=user
```

#### VAULT-02C Configure client role configuration:
- Add role to Vault: Allow client to sign their public key using vault. Adjust TTL, allowed users here if needed.
```
vi signer-clientrole.json
```
  * `allow_user_certificates` declares that this role will be for signing user certificates, instead of host certificates
  * `allowed_users`: allows this role to sign for any users. If, for example, you wanted to create a role which allowed only keys for a particular service name (say you wanted only to sign keys for an `ansible` user if you were using Ansible)
  * `default_extensions` sets the default certificate options when it signs the key. In this case, `permit-pty` allows the key to get a PTY on login, permitting interactive terminal sessions. For more information, consult the `ssh-keygen` documentation
  * `key_type` specifies that this is for SSH CA signing
  * `ttl` specifies that the signed certificate will be valid for no more than 30 minutes.

- Issue the command below to add this role:
```
vault write ssh-client-signer/roles/clientrole @signer-clientrole.json
```

### SSH-01 - OpenSSH Server Setup

#### SSH-01A - Add `TrustedUserCAKeys` directive:
- SFTP the `trusted-user-ca-keys.pem` from step **VAULT-02A**
- Then add the `TrustedUserCAKeys` directive to ssh_config file
```
sudo cp trusted-user-ca-keys.pem /etc/ssh/
echo "TrustedUserCAKeys /etc/ssh/trusted-user-ca-keys.pem" | sudo tee -a /etc/ssh/sshd_config
sudo service sshd restart
```

### CLIENT-01 - OpenSSH Client Setup

#### CLIENT-01A - Create key pair and sign with Vault:
- Create key pair. Note that `ssh_user` must exist in in SSH host:
```
export SSH_USER="ubuntu"
export SSH_SERVER="ssh_server_dns"
export VAULT_ADDR="http://vault_server:8200"
ssh-keygen -t rsa -N "" -C "${SSH_USER}" -f .ssh/id_rsa_${SSH_USER}
export public_key=$(cat .ssh/id_rsa_${SSH_USER}.pub)
echo ${public_key}
```
- Login to Vault and export Vault token:
```
curl \
    --request POST \
    --data '{"password": "test"}' \
    ${VAULT_ADDR}/v1/auth/userpass/login/${SSH_USER}

export VAULT_TOKEN=<auth.client_token>
```

- Get the public key signed by Vault:
```
cat <<EOF > ssh-ca.json
{
    "public_key": "${public_key}",
    "valid_principals": "${SSH_USER}"
}
EOF
cat ssh-ca.json

# If jq is installed:
curl -s \
  --header "X-Vault-Token: ${VAULT_TOKEN}" \
  --request POST \
  --data @ssh-ca.json \
  $VAULT_ADDR/v1/ssh-client-signer/sign/clientrole | jq -r .data.signed_key > .ssh/id_rsa_${SSH_USER}.signed.pub

# Otherwise:
curl -s \
  --header "X-Vault-Token: ${VAULT_TOKEN}" \
  --request POST \
  --data @ssh-ca.json \
  $VAULT_ADDR/v1/ssh-client-signer/sign/clientrole > vault_response.txt
  cat vault_response.txt
  # Copy the .data.signed_key field:
  vi .ssh/id_rsa_${SSH_USER}.signed.pub
```

#### CLIENT-01B - perform SSH Login:
- Try to only sign-in with unsigned key, you should get the output `Permission denied (publickey).` error:
```
ssh -i .ssh/id_rsa_${SSH_USER} ${SSH_USER}@${SSH_SERVER}
```
- Sign-in with signed public key and private key and validate you can login:
```
ssh -i .ssh/id_rsa_${SSH_USER}.signed.pub -i .ssh/id_rsa_${SSH_USER} ${SSH_USER}@${SSH_SERVER}
```

#### VAULT-03 Configure client role with short TTL:

Previously we configured `clientrole` with 30m TTL. Lets make this 1m to enforce a shorter TTL:
```
vi signer-clientrole2.json
vault write ssh-client-signer/roles/clientrole @signer-clientrole.json
```

#### CLIENT-02 Configure client role with short TTL:
- Remove previous key pair:
```
rm -f .ssh/id_rsa_${SSH_USER}*
```
- Repeat steps in CLIENT-01A
- Perform SSH Login:
```
ssh -i .ssh/id_rsa_${SSH_USER}.signed.pub -i .ssh/id_rsa_${SSH_USER} ${SSH_USER}@${SSH_SERVER}
exit
```
- Wait one minute and re-try. You should get a permission denied error.
```
sleep 60
ssh -i .ssh/id_rsa_${SSH_USER}.signed.pub -i .ssh/id_rsa_${SSH_USER} ${SSH_USER}@${SSH_SERVER}
```

### CLIENT-03 - Example bash function:
- Assuming the `jq` utility is installed, we can create a function for ease of use:
```
ssh_vault () {
  export SSH_USER="$(whoami)"
  export SSH_SERVER="<ssh_host>"
  export VAULT_ADDR="http://<vault_dns>:8200"
  rm -f token ssh-ca.json .ssh/id_rsa_${SSH_USER}*
  ssh-keygen -t rsa -N "" -C "${SSH_USER}" -f .ssh/id_rsa_${SSH_USER}
  export public_key=$(cat .ssh/id_rsa_${SSH_USER}.pub)
  curl -s \
      --request POST \
      --data '{"password": "test"}' \
      ${VAULT_ADDR}/v1/auth/userpass/login/${SSH_USER} | jq -r .auth.client_token > token
  export VAULT_TOKEN=$(cat token)
  curl -s \
    --header "X-Vault-Token: ${VAULT_TOKEN}" \
    --request POST \
    --data "{\"public_key\":\"${public_key}\",\"valid_principals\":\"${SSH_USER}\"}" \
    $VAULT_ADDR/v1/ssh-client-signer/sign/clientrole | jq -r .data.signed_key > .ssh/id_rsa_${SSH_USER}.signed.pub
  chmod 400 .ssh/id_rsa_${SSH_USER}*
  ssh -i .ssh/id_rsa_${SSH_USER}.signed.pub -i .ssh/id_rsa_${SSH_USER} ${SSH_USER}@${SSH_SERVER}
}
```

#### Appendix:
- signer-clientrole.json file:
```
{
  "allow_user_certificates": true,
  "allowed_users": "*",
  "default_extensions": [
    {
      "permit-pty": ""
    }
  ],
  "key_type": "ca",
  "default_user": "ubuntu",
  "ttl": "30m0s"
}
```
- user-policy.hcl file:
```
path "sys/mounts" {
  capabilities = ["list", "read"]
}

path "ssh-client-signer/sign/clientrole" {
  capabilities = ["create", "update"]
}

path "ssh-client-signer/config/ca" {
  capabilities = ["read"]
}

path "ssh-host-signer/config/ca" {
  capabilities = ["read"]
}
```
- signer-clientrole2.json file:
```
{
  "allow_user_certificates": true,
  "allowed_users": "*",
  "default_extensions": [
    {
      "permit-pty": ""
    }
  ],
  "key_type": "ca",
  "default_user": "ubuntu",
  "ttl": "1m0s"
}
```
