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
