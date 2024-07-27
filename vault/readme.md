Managing SSH authentication with Vault
======================================

##
#
https://gist.github.com/michaellihs/32d2abb0be0e2936654d7d169133a94f
#
##

Managing SSH keys with Vault requires 3 steps:

1. Setting up Vault
2. Setting up the host
3. Setting up the client / using the signed client keys

For a full documentation, see this [HashiCorp Blog Post](https://www.vaultproject.io/docs/secrets/ssh/signed-ssh-certificates.html)


(0) Challenges with ssh public key authentication
-------------------------------------------------

For a good article on this topic, read this [blog post from Uber](https://medium.com/uber-security-privacy/introducing-the-uber-ssh-certificate-authority-4f840839c5cc)

* basic idea: use public/private key pair
  * keep private part on client's  machine
  * make public part known to host
* challenges:
  * all public keys must be managed
    * hard to keep track on all of them
    * removal might lead to security risks (ex-employee still having access to machines...)
  * ideally, keys should expire after a certain amount of time
    * ssh keys do not expire
    * manually invalidating them is brittle
  * mitigation: 2-factor authentication, e.g. with 
    * problem: inconvenient, users tend to carelessly handle 2FA if annoyed by it
* solution:
  * use certification authority for SSH keys
    * inventory public keys
    * enable automatic expiration of SSH keys
    * improve host authentication


(1) Set up Vault
----------------

1. mount a ssh secrets engine

   ```shell
   vault secrets enable -path=ssh ssh
   ```

1. configure Vault with a CA for signing client keys using the `/config/ca` endpoint. If you do not have an internal CA, Vault can generate a keypair for you

   ```shell
   vault write ssh-client-signer/config/ca generate_signing_key=true
   ```

1. create role for signing client keys

   ```shell
   vault write ssh/roles/my-role -<<"EOH"
   {
       "allow_user_certificates": true,
       "allowed_users": "*",
       "valid_principals": "vagrant",
       "default_extensions": [
           {
               "permit-pty": ""
           }
       ],
       "key_type": "ca",
       "default_user": "vagrant",
       "ttl": "30m0s"
   }
   EOH
   ```
   

(2) Set up the host
-------------------

1. (on the machine running Vault) Obtain the public key for the ssh key signing

   ```shell
   curl -o /etc/ssh/trusted-user-ca-keys.pem http://127.0.0.1:8200/v1/ssh-client-signer/public_key
   ```

1. store the public key to a proper location on the target host (e.g. `/etc/ssh/trusted-user-ca-keys.pem`)

1. add the following line to configure sshd to use the public key (`vi /etc/ssh/sshd_config`)

   ```
   TrustedUserCAKeys /etc/ssh/trusted-user-ca-keys.pem
   ```

1. restart sshd

   ```shell
   service sshd restart
   ```


(3) Using the signed keys
-------------------------

1. Signing a key with Vault

   ```shell
   vault write -field=signed_key ssh/sign/my-role public_key=@$HOME/.ssh/id_rsa.pub > signed-cert.pub
   ```

1. Log in to the remote host via

   ```shell
   ssh -i signed-cert.pub -i ~/.ssh/id_rsa <USER>@<HOST>
   ```


### Convenience wrapper for ssh with signed keys

1. add the following function to your `~/.bashrc`

   ```shell
   sshv () {
      vault write -field=signed_key ssh/sign/my-role public_key=@$HOME/.ssh/id_rsa.pub > /tmp/${1}-signed-cert.pub
      ssh -i /tmp/${1}-signed-cert.pub -i ~/.ssh/id_rsa ${1}
   }
   ```
   
1. ssh to your host via

   ```shell
   sshv <USER>@<HOST>
   ```


Debugging
---------

### SSH issues

* on the host, check the ssh logs via

   ```shell
   tail -f /var/log/auth.log
   ```
   
   on Centos, the logs are in `/var/log/secure`

* on the client, add `-vvv` to your ssh command

   ```shell
   ssh -i signed-cert.pub -i ~/.ssh/id_rsa <USER>@<HOST> -vvv
   ```

* common errors

   ```
   Dec 15 11:03:42 ipa sshd[2144]: error: Certificate invalid: name is not a listed principal
   Dec 15 11:17:01 ipa CRON[2154]: pam_unix(cron:session): session opened for user root by (uid=0)
   Dec 15 11:17:01 ipa CRON[2154]: pam_unix(cron:session): session closed for user root
   Dec 15 11:29:59 ipa sshd[2165]: error: Certificate invalid: not yet valid
   Dec 15 11:30:13 ipa sshd[2165]: Connection closed by authenticating user vagrant 192.168.33.1 port 51154 [preauth]
   Dec 15 11:30:14 ipa sshd[2167]: error: Certificate invalid: not yet valid
   ```

* `error: Certificate invalid: name is not a listed principal`: add `allowed_principals` to Vagrant role (check above)

* `error: Certificate invalid: not yet valid`: fix date with

   ```shell
   sudo date --set "14 Dec 2018 12:35:00"
   ```


### Check contents of signed key

    ssh-keygen -Lf /tmp/ipa-dev-signed-cert.pub


### Check Vault roles

    vault read ssh/roles/<ROLE NAME>


References
----------

* [SSH Management at Uber](https://medium.com/uber-security-privacy/introducing-the-uber-ssh-certificate-authority-4f840839c5cc)
* [Vault SSH Backend](https://www.vaultproject.io/docs/secrets/ssh/signed-ssh-certificates.html)
* [Vault SSH Backend API](https://www.vaultproject.io/api/secret/ssh/index.html)
* [Blog Post about Vault SSH Backend](https://www.sweharris.org/post/2016-10-30-ssh-certs/)
* [Using CA with SSH](https://www.lorier.net/docs/ssh-ca.html)




$ Vault ssh

OpenSSH 5.4 (March 2010), an SSH signed certificate contains a public key and metadata: Validity, Principals and Extensions

# Client Signing

## Create a key for user

    ssh-keygen -t rsa -C "sebastien@v2.prod.yet.org"

## Enable/Configure engine

    vault secrets enable ssh
    vault write ssh/config/ca generate_signing_key=true

Create a role

    vault write ssh/roles/gcp -<<"EOH"
{
  "allow_user_certificates": true,
  "allowed_users": "<USER>",
  "default_extensions": [
    {
      "permit-pty": "",
      "permit-port-forwarding": ""
    }
  ],
  "key_type": "ca",
  "default_user": "sebastien",
 "allow_user_key_ids": "false",
 "key_id_format": "{{token_display_name}}",
 "ttl": "5m0s"
}
EOH

Check

    vault read ssh/roles/gcp

Note: allowed_users specify the list of users for which a signature can be generated, if no users provided when signing request, the default one will be used.

## Configure OpenSSH

Get the Public key to your servers

    sudo curl -o /etc/ssh/trusted-user-ca-keys.pem https://<VAULT_API>/v1/ssh/public_key

or

    sudo vault read -field=public_key ssh/config/ca > /etc/ssh/trusted-user-ca-keys.pem

## Configure OpenSSH

    vi /etc/ssh/sshd_config
    TrustedUserCAKeys /etc/ssh/trusted-user-ca-keys.pem
    systemctl restart ssh

## Sign your public key by Vault ssh secret engine

    vault write -field=signed_key ssh/sign/gcp \
        public_key=@$HOME/.ssh/id_rsa.pub > ~/.ssh/id_rsa-cert.pub

    vault write -field=signed_key ssh/sign/gcp \
        valid_principals=<USER>
        public_key=@$HOME/.ssh/id_rsa.pub > ~/.ssh/id_rsa-cert.pub

## Sign with customized payload

    vault write ssh-client-signer/sign/my-role -<<"EOH"
{
  "public_key": "ssh...",
  "valid_principals": "<USER>",
  "key_id": "custom-prefix",
  "extension": {
    "permit-pty": ""
  }
}
EOH

API

    export TOKEN=`cat ~/.vault-token`; curl -k -sS -X POST -H "X-Vault-Token: $TOKEN" https://<VAULT_API>/v1/ssh/sign/gcp --data '{"public_key": "ssh-rsa XXX <USER_EMAIL>"}' | jq

## Login

    ssh -i ~/.ssh/id_rsa <USER>@<ASSET>

# Host Signing

## Enable & Configure another engine

     vault secrets enable -path=ssh-host-signer ssh
     vault write ssh-host-signer/config/ca generate_signing_key=true
     vault secrets tune -max-lease-ttl=87600h ssh-host-signer [10 years]

## Create a role

    vault write ssh-host-signer/roles/hostrole \
      key_type=ca \
      ttl=87600h \
      allow_host_certificates=true \
      allowed_domains="localdomain,<DOMAIN>" \
      allow_subdomains=true

## Sign Host - go on host

    vault login -method=userpass username=admin
    vault write -field=signed_key ssh-host-signer/sign/hostrole \
        cert_type=host \
        public_key=@/etc/ssh/ssh_host_rsa_key.pub > ssh_host_rsa_key-cert.pub
    sudo mv ssh_host_rsa_key-cert.pub /etc/ssh/
    sudo chmod 0640 /etc/ssh/ssh_host_rsa_key-cert.pub
   
## Configure OpenSSH host side

    vi /etc/ssh/sshd_config
    # For host keys
    HostKey /etc/ssh/ssh_host_rsa_key
    HostCertificate /etc/ssh/ssh_host_rsa_key-cert.pub
    sudo systemctl restart sshd

## Configure Client-Side verification

    curl https://vault.prod.yet.org/v1/ssh-host-signer/public_key

or

    vault read -field=public_key ssh-host-signer/config/ca

Add it to `known_hosts`

    vi ~/.ssh/known_hosts
    @cert-authority 34.77.222.135 ssh-rsa ssh-rsa <KEY>

## Connect

    ssh <USER>@<ASSET>

# One Time Password [OTP]

## Install Helper on target machine

    wget https://releases.hashicorp.com/vault-ssh-helper/0.1.4/vault-ssh-helper_0.1.4_linux_amd64.zip
    unzip vault-ssh-helper_0.1.4_linux_amd64.zip
    sudo mv vault-ssh-helper /usr/local/bin

## Install sshpass on source machine

    brew install http://git.io/sshpass.rb

## Configure SSHD

    vi /etc/ssh/sshd_config
    ChallengeResponseAuthentication yes
    UsePAM yes
    PasswordAuthentication no

## Configure vault-ssh-helper

    mkdir /etc/vault-ssh-helper.d/
    cd /etc/vault-ssh-helper.d/
    vi config.hcl
    vault_addr = "https://<VAULT_API>"
    ssh_mount_point = "ssh"
    ca_cert = "/etc/vault-ssh-helper.d/ca.crt"
    tls_skip_verify = false
    allowed_roles = "*"

download Vault `ca.crt` to `/etc/vault-ssh-helper.d/ca.crt`

## Dry run

    vault-ssh-helper -verify-only -config=/etc/vault-ssh-helper.d/config.hcl

## Configure PAM

    vi /etc/pam.d/sshd

comment following lines

    #@include common-auth

add following lines

    auth requisite pam_exec.so quiet expose_authtok log=/tmp/vaultssh.log /usr/local/bin/vault-ssh-helper -config=/etc/vault-ssh-helper.d/config.hcl
    auth optional pam_unix.so not_set_pass use_first_pass nodelay

## Create a role

    vault write ssh/roles/otp \
    key_type=otp \
    default_user=sebastien \
    cidr_list=<ASSET_CIDR>

## Ask for an OTP

    vault write ssh/creds/otp ip=<IP>
    Key                Value
    ---                -----
    lease_id           ssh/creds/otp/QTu4mea9BhCpev2Q7ymoOLE9
    lease_duration     768h
    lease_renewable    false
    ip                 <IP>
    key                <KEY>
    key_type           otp
    port               22
    username           <USER>

## Login

    ssh <USER>@<IP>
    vault ssh -role otp -mode otp sebastien@104.199.102.226

# JumpHost

On old ssh version

    ssh -o ProxyCommand="ssh <USER>@<HOST_BORDER> nc %h %p" <USER>@<HOST_IN>

On newer version use -J, require `AllowTcpForwarding yes`

    ssh -J <USER>@<HOST_BORDER> <USER>@<HOST_IN>

Or 

    ssh -o ProxyCommand='ssh -W %h:%p <USER>@<HOST_BORDER>' <USER>@<HOST_IN>

Or
    vi ~/.ssh/config
    Host c1
      HostName <HOST_IN>
      ProxyJump <USER>@<HOST_BORDER>
      User sebastien
    ssh c1

Possible to mix auth method, jumphost can be CERT and target OTP

    vault write ssh/creds/otp ip=<IP>
    ssh c2

## Tunnel RDP thru bastion

    ssh -L 3390:<WINDOWS_IP>:3389 <USER>@<HOST_BORDER> -N

## Troubleshoot

    tail -f /var/log/auth.log

If port forwarding not working, make sure you've added

# windows otp

    puttyfullpath <USER>@<ASSET> -pw OTPpass
    vault ssh -mode=ca -role=gcp <USER>@<ASSET>

or 

    vault ssh -role otp -mode otp <USER>@<IP>

# windows ca

    vault ssh -role gcp -mode ca <USER>@<ASSET>
