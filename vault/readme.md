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
