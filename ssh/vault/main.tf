terraform {
  required_version = ">= 1.8.0"

  required_providers {
    vault = {
      source  = "hashicorp/vault"
      version = "~> 4.3"
    }
  }
}

provider "vault" {
  address = var.vault_addr
  token   = var.vault_token
}

variable "vault_addr" {
  description = "Vault server address"
  type        = string
  default     = "https://vault.internal:8200"
}

variable "vault_token" {
  description = "Admin Vault token for provisioning"
  type        = string
  sensitive   = true
}

# --------------------------------------------------------------------
# Enable Vault SSH CA Secrets Engine
# --------------------------------------------------------------------
resource "vault_mount" "ssh_ca" {
  path        = "ssh-client-signer"
  type        = "ssh"
  description = "Vault-managed SSH CA for ephemeral user certificates"
}

# --------------------------------------------------------------------
# Generate SSH CA Key Pair (Ed25519)
# --------------------------------------------------------------------
resource "vault_ssh_secret_backend_ca" "ca" {
  backend              = vault_mount.ssh_ca.path
  generate_signing_key = true
  key_type             = "ed25519"
}

# --------------------------------------------------------------------
# Vault Policy Allowing Signing and CA Read
# --------------------------------------------------------------------
resource "vault_policy" "ssh_user_policy" {
  name = "ssh-user-policy"
  policy = <<EOT
path "ssh-client-signer/sign/clientrole" {
  capabilities = ["create", "update"]
}
path "ssh-client-signer/config/ca" {
  capabilities = ["read"]
}
EOT
}

# --------------------------------------------------------------------
# Create SSH Role for Client Certificate Signing
# --------------------------------------------------------------------
resource "vault_ssh_secret_backend_role" "clientrole" {
  backend                 = vault_mount.ssh_ca.path
  name                    = "clientrole"
  allow_user_certificates  = true
  allowed_users            = ["*"]
  key_type                = "ca"
  default_user            = "ubuntu"
  default_extensions_json  = jsonencode({
    "permit-pty" = ""
  })
  ttl      = "15m"
  max_ttl  = "30m"
}

# --------------------------------------------------------------------
# Optional: Enable Legacy userpass Authentication for Testing
# --------------------------------------------------------------------
resource "vault_auth_backend" "userpass" {
  type        = "userpass"
  description = "Userpass auth backend for testing Vault SSH CA"
}

resource "vault_generic_endpoint" "user_ubuntu" {
  depends_on = [vault_auth_backend.userpass]
  path       = "auth/userpass/users/ubuntu"
  data_json  = jsonencode({
    password = "changeme"
    policies = [vault_policy.ssh_user_policy.name]
  })
}

# --------------------------------------------------------------------
# Output CA Public Key for Placement on SSH Servers
# --------------------------------------------------------------------
output "trusted_user_ca_public_key" {
  description = "Public CA key to copy to /etc/ssh/trusted-user-ca-keys.pem on servers"
  value       = vault_ssh_secret_backend_ca.ca.public_key
}

output "ssh_ca_mount_path" {
  description = "Path where the SSH CA engine is mounted"
  value       = vault_mount.ssh_ca.path
}

output "ssh_role_name" {
  description = "Name of the Vault role used for signing SSH certs"
  value       = vault_ssh_secret_backend_role.clientrole.name
}
