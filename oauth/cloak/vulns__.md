
# Keycloak Misconfigurations, Exploits, and Mitigations

| Misconfiguration                          | How to Implement                                                                                                  | Exploit Scenario                                                                                                                                          | Mitigation in Real Life                                                                                                                                                                                                                                                                                                                                                                                                                   |
|-------------------------------------------|---------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Weak Signing Algorithm**                | Set `alg` to `none` in **Realm Settings** → **Tokens**.                                                            | Participants modify JWT payloads directly without needing to re-sign them.                                                                                | **Use Strong Algorithms:** Configure your realm to use `RS256` or `HS256`. Avoid using `none` for token signatures. <br>**Regular Checks:** Periodically verify that no realm or client is configured with an insecure algorithm. <br>**Up-to-Date Keycloak:** Keep Keycloak updated to ensure that any vulnerabilities related to token algorithms are patched. |
| **Weak Secret Key**                       | Set a weak or guessable client secret (e.g., `supersecret`) in **Clients** → **Credentials**.                       | Participants forge valid JWTs using the leaked or guessable secret.                                                                                         | **Strong Secrets:** Use long, random, and complex secrets. <br>**Secret Rotation:** Change secrets periodically and whenever a breach is suspected. <br>**Secret Storage:** Store secrets securely (e.g., encrypted in Vault). <br>**No Hardcoding:** Don’t hardcode secrets in source code; use environment variables or secure credential stores. |
| **Arbitrary Scope Injection**             | Enable **Full Scope Allowed** in **Clients** → **Scope**, allowing the client to request any defined scope.          | Participants request tokens with unauthorized scopes (e.g., `admin`).                                                                                     | **Least Privilege:** Disable “Full Scope Allowed” unless absolutely necessary. <br>**Restricted Scopes:** Assign scopes to clients based on their purpose and limit what can be requested. <br>**Scope Verification:** The resource server should verify that only expected scopes are present and deny any unexpected ones.                                 |
| **Improper Scope Validation**             | Don’t verify JWT signatures or trust `scope` claims in the resource server without validation.                      | Participants add unauthorized scopes in JWT payloads to access restricted endpoints.                                                                      | **Signature Verification:** Always verify JWT signatures in the resource server. <br>**Claim Validation:** Check `aud`, `iss`, `exp`, and `scope` against known, expected values. <br>**Defense in Depth:** Implement authorization checks at the resource server even if the token seems valid and well-formed.                       |
| **Leaked Secrets via Other Challenges**   | Expose realm secrets or weak signing keys in other CTF challenges (files, configs, logs).                            | Participants piece together information from multiple CTF challenges to exploit Keycloak and Warbird API integration.                                      | **Segregation of Duties:** Keep secrets in secure storage accessible only to authorized personnel. <br>**No Sensitive Info in Code/Logs:** Avoid leaking secrets in code, configuration files, or logs. <br>**Code Reviews:** Regularly review code and configs to ensure no sensitive data is exposed.                                                  |
| **Excessive Token Lifetime**              | Set very long token lifespans in **Realm Settings** → **Tokens** (e.g., 24 hours).                                   | Participants reuse tokens for extended periods, bypassing normal session controls or token revocation.                                                    | **Short-Lived Tokens:** Use shorter token lifetimes and rely on refresh tokens or session tokens. <br>**Revocation Support:** Enable token revocation and consider a token introspection endpoint to dynamically check token validity. <br>**Session Policies:** Apply strict session policies to prevent token abuse.        |
| **Public Clients with Excessive Privileges** | Configure a public client (no secret required) with access to sensitive scopes in **Clients** → **Settings**.       | Participants obtain tokens from a public client to access sensitive scopes without authentication.                                                         | **Confidential Clients:** Use confidential clients for operations requiring authentication or privileged access. <br>**Scoped Access:** Assign minimal scopes to public clients. <br>**Strict Client Policies:** Enforce authentication flows that require client secrets or mutual TLS.                          |
| **Misconfigured Audience Claim**          | Allow tokens meant for another client or audience to be accepted by your resource server or other clients.           | Participants use tokens intended for one client to access another client’s protected resources.                                                             | **Audience Verification:** Check the `aud` claim in tokens to ensure they are intended for your resource server. <br>**Client-Specific Audiences:** Configure clients so that tokens are audience-specific. <br>**Strict Validation:** Reject tokens that do not match the expected `aud` claim.                  |
| **Unrestricted Token Exchange**           | Enable token exchange in **Clients** → **Advanced Settings** without proper permissions.                             | Participants exchange tokens to gain privileges or impersonate other users.                                                                                | **Limit Token Exchange:** Disable token exchange unless needed. <br>**Fine-Grained Permissions:** If token exchange is enabled, apply strict policies to determine who can exchange tokens and under what conditions. <br>**Monitor Usage:** Track token exchange requests and audit suspicious activity.        |
| **Open Redirects in Login Endpoints**     | Allow overly permissive or wildcard redirect URIs in **Clients** → **Settings**.                                     | Participants craft malicious URLs to steal tokens or credentials through phishing (Open Redirect attacks).                                                  | **Restricted Redirect URIs:** Only allow exact redirect URIs. Avoid wildcards. <br>**Use PKCE:** Implement Proof Key for Code Exchange to mitigate token interception. <br>**Validate Origins:** Enforce strict redirect URI validation to prevent token leakage to malicious sites.                                 |
| **Insecure Communication (No HTTPS)**     | Use HTTP instead of HTTPS for Keycloak or the Warbird API.                                                           | Participants intercept tokens and credentials in plaintext with network sniffing tools.                                                                    | **Enforce TLS:** Always use HTTPS to prevent man-in-the-middle attacks. <br>**Strong Cipher Suites:** Configure TLS with strong cipher suites and updated certificates. <br>**HSTS:** Enable HTTP Strict Transport Security (HSTS) to enforce secure connections.                                                    |

---

## Example `kcadm.sh` Commands

Below are example `kcadm.sh` commands to help set up and configure Keycloak realms, clients, and scopes for your CTF scenario. These assume you have `kcadm.sh` available and are authenticated as the Keycloak admin:

1. **Login to the master realm:**
   ```bash
   kcadm.sh config credentials \
     --server http://<KEYCLOAK_URL>/auth \
     --realm master \
     --user admin \
     --password <ADMIN_PASSWORD>

---

## Notes 

- These misconfigurations are designed for educational and controlled environments only.
- Ensure your production environments follow strict security practices and industry guidelines.



## Example `kcadm.sh` Commands

Below are example `kcadm.sh` commands to help set up and configure Keycloak realms, clients, and scopes for your CTF scenario. These assume you have `kcadm.sh` available and are authenticated as the Keycloak admin:

1. **Login to the master realm:**
   ```bash
   kcadm.sh config credentials \
     --server http://<KEYCLOAK_URL>/auth \
     --realm master \
     --user admin \
     --password <ADMIN_PASSWORD>
Create a new realm (e.g., ctf-realm):


```
kcadm.sh create realms -s realm=ctf-realm -s enabled=true
```


Create a confidential client (e.g., warbird-api) with a weak secret (for CTF):

```
kcadm.sh create clients -r ctf-realm \
  -s clientId=warbird-api \
  -s enabled=true \
  -s publicClient=false \
  -s secret=supersecret \
  -s directAccessGrantsEnabled=true
```

Enable Full Scope Allowed (Not recommended in real life):

```
CLIENT_ID=$(kcadm.sh get clients -r ctf-realm --fields id,clientId | jq -r '.[] | select(.clientId=="warbird-api").id')
kcadm.sh update clients/$CLIENT_ID -r ctf-realm -s 'fullScopeAllowed=true'
```

Create Custom Scopes:

```
kcadm.sh create client-scopes -r ctf-realm -s name=view-schematics -s protocol=openid-connect
kcadm.sh create client-scopes -r ctf-realm -s name=edit-schematics -s protocol=openid-connect
```

# To associate a default client scope
```
VIEW_SCOPE_ID=$(kcadm.sh get client-scopes -r ctf-realm --fields id,name | jq -r '.[] | select(.name=="view-schematics").id')
EDIT_SCOPE_ID=$(kcadm.sh get client-scopes -r ctf-realm --fields id,name | jq -r '.[] | select(.name=="edit-schematics").id')

kcadm.sh update clients/$CLIENT_ID -r ctf-realm -s "defaultClientScopes=[\"$VIEW_SCOPE_ID\",\"$EDIT_SCOPE_ID\"]"
```

Set a Weak Algorithm (for demonstration only):


```
kcadm.sh update realms/ctf-realm -s "defaultSignatureAlgorithm=RS256"   # Set to RS256 initially
```
# If you'd like to simulate a weak scenario (not recommended in prod):
kcadm.sh update realms/ctf-realm -s "accessTokenLifespan=3600" -s "tokenExchangeEnabled=true"
# Note: Changing algorithms to 'none' might require direct database or advanced config tweaks not recommended here.
Configure Token Lifetimes:

```
kcadm.sh update realms/ctf-realm -s "accessTokenLifespan=86400"  # Set token lifespan to 24h for the CTF scenario
```


# Keycloak Admin CLI Cheat Sheet

This document provides some examples about how to use `kcadm` to manage a realm's configuration.

## Configuring Token Exchange Permission for a Client

### Enable permissions to a client

```bash
./kcadm.sh update clients/{client_id}/management/permissions -f - << EOF 
    {"enabled": true} 
EOF
```

### Enable Permissions to a client

```bash
./kcadm.sh update clients/{client_id}/management/permissions -f - << EOF 
    {"enabled": true} 
EOF
```

### Get the id of the realm-management client so that you can manage permissions

```bash
./kcadm.sh get clients | jq '.[] | select(.clientId == "realm-management") | .id'
```

### Create the token-exchange permission

```bash
./kcadm.sh create clients/{realm_management_client_id}/authz/resource-server/permission/scope -f - << EOF 
    {
        "name":"token-exchange.permission.client.{client_id}",
        "type":"scope",
        "resources":["client.resource.{client_id}"],
        "scopes":["token-exchange"],"policies":[]
    }
EOF
```

### Get the token-exchange permission id for a client

```bash
./kcadm.sh get clients/{realm_management_client_id}/authz/resource-server/permission | jq '.[] | select(.name == "token-exchange.permission.client.{client_id}") | .id'
```

### Update the token-exchnge permission

```bash
./kcadm.sh update clients/{realm_management_client_id}/authz/resource-server/permission/scope/{permission_id} -f - << EOF 
    {
        "name":"token-exchange.permission.client.{client_id}",
        "type":"scope",
        "logic":"POSITIVE",
        "decisionStrategy":"AFFIRMATIVE",
        "description":"teste",
        "resources":["client.resource.{client_id}"],
        "scopes":["token-exchange"],"policies":[]
    }
EOF
```

### Delete the token-exchange permission

```bash
./kcadm.sh delete clients/{realm_management_client_id}/authz/resource-server/permission/scope/{permission_id}
```

## Managing Client Policies

### Create a Client Policy 

```bash
./kcadm.sh create clients/{realm_management_client_id}/authz/resource-server/policy/client -f - << EOF 
    {
        "name":"My Client Policy",
        "type":"client",
        "clients":["admin"]
    }
EOF
```

### Get the policy id 

```bash
./kcadm.sh get clients/{realm_management_client_id}/authz/resource-server/policy/client | jq '.[] | select(.name == "My Client Policy") | .id'
```

### Update the policy

```bash
./kcadm.sh update clients/{realm_management_client_id}/authz/resource-server/policy/client/{policy_id} -f - << EOF 
    {
        "name":"My Client Policy",
        "type":"client",
        "clients":["account"]
    }
EOF
```

### Delete the policy

```bash
./kcadm.sh delete clients/{realm_management_client_id}/authz/resource-server/policy/client/{policy_id}
```



```

#!/bin/bash

export TKN=$(curl -X POST 'http://localhost:8080/auth/realms/master/protocol/openid-connect/token' \
 -H "Content-Type: application/x-www-form-urlencoded" \
 -d "username=admin" \
 -d 'password=admin' \
 -d 'grant_type=password' \
 -d 'client_id=admin-cli' | jq -r '.access_token')

curl -X GET 'http://localhost:8080/auth/admin/realms' \
-H "Accept: application/json" \
-H "Authorization: Bearer $TKN" | jq .

