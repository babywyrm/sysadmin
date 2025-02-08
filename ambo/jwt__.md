
# Integrating Both in Ambassador on EKS

Deployment in EKS:
Deploy Ambassador as your ingress gateway on EKS. Ambassador routes external traffic to your internal services (apps) hosted within the cluster.

JWT Configuration:
Use Ambassador Edge Stack’s built‑in authentication features to configure JWT validation. For example, you can define an Authentication or Mapping resource that specifies:

The issuer URL (or JWKS endpoint)
Allowed audiences
Required scopes
This ensures that only requests with valid tokens and proper permissions are forwarded to your services.

CORS Configuration:
Configure CORS settings within your Ambassador Mapping resources (or via annotations) to allow only specific origins. For instance, your configuration might look like this:

```
apiVersion: getambassador.io/v3alpha1
kind: Mapping
metadata:
  name: myservice
spec:
  prefix: /api/
  service: myservice.namespace:80
  cors:
    origins:
      - "https://example.com"
    methods:
      - GET
      - POST
      - OPTIONS
    headers:
      - "Authorization"
      - "Content-Type"
    credentials: true
```
    
With this setup:

Browser-based clients from https://example.com will be allowed (subject to a successful JWT check).
Requests from unapproved origins will be blocked by the browser’s enforcement of the CORS policy.
Defense in Depth:

JWT Validation: Protects the API by ensuring that only properly authenticated and authorized requests reach your backend services. This layer protects against unauthorized access even if someone bypasses client-side restrictions.
CORS Checks: Add an extra layer that helps prevent malicious or accidental cross-origin requests from browser-based applications. Even if an attacker somehow obtains a valid JWT (or if a user’s token is compromised), the CORS policy helps ensure that only requests from trusted origins can execute in a browser context.
Keep in mind that CORS is not a substitute for authentication and authorization—it only works for enforcing rules on browser clients. Non-browser clients can ignore CORS rules, which is why JWT validation remains essential.

Practical Considerations in EKS
Configuration Management:
Use Kubernetes manifests or Helm charts to manage your Ambassador configuration. This allows you to version-control your security settings and apply them consistently across environments.

Testing:
Test both the JWT validation and CORS policies. For instance, verify that:
```
A request from an unauthorized domain is blocked (or fails preflight).
A request with an invalid/missing JWT is rejected.
Only requests that satisfy both conditions reach your backend service.
```

Monitoring and Logging:
Enable logging in Ambassador to monitor authentication failures and CORS-related errors. This helps in debugging and ensuring that your security policies are effective.

