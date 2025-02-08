
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

##
##
##




1. Embedding Domain/Origin Claims in Your JWT


Proposal:

Have your identity provider include a claim in the JWT (for example, allowed_origins or allowed_domains) that lists the domains or subdomains for which the token is valid. For example, a token might include:

```
{
  "sub": "user123",
  "scope": "read:data",
  "allowed_origins": ["https://app.example.com", "https://admin.example.com"],
  "iss": "https://your-idp.com",
  "aud": "your-api"
}
```

This claim allows downstream services (or an intermediary) to check that the request’s Origin header matches one of the approved origins in the token.




# 2. Ambassador’s Native Capabilities

JWT Validation
Ambassador (especially the Edge Stack version) supports built-in JWT validation. You can configure it to:

Validate the token’s signature.
Check required claims like issuer, audience, and scopes.
Static CORS Configuration
Ambassador also supports configuring CORS on a per‑Mapping basis. For example, you can define a Mapping with a CORS block:

```
apiVersion: getambassador.io/v3alpha1
kind: Mapping
metadata:
  name: service-a
spec:
  prefix: /service-a/
  service: service-a.namespace:80
  cors:
    origins:
      - "https://app.example.com"
      - "https://admin.example.com"
    methods:
      - GET
      - POST
      - OPTIONS
    headers:
      - Authorization
      - Content-Type
    credentials: true
```

    
This configuration tells the browser which origins are allowed to access the service. However, note that this is a static list. In environments where subdomains or allowed origins might differ per token, you may need a more dynamic approach.

# 3. Dynamic Origin Enforcement with an External Authorization Service
Since Ambassador’s built‑in CORS configuration is static, if you want to dynamically validate the request’s Origin header against the JWT’s allowed_origins claim, you’ll likely need to integrate an external authorization (ext_auth) service. Here’s how that could work:

Request Arrival:

A client sends a request with an Authorization header (bearing the JWT) and an Origin header.
JWT Validation:

Ambassador (or a preliminary ext_auth service) validates the JWT for signature, issuer, audience, and scopes.
Custom Domain Check:

The ext_auth service extracts the allowed_origins (or equivalent) claim from the JWT.
It compares the incoming request’s Origin header against the allowed list.
If the origin is not in the allowed list, the service denies the request (for example, returning a 403).
Return Decision:

If the ext_auth service approves the request, it can also inject the appropriate CORS headers (or let Ambassador’s static CORS configuration handle the response) before forwarding the request to the internal service.
A simplified Ambassador ext_auth configuration might look like this:



```

apiVersion: getambassador.io/v3alpha1
kind: AuthService
metadata:
  name: jwt-domain-auth
spec:
  auth_service: "ext-auth.namespace:3000"  # Your custom auth service endpoint
  proto: http
  allowed_request_headers:
    - "authorization"
    - "origin"
  include_body: true
  ```


Your custom external authorization service (running as a microservice in your cluster) would contain the logic to:

Parse the JWT (possibly reusing the JWT validation Ambassador already performed).
Verify that the Origin header matches one of the allowed origins from the token.
Approve or reject the request accordingly.
This dynamic check complements the static CORS rules and ensures that even if a token is valid, the request must also come from an approved domain.

# 4. Handling Multiple Subdomains and Services
In a scenario where different subdomains correspond to different services:

Per-Mapping CORS Settings:
You might have different Ambassador Mappings for each subdomain/service with their own CORS configurations. This works well if the allowed origins are predetermined and relatively static.

JWT Domain Claims with Ext_Auth:
If the allowed origins vary per user or token, then the ext_auth approach described above is more appropriate. Your authorization service can look at the JWT’s claims and decide which subdomains are valid for that request.

For example, if service-a is meant to be accessed only from https://app.example.com and service-b only from https://api.example.com, your ext_auth service can enforce this by checking both the Mapping context (or routing logic) and the token’s claims.

# 5. Putting It All Together in Ambassador Pods
Since Ambassador is typically deployed as a set of pods in EKS, you would:

Deploy Ambassador with the necessary configuration:
Include both your static JWT validation and CORS settings in your Mapping definitions.

Deploy your ext_auth Service:
Run your custom authorization service as a separate deployment in your cluster. Ensure that Ambassador’s configuration (via the AuthService resource) points to it.

Version-Control Configurations:
Use Kubernetes manifests (or Helm charts) to manage these configurations. This allows you to adjust policies as your subdomain or service landscape evolves.

Monitor and Test:
Verify that requests from an allowed origin with a proper JWT pass through, and that requests with either an invalid token or an unauthorized origin are blocked.

Summary
Static CORS: Use Ambassador’s Mapping CORS configuration for fixed, known allowed origins.
Dynamic Checks via JWT Claims: Include domain or origin claims in your JWT and enforce them with a custom external authorization service.
Combined Defense: Ambassador first validates the JWT (ensuring proper scopes, issuer, etc.) and then—via an external auth filter—checks that the request’s Origin header matches the approved domains from the token.
Deployment on EKS: Both Ambassador and your custom ext_auth service run as pods, with configurations managed via Kubernetes manifests, ensuring that each service or subdomain receives the appropriate security controls.


##
##


# 1. Ambassador Configuration

A. AuthService Resource
This tells Ambassador to call your external auth service for every incoming request that needs dynamic validation.

```
apiVersion: getambassador.io/v3alpha1
kind: AuthService
metadata:
  name: jwt-auth
spec:
  # The DNS name and port of your external auth service (running in your cluster)
  auth_service: "ext-auth-service.default:3000"
  proto: http
  # Path that your ext_auth service will listen on (see below in the Flask app)
  path_prefix: "/check"
  # Forward these headers from the client to the external auth service.
  allowed_request_headers:
    - "authorization"
    - "origin"
  # Optionally include the body if your ext_auth service needs it.
  include_body: true
```

  
B. Mapping Resource with JWT and Static CORS
This example Mapping shows how you might configure Ambassador to do the initial JWT validation and to provide a baseline (static) CORS configuration. The ext_auth call (from the AuthService above) will then enforce dynamic checks.

```
apiVersion: getambassador.io/v3alpha1
kind: Mapping
metadata:
  name: service-mapping
spec:
  prefix: /api/
  service: my-backend-service.default:80
  # Static CORS settings to inform the browser which origins are allowed.
  # These can be used in tandem with the dynamic ext_auth check.
  cors:
    origins:
      - "https://app.example.com"
      - "https://admin.example.com"
    methods:
      - GET
      - POST
      - OPTIONS
    headers:
      - "Authorization"
      - "Content-Type"
    credentials: true
  # Built-in JWT configuration (Ambassador will verify signature, issuer, audience, etc.)
  jwt:
    issuer: "https://your-idp.com"
    audiences:
      - "your-api"
    remote_jwks:
      url: "https://your-idp.com/.well-known/jwks.json"

```
      
Note:

The JWT configuration here tells Ambassador to verify that the token is issued by your identity provider.
The ext_auth service (configured in the AuthService) is called after the basic JWT validation. It can then decode the same token again (or use information passed from Ambassador) to check custom claims like allowed_origins.
2. Building a Custom External Authorization Service
Let’s create a simple Python (Flask) app that:

Reads the Authorization header and decodes the JWT (using a public key)
Extracts a custom claim (here, allowed_origins)
Compares the incoming request’s Origin header with the allowed origins
Returns an OK response if the check passes or an error if it fails
A. Python Code (ext_auth.py)

```
from flask import Flask, request, jsonify, abort
import jwt  # PyJWT
import os

app = Flask(__name__)

# You would typically load your public key from a secure location or environment variable.
PUBLIC_KEY = os.environ.get("JWT_PUBLIC_KEY", """
-----BEGIN PUBLIC KEY-----
YOUR_PUBLIC_KEY_HERE
-----END PUBLIC KEY-----
""")

# Expected values for validation; adjust these as needed.
EXPECTED_ISSUER = "https://your-idp.com"
EXPECTED_AUDIENCE = "your-api"

@app.route("/check", methods=["GET", "POST", "OPTIONS"])
def check_auth():
    # Handle preflight requests (if necessary)
    if request.method == "OPTIONS":
        return '', 200

    auth_header = request.headers.get("authorization")
    if not auth_header:
        abort(401, description="Missing Authorization header")

    # Assume token comes as "Bearer <token>"
    try:
        token = auth_header.split(" ")[1]
    except IndexError:
        abort(401, description="Malformed Authorization header")

    try:
        # Decode and verify the JWT
        decoded = jwt.decode(
            token,
            PUBLIC_KEY,
            algorithms=["RS256"],
            audience=EXPECTED_AUDIENCE,
            issuer=EXPECTED_ISSUER,
        )
    except Exception as e:
        abort(401, description=f"Invalid token: {str(e)}")

    # Get the allowed origins from the token (this should be a list of origins)
    allowed_origins = decoded.get("allowed_origins", [])
    origin = request.headers.get("origin", "")

    if origin not in allowed_origins:
        abort(403, description="Origin not allowed")

    # If all checks pass, return a 200 OK response.
    return jsonify({"message": "Authorized"}), 200

if __name__ == "__main__":
    # Listen on port 3000 as specified in our Ambassador AuthService configuration.
    app.run(host="0.0.0.0", port=3000)
    ```
    
B. Dockerfile for the ext_auth Service
```
Create a Dockerfile in the same directory as your ext_auth.py:

```
# Use a lightweight Python image.
FROM python:3.9-slim

WORKDIR /app

# Copy and install dependencies.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code.
COPY ext_auth.py .

# Expose port 3000 as expected by Ambassador.
EXPOSE 3000

# Run the ext_auth service.
CMD ["python", "ext_auth.py"]
```

C. requirements.txt
Create a requirements.txt file with the following content:

```
Flask==2.2.2
PyJWT==2.6.0
```


D. Build and Push Your Docker Image
In your terminal, run:


# Build the Docker image.
docker build -t yourdockerhubusername/ext-auth-service:latest .

# Push the image to your container registry.
docker push yourdockerhubusername/ext-auth-service:latest
Replace yourdockerhubusername with your actual Docker Hub (or other registry) username.

3. Kubernetes YAML for Deploying the ext_auth Service
Create a Kubernetes manifest (for example, ext-auth-deployment.yaml) to deploy your ext_auth service in your cluster:

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ext-auth-service
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: ext-auth
  template:
    metadata:
      labels:
        app: ext-auth
    spec:
      containers:
      - name: ext-auth
        image: yourdockerhubusername/ext-auth-service:latest
        ports:
        - containerPort: 3000
        env:
          # Optionally pass your public key via an environment variable
          - name: JWT_PUBLIC_KEY
            value: |
              -----BEGIN PUBLIC KEY-----
              YOUR_PUBLIC_KEY_HERE
              -----END PUBLIC KEY-----
---
apiVersion: v1
kind: Service
metadata:
  name: ext-auth-service
  namespace: default
spec:
  ports:
    - port: 3000
      targetPort: 3000
  selector:
    app: ext-auth
```
    
Apply this manifest with:

```
kubectl apply -f ext-auth-deployment.yaml
```

4. How It Works Together
Client Request:
A client (for example, a browser-based app) sends a request to your API endpoint (e.g., https://your-ambassador-domain/api/) with:

An Authorization header bearing a JWT that includes an allowed_origins claim (e.g., ["https://app.example.com", "https://admin.example.com"])
An Origin header (e.g., https://app.example.com)
Ambassador JWT Check:
Ambassador’s Mapping configuration uses the jwt field to perform basic validation of the token (signature, issuer, audience).

Dynamic Origin Check:
Because you’ve configured an AuthService pointing to /check on your ext_auth service, Ambassador will forward the request headers (including authorization and origin) to your ext_auth service.
The ext_auth service decodes the JWT, checks that the Origin header is within the token’s allowed_origins list, and returns an OK (or error) response accordingly.

Request Routing:
If the external authorization call returns a successful response (HTTP 200), Ambassador forwards the original request to your internal backend service.

Summary
Ambassador Configuration:
You define both a Mapping (with JWT and static CORS settings) and an AuthService (pointing to your ext_auth service).

ext_auth Service:
A small Flask app that decodes the JWT and verifies that the incoming request’s Origin header is allowed per a custom claim.

Deployment:
You build the ext_auth service into a Docker image, push it to your registry, and deploy it (with a Deployment and Service YAML) into your Kubernetes cluster (EKS).


