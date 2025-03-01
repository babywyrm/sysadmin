
# Secure communication with ALB (AWS Application Load Balancer)
# mTLS authentication between clients and Ambassador
# mTLS/TLS between Ambassador and backend services
# Failover to standard TLS 1.3 if mTLS fails


# 1. High-Level Architecture
Amazon ALB → Ambassador Edge Stack (AES): Accepts TLS 1.3 and mTLS.
Ambassador Edge Stack → Internal Services: Enforces mTLS (can failover to TLS).
Clients (trusted applications) must authenticate using mTLS certificates.
Fallback to TLS 1.3 if mTLS fails (for backward compatibility).

# 2. AWS ALB Ingress Setup (Handles TLS 1.3)
💡 AWS ALB will handle TLS termination before forwarding requests to Ambassador.

```
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: ambassador-ingress
  namespace: ambassador
  annotations:
    alb.ingress.kubernetes.io/load-balancer-name: "ambassador-alb"
    alb.ingress.kubernetes.io/scheme: internet-facing
    alb.ingress.kubernetes.io/target-type: instance
    alb.ingress.kubernetes.io/backend-protocol: HTTPS
    alb.ingress.kubernetes.io/ssl-policy: "ELBSecurityPolicy-TLS13-1-2-2021-06"
    alb.ingress.kubernetes.io/certificate-arn: "arn:aws:acm:us-east-1:123456789012:certificate/example-cert"
spec:
  ingressClassName: alb
  rules:
    - host: secure.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: ambassador
                port:
                  number: 443
```

                  
📌 Explanation:

ALB handles TLS 1.3 (ELBSecurityPolicy-TLS13-1-2-2021-06).
Ambassador runs behind ALB and will still handle mTLS internally.
ACM (AWS Certificate Manager) handles certs for ALB termination.
3. Ambassador mTLS Setup
💡 Ambassador enforces mTLS for internal and external clients but allows TLS 1.3 failover.

Ambassador Global TLS/mTLS Config

```
apiVersion: getambassador.io/v3alpha1
kind: Module
metadata:
  name: ambassador
  namespace: ambassador
spec:
  config:
    tls:
      server:
        enabled: True
        secret: ambassador-server-cert # Ambassador’s TLS cert
      client:
        enabled: True
        secret: ambassador-ca-cert # CA cert to verify client certs
        certificate_required: False # Allows fallback to TLS 1.3
```
        
📌 Key Features:

mTLS is enforced, but if the client doesn’t provide a cert, it falls back to TLS 1.3.
certificate_required: False enables TLS 1.3 failover.
Server cert is stored securely in Kubernetes secrets.
4. Storing TLS Certificates in Kubernetes Secrets
💡 Store the required TLS and CA certificates securely.

```
kubectl create secret tls ambassador-server-cert \
  --cert=server.crt --key=server.key -n ambassador

kubectl create secret generic ambassador-ca-cert \
  --from-file=ca.crt -n ambassador
```

5. Internal Services with mTLS Enforcement
💡 Ambassador enforces mTLS between itself and backend services.

```
apiVersion: getambassador.io/v3alpha1
kind: Mapping
metadata:
  name: secure-service
  namespace: ambassador
spec:
  prefix: /secure/
  service: secure-backend.default.svc.cluster.local
  tls: upstream
```


📌 Explanation:

Ambassador to backend must use TLS/mTLS (tls: upstream).
Ensures backend services also verify Ambassador’s identity.
6. Host Configuration for Fine-Tuned mTLS Control
💡 Ensures Ambassador accepts mTLS from external clients but can fall back to TLS.

```
apiVersion: getambassador.io/v3alpha1
kind: Host
metadata:
  name: secure-host
  namespace: ambassador
spec:
  hostname: secure.example.com
  tlsSecret:
    name: ambassador-server-cert
  requestPolicy:
    insecure:
      action: Reject # No HTTP allowed
  authentication:
    mTLS:
      caSecret: ambassador-ca-cert
      certRequired: False # Allows TLS fallback if mTLS fails
```

📌 Key Features:

Rejects HTTP connections.
Requires mTLS but allows TLS 1.3 failover (certRequired: False).
7. Testing the Configuration
💡 Use curl to test both mTLS and TLS 1.3 fallback.

Test with mTLS (Expected: Success)

```
curl --cert client.crt --key client.key --cacert ca.crt https://secure.example.com/secure/
```

Test with Only TLS (Expected: Success with fallback)

```
curl --cacert ca.crt https://secure.example.com/secure/
```

Test Without Certs (Expected: Failure)
```
curl -k https://secure.example.com/secure/
```

🚀 Properly configured mTLS will reject this request!

```
AWS ALB	Handles TLS 1.3 termination, routes traffic to Ambassador
Ambassador	Enforces mTLS, but allows TLS 1.3 fallback
Backend Services	Require mTLS from Ambassador
Clients	Must authenticate using mTLS certs (or fallback to TLS)
Security	No HTTP allowed, full TLS/mTLS enforcement
```
