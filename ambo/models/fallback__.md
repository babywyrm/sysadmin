


# 1. Understanding mTLS vs. “Optional” TLS in Ambassador
Ambassador (built on Envoy) typically has a TLSContext for upstream or downstream connections. 

The key parameter is:

```
requireClientCertificate: true | false
```

true means client certificates must be presented. If the client doesn’t present one, the TLS handshake fails.
false means client certificates are not required (i.e., standard one-way TLS). If the client does present a certificate, Ambassador may still accept it — but typically it won’t require any particular validation.
If you want an “optional client certificate” scenario (meaning: accept the certificate if offered, otherwise proceed with plain TLS), Envoy supports a concept called tls.require_client_certificate: false with a tls.ocsp_staple_policy: lenient or “optional” mode in some configurations. In older docs, you might see references to “optional client auth.” Ambassador Edge Stack may not fully expose that setting in a single toggle, so you often end up with either:

Strict mTLS (requireClientCertificate: true) — handshake fails if no client cert.
No mTLS (requireClientCertificate: false) — no client cert needed, though you can parse a provided cert in advanced Envoy configurations.
In practice, you can achieve a fallback approach by:

Running two different listeners/hosts (one requiring mTLS, one not)
OR
Setting requireClientCertificate: false (thus effectively optional) and adding specialized Envoy filters to check if a client cert was provided and then deciding how to route.


# 2. High-Level Approach: “Optional” mTLS on a Single Host
Below is a conceptual example using Ambassador CRDs. Note that the exact syntax can differ by Ambassador versions (Edge Stack vs. Emissary Ingress) and whether you use the newer Host/TLSContext or the older Module approach.

2.1 Host CRD


```
apiVersion: getambassador.io/v3alpha1
kind: Host
metadata:
  name: billing-host
spec:
  hostname: billing.example.com
  acmeProvider:
    authority: https://acme-v02.api.letsencrypt.org/directory
  tlsSecret:
    name: ambassador-edge-stack-certs

  # We want to allow both mTLS and fallback to normal TLS if the client doesn't present a cert:
  requestPolicy:
    insecure:
      action: Redirect   # Force HTTPS if someone attempts HTTP
    tls:
      # CA secret to validate the client cert if presented
      # (if your environment can do partial/optional validation)
      caSecret:
        name: client-ca-secret

      # If 'enabled' is set to true, some versions treat that as "strict"
      # but let's see how we can set 'optional' or partial:
      client:
        enabled: true
        # Some Ambassador versions let you specify 'optional: true' to allow fallback
        # but often you must do it at the underlying Envoy layer.
```

        
In some Envoy-based deployments, 
you can set mode: OPTIONAL in the underlying envoy config so that if the client does not present a certificate, the handshake will continue with normal TLS 1.3.
If the client does present a cert, then Ambassador will verify it against client-ca-secret. However, Ambassador’s configuration for “optional client cert” is not always straightforward.

# 2.2 TLSContext (Upstream from Ambassador → Billing Service)
If you also want mTLS from Ambassador to the Billing Service, you’d define a TLSContext referencing the Billing Service’s CA/cert. You can similarly set it to optional, though typically internal traffic is either strictly mTLS or plain TLS. Example:

```
apiVersion: getambassador.io/v3alpha1
kind: TLSContext
metadata:
  name: billing-service-tls
spec:
  ambassador_id: [ "default" ]

  # The certificate Ambassador presents TO the Billing Service
  secrets:
    - secretName: ambassador-client-cert
  
  # CA used to validate the Billing Service's certificate
  ca_secret: billing-service-ca

  # Minimum and maximum TLS versions
  min_tls_version: v1.2
  max_tls_version: v1.3

  # Possibly set to optional
  requireClientCertificate: false
```

Then, in your Mapping:

```
apiVersion: getambassador.io/v3alpha1
kind: Mapping
metadata:
  name: billing-mapping
spec:
  hostname: billing.example.com
  prefix: /billing/
  service: https://billing-service.billing.svc.cluster.local:8443
  tls: billing-service-tls
```
  
This means Ambassador → Billing service uses TLS, and if you want strict mTLS, set requireClientCertificate: true. If you want fallback or “one-way” only, keep it false.

# 3. Using Two Separate Listeners or Host Definitions
If you can’t configure a single host as optional for the client certificate, another strategy is to define:

Strict-mTLS Host: which requires a client certificate. If the handshake fails, the client can’t proceed.
Plain TLS Host: which only requires server-side TLS. No client certificate.
Then, you can route traffic accordingly (or have the client “fail over” if the strict host fails). This is effectively a “fallback,” but from a security standpoint, it’s just two distinct endpoints—one with strong mutual auth, one that’s weaker. You might do that if you have a heterogeneous set of clients, some that can do mTLS and some that cannot.

```
# Host #1 (strict mTLS)
apiVersion: getambassador.io/v3alpha1
kind: Host
metadata:
  name: billing-strict-mtls
spec:
  hostname: mtls.billing.example.com
  requestPolicy:
    tls:
      client:
        enabled: true     # require client cert
      # ...



# Host #2 (plain TLS only)
apiVersion: getambassador.io/v3alpha1
kind: Host
metadata:
  name: billing-tls-fallback
spec:
  hostname: fallback.billing.example.com
  requestPolicy:
    tls:
      # no client CA or set client: enabled=false
      client:
        enabled: false

```

Clients that cannot maintain mTLS (or fail the cert handshake) could attempt the fallback hostname fallback.billing.example.com. This is a fairly common approach for a transitional or multi-tenant environment.



# 4. TLS 1.3 Negotiation vs. mTLS
TLS version fallback (e.g. from 1.3 down to 1.2) is handled by the standard TLS handshake negotiation. If one side doesn’t support 1.3, they’ll settle on 1.2 automatically, as long as you set:
```
min_tls_version: v1.2
max_tls_version: v1.3
```

mTLS fallback is different. mTLS is about requiring (or optionally accepting) a client certificate. If you require it, there’s no fallback—handshake fails. If you set it to optional, in principle the handshake will proceed even if the client doesn’t present a cert. (But note that not all Ambassador versions expose an “optional” mode directly; you might need to hack the underlying Envoy config.)

# 5. Security Considerations
If “optional” client cert is used

The handshake may succeed with or without a cert. That means you lose the guaranteed identity on the client side. You’ll need other forms of auth (JWT, etc.) to identify the user.
Attackers who do not present a client cert can slip by unless you do additional checks at the application layer.
Two-host approach

You end up with two different endpoints. This might be simpler for some clients that can’t handle advanced TLS.
But it does mean your environment has a “strict” path and a “lax” path. If an attacker can simply choose the “lax” path, they bypass your mTLS requirement.
Logging & Monitoring

Ensure you log whether the client certificate was presented and validated. You may want to treat “client certificate missing” as a special event if you truly want to encourage mTLS adoption.


# 6. In Practice, Strict is Simpler
In real-world PCI-compliant environments, you typically see:

Strictly enforced mTLS for internal services (Ambassador → Billing).
Possibly normal TLS from external clients → Ambassador, but with JWT or OAuth-based identity.
If you must eventually require external clients to present a cert, you typically create a separate Host or route that enforces it—rather than “fallback.”
Fallback tends to create confusion and potential security blind spots.
