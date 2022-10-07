Example policies to enforce mTLS between sidecar and egress gateway
egress-mtls-authz.yaml
# Example policies to enforce mTLS between sidecar and egress gateway, the connection between sidecar
# and egress gateway could be:
#   1. plaintext in (Istio) mTLS or
#   2. TLS in (Istio) mTLS;
# An AuthorizationPolicy is applied on egress gateway to enforce egress access control.
---
apiVersion: networking.istio.io/v1beta1
kind: ServiceEntry
metadata:
  name: httpbin-org-ext
  namespace: default
spec:
  hosts:
  - httpbin.org
  ports:
  - number: 80
    name: http
    protocol: HTTP
  - number: 443
    name: tls
    protocol: TLS
  resolution: DNS
  location: MESH_EXTERNAL
---
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: direct-httpbin-org-through-egress-gateway
  namespace: default
spec:
  hosts:
  - httpbin.org
  gateways:
  - mesh
  - istio-system/egress-gateway
  http:
  - match:
    - gateways:
      - mesh
      port: 80
    route:
    - destination:
        host: istio-egressgateway.istio-system.svc.cluster.local
        subset: httpbin-org-egress-mTLS
        port:
          number: 80
  - match:
    - gateways:
      - istio-system/egress-gateway
      port: 80
    route:
    - destination:
        host: httpbin.org
        port:
          number: 80
      weight: 100
  tls:
  - match:
    - gateways:
      - mesh
      port: 443
      sniHosts:
      - httpbin.org
    route:
    - destination:
        host: istio-egressgateway.istio-system.svc.cluster.local
        subset: httpbin-org-egress-mTLS
        port:
          number: 443
  - match:
    - gateways:
      - istio-system/egress-gateway
      port: 443
      sniHosts:
      - httpbin.org
    route:
    - destination:
        host: httpbin.org
        port:
          number: 80
      weight: 100
  tcp:
  - match:
    - gateways:
      - istio-system/egress-gateway
      port: 443
    route:
    - destination:
        host: httpbin.org
        port:
          number: 443
      weight: 100
---
apiVersion: networking.istio.io/v1beta1
kind: DestinationRule
metadata:
  name: egress-gateway-httpbin-org
  namespace: default
spec:
  host: istio-egressgateway.istio-system.svc.cluster.local
  subsets:
  - name: httpbin-org-egress-mTLS
    trafficPolicy:
      loadBalancer:
        simple: ROUND_ROBIN
      tls:
        mode: ISTIO_MUTUAL
        sni: httpbin.org
---
apiVersion: networking.istio.io/v1beta1
kind: Gateway
metadata:
  name: egress-gateway
  namespace: istio-system
spec:
  selector:
    istio: egressgateway
  servers:
  - port:
      number: 80
      name: https
      protocol: HTTPS
    hosts:
      - '*'
    tls:
      mode: ISTIO_MUTUAL
  - port:
      number: 443
      name: tls
      protocol: TLS
    hosts:
    - '*'
    tls:
      mode: ISTIO_MUTUAL
---
apiVersion: "security.istio.io/v1beta1"
kind: "AuthorizationPolicy"
metadata:
  name: "egress"
  namespace: istio-system
spec:
  selector:
    matchLabels:
      app: istio-egressgateway
  rules:
  # 1st rule for TLS in mTLS (port 8443), only source namespace/principal and sni can be used.
  - from:
    - source:
        namespaces:
        - "default"
    to:
    - operation:
        ports:
        - "8443"
    when:
    - key: connection.sni
      values:
      - "httpbin.org"
  # 2nd rule for plaintext in mTLS (port 8080), normal HTTP attriubtes can also be used.
  - from:
    - source:
        namespaces:
        - "default"
    to:
    - operation:
        paths:
        - "/headers"
        methods:
        - "GET"
        ports:
        - "8080"
---
@yangminzhu
Author
yangminzhu commented on Sep 17, 2020
Example policies to enforce mTLS between sidecar and egress gateway

@dmarkey
dmarkey commented on Sep 18, 2020
Great I'll give this a go later!

@yangminzhu
Author
yangminzhu commented on Sep 18, 2020
The above config has a limitation that it only supports 1 host ("httpbin.org") on egress gateway, this is due to we're using tcp route in the virtual service on egress gateway based on port (doesn't support sni).

I only found a workaround by exposing a new port on egress gateway for the new host, not sure if there are better way to handle this:

# Example policies to enforce mTLS between sidecar and egress gateway for multiple (>1) hosts.
#
# First, modify the egress gateway service and deployment to open expose another port 8444, similiar to
# the exising 443/8443 specification.
#
# Second, apply the following policies so that a sidecar could access
#  1. http://wikipedia.org  through egress (port 8080) using plaintext in mTLS
#  2. https://wikipedia.org through egress (port 8443) using TLS in mTLS
#  3. http://httpbin.org    through egress (port 8080) using plaintext in mTLS
#  4. https://httpbin.org   through egress (port 8444) using TLS in mTLS
#
# Third, an AuthorizationPolicy is applied on egress gateway to enforce egress access control.
---
apiVersion: networking.istio.io/v1beta1
kind: ServiceEntry
metadata:
  name: httpbin-and-wikipedia
  namespace: default
spec:
  hosts:
  - httpbin.org
  - wikipedia.org
  ports:
  - number: 80
    name: http
    protocol: HTTP
  - number: 443
    name: tls
    protocol: TLS
  resolution: DNS
  location: MESH_EXTERNAL
---
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: direct-sidecar-httpbin-wikipedia-through-egress-gateway
  namespace: default
spec:
  hosts:
  - httpbin.org
  - wikipedia.org
  gateways:
  - mesh
  - istio-system/egress-gateway
  http:
  - match:
    - gateways:
      - mesh
      port: 80
    route:
    - destination:
        host: istio-egressgateway.istio-system.svc.cluster.local
        subset: sidecar-to-egress-in-mTLS
        port:
          number: 80
  - match:
    - gateways:
      - istio-system/egress-gateway
      port: 80
      authority:
        exact: wikipedia.org
    route:
    - destination:
        host: wikipedia.org
        port:
          number: 80
      weight: 100
  - match:
    - gateways:
      - istio-system/egress-gateway
      port: 80
      authority:
        exact: httpbin.org
    route:
    - destination:
        host: httpbin.org
        port:
          number: 80
      weight: 100
  tls:
  - match:
    - gateways:
      - mesh
      port: 443
      sniHosts:
      - wikipedia.org
    route:
    - destination:
        host: istio-egressgateway.istio-system.svc.cluster.local
        subset: sidecar-to-egress-in-mTLS-wikipedia-sni
        port:
          number: 443
  - match:
    - gateways:
      - mesh
      port: 443
      sniHosts:
      - httpbin.org
    route:
    - destination:
        host: istio-egressgateway.istio-system.svc.cluster.local
        subset: sidecar-to-egress-in-mTLS-httpbin-sni
        port:
          number: 8444
  tcp:
  - match:
    - gateways:
      - istio-system/egress-gateway
      port: 443
    route:
    - destination:
        host: wikipedia.org
        port:
          number: 443
      weight: 100
  - match:
    - gateways:
      - istio-system/egress-gateway
      port: 8444
    route:
    - destination:
        host: httpbin.org
        port:
          number: 443
      weight: 100
---
apiVersion: networking.istio.io/v1beta1
kind: DestinationRule
metadata:
  name: sidecar-egress-gateway
  namespace: default
spec:
  host: istio-egressgateway.istio-system.svc.cluster.local
  subsets:
  - name: sidecar-to-egress-in-mTLS
    trafficPolicy:
      loadBalancer:
        simple: ROUND_ROBIN
      tls:
        mode: ISTIO_MUTUAL
  - name: sidecar-to-egress-in-mTLS-wikipedia-sni
    trafficPolicy:
      loadBalancer:
        simple: ROUND_ROBIN
      tls:
        mode: ISTIO_MUTUAL
        sni: wikipedia.org
  - name: sidecar-to-egress-in-mTLS-httpbin-sni
    trafficPolicy:
      loadBalancer:
        simple: ROUND_ROBIN
      tls:
        mode: ISTIO_MUTUAL
        sni: httpbin.org
---
apiVersion: networking.istio.io/v1beta1
kind: Gateway
metadata:
  name: egress-gateway
  namespace: istio-system
spec:
  selector:
    istio: egressgateway
  servers:
  - port:
      number: 80
      name: https
      protocol: HTTPS
    hosts:
      - '*'
    tls:
      mode: ISTIO_MUTUAL
  - port:
      number: 443
      name: tls-wikipedia-org
      protocol: TLS
    hosts:
    - '*'
    tls:
      mode: ISTIO_MUTUAL
  - port:
      number: 8444
      name: tls-httpbin-org
      protocol: TLS
    hosts:
    - '*'
    tls:
      mode: ISTIO_MUTUAL
---
apiVersion: "security.istio.io/v1beta1"
kind: "AuthorizationPolicy"
metadata:
  name: "egress"
  namespace: istio-system
spec:
  selector:
    matchLabels:
      app: istio-egressgateway
  rules:
  # 1st rule for wikipedia.org TLS in mTLS (port 8443), only source namespace/principal and sni can be used.
  - from:
    - source:
        namespaces:
        - "default"
    to:
    - operation:
        ports:
        - "8443"
    when:
    - key: connection.sni
      values:
      - "wikipedia.org"
  # 2nd rule for httpbin.org TLS in mTLS (port 8444), only source namespace/principal and sni can be used.
  - from:
    - source:
        namespaces:
        - "default"
    to:
    - operation:
        ports:
        - "8444"
    when:
    - key: connection.sni
      values:
      - "httpbin.org"
  # 3rd rule for plaintext in mTLS (port 8080), normal HTTP attriubtes can also be used.
  - from:
    - source:
        namespaces:
        - "default"
    to:
    - operation:
        methods:
        - "GET"
        hosts:
        - "wikipedia.org"
        - "httpbin.org"
        ports:
        - "8080"
---
@yangminzhu
Author
