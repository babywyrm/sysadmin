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


##
#
https://kubebyexample.com/learning-paths/istio/gateway-virtualservice
#
##

----------

Guided Exercise: Configuring Istio Traffic Management

In this exercise, you will configure the amount of traffic that is routed to the back-end services by using virtual services and destination rules.

Outcomes

You should be able to:

    Deploy the book info application in the Kubernetes cluster.

    Configure the gateway, virtual services, and destination rules to manage ingress traffic.

To perform this exercise, ensure that you have:

    The kubectl, and minikube executables version 1.24 or later on a directory listed in ${PATH}.

    The istioctl executable version 1.12.1 or later on a directory listed in ${PATH}.

    MetalLB installed in the cluster. You can consult the installation guided exercise.

    Istio installed in the cluster. You can consult the installation guided exercise.

Procedure instructions

1) Start the minikube instance, and verify that Istio is installed.

1.1) Start the minikube instance.

[user@host kbe]$ minikube start
...output omitted...

1.2) Verify that the pods in the metallb-system namespace are running.

[user@host kbe]$ kubectl get pods -n metallb-system
NAME                          READY   STATUS    RESTARTS   AGE
controller-66bc445b99-2gv6w   1/1     Running   0          3d
speaker-jxjdm                 1/1     Running   0          3d

Warning
	

This guided exercise assumes that MetalLB is installed and configured.

1.3) Verify that MetalLB has the IP address range configured.

[user@host kbe]$ kubectl get configmap config -n metallb-system -o yaml
apiVersion: v1
data:
  config: |
    address-pools:
    - name: default
      protocol: layer2
      addresses:
      - 192.168.59.20-192.168.59.30
...output omitted...

Warning
	

If the IP address range for MetalLB is empty, then review the troubleshooting section in the MetalLB lecture.

1.4) Verify that the deployments in the istio-system namespace are running.

[user@host kbe]$ kubectl get deployments -n istio-system
NAME                   READY   UP-TO-DATE   AVAILABLE   AGE
grafana                1/1     1            1           2d
istio-egressgateway    1/1     1            1           2d
istio-ingressgateway   1/1     1            1           2d
istiod                 1/1     1            1           2d
jaeger                 1/1     1            1           2d
kiali                  1/1     1            1           2d
prometheus             1/1     1            1           2d

Warning
	

This guided exercise assumes that Istio is installed and configured.

2) Retrieve the Istio ingress IP address and port.

Warning
	

This GE assumes that the IP address for the ingress load balancer service is provided by MetalLB. If MetalLB is not deployed, then the service internal IP address and node port number should be used instead.

2.1) Get the Istio ingress IP address.

[user@host kbe]$ kubectl get service istio-ingressgateway \
  -n istio-system \
  -o jsonpath='{.status.loadBalancer.ingress[0].ip}{"\n"}'
192.168.59.20

[user@host kbe]$ export INGRESS_HOST="192.168.59.20"

Note
	

You can export the IP address by using a single command.

[user@host kbe]$ export INGRESS_HOST=$(kubectl get service \
  istio-ingressgateway -n istio-system \
  -o jsonpath='{.status.loadBalancer.ingress[0].ip}')

2.2) Get the Istio ingress port numbers for the HTTP and HTTPS endpoints. The service ports match the standard port numbers because MetalLB provided an IP address for the Istio load balancer service.

[user@host kbe]$ kubectl get service istio-ingressgateway \
  -n istio-system \
  -o jsonpath='{.spec.ports[?(@.name=="http2")].port}{"\n"}'
80

[user@host kbe]$ export INGRESS_PORT="80"

[user@host kbe]$ kubectl get service istio-ingressgateway \
  -n istio-system \
  -o jsonpath='{.spec.ports[?(@.name=="https")].port}{"\n"}'
443

[user@host kbe]$ export SECURE_INGRESS_PORT="443"

Note
	

You can export the port numbers by using a single command.

[user@host kbe]$ export INGRESS_PORT=$(kubectl get service \
  istio-ingressgateway -n istio-system \
  -o jsonpath='{.spec.ports[?(@.name=="http2")].port}')

[user@host kbe]$ export SECURE_INGRESS_PORT=$(kubectl get service \
  istio-ingressgateway -n istio-system \
  -o jsonpath='{.spec.ports[?(@.name=="https")].port}')

3) Deploy the book info application.

3.1) Create a namespace and update the current context to use it.

[user@host kbe]$ kubectl create namespace bookinfo
namespace/bookinfo created

[user@host kbe]$ kubectl config set-context --current --namespace=bookinfo
Context "minikube" modified.

[user@host kbe]$ kubectl config get-contexts
CURRENT   NAME       CLUSTER    AUTHINFO   NAMESPACE
*         minikube   minikube   minikube   bookinfo

3.2) Enable the sidecar injection for the bookinfo namespace to add an istio-proxy container on each pod to control ingress and egress traffic.

[user@host kbe]$ kubectl label namespace bookinfo istio-injection=enabled --overwrite
namespace/bookinfo labeled

3.3) Deploy the bookinfo application.

[user@host kbe]$ export ISTIO_VERSION=1.12.1

[user@host kbe]$ kubectl apply -f \
 istio-${ISTIO_VERSION}/samples/bookinfo/platform/kube/bookinfo.yaml
serviceaccount/bookinfo-productpage created
service/productpage created
deployment.apps/productpage-v1 created
serviceaccount/bookinfo-details created
deployment.apps/details-v1 created
service/details created
serviceaccount/bookinfo-reviews created
deployment.apps/reviews-v1 created
deployment.apps/reviews-v2 created
deployment.apps/reviews-v3 created
service/reviews created
serviceaccount/bookinfo-ratings created
deployment.apps/ratings-v1 created
service/ratings created

Note
	

You can use the resource manifest from GitHub if you do not have the Istio release archive files.

[user@host kbe]$ export ISTIO_VERSION=1.12.1

[user@host kbe]$ kubectl apply -f \
  https://github.com/istio/istio/raw/${ISTIO_VERSION}/samples/bookinfo/platform/kube/bookinfo.yaml
...output omitted...

3.4) Verify that the deployments are ready, and the services are created. The pod ready status displays 2/2 indicating that there are two containers running on each pod.

[user@host kbe]$ kubectl get deployments,pods,services
NAME                             READY   UP-TO-DATE   AVAILABLE   AGE
deployment.apps/details-v1       1/1     1            1           57s
deployment.apps/productpage-v1   1/1     1            1           56s
deployment.apps/ratings-v1       1/1     1            1           57s
deployment.apps/reviews-v1       1/1     1            1           56s
deployment.apps/reviews-v2       1/1     1            1           56s
deployment.apps/reviews-v3       1/1     1            1           56s

NAME                                  READY   STATUS    RESTARTS   AGE
pod/details-v1-7fdb56cffb-xgqb9      2/2     Running   0          74s
pod/productpage-v1-54777f49b-wq5nw   2/2     Running   0          74s
pod/ratings-v1-79f6f7d9d5-mn2b8      2/2     Running   0          74s
pod/reviews-v1-67cc5765c7-cswx8      2/2     Running   0          74s
pod/reviews-v2-6cc9d468f7-48qtn      2/2     Running   0          74s
pod/reviews-v3-6d78c4f789-5przh      2/2     Running   0          74s

NAME                  TYPE        CLUSTER-IP       EXTERNAL-IP   PORT(S)    AGE
service/details       ClusterIP   10.107.161.186   <none>        9080/TCP   60s
service/productpage   ClusterIP   10.108.47.152    <none>        9080/TCP   59s
service/ratings       ClusterIP   10.99.191.190    <none>        9080/TCP   60s
service/reviews       ClusterIP   10.107.90.88     <none>        9080/TCP   60s

Note
	

You might need to repeat the command until the desired condition is reached.

3.5) List the IP address of the ingress host that you obtained previously.

[user@host kbe]$ printenv INGRESS_HOST
192.168.59.20

3.6) Create a file called bookinfo-gateway.yaml with the following Istio gateway resource manifest.

    Replace the 192.168.59.20 string with your value for INGRESS_HOST.

---
apiVersion: networking.istio.io/v1alpha3
kind: Gateway
metadata:
  name: bookinfo-gateway
spec:
  selector:
    istio: ingressgateway  # (1)
  servers:
  - hosts:
    - "bookinfo.192.168.59.20.nip.io"  # (2)
    port:       # (3)
      name: http
      number: 80
      protocol: HTTP

    Use the Istio default ingress gateway.

    DNS host name where the gateway serves traffic.

    Port number of the proxy listen for incoming connections.

Note
	

The YAML indentation in this file is set to two white spaces.

There is a bookinfo-gateway.yaml file in the KBE repository in case you want to check for syntax errors.

    specs/istio/bookinfo-gateway.yaml

    https://github.com/openshift-evangelists/kbe/raw/main/specs/istio/bookinfo-gateway.yaml

3.7) Create a file called bookinfo-virtualservice.yaml with the following Istio virtual service resource manifest.

    Replace the 192.168.59.20 string with your value for INGRESS_HOST.

---
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: bookinfo
spec:
  gateways:
  - bookinfo-gateway  # (1)
  hosts:
  - "bookinfo.192.168.59.20.nip.io"  # (2)
  http:  # (3)
  - match:  # (4)
    - uri:
        exact: /productpage
    - uri:
        prefix: /static
    - uri:
        exact: /login
    - uri:
        exact: /logout
    - uri:
        prefix: /api/v1/products
    route:  # (5)
    - destination:
        host: productpage
        port:
          number: 9080

    Apply the virtual service rules to the specified gateway in the current namespace.

    DNS host name where the gateway serves traffic.

    List of routing rules for the HTTP traffic.

    List of rules to match against incoming requests.

    The matching requests are be forwarded to this service and port number.

Note
	

The YAML indentation in this file is set to two white spaces.

There is a bookinfo-virtualservice.yaml file in the KBE repository in case you want to check for syntax errors.

    specs/istio/bookinfo-virtualservice.yaml

    https://github.com/openshift-evangelists/kbe/raw/main/specs/istio/bookinfo-virtualservice.yaml

3.8) Create the gateway and virtual service resources.

[user@host kbe]$ kubectl apply -f bookinfo-gateway.yaml
gateway.networking.istio.io/bookinfo-gateway created

[user@host kbe]$ kubectl apply -f bookinfo-virtualservice.yaml
virtualservice.networking.istio.io/bookinfo created

3.9) Verify that the resources are present in the cluster.

[user@host kbe]$ kubectl get gateways
NAME               AGE
bookinfo-gateway   60s

[user@host kbe]$ kubectl get virtualservices
NAME       GATEWAYS               HOSTS                               AGE
bookinfo   ["bookinfo-gateway"]   ["bookinfo.192.168.59.20.nip.io"]   60s

3.10) Verify that the service responds with curl.

    Replace the 192.168.59.20 string with your value for INGRESS_HOST.

[user@host kbe]$ printenv INGRESS_HOST
192.168.59.20

[user@host kbe]$ curl -vk# 'http://bookinfo.192.168.59.20.nip.io/productpage' | \
  egrep '</?title>'
*   Trying 192.168.59.20...
* TCP_NODELAY set
* Connected to bookinfo.192.168.59.20.nip.io (192.168.59.20) port 80 (#0)
> GET /productpage HTTP/1.1
> Host: bookinfo.192.168.59.20.nip.io
> User-Agent: curl/7.61.1
> Accept: */*
>
< HTTP/1.1 200 OK
< content-type: text/html; charset=utf-8
< content-length: 5183
< server: istio-envoy
< date: Tue, 22 Feb 2022 19:40:49 GMT
< x-envoy-upstream-service-time: 18
<
{ [5183 bytes data]
######################################################################### 100.0%
* Connection #0 to host bookinfo.192.168.59.20.nip.io left intact

    <title>Simple Bookstore App</title>

3.11) Visit the service URL with a web browser to see the page.

    http://bookinfo.192.168.59.20.nip.io/productpage

    Replace the 192.168.59.20 string with your value for INGRESS_HOST.

Bookinfo application

Bookinfo application

4) Generate traffic and inspect the application topology on the Kiali dashboard.

4.1) Open another terminal window and execute a command to generate traffic for the bookinfo application.

    Replace the 192.168.59.20 string with your value for INGRESS_HOST.

[user@host kbe]$ printenv INGRESS_HOST
192.168.59.20

[user@host kbe]$ while true ; do sleep 0.1 ; curl -fsSLo /dev/null \
  "http://bookinfo.192.168.59.20.nip.io/productpage" ; done ;

4.2) Open another terminal window and execute istioctl to open the Kiali dashboard.

[user@host kbe]$ istioctl dashboard kiali
http://localhost:20001/kiali

4.3) Click Graph, then select the bookinfo namespace to view the topology. There are three versions of the reviews pods, two of which connect to the ratings service.
Bookinfo application topology

Bookinfo application topology

4.4) Click Services, then select the bookinfo namespace. Click on the reviews service to view the statistics. The service distributes all the traffic equally among the three back end pods (33% approximately).
Reviews service traffic

Reviews service traffic

5) Create destination rules and adjust the traffic for each back end service.

5.1) Refresh several times the browser window where the bookinfo web page is open.

    http://bookinfo.192.168.59.20.nip.io/productpage

    Replace the 192.168.59.20 string with your value for INGRESS_HOST.

The star rating for the books is different, this happens because every request is processed in a different pod of the reviews service.
Bookinfo ratings

Bookinfo ratings

5.2) Create a virtual service resource manifest that routes different traffic percentages to different pod versions. Create a file called reviews-virtualservice.yaml with the following Istio virtual service resource manifest.

---
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: reviews
spec:
  hosts:
  - reviews
  http:
  - route:
    - weight: 10  # (1)
      destination:
        host: reviews
        subset: v1
    - weight: 30  # (2)
      destination:
        host: reviews
        subset: v2
    - weight: 60  # (3)
      destination:
        host: reviews
        subset: v3

    10% of the traffic is redirected to reviews subset v1.

    30% of the traffic is redirected to reviews subset v2.

    60% of the traffic is redirected to reviews subset v3.

Note
	

The YAML indentation in this file is set to two white spaces.

There is a reviews-virtualservice.yaml file in the KBE repository in case you want to check for syntax errors.

    specs/istio/reviews-virtualservice.yaml

    https://github.com/openshift-evangelists/kbe/raw/main/specs/istio/reviews-virtualservice.yaml

5.3) Create a destination rule resource manifest with selectors for the different versions of the reviews pods. Create a file called reviews-destinationrule.yaml with the following Istio destination rule resource manifest.

---
apiVersion: networking.istio.io/v1alpha3
kind: DestinationRule
metadata:
  name: reviews
spec:
  host: reviews
  subsets:
  - name: v1  # (1)
    labels:
      version: v1
  - name: v2  # (2)
    labels:
      version: v2
  - name: v3  # (3)
    labels:
      version: v3

    The subset v1 references pods with label version: v1.

    The subset v2 references pods with label version: v2.

    The subset v3 references pods with label version: v3.

Note
	

The YAML indentation in this file is set to two white spaces.

There is a reviews-destinationrule.yaml file in the KBE repository in case you want to check for syntax errors.

    specs/istio/reviews-destinationrule.yaml

    https://github.com/openshift-evangelists/kbe/raw/main/specs/istio/reviews-destinationrule.yaml

5.4) Create the virtualservice and destination rule resources.

[user@host kbe]$ kubectl apply -f reviews-virtualservice.yaml
virtualservice.networking.istio.io/reviews created

[user@host kbe]$ kubectl apply -f reviews-destinationrule.yaml
destinationrule.networking.istio.io/reviews created

5.5) Verify that the virtualservice and destination rule were created.

[user@host kbe]$ kubectl get virtualservices
NAME       GATEWAYS               HOSTS                               AGE
bookinfo   ["bookinfo-gateway"]   ["bookinfo.192.168.59.20.nip.io"]   1h
reviews                           ["reviews"]                         60s

[user@host kbe]$ kubectl get destinationrules
NAME      HOST      AGE
reviews   reviews   60s

5.6) Wait for the Kiali dashboard window to refresh and view the traffic percentage on each version of the reviews pod.

Warning
	

Verify the order of the pods in the dashboard window, the image below displays them in a different order:

    reviews-v2 with 27.4% of the traffic.

    reviews-v1 with 9.4% of the traffic.

    reviews-v3 with 63.2% of the traffic.

Bookinfo reviews traffic split with destination rule selector

Bookinfo reviews traffic split with destination rule selector

6) Clean up

6.1) Press Ctrl+C on the terminal window where the traffic generation command is running.

[user@host kbe]$ while true ; do sleep 0.1 ; curl -fsSLo /dev/null \
  "http://bookinfo.192.168.59.20.nip.io/productpage" ; done ;
^C

6.2) Press Ctrl+C on the terminal window where istioctl is running.

[user@host kbe]$ istioctl dashboard kiali
http://localhost:20001/kiali
^C

6.3) Remove the label from the bookinfo namespace.

[user@host kbe]$ kubectl label namespace bookinfo istio-injection-
namespace/bookinfo labeled

Note
	

The dash at the end of the command is used to instruct kubectl to remove the label.

6.4) Delete the bookinfo namespace.

[user@host kbe]$ kubectl delete namespace bookinfo
namespace/bookinfo deleted

6.5) Update the current context for kubectl.

[user@host kbe]$ kubectl config set-context --current --namespace=default
Context "minikube" modified.

[user@host kbe]$ kubectl config get-contexts
CURRENT   NAME       CLUSTER    AUTHINFO   NAMESPACE
*         minikube   minikube   minikube   default

This concludes the guided exercise.​​​

Share

NextBack
Beyond KBE

    https://github.com/istio/istio/tree/1.12.1/samples/bookinfo

    https://istio.io/v1.12/blog/2019/proxy/

    https://istio.io/v1.12/docs/tasks/traffic-management/request-routing/

    https://istio.io/v1.12/docs/tasks/traffic-management/traffic-shifting/

    https://istio.io/v1.12/docs/reference/config/networking/gateway/

    https://istio.io/v1.12/docs/reference/config/networking/virtual-service/

    https://istio.io/v1.12/docs/reference/config/networking/destination-rule/

    https://istio.io/v1.12/docs/examples/bookinfo/

    https://istio.io/v1.12/docs/examples/microservices-istio/add-istio/

    https://istio.io/v1.12/docs/examples/microservices-istio/enable-istio-all-microservices/

    https://istio.io/v1.12/docs/examples/microservices-istio/istio-ingress-gateway/

    https://istio.io/v1.12/docs/setup/additional-setup/gateway/
    KBE Community Forum Have more questions? Join our KBE community forum sponsored by Red Hat Learning and get your questions answered in real time or start a discussion with hundreds of learning community members. Engage with the KBE community and meet fellow KBE members, contributors, and subject matter experts. Join now!

LEARNING PATHS

    Command Line Essentials
    Linux Essentials
    Kubernetes Fundamentals
    Container Fundamentals
    Application Development on Kubernetes
    Developing with Java on Kubernetes
    Developing with Spring Boot on Kubernetes
    Operators with Helm, Ansible, and Go
    Migrating to Kubernetes
    Load Balancing Fundamentals with MetalLB
    Istio Fundamentals
        Istio Overview
        Guided Exercise: Installing Istio on a Minikube Cluster
        Istio Ingress Control
        Guided Exercise: Configuring Istio Ingress Control
        Istio Traffic Management
        Guided Exercise: Configuring Istio Traffic Mangement
    Developing with Knative on Kubernetes
    Storage for Kubernetes with Rook
    AI/ML with Jupyter on Kubernetes: JupyterHub
    Kubernetes Security
    Argo CD
    Tekton

