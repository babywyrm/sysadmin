
##
#
https://www.solo.io/blog/cilium-1-14-istio/
#
https://www.reddit.com/r/kubernetes/comments/11pgmsa/cilium_vs_calico_k3s_what_do_you_use_and_why/
#
https://cilium.io/blog/2020/02/18/cilium-17/
#
##

A Quick Tour of Cilium 1.14 with Istio
Lin Sun | August 07, 2023

Cilium 1.14 was released a few days ago – congratulations to the entire Cilium community on achieving this significant milestone! Per Cilium’s annual report for 2022, Cilium earned the recognition of Container Network Interface (CNI) of the year where Cilium became the de-facto CNI. For the Cilium 1.14 release, I am excited about some of the enhancements to the Cilium CNI which many of us are passionate about.
A Tour of Cilium CNI 1.14

Let’s walk through a tour of some of the features and functionality in the Cilium 1.14 release, starting by installing Cilium, then working through deny policy and debugging with Hubble.
Install Cilium 1.14

First, deploy a kind cluster following the instructions provided by Cilium’s documentation.

kindConfig="
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
- role: worker
- role: worker
- role: worker
networking:
  disableDefaultCNI: true
"
kind create cluster --config=- <<<"${kindConfig[@]}"

One interesting feature from Cilium 1.14 is that helm mode is the default in Cilium CLI 0.15 and you can follow the instructions to install Cilium 0.15.3. Use the following command and to Cilium 1.14:

cilium install --version 1.14.0 --namespace kube-system --set externalIPs.enabled=true,bpf.masquerade=false,image.pullPolicy=IfNotPresent,ipam.mode=kubernetes,l7Proxy=false

Love the cilium status command—it’s so easy to use!

Yay, I got Cilium 1.14.0 installed with a few of my favorite base configurations such as disabling the layer 7 proxy, or masquerade for easy troubleshooting!

Cilium 1.14.0 installed
Deny Policy

Now that deny policies have graduated to stable in v1.14, let’s quickly review Cilium’s deny policy. I usually use least-privilege allow policies in my network policies to allow matching source endpoints to ingress or egress, and target endpoints on given port number(s). A deny policy in Cilium takes precedence over allow policies. You must specify the exact conditions you want for the traffic to be denied, but no more than that. In addition, you have to specify the allowed condition as well, otherwise everything is denied.

Apply the following deny policy to deny any egress requests to outside of the cluster while allowing all egress requests within the cluster to the default namespace. In this deny policy, EgressDeny is a list of rules to deny egress connections regardless of the allowed egress rules in the Egress field. ToEntities is a list of special entities to which the endpoints matching the rule are disallowed to initiate connections to. For example, the world entity corresponds to all endpoints outside of the cluster.

kubectl apply -f - <<EOF
apiVersion: "cilium.io/v2"
kind: CiliumNetworkPolicy
metadata:
  name: "lockdown-ns-egress"
spec:
  endpointSelector:
    matchLabels:
      "k8s:io.kubernetes.pod.namespace": default
  egressDeny:
  - toEntities:
    - "world"
  egress:
  - toEntities:
    - "cluster"
EOF

Deploy the sleep and httpbin applications:

kubectl apply -f https://raw.githubusercontent.com/istio/istio/master/samples/sleep/sleep.yaml
kubectl apply -f https://raw.githubusercontent.com/istio/istio/master/samples/httpbin/httpbin.yaml

Since the deny policy should not impact anything in the Kubernetes cluster, I can continue to call the httpbin service running in the cluster from the sleep pod:

# expect to succeed
kubectl exec deploy/sleep -- curl http://httpbin:8000/headers

While the deny policy denies anything to outside of the cluster (world entity here), the sleep pod will not be able to call the httpbin.org service because the deny policy is enforced by Cilium, so you’ll see the command hang:

# expect to fail because of the deny policy
kubectl exec deploy/sleep -- curl http://httpbin.org/headers

Debug What Is Going On with Hubble

To enable Hubble, you can use cilium hubble enable.

The cilium status output should include your hubble-relay deployment, container, and image information. If you don’t have the Hubble CLI yet, follow the instructions to install it, and use cilium hubble port-forward to enable your Hubble CLI to access the hubble-relay service easily.

Let’s observe any package drops using hubble observe -t drop –from-pod default/sleep from the sleep pod:

deny policy

The deny policy is enforced by the Cilium agent and its eBPF programs that run in the same node as the sleep pod. Let’s visualize this in the Hubble UI.

First, enable Hubble UI using cilium hubble enable --ui, then launch Hubble UI by running cilium hubble ui:

 

Very nice! The UI shows dropped packages (to httpbin.org outside of the cluster) and also forwarded packages (to the httpbin service in the cluster).
Cilium and Istio

Per Istio’s security best practice, the Istio community recommends that users layer Istio policies with NetworkPolicy that can be enforced by your preferred CNI (e.g. Cilium or any CNI that supports the NetworkPolicy API). This defense in depth strategy can be used to further strengthen the security posture of your cloud native applications.

You can think of Cilium identities and Layer 3/4 network policies as cloud native firewall rules, which complement—not replace—the cryptographic identities provided by Istio. For example, would you turn off SSL on your website because you already have top-notch firewall rules configured and enforced? Probably not. To learn more about the difference between Cilium identity and Istio identity, check out my prior blog.

Next, let’s look at what happens when you install Istio.
Install Istio

Install Istio 1.18 with the demo profile, along with Istio’s dashboard Kiali, and Prometheus.

istioctl install --set profile=demo
kubectl apply -f https://raw.githubusercontent.com/istio/istio/release-1.18/samples/addons/kiali.yaml
kubectl apply -f https://raw.githubusercontent.com/istio/istio/release-1.18/samples/addons/prometheus.yaml

Cilium Policies Continue to Be Enforced

Label the default namespace for istio-injection=enabled and restart the sleep and httpbin deployments so that they both are included in the Istio mesh:

kubectl label namespace default istio-injection=enabled
kubectl rollout restart deployment

You can confirm that the deny policy lockdown-ns-egress is still enforced by running the prior commands to call the httpbin service (in the cluster) and httpbin.org (out of the cluster). When calling httpbin.org, you’ll get the error message upstream connect error or disconnect/reset before headers. reset reason: connection failure from the sleep pod’s sidecar vs. no error message earlier.

# expect to succeed
kubectl exec deploy/sleep -- curl http://httpbin:8000/headers
# expect connection to fail because of the deny policy
kubectl exec deploy/sleep -- curl http://httpbin.org/headers

Very cool! The Hubble UI also continues to work, and you’ll see the sleep and httpbin’s sidecar proxies connecting to Istiod on port 15012 (the xDS port), in addition to connecting to the httpbin service (in cluster) and httpbin.org (out of cluster).

Controlled Egress Traffic

So, what if the sleep pod wants to call the httpbin.org external service on port 80 or any other external service? Following Istio’s best security practice, configure all pods in the namespace to route to the egress gateway first when calling httpbin.org on port 80:

kubectl apply -f - <<EOF
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: direct-httpbin-through-egress-gateway
spec:
  hosts:
  - httpbin.org
  gateways:
  - istio-egressgateway
  - mesh
  http:
  - match:
    - gateways:
      - mesh
      port: 80
    route:
    - destination:
        host: istio-egressgateway.istio-system.svc.cluster.local
        subset: httpbin
        port:
          number: 80
      weight: 100
  - match:
    - gateways:
      - istio-egressgateway
      port: 80
    route:
    - destination:
        host: httpbin.org
        port:
          number: 80
      weight: 100
EOF

Secondly, create the service entry for httpbin.org so the httpbin.org external service is registered with Istio:

kubectl apply -f - <<EOF
apiVersion: networking.istio.io/v1alpha3
kind: ServiceEntry
metadata:
  name: httpbin
spec:
  hosts:
  - httpbin.org
  ports:
  - number: 80
    name: http-port
    protocol: HTTP
  resolution: DNS
EOF

Thirdly, create a gateway resource for httpbin.org, port 80, and destination rule for traffic directed to the egress gateway:

kubectl apply -f - <<EOF
apiVersion: networking.istio.io/v1alpha3
kind: Gateway
metadata:
  name: istio-egressgateway
spec:
  selector:
    istio: egressgateway
  servers:
  - port:
      number: 80
      name: http
      protocol: HTTP
    hosts:
    - httpbin.org
---
apiVersion: networking.istio.io/v1alpha3
kind: DestinationRule
metadata:
  name: egressgateway-for-httpbin
spec:
  host: istio-egressgateway.istio-system.svc.cluster.local
  subsets:
  - name: httpbin
EOF

Re-run the curl commands to call the httpbin service and httpbin.org from the sleep pod, YAY, both work now!

# expect to continue to succeed
kubectl exec deploy/sleep -- curl http://httpbin:8000/headers
# expect to succeed because the request is routed to egress gateway first then to httpbin.org
kubectl exec deploy/sleep -- curl http://httpbin.org/headers

Visualize Requests Using Hubble and Kiali

We know the request has to go through the egress gateway as the sleep  pod isn’t allowed to egress to anything outside of the cluster. Let’s visualize this in the Hubble UI, using cilium hubble ui if you don’t have the Hubble UI launched yet. The Hubble UI shows the request from sleep is forwarded to istio-egressgateway then to the world – very nice!

You can also visualize the requests from the Kiali dashboard (use istioctl dashboard kiali to launch Kiali), which includes more information such as an mTLS badge on the connection, live traffic animation, request response time, inbound and outbound HTTP success, and error rates:

Note: the request from sleep to istio-egressgateway isn’t mutual TLS above. You can follow Istio’s egress TLS origination document to configure mTLS from the sleep to istio-egressgateway pod and TLS origination from the istio-egressgateway pod to httpbin.org using https with simple TLS.
Cilium and Solo.io

Open source projects thrive on community involvement, and Cilium is no exception. I am thrilled to see the continued Cilium community growth as well as the increasing importance of Cilium in the CNI ecosystem.

Earlier this year, Solo.io decided to become an actively contributing company to the Cilium project with our very own Solo contributors Daneyon Hansen, Daniel Hawton, Peter Jausovec, and Ben Leggett! Thank you to the Cilium community for providing a positive contribution experience and the warm welcome to the hive!

    🐝 New Cilium Contributor 🐝

    The newest Cilium contributor is @pjausovec

    They helped fix a typo on the main page of https://t.co/L1bCbbfWbi

    Welcome to the hive!https://t.co/ejN3NS8JR3

    — Cilium (@ciliumproject) July 4, 2023

To show Solo’s commitment to the Cilium community, we are thrilled to announce that we are a Diamond Sponsor at CiliumCon during KubeCon + CloudNativeCon in Chicago this November.
Wrapping Up

You can see from this quick tour how simple it is to use Cilium CNI and Hubble to troubleshoot network problems. I am also excited by how Cilium network policies can be layered with Istio resources seamlessly to provide the defense in depth strategy following Istio’s best security practices. There are many new features in the Cilium 1.14 release, and I’ve only explored a few above features of Cilium 1.14. If you are interested in layer 2 or BGP enhancements, newly added support to allocate IPs for pods via multi-pool IPAM or BIG TCP for IPv4 and many others, check out the latest Cilium documentation to learn more.
Cilium Resources

    Learn more Cilium topics
    How to get involved with Cilium
    Check out this complimentary Introduction to Cilium hands-on workshop to learn Cilium interactively from your browser
    Upcoming Cilium 1.14 CNI overview livestream on 8/8 at 10 AM PT & 1 PM ET

 
