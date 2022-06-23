# Istio Security Analyzer

This is a tool to analyze Istio security. Roughly the tool covers two aspects

1. Ensure configuration adhering to [Istio Security Best Practice](https://istio.io/latest/docs/ops/best-practices/security).
1. Checks the running Istio version to see if has any known CVE issues.

## Get Started

### Install Istio

Install Istio 1.12.1. We choose this specific version so that we can demo how CVE detection works.

```sh
curl -L https://git.io/getLatestIstio | ISTIO_VERSION=1.12.1 sh
pushd istio-1.12.1
./bin/istioctl install --set profile=demo -y
```

### Check Basics

Now let's just run the tool without any configuration.

```sh
make build  && ./build/scanner_linux_amd64/scanner
```

You will see some report as below. In this report, we identified a few issues.

- Reminds you that you can harden your Istio deployment via using hardened distroless image.
- Reports security vunerabilities found for Istio 1.12.1. For example, [Istio-security-2022-004](https://istio.io/latest/news/security/istio-security-2022-004/) means unauthenticated request to Istiod control plane can make
Istiod crash by exhausting its memory.
- Config Warnings section reminds you that the cluster does not have k8s RBAC to
[control](https://istio.io/latest/docs/ops/best-practices/security/#restrict-gateway-creation-privileges)
who can create Istio gateway resource.

```text
==========================================
    Istio Security Scanning Report

Control Plane Version
- 1.12.1

Distroless Warning
- pod istio-egressgateway-687f4db598-rn5hs can use a distroless image for better security, current
docker.io/istio/proxyv2:1.12.1

CVE Report
- ISTIO-SECURITY-2022-004
- ISTIO-SECURITY-2022-003
- ISTIO-SECURITY-2022-001
- ISTIO-SECURITY-2022-002

Config Warnings
We scanned 0 security configurations, and 0 networking configurations.

❌ failed to find cluster role and role bindings to control istio gateway creation
```
##
##

https://github.com/tetratelabs/istio-security-analyzer/blob/main/README.md

##
##

### Config Scanning

Now we try to apply some configuration to see how the analyzer can help detecting the potential security issues.

In [`./samples/gateway-k8s-rbac.yaml`](https://github.com/tetratelabs/istio-security-analyzer/blob/main/samples/gateway-k8s-rbac.yaml),
we set up the some Kubernets RBAC to only allow specific users to create Istio Gateway resource,
this should fix the warning above.

```sh
kubectl apply -f ./samples/
```

And run the tool again

```sh
./build/scanner_linux_amd64/scanner
```

This time we see `Config Report` changes.

```
Config Warnings
We scanned 2 security configurations, and 3 networking configurations.

❌ security.istio.io/v1beta1/AuthorizationPolicy foo/httpbin-allow-negative: authorization policy: found negative matches in allow policy
❌ networking.istio.io/v1alpha3/DestinationRule default/httpbin-tls-bad: destination rule: either caCertificates or subjectAltNames is not set.
❌ networking.istio.io/v1alpha3/Gateway default/httpbin-gateway: host "*" is overly broad, consider to assign aspecific domain name such as foo.example.com
```

- For warning "found negative matches in allow policy", see [Use ALLOW-with-positive-matching and DENY-with-negative-match patterns
](https://istio.io/latest/docs/ops/best-practices/security/#use-allow-with-positive-matching-and-deny-with-negative-match-patterns)
- For "either caCertificates or subjectAltNames is not set", see [Configure TLS verification in Destination Rule when using TLS origination](https://istio.io/latest/docs/ops/best-practices/security/#use-allow-with-positive-matching-and-deny-with-negative-match-patterns)
- For "host * is overly broad", see [Avoid overly broad hosts configurations
](https://istio.io/latest/docs/ops/best-practices/security/#avoid-overly-broad-hosts-configurations) 
