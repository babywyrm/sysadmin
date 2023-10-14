## ThousandEyes Kubernetes Operator

##
#
https://github.com/CiscoDevNet/thousandeyes-kubernetes-operator/
#
##

[![published](https://static.production.devnetcloud.com/codeexchange/assets/images/devnet-published.svg)](https://developer.cisco.com/codeexchange/github/repo/CiscoDevNet/thousandeyes-kubernetes-operator)
[![Language](https://img.shields.io/badge/Language-Go-blue.svg)](https://golang.org/)

ThousandEyes Kubernetes Operator is a Kubernetes operator used to manage ThousandEyes [Tests](https://developer.thousandeyes.com/v6/tests/) deployed via Kubernetes cluster.
It is built using the [Operator SDK](https://github.com/operator-framework/operator-sdk), which is part of the [Operator Framework](https://github.com/operator-framework/).

## Table of Contents
* [Supported Test Types](#supported-test-types)
* [Installation](#installation)
* [Quick Start](#quick-start)
* [Advanced Usage](#advanced-usage)
* [Reference](#reference)

## Supported Test Types
ThousandEyes Kubernetes Operator supports managing the following test types.
- [HTTP Server Test](https://docs.thousandeyes.com/product-documentation/internet-and-wan-monitoring/tests/http-server-tests)
- [Page Load Test](https://docs.thousandeyes.com/product-documentation/browser-synthetics/page-load-tests)
- [Web Transaction Test](https://docs.thousandeyes.com/product-documentation/browser-synthetics/transaction-tests)

More types will be supported in the future.

## Installation

### Prerequisites
1. Access to working kubernetes cluster (version `>=1.18.0`) and local kubectl cli. [Docker desktop kubernetes](https://docs.docker.com/desktop/kubernetes/), [Minikube](https://minikube.sigs.k8s.io/docs/start/) or [kind](https://kind.sigs.k8s.io/) are some of popular options to setup local kubernetes cluster.
2. [Trial account for ThousandEyes](https://www.thousandeyes.com/lps/network-monitoring/#lps-free-trial)

### Deploy ThousandEyes Kubernetes Operator

1. Clone the project
   ```
   git clone https://github.com/CiscoDevNet/thousandeyes-kubernetes-operator.git
   cd thousandeyes-kubernetes-operator
   ```

2. Get OAuth Bearer Token from [ThousandEyes dashboard](https://app.thousandeyes.com/login)

   ![OAuth Bearer Token](./docs/thousandeyes_token.gif)

   If this token has been generated, you can get it from your admin or revoke it to create a new one. 

3. Update the OAuth bearer token

   Encode the token in base64
   ```
   echo -n "YOUR_OAUTH_BEARER_TOKEN" | base64
   ```

   Modify OAuthBearerToken (base64 encoded) in [config/deploy/thousandeyes_kubernetes_operator.yaml](./config/deploy/thousandeyes_kubernetes_operator.yaml#L7)

4. Install the operator
   ```
   kubectl apply -f config/deploy/thousandeyes_kubernetes_operator.yaml
   ```

5. Verify installation status

   i. Check ThousandEyes Kubernetes Operator pod status
   ```
   kubectl get pods | grep thousandeyes
   
     NAME                                                            READY   STATUS    RESTARTS   AGE
     devnet-thousandeyes-kubernetes-operator-564b5d75d-jllzk         1/1     Running   0          108s
   ```
   ii. Check ThousandEyes CRD status
   ```
   kubectl get crd | grep thousandeyes
   
     NAME                                                  CREATED AT
     annotationmonitorings.thousandeyes.devnet.cisco.com   2021-07-07T15:44:40Z
     httpservertests.thousandeyes.devnet.cisco.com         2021-07-07T15:44:41Z
     pageloadtests.thousandeyes.devnet.cisco.com           2021-07-07T15:44:42Z
     webtransactiontests.thousandeyes.devnet.cisco.com     2021-07-07T15:44:44Z 
   ```

## Quick Start

Let`s run a Nginx web app, then create a **Page Load** test to monitor this app

1. Create a Nginx web app
   ```
   kubectl apply -f config/samples/nginx.yaml
   ```
2. Check the Nginx pod status
   ```
   kubectl get pods -A | grep nginx
   default       nginx-6976ddb986-rxqv6          1/1     Running    0        12s
   ```
3. Expose **Nginx service** to Internet Using [ngrok](https://ngrok.com/)
   ```
   kubectl apply -f config/samples/ngrok.yaml  
   ```
4. Check the ngrok pod status
   ```
   kubectl get pods -A | grep ngrok
   default       ngrok-5dfd559764-zx9r7          1/1     Running   0         7s
   ```
5. Get the public URL of this web app
   ```
   ./config/samples/public_url.sh
   ```
   Your public URL for Nginx web app is similar to:
   ```
   https://9c5f-64-104-125-230.eu.ngrok.io
   ```
6. Access this app

   Open your favorite browser and navigate to the public URL.

   You should see the Nginx welcome page which means you have run the app successfully.

7. Update your public URL in [config/samples/pageload_cr.yaml](./config/samples/pageload_cr.yaml#L6)
8. Apply the page load test CR
   ```
   kubectl apply -f config/samples/pageload_cr.yaml
   ```
9. Go to [ThousandEyes dashboard](https://app.thousandeyes.com/settings/tests/?tab=settings)

   You will find this test on ThousandEyes dashboard.
   ![Page Load Test](./docs/pageload-test.png)

## Advanced Usage
For advanced usage, please refer to the following documentations:
1. [Create a Kubernetes Custom Resource](./docs/custom_resource.md)
2. [Annotate Kubernetes Ingress / Service](./docs/annotations.md)

## Reference
1. [ThousandEyes Getting Started](https://docs.thousandeyes.com/product-documentation/getting-started)
2. [ThousandEyes Test MetaData](https://developer.thousandeyes.com/v6/tests/#/test_metadata)












