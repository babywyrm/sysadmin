##
#
https://gist.github.com/salrashid123/75c22afcbdbf1b706ab76d9063122429
#
https://www.codingforentrepreneurs.com/blog/kubernetes-rbac-service-account-github-actions
#
https://gist.github.com/reegnz/c687508459d0258544dc7cdda6e284bc
#
##

Simple go app that reads and validates a kubernetes service accounts token using the `TokenReviews` API.
also see [https://github.com/salrashid123/k8s_tokenreview](https://github.com/salrashid123/k8s_tokenreview)

to use make a copy of all the files and run

```bash
minikube start

$ kubectl apply -f app.yaml
$ kubectl get po,deployment,serviceaccount

NAME                       READY   STATUS    RESTARTS   AGE
pod/app-79696565d5-nk6v2   1/1     Running   0          75s

NAME                  READY   UP-TO-DATE   AVAILABLE   AGE
deployment.apps/app   1/1     1            1           75s

NAME                                 SECRETS   AGE
serviceaccount/app-service-account   0         75s
serviceaccount/default               0         28d

kubectl exec --stdin --tty pod/app-79696565d5-nk6v2  -- /bin/bash

# incluster
mkdir client/
cd client
go mod init main

## add code from main.go
vi main.go

go mod tidy
go run main.go
```


---

### `app.yaml`

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: app-service-account
  namespace: default
automountServiceAccountToken: false
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: role-tokenreview-binding
  namespace: default
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: system:auth-delegator
subjects:
  - kind: ServiceAccount
    name: app-service-account
    namespace: default
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
  labels:
    type: app-service
spec:
  replicas: 1
  selector:
    matchLabels:
      name: app-service
  template:
    metadata:
      labels:
        name: app-service
    spec:
      serviceAccountName: app-service-account
      automountServiceAccountToken: true
      containers:
      - name: app
        image: golang:1.19
        command:
          - /bin/bash
          - -c
          - sleep 3600
        volumeMounts:
        - mountPath: /var/run/secrets/tokens
          name: tpmds-token
        env:
          - name: POD_SERVICE_ACCOUNT
            valueFrom:
              fieldRef:
                fieldPath: spec.serviceAccountName
      volumes:
      - name: tpmds-token
        projected:
          sources:
          - serviceAccountToken:
              path: tpmds-token
              expirationSeconds: 3600
              audience: tpmds
```

---

### `main.go`

```golang
package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"

	v1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func main() {

	//b, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	b, err := ioutil.ReadFile("/var/run/secrets/tokens/tpmds-token")

	if err != nil {
		fmt.Printf("Error reading servie account token: %v\n", err)
		os.Exit(1)
	}
	serviceToken := string(b)

	// userHomeDir, err := os.UserHomeDir()
	// if err != nil {
	// 	fmt.Printf("error getting user home dir: %v\n", err)
	// 	os.Exit(1)
	// }
	// kubeConfigPath := filepath.Join(userHomeDir, ".kube", "config")
	// kubeConfig, err := clientcmd.BuildConfigFromFlags("", kubeConfigPath)
	// if err != nil {
	// 	fmt.Printf("Error getting kubernetes config: %v\n", err)
	// 	os.Exit(1)
	// }

	kubeConfig, err := rest.InClusterConfig()
	if err != nil {
		fmt.Printf("Error getting kubernetes config: %v\n", err)
		os.Exit(1)
	}

	// send the serviceToken to the daemonset as an authorization bearer token
	// on the server, use the unaryAuthHandler
	client, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		fmt.Printf("error getting kubernetes config: %v\n", err)
		os.Exit(1)
	}

	ctx := context.Background()

	tr := &v1.TokenReview{
		Spec: v1.TokenReviewSpec{
			Token:     serviceToken,
			Audiences: []string{"tpmds"},
		},
	}
	result, err := client.AuthenticationV1().TokenReviews().Create(ctx, tr, metav1.CreateOptions{})
	if err != nil {
		fmt.Printf("error getting kubernetes config: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("%s\n", result.Status.User.Username)
	fmt.Printf("%t\n", result.Status.Authenticated)

}
```

---

```json
{
  "alg": "RS256",
  "kid": "uAEAbVtS7LTtQw07lcd7E-zPv1cYfMZVN_GbTBcpE6Y"
}
{
  "aud": [
    "tpmds"
  ],
  "exp": 1686635492,
  "iat": 1686628292,
  "iss": "https://kubernetes.default.svc.cluster.local",
  "kubernetes.io": {
    "namespace": "default",
    "pod": {
      "name": "app-5d6456bf87-qxzg6",
      "uid": "6ad4a1ad-1d3a-4bd5-9522-2bf5f0912d21"
    },
    "serviceaccount": {
      "name": "app-service-account",
      "uid": "e8c9f5e1-ef07-4cd2-8aa5-368a76956244"
    }
  },
  "nbf": 1686628292,
  "sub": "system:serviceaccount:default:app-service-account"
}
```
