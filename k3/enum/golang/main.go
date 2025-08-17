package main

import (
    "bytes"
    "crypto/tls"
    "crypto/x509"
    "encoding/json"
    "flag"
    "fmt"
    "io/ioutil"
    "net/http"
    "os"
    "strings"
)

const (
    apiServer = "https://kubernetes.default.svc"
    caCert    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
    tokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"
    nsFile    = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
)

var verbs = []string{"get", "list", "create", "update", "delete", "patch"}
var nsResources = []string{"configmaps", "secrets", "pods", "services", "deployments", "daemonsets", "statefulsets", "roles", "rolebindings"}
var clusterResources = []string{"nodes", "namespaces", "clusterroles", "clusterrolebindings"}

type ssarSpec struct {
    Kind       string `json:"kind"`
    APIVersion string `json:"apiVersion"`
    Spec       struct {
        ResourceAttributes struct {
            Verb      string `json:"verb"`
            Resource  string `json:"resource"`
            Namespace string `json:"namespace,omitempty"`
        } `json:"resourceAttributes"`
    } `json:"spec"`
}

type ssarResponse struct {
    Status struct {
        Allowed bool `json:"allowed"`
    } `json:"status"`
}

type namespaceList struct {
    Items []struct {
        Metadata struct {
            Name string `json:"name"`
        } `json:"metadata"`
    } `json:"items"`
}

func newClient() (*http.Client, string, string, error) {
    token, err := ioutil.ReadFile(tokenFile)
    if err != nil {
        return nil, "", "", err
    }
    namespace, _ := ioutil.ReadFile(nsFile)
    caCertData, err := ioutil.ReadFile(caCert)
    if err != nil {
        return nil, "", "", err
    }
    caPool := x509.NewCertPool()
    caPool.AppendCertsFromPEM(caCertData)
    tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: caPool}}
    client := &http.Client{Transport: tr}
    return client, strings.TrimSpace(string(token)), strings.TrimSpace(string(namespace)), nil
}

func checkAccess(client *http.Client, token, resource, verb, namespace string) bool {
    payload := ssarSpec{
        Kind:       "SelfSubjectAccessReview",
        APIVersion: "authorization.k8s.io/v1",
    }
    payload.Spec.ResourceAttributes.Verb = verb
    payload.Spec.ResourceAttributes.Resource = resource
    if namespace != "" {
        payload.Spec.ResourceAttributes.Namespace = namespace
    }

    data, _ := json.Marshal(payload)
    req, _ := http.NewRequest("POST", apiServer+"/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", bytes.NewBuffer(data))
    req.Header.Set("Authorization", "Bearer "+token)
    req.Header.Set("Content-Type", "application/json")

    resp, err := client.Do(req)
    if err != nil {
        return false
    }
    defer resp.Body.Close()
    body, _ := ioutil.ReadAll(resp.Body)

    var out ssarResponse
    if err := json.Unmarshal(body, &out); err != nil {
        return false
    }
    return out.Status.Allowed
}

func getNamespaces(client *http.Client, token, currentNS string) []string {
    if !checkAccess(client, token, "namespaces", "list", "") {
        return []string{currentNS}
    }

    req, _ := http.NewRequest("GET", apiServer+"/api/v1/namespaces", nil)
    req.Header.Set("Authorization", "Bearer "+token)

    resp, err := client.Do(req)
    if err != nil {
        return []string{currentNS}
    }
    defer resp.Body.Close()
    body, _ := ioutil.ReadAll(resp.Body)

    var nsList namespaceList
    if err := json.Unmarshal(body, &nsList); err != nil {
        return []string{currentNS}
    }

    namespaces := []string{}
    for _, item := range nsList.Items {
        namespaces = append(namespaces, item.Metadata.Name)
    }
    return namespaces
}

func dumpResource(client *http.Client, token, ns, resource string) {
    url := fmt.Sprintf("%s/api/v1/namespaces/%s/%s", apiServer, ns, resource)
    if resource == "deployments" || resource == "daemonsets" || resource == "statefulsets" {
        url = fmt.Sprintf("%s/apis/apps/v1/namespaces/%s/%s", apiServer, ns, resource)
    }
    req, _ := http.NewRequest("GET", url, nil)
    req.Header.Set("Authorization", "Bearer "+token)

    resp, err := client.Do(req)
    if err != nil {
        fmt.Printf("  [!] Error fetching %s: %v\n", resource, err)
        return
    }
    defer resp.Body.Close()
    body, _ := ioutil.ReadAll(resp.Body)
    fmt.Printf("  --- Dump of %s ---\n%s\n", resource, string(body))
}

func summarize(resources []string, scope string, client *http.Client, token string, namespaces []string, dump bool) {
    fmt.Printf("\n=== %s RESOURCES ===\n", strings.ToUpper(scope))
    if scope == "namespace" {
        for _, ns := range namespaces {
            fmt.Printf("\n-- Namespace: %s --\n", ns)
            for _, r := range resources {
                allowedVerbs := []string{}
                for _, v := range verbs {
                    if checkAccess(client, token, r, v, ns) {
                        allowedVerbs = append(allowedVerbs, v)
                    }
                }
                if len(allowedVerbs) > 0 {
                    flag := ""
                    if r == "secrets" && contains(allowedVerbs, "get") {
                        flag = " <<!! ESCALATION: can read secrets !!>>"
                        if dump {
                            dumpResource(client, token, ns, "secrets")
                        }
                    }
                    if r == "configmaps" && contains(allowedVerbs, "list") {
                        if dump {
                            dumpResource(client, token, ns, "configmaps")
                        }
                    }
                    if r == "pods" && contains(allowedVerbs, "list") {
                        if dump {
                            dumpResource(client, token, ns, "pods")
                        }
                    }
                    if r == "services" && contains(allowedVerbs, "list") {
                        if dump {
                            dumpResource(client, token, ns, "services")
                        }
                    }
                    if r == "pods" && (contains(allowedVerbs, "create") || contains(allowedVerbs, "update")) {
                        flag = " <<!! ESCALATION: can create/modify pods !!>>"
                    }
                    if (r == "roles" || r == "rolebindings") && contains(allowedVerbs, "create") {
                        flag = " <<!! ESCALATION: can escalate RBAC !!>>"
                    }
                    fmt.Printf("%-20s -> \033[92m%s\033[0m%s\n", r, strings.Join(allowedVerbs, ","), flag)
                } else {
                    fmt.Printf("%-20s -> \033[91mNONE\033[0m\n", r)
                }
            }
        }
    } else {
        for _, r := range resources {
            allowedVerbs := []string{}
            for _, v := range verbs {
                if checkAccess(client, token, r, v, "") {
                    allowedVerbs = append(allowedVerbs, v)
                }
            }
            if len(allowedVerbs) > 0 {
                flag := ""
                if (r == "clusterroles" || r == "clusterrolebindings") && contains(allowedVerbs, "create") {
                    flag = " <<!! ESCALATION: cluster‑wide RBAC !!>>"
                }
                fmt.Printf("%-20s -> \033[92m%s\033[0m%s\n", r, strings.Join(allowedVerbs, ","), flag)
            } else {
                fmt.Printf("%-20s -> \033[91mNONE\033[0m\n", r)
            }
        }
    }
}

func contains(slice []string, val string) bool {
    for _, v := range slice {
        if v == val {
            return true
        }
    }
    return false
}

func main() {
    dump := flag.Bool("dump", false, "Dump resources if readable")
    flag.Parse()

    client, token, namespace, err := newClient()
    if err != nil {
        fmt.Println("Error:", err)
        os.Exit(1)
    }

    fmt.Printf("Current namespace: %s\n", namespace)
    namespaces := getNamespaces(client, token, namespace)
    summarize(nsResources, "namespace", client, token, namespaces, *dump)
    summarize(clusterResources, "cluster", client, token, namespaces, *dump)
}
