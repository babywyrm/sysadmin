package main

import (
    "bytes"
    "crypto/tls"
    "crypto/x509"
    "encoding/base64"
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

func dumpResource(client *http.Client, token, ns, resource string) string {
    url := fmt.Sprintf("%s/api/v1/namespaces/%s/%s", apiServer, ns, resource)
    if resource == "deployments" || resource == "daemonsets" || resource == "statefulsets" {
        url = fmt.Sprintf("%s/apis/apps/v1/namespaces/%s/%s", apiServer, ns, resource)
    }
    req, _ := http.NewRequest("GET", url, nil)
    req.Header.Set("Authorization", "Bearer "+token)

    resp, err := client.Do(req)
    if err != nil {
        return fmt.Sprintf("error: %v", err)
    }
    defer resp.Body.Close()
    body, _ := ioutil.ReadAll(resp.Body)
    return string(body)
}

func contains(slice []string, val string) bool {
    for _, v := range slice {
        if v == val {
            return true
        }
    }
    return false
}

// Decode JWT payload (2nd part of token)
func decodeJWT(token string) map[string]interface{} {
    parts := strings.Split(token, ".")
    if len(parts) < 2 {
        return nil
    }
    payload, err := base64.RawURLEncoding.DecodeString(parts[1])
    if err != nil {
        return nil
    }
    var claims map[string]interface{}
    if err := json.Unmarshal(payload, &claims); err != nil {
        return nil
    }
    return claims
}

func main() {
    dump := flag.Bool("dump", false, "Dump resources if readable")
    jsonOut := flag.Bool("json", false, "Output results in JSON")
    flag.Parse()

    client, token, namespace, err := newClient()
    if err != nil {
        fmt.Println("Error:", err)
        os.Exit(1)
    }

    claims := decodeJWT(token)
    namespaces := getNamespaces(client, token, namespace)

    // JSON mode
    if *jsonOut {
        result := map[string]interface{}{
            "namespace": namespace,
            "claims":    claims,
            "permissions": map[string]interface{}{
                "namespaces": map[string]map[string][]string{},
                "cluster":    map[string][]string{},
            },
        }

        nsPerms := result["permissions"].(map[string]interface{})["namespaces"].(map[string]map[string][]string)
        for _, ns := range namespaces {
            nsPerms[ns] = map[string][]string{}
            for _, r := range nsResources {
                allowed := []string{}
                for _, v := range verbs {
                    if checkAccess(client, token, r, v, ns) {
                        allowed = append(allowed, v)
                    }
                }
                nsPerms[ns][r] = allowed
                if *dump && len(allowed) > 0 && (r == "secrets" || r == "configmaps" || r == "pods" || r == "services") {
                    nsPerms[ns][r+"_dump"] = []string{dumpResource(client, token, ns, r)}
                }
            }
        }

        clPerms := result["permissions"].(map[string]interface{})["cluster"].(map[string][]string)
        for _, r := range clusterResources {
            allowed := []string{}
            for _, v := range verbs {
                if checkAccess(client, token, r, v, "") {
                    allowed = append(allowed, v)
                }
            }
            clPerms[r] = allowed
        }

        out, _ := json.MarshalIndent(result, "", "  ")
        fmt.Println(string(out))
        return
    }

    // Default human-readable mode
    fmt.Printf("Current namespace: %s\n", namespace)
    if claims != nil {
        fmt.Println("ServiceAccount Token Claims:")
        for k, v := range claims {
            fmt.Printf("  %s: %v\n", k, v)
        }
    }

    // Print namespace resources
    fmt.Printf("\n=== NAMESPACE RESOURCES ===\n")
    for _, ns := range namespaces {
        fmt.Printf("\n-- Namespace: %s --\n", ns)
        for _, r := range nsResources {
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
                    if *dump {
                        fmt.Println(dumpResource(client, token, ns, "secrets"))
                    }
                }
                if r == "configmaps" && contains(allowedVerbs, "list") && *dump {
                    fmt.Println(dumpResource(client, token, ns, "configmaps"))
                }
                if r == "pods" && contains(allowedVerbs, "list") && *dump {
                    fmt.Println(dumpResource(client, token, ns, "pods"))
                }
                if r == "services" && contains(allowedVerbs, "list") && *dump {
                    fmt.Println(dumpResource(client, token, ns, "services"))
                }
                fmt.Printf("%-20s -> \033[92m%s\033[0m%s\n", r, strings.Join(allowedVerbs, ","), flag)
            } else {
                fmt.Printf("%-20s -> \033[91mNONE\033[0m\n", r)
            }
        }
    }

    // Print cluster resources
    fmt.Printf("\n=== CLUSTER RESOURCES ===\n")
    for _, r := range clusterResources {
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
