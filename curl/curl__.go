package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// =============================================================================
// Types
// =============================================================================

type CurlMetrics struct {
	Start      time.Time
	End        time.Time
	BytesSent  int64
	BytesRecv  int64
	HTTPCode   int
	NumRedirs  int
	TimeTotal  float64
	ContentLen int64
}

type Config struct {
	URL            string
	Method         string
	Headers        []string
	Data           string
	Form           []string
	UploadFile     string
	User           string
	Cookie         string
	Insecure       bool
	Location       bool
	MaxTime        int
	ConnTimeout    int
	Include        bool
	Silent         bool
	JSONMode       bool
	Metrics        bool
}

// =============================================================================
// Client Factory
// =============================================================================

func makeClient(cfg *Config) *http.Client {
	timeout := time.Duration(cfg.MaxTime) * time.Second
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.Insecure,
		},
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  false,
		DisableKeepAlives:   false,
	}

	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}

	if !cfg.Location {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	return client
}

// =============================================================================
// Header Parsing
// =============================================================================

func parseHeaders(headerList []string) (map[string]string, error) {
	headers := make(map[string]string)
	for _, h := range headerList {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid header format: %s", h)
		}
		headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	}
	return headers, nil
}

func parseCookies(cookieStr string) map[string]string {
	if cookieStr == "" {
		return nil
	}
	cookies := make(map[string]string)
	for _, part := range strings.Split(cookieStr, ";") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) == 2 {
			cookies[kv[0]] = kv[1]
		}
	}
	return cookies
}

// =============================================================================
// Body Construction
// =============================================================================

func buildRequestBody(cfg *Config) (io.Reader, string, error) {
	// Streaming upload (-T)
	if cfg.UploadFile != "" {
		file, err := os.Open(cfg.UploadFile)
		if err != nil {
			return nil, "", err
		}
		return file, "application/octet-stream", nil
	}

	// Buffered data (-d)
	if cfg.Data != "" {
		var data []byte
		if strings.HasPrefix(cfg.Data, "@") {
			content, err := os.ReadFile(cfg.Data[1:])
			if err != nil {
				return nil, "", err
			}
			data = content
		} else {
			data = []byte(cfg.Data)
		}
		return bytes.NewReader(data), "application/x-www-form-urlencoded", nil
	}

	// Form data (-F) - simplified version
	if len(cfg.Form) > 0 {
		// For production, use multipart/form-data with proper boundaries
		formData := make(map[string]string)
		for _, entry := range cfg.Form {
			kv := strings.SplitN(entry, "=", 2)
			if len(kv) == 2 {
				formData[kv[0]] = kv[1]
			}
		}
		jsonData, _ := json.Marshal(formData)
		return bytes.NewReader(jsonData), "application/json", nil
	}

	return nil, "", nil
}

// =============================================================================
// Request Execution
// =============================================================================

func performRequest(cfg *Config) (*http.Response, []byte, *CurlMetrics, error) {
	client := makeClient(cfg)
	metrics := &CurlMetrics{Start: time.Now()}

	// Build body
	body, contentType, err := buildRequestBody(cfg)
	if err != nil {
		return nil, nil, nil, err
	}

	// Create request
	req, err := http.NewRequest(cfg.Method, cfg.URL, body)
	if err != nil {
		return nil, nil, nil, err
	}

	// Set headers
	headers, err := parseHeaders(cfg.Headers)
	if err != nil {
		return nil, nil, nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	// Set content type if we have a body
	if body != nil && contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	// Set cookies
	if cfg.Cookie != "" {
		cookies := parseCookies(cfg.Cookie)
		for k, v := range cookies {
			req.AddCookie(&http.Cookie{Name: k, Value: v})
		}
	}

	// Basic auth
	if cfg.User != "" {
		parts := strings.SplitN(cfg.User, ":", 2)
		if len(parts) == 2 {
			req.SetBasicAuth(parts[0], parts[1])
		}
	}

	// Execute request
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, nil, err
	}
	defer resp.Body.Close()

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, nil, err
	}

	metrics.End = time.Now()
	metrics.HTTPCode = resp.StatusCode
	metrics.BytesRecv = int64(len(respBody))
	metrics.TimeTotal = metrics.End.Sub(metrics.Start).Seconds()
	metrics.ContentLen = resp.ContentLength

	return resp, respBody, metrics, nil
}

// =============================================================================
// Output
// =============================================================================

func printResponse(resp *http.Response, body []byte, jsonMode bool) {
	fmt.Printf("Status: %d\n", resp.StatusCode)
	fmt.Println("Headers:")
	for k, v := range resp.Header {
		fmt.Printf("  %s: %s\n", k, strings.Join(v, ", "))
	}
	fmt.Println()

	if jsonMode {
		var jsonData interface{}
		if err := json.Unmarshal(body, &jsonData); err == nil {
			pretty, _ := json.MarshalIndent(jsonData, "", "  ")
			fmt.Println(string(pretty))
			return
		}
	}

	output := string(body)
	if len(output) > 2000 {
		output = output[:2000]
	}
	fmt.Println(output)
}

func printMetrics(m *CurlMetrics, resp *http.Response) {
	metrics := map[string]interface{}{
		"http_code":     m.HTTPCode,
		"url_effective": resp.Request.URL.String(),
		"content_type":  resp.Header.Get("Content-Type"),
		"size_upload":   m.BytesSent,
		"size_download": m.BytesRecv,
		"time_total":    fmt.Sprintf("%.6f", m.TimeTotal),
		"content_length": m.ContentLen,
	}

	pretty, _ := json.MarshalIndent(metrics, "", "  ")
	fmt.Println(string(pretty))
}

// =============================================================================
// CLI
// =============================================================================

type headerFlags []string

func (h *headerFlags) String() string {
	return strings.Join(*h, ", ")
}

func (h *headerFlags) Set(value string) error {
	*h = append(*h, value)
	return nil
}

type formFlags []string

func (f *formFlags) String() string {
	return strings.Join(*f, ", ")
}

func (f *formFlags) Set(value string) error {
	*f = append(*f, value)
	return nil
}

func parseArgs() *Config {
	cfg := &Config{}

	var headers headerFlags
	var form formFlags

	flag.StringVar(&cfg.Method, "X", "GET", "HTTP method")
	flag.Var(&headers, "H", "Headers (repeatable)")
	flag.StringVar(&cfg.Data, "d", "", "Request data")
	flag.Var(&form, "F", "Form data (repeatable)")
	flag.StringVar(&cfg.UploadFile, "T", "", "Upload file (streaming)")
	flag.StringVar(&cfg.User, "u", "", "user:password for basic auth")
	flag.StringVar(&cfg.Cookie, "b", "", "Cookie string")
	flag.BoolVar(&cfg.Insecure, "k", false, "Skip TLS verification")
	flag.BoolVar(&cfg.Location, "L", false, "Follow redirects")
	flag.IntVar(&cfg.MaxTime, "m", 10, "Max time in seconds")
	flag.IntVar(&cfg.ConnTimeout, "connect-timeout", 5, "Connection timeout")
	flag.BoolVar(&cfg.Include, "i", false, "Include headers in output")
	flag.BoolVar(&cfg.Silent, "s", false, "Silent mode")
	flag.BoolVar(&cfg.JSONMode, "json", false, "JSON output mode")
	flag.BoolVar(&cfg.Metrics, "metrics", false, "Show metrics")

	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "Error: URL required")
		flag.Usage()
		os.Exit(1)
	}

	cfg.URL = flag.Arg(0)
	cfg.Headers = headers
	cfg.Form = form

	// curl semantics: -d implies POST
	if cfg.Data != "" && cfg.Method == "GET" {
		cfg.Method = "POST"
	}

	return cfg
}

// =============================================================================
// Main
// =============================================================================

func main() {
	cfg := parseArgs()

	resp, body, metrics, err := performRequest(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if cfg.Include {
		for k, v := range resp.Header {
			fmt.Printf("%s: %s\n", k, strings.Join(v, ", "))
		}
		fmt.Println()
	}

	if !cfg.Silent {
		printResponse(resp, body, cfg.JSONMode)
	}

	if cfg.Metrics {
		printMetrics(metrics, resp)
	}
}
