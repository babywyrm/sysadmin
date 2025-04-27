package main

import (
  "bufio"
  "bytes"
  "context"
  "encoding/json"
  "flag"
  "fmt"
  "io"
  "log"
  "net/http"
  "os"
  "os/exec"
  "path/filepath"
  "regexp"
  "strings"
  "time"

  "github.com/bmatcuk/doublestar/v4"
)

// OWASP category constants
const (
  OWASP_A01 = "A01" // Broken Access Control
  OWASP_A02 = "A02" // Cryptographic Failures
  OWASP_A03 = "A03" // Injection
  OWASP_A05 = "A05" // Security Misconfiguration
  OWASP_A06 = "A06" // Vulnerable & Outdated Components
  OWASP_A07 = "A07" // Cross-Site Scripting (XSS)
  OWASP_A08 = "A08" // Software/Data Integrity Failures
  OWASP_A10 = "A10" // SSRF
)

// Finding represents a single security finding.
type Finding struct {
  File      string    `json:"file"`
  Line      int       `json:"line"`
  RuleName  string    `json:"rule_name"`
  Match     string    `json:"match"`
  Severity  string    `json:"severity"`
  Category  string    `json:"category"`
  Timestamp time.Time `json:"timestamp"`
}

// Rule defines a scanning rule.
type Rule struct {
  Name        string
  Regex       string
  Pattern     *regexp.Regexp
  Severity    string
  Category    string
  Description string
  Remediation string
}

// Base OWASP-related rules
var rules = []Rule{
  // A01
  {
    Name:        "Go FormValue",
    Regex:       `(?i)r\.FormValue\(`,
    Severity:    "HIGH",
    Category:    OWASP_A01,
    Description: "Unvalidated form input",
    Remediation: "Validate & sanitize all form inputs.",
  },
  {
    Name:        "Java getParameter",
    Regex:       `(?i)request\.getParameter\(`,
    Severity:    "HIGH",
    Category:    OWASP_A01,
    Description: "Unvalidated request parameter",
    Remediation: "Use input validation frameworks.",
  },
  {
    Name:        "Node req.query/body",
    Regex:       `(?i)(req\.body|req\.query)\s*[\.\[]`,
    Severity:    "HIGH",
    Category:    OWASP_A01,
    Description: "Unvalidated Node.js request input",
    Remediation: "Use libraries like joi or express-validator.",
  },
  {
    Name:        "Flask Input",
    Regex:       `(?i)(request\.args|getattr\(request, )`,
    Severity:    "HIGH",
    Category:    OWASP_A01,
    Description: "Unvalidated Flask input",
    Remediation: "Validate Flask request data explicitly.",
  },

  // A02
  {
    Name:        "Hardcoded Password",
    Regex:       `(?i)password\s*=\s*["'][^"']+["']`,
    Severity:    "HIGH",
    Category:    OWASP_A02,
    Description: "Credentials in code",
    Remediation: "Use environment variables or vaults.",
  },
  {
    Name:        "API Key",
    Regex:       `(?i)(api[_-]?key|secret)\s*=\s*["'][^"']+["']`,
    Severity:    "HIGH",
    Category:    OWASP_A02,
    Description: "API key in code",
    Remediation: "Use secure secret storage.",
  },
  {
    Name:        "JWT Secret",
    Regex:       `(?i)(jwt.*secret|signingkey)\s*=\s*["'][^"']+["']`,
    Severity:    "HIGH",
    Category:    OWASP_A02,
    Description: "JWT secret in code",
    Remediation: "Use env-vars or vaults.",
  },
  {
    Name:        "MD5",
    Regex:       `(?i)md5\s*\(`,
    Severity:    "MEDIUM",
    Category:    OWASP_A02,
    Description: "Weak MD5 hash",
    Remediation: "Use SHA-256 or better.",
  },
  {
    Name:        "SHA1",
    Regex:       `(?i)sha1\s*\(`,
    Severity:    "MEDIUM",
    Category:    OWASP_A02,
    Description: "Weak SHA1 hash",
    Remediation: "Use SHA-256 or better.",
  },

  // A03
  {
    Name:        "Eval Usage",
    Regex:       `(?i)eval\s*\(`,
    Severity:    "MEDIUM",
    Category:    OWASP_A03,
    Description: "Use of eval()",
    Remediation: "Avoid eval(); use safe parsing.",
  },
  {
    Name:        "Command Exec",
    Regex:       `(?i)(system|exec)\s*\(`,
    Severity:    "HIGH",
    Category:    OWASP_A03,
    Description: "System/exec call",
    Remediation: "Use allow-lists & sanitize args.",
  },

  // A05
  {
    Name:        "TLS SkipVerify",
    Regex:       `(?i)InsecureSkipVerify\s*:\s*true`,
    Severity:    "HIGH",
    Category:    OWASP_A05,
    Description: "TLS Verify disabled",
    Remediation: "Enable certificate validation.",
  },
  {
    Name:        "Flask Debug",
    Regex:       `(?i)app\.run\(.*debug\s*=\s*True`,
    Severity:    "MEDIUM",
    Category:    OWASP_A05,
    Description: "Debug mode on",
    Remediation: "Disable debug in prod.",
  },

  // A06
  {
    Name:        "Old jQuery",
    Regex:       `jquery-1\.(3|4|5|6|7|8|9)`,
    Severity:    "HIGH",
    Category:    OWASP_A06,
    Description: "Legacy jQuery",
    Remediation: "Upgrade to latest jQuery.",
  },
  {
    Name:        "Known Vuln Lib",
    Regex:       `(?i)(flask==0\.10|lodash@3)`,
    Severity:    "HIGH",
    Category:    OWASP_A06,
    Description: "Vulnerable library version",
    Remediation: "Update dependencies.",
  },

  // A07
  {
    Name:        "Raw Jinja2",
    Regex:       `(?i){{\s*[^}]+\s*}}`,
    Severity:    "HIGH",
    Category:    OWASP_A07,
    Description: "Unescaped template",
    Remediation: "Use safe filters or escape.",
  },
  {
    Name:        "innerHTML",
    Regex:       `(?i)\.innerHTML\s*=`,
    Severity:    "HIGH",
    Category:    OWASP_A07,
    Description: "innerHTML assignment",
    Remediation: "Use textContent or sanitize.",
  },
  {
    Name:        "document.write",
    Regex:       `(?i)document\.write\s*\(`,
    Severity:    "MEDIUM",
    Category:    OWASP_A07,
    Description: "document.write used",
    Remediation: "Avoid document.write().",
  },
  {
    Name:        "jQuery .html()",
    Regex:       `(?i)\$\(.+\)\.html\(`,
    Severity:    "HIGH",
    Category:    OWASP_A07,
    Description: "jQuery .html()",
    Remediation: "Use .text() or sanitize.",
  },
  {
    Name:        "Inline JS Handler",
    Regex:       `(?i)on\w+\s*=\s*["'].*["']`,
    Severity:    "MEDIUM",
    Category:    OWASP_A07,
    Description: "Inline JS event",
    Remediation: "Use addEventListener().",
  },

  // A08
  {
    Name:        "Go: exec w/ download",
    Regex:       `(?i)http\.Get.*\|\s*exec\.Command`,
    Severity:    "HIGH",
    Category:    OWASP_A08,
    Description: "Exec downloaded code",
    Remediation: "Verify & sign before exec.",
  },
  {
    Name:        "Shell curl + sh",
    Regex:       `curl.*\|\s*sh`,
    Severity:    "HIGH",
    Category:    OWASP_A08,
    Description: "curl | sh",
    Remediation: "Download, verify, then exec.",
  },

  // A10
  {
    Name:        "Python SSRF",
    Regex:       `requests\.get\([^)]+\)`,
    Severity:    "HIGH",
    Category:    OWASP_A10,
    Description: "Unvalidated requests.get",
    Remediation: "Whitelist URLs/domains.",
  },
  {
    Name:        "Go SSRF",
    Regex:       `http\.Get\([^)]+\)`,
    Severity:    "HIGH",
    Category:    OWASP_A10,
    Description: "Unvalidated http.Get",
    Remediation: "Whitelist URLs/domains.",
  },
}

// Extended OWASP rules
var extendedRules = []Rule{
  // A01
  {
    Name:        "Java Servlet getHeader",
    Regex:       `(?i)request\.getHeader\(`,
    Severity:    "HIGH",
    Category:    OWASP_A01,
    Description: "Header input unchecked",
    Remediation: "Validate & sanitize headers.",
  },
  {
    Name:        "Spring Security Disabled",
    Regex:       `(?i)http\.csrf\(\)\.disable\(\)`,
    Severity:    "HIGH",
    Category:    OWASP_A01,
    Description: "CSRF disabled",
    Remediation: "Enable CSRF protection.",
  },

  // A02
  {
    Name:        "Hardcoded RSA Key",
    Regex:       `(?i)privateKey\s*=\s*["'][^"']+["']`,
    Severity:    "HIGH",
    Category:    OWASP_A02,
    Description: "RSA key in code",
    Remediation: "Use secure key mgmt.",
  },
  {
    Name:        "Weak Cipher",
    Regex:       `(?i)Cipher\.getInstance\(["']?(DES|RC4|MD5|SHA1)["']?\)`,
    Severity:    "HIGH",
    Category:    OWASP_A02,
    Description: "Weak cipher use",
    Remediation: "Use AES-GCM or better.",
  },
  {
    Name:        "Python hashlib md5",
    Regex:       `(?i)hashlib\.md5\(`,
    Severity:    "MEDIUM",
    Category:    OWASP_A02,
    Description: "hashlib.md5",
    Remediation: "Use hashlib.sha256.",
  },
  {
    Name:        "Go crypto/md5",
    Regex:       `(?i)md5\.New\(`,
    Severity:    "MEDIUM",
    Category:    OWASP_A02,
    Description: "crypto/md5",
    Remediation: "Use crypto/sha256.",
  },

  // A03
  {
    Name:        "Java PreparedStatement Concatenation",
    Regex:       `(?i)createStatement\(\)\.executeQuery\(".*"\s*\+\s*.*\)`,
    Severity:    "HIGH",
    Category:    OWASP_A03,
    Description: "SQL concatenation",
    Remediation: "Use parameterized queries.",
  },
  {
    Name:        "JS eval with template literals",
    Regex:       `(?i)eval\(`,
    Severity:    "HIGH",
    Category:    OWASP_A03,
    Description: "eval in JS",
    Remediation: "Avoid eval(); use safe parsing.",
  },
  {
    Name:        "Python os.system",
    Regex:       `(?i)os\.system\(`,
    Severity:    "HIGH",
    Category:    OWASP_A03,
    Description: "os.system call",
    Remediation: "Use subprocess with shell=False.",
  },
  {
    Name:        "Go exec.CommandContext",
    Regex:       `(?i)exec\.CommandContext\(`,
    Severity:    "HIGH",
    Category:    OWASP_A03,
    Description: "exec.CommandContext",
    Remediation: "Sanitize args; use allow-lists.",
  },

  // A05
  {
    Name:        "Java Debug Enabled",
    Regex:       `(?i)spring\.boot\.devtools\.restart\.enabled\s*=\s*true`,
    Severity:    "MEDIUM",
    Category:    OWASP_A05,
    Description: "Devtools in prod",
    Remediation: "Disable devtools in prod.",
  },
  {
    Name:        "Node.js Express Error Handler",
    Regex:       `(?i)app\.use\(errorHandler\)`,
    Severity:    "MEDIUM",
    Category:    OWASP_A05,
    Description: "Default error handler",
    Remediation: "Use custom error handler.",
  },

  // A06
  {
    Name:        "Old AngularJS",
    Regex:       `angular\.module\(`,
    Severity:    "HIGH",
    Category:    OWASP_A06,
    Description: "Legacy AngularJS",
    Remediation: "Migrate to Angular 2+.",
  },
  {
    Name:        "Python Requests Old Version",
    Regex:       `requests==2\.18\.\d+`,
    Severity:    "HIGH",
    Category:    OWASP_A06,
    Description: "Old requests lib",
    Remediation: "Upgrade requests package.",
  },
  {
    Name:        "Go Old Gin Version",
    Regex:       `github\.com/gin-gonic/gin v1\.3\.\d+`,
    Severity:    "HIGH",
    Category:    OWASP_A06,
    Description: "Old Gin framework",
    Remediation: "Upgrade Gin to latest.",
  },

  // A07
  {
    Name:        "JS document.cookie",
    Regex:       `(?i)document\.cookie`,
    Severity:    "HIGH",
    Category:    OWASP_A07,
    Description: "Cookie access in JS",
    Remediation: "Avoid direct cookie use; use HttpOnly.",
  },
  {
    Name:        "Python Flask Markup Unsafe",
    Regex:       `(?i)Markup\(.*\)`,
    Severity:    "HIGH",
    Category:    OWASP_A07,
    Description: "Flask Markup()",
    Remediation: "Use safe rendering; escape data.",
  },
  {
    Name:        "Go html/template Unsafe",
    Regex:       `(?i)template\.HTML\(`,
    Severity:    "HIGH",
    Category:    OWASP_A07,
    Description: "template.HTML use",
    Remediation: "Use auto-escaping templates.",
  },

  // A08
  {
    Name:        "Python pickle load",
    Regex:       `(?i)pickle\.load\(`,
    Severity:    "HIGH",
    Category:    OWASP_A08,
    Description: "pickle.load()",
    Remediation: "Avoid pickle; use safe formats.",
  },
  {
    Name:        "Go json.Unmarshal unchecked",
    Regex:       `(?i)json\.Unmarshal\(`,
    Severity:    "MEDIUM",
    Category:    OWASP_A08,
    Description: "json.Unmarshal",
    Remediation: "Validate JSON before unmarshal.",
  },

  // A10
  {
    Name:        "Java URL openStream",
    Regex:       `(?i)new\s+URL\([^)]*\)\.openStream\(`,
    Severity:    "HIGH",
    Category:    OWASP_A10,
    Description: "URL.openStream",
    Remediation: "Whitelist remote endpoints.",
  },
  {
    Name:        "Node.js http.request",
    Regex:       `(?i)http\.request\(`,
    Severity:    "HIGH",
    Category:    OWASP_A10,
    Description: "http.request",
    Remediation: "Whitelist URLs/domains.",
  },
  {
    Name:        "Python urllib urlopen",
    Regex:       `(?i)urllib\.request\.urlopen\(`,
    Severity:    "HIGH",
    Category:    OWASP_A10,
    Description: "urlopen()",
    Remediation: "Whitelist URLs/domains.",
  },
  {
    Name:        "Go net/http Get",
    Regex:       `(?i)http\.Get\(`,
    Severity:    "HIGH",
    Category:    OWASP_A10,
    Description: "http.Get()",
    Remediation: "Whitelist URLs/domains.",
  },
}

var supportedExtensions = map[string]bool{
  ".go": true, ".js": true, ".py": true, ".java": true, ".html": true,
}

var ruleMap = map[string]Rule{}

func init() {
  for i := range rules {
    rules[i].Pattern = regexp.MustCompile(rules[i].Regex)
    ruleMap[rules[i].Name] = rules[i]
  }
  for _, r := range extendedRules {
    r.Pattern = regexp.MustCompile(r.Regex)
    rules = append(rules, r)
    ruleMap[r.Name] = r
  }
}

func runCommand(ctx context.Context, cmd string, args ...string) (string, error) {
  c := exec.CommandContext(ctx, cmd, args...)
  out, err := c.CombinedOutput()
  return string(out), err
}

func getGitChangedFiles(ctx context.Context) ([]string, error) {
  out, err := runCommand(ctx, "git", "diff", "--name-only", "HEAD~1")
  if err != nil {
    return nil, err
  }
  return strings.Split(strings.TrimSpace(out), "\n"), nil
}

func loadIgnorePatterns(ignoreFlag string) ([]string, error) {
  var patterns []string
  if ignoreFlag != "" {
    patterns = append(patterns, strings.Split(ignoreFlag, ",")...)
  }
  f, err := os.Open(".scannerignore")
  if err != nil {
    if os.IsNotExist(err) {
      return patterns, nil
    }
    return nil, err
  }
  defer f.Close()
  scanner := bufio.NewScanner(f)
  for scanner.Scan() {
    line := strings.TrimSpace(scanner.Text())
    if line != "" && !strings.HasPrefix(line, "#") {
      patterns = append(patterns, line)
    }
  }
  return patterns, scanner.Err()
}

func shouldIgnore(path string, patterns []string) bool {
  for _, pat := range patterns {
    if ok, _ := doublestar.PathMatch(pat, path); ok {
      return true
    }
  }
  return false
}

func scanFile(path string, debug bool) ([]Finding, error) {
  if debug {
    log.Printf("Scanning file: %s", path)
  }
  var findings []Finding
  f, err := os.Open(path)
  if err != nil {
    return findings, err
  }
  defer f.Close()

  scanner := bufio.NewScanner(f)
  lineNum := 0
  for scanner.Scan() {
    lineNum++
    text := scanner.Text()
    for _, r := range rules {
      if r.Pattern.MatchString(text) {
        match := r.Pattern.FindString(text)
        if len(match) > 80 {
          match = match[:80] + "..."
        }
        findings = append(findings, Finding{
          File:      path,
          Line:      lineNum,
          RuleName:  r.Name,
          Match:     match,
          Severity:  r.Severity,
          Category:  r.Category,
          Timestamp: time.Now(),
        })
      }
    }
  }
  return findings, scanner.Err()
}

func scanDir(ctx context.Context, root string, useGit, debug bool, ignorePatterns []string) ([]Finding, error) {
  if debug {
    log.Printf("Starting scan in %s (git=%v)", root, useGit)
  }
  var files []string
  if useGit {
    fs, err := getGitChangedFiles(ctx)
    if err != nil {
      return nil, err
    }
    files = fs
  } else {
    filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
      if err != nil {
        return err
      }
      if !d.IsDir() && supportedExtensions[filepath.Ext(path)] && !shouldIgnore(path, ignorePatterns) {
        files = append(files, path)
      }
      return nil
    })
  }

  var all []Finding
  for _, f := range files {
    fs, err := scanFile(f, debug)
    if err != nil {
      log.Printf("Warning: failed to scan %s: %v", f, err)
      continue
    }
    all = append(all, fs...)
  }
  return all, nil
}

func summarize(findings []Finding) {
  sev := map[string]int{}
  cat := map[string]int{}
  for _, f := range findings {
    sev[f.Severity]++
    cat[f.Category]++
  }
  fmt.Println("\n[ Severity Summary ]")
  for k, v := range sev {
    fmt.Printf("  %s: %d\n", k, v)
  }
  fmt.Println("\n[ OWASP Category Summary ]")
  for k, v := range cat {
    fmt.Printf("  %s: %d\n", k, v)
  }
}

func outputMarkdownBody(findings []Finding) string {
  var b strings.Builder
  b.WriteString("### 🔍 Static Analysis Findings\n\n")
  b.WriteString("| File | Line | Rule | Match | Severity | OWASP |\n")
  b.WriteString("|------|------|------|-------|----------|-------|\n")
  for _, f := range findings {
    b.WriteString(fmt.Sprintf(
      "| `%s` | %d | %s | `%s` | **%s** | %s |\n",
      f.File, f.Line, f.RuleName, f.Match, f.Severity, f.Category,
    ))
  }
  return b.String()
}

func postGitHubComment(body string) error {
  repo := os.Getenv("GITHUB_REPOSITORY")
  pr := os.Getenv("GITHUB_PR_NUMBER")
  token := os.Getenv("GITHUB_TOKEN")
  if repo == "" || pr == "" || token == "" {
    return fmt.Errorf("GitHub environment variables not set")
  }
  url := fmt.Sprintf("https://api.github.com/repos/%s/issues/%s/comments", repo, pr)
  payload := map[string]string{"body": body}
  data, _ := json.Marshal(payload)
  req, _ := http.NewRequest("POST", url, bytes.NewReader(data))
  req.Header.Set("Authorization", "Bearer "+token)
  req.Header.Set("Accept", "application/vnd.github.v3+json")
  resp, err := http.DefaultClient.Do(req)
  if err != nil {
    return err
  }
  defer resp.Body.Close()
  io.Copy(io.Discard, resp.Body)
  if resp.StatusCode != 201 {
    return fmt.Errorf("GitHub comment failed with status %d", resp.StatusCode)
  }
  return nil
}

func main() {
  flag.Usage = func() {
    fmt.Fprint(os.Stderr, "Static Code Scanner - OWASP-focused\n\n")
    flag.PrintDefaults()
  }

  dir := flag.String("dir", ".", "Directory to scan")
  output := flag.String("output", "text", "Output: text/json/markdown")
  debug := flag.Bool("debug", false, "Debug mode")
  useGit := flag.Bool("git-diff", false, "Scan changed files only")
  exitHigh := flag.Bool("exit-high", false, "Exit 1 if any HIGH findings")
  ignoreFlag := flag.String("ignore", "vendor,node_modules,dist,public,build", "Ignore patterns")
  postToGitHub := flag.Bool("github-pr", false, "Post results to GitHub PR")
  verbose := flag.Bool("verbose", false, "Show short remediation advice")
  flag.Parse()

  if *debug {
    log.Println("Debug mode enabled")
  }

  ignorePatterns, err := loadIgnorePatterns(*ignoreFlag)
  if err != nil {
    log.Fatalf("Failed to load ignore patterns: %v", err)
  }

  findings, err := scanDir(context.Background(), *dir, *useGit, *debug, ignorePatterns)
  if err != nil {
    log.Fatalf("Scan error: %v", err)
  }

  if len(findings) == 0 {
    fmt.Println("✅ No issues found.")
    return
  }

  summarize(findings)

  switch *output {
  case "text":
    for _, f := range findings {
      fmt.Printf("[%s] %s:%d – %s (%s)\n",
        f.Severity, f.File, f.Line, f.RuleName, f.Match)
      if *verbose {
        r := ruleMap[f.RuleName]
        fmt.Printf("    ▶ %s\n", r.Description)
        fmt.Printf("    ⚑ %s\n\n", r.Remediation)
      }
    }

  case "json":
    data, _ := json.MarshalIndent(findings, "", "  ")
    fmt.Println(string(data))

  case "markdown":
    body := outputMarkdownBody(findings)
    fmt.Println(body)
    if *postToGitHub {
      if err := postGitHubComment(body); err != nil {
        log.Printf("GitHub comment failed: %v", err)
      } else {
        fmt.Println("✅ Comment posted to PR.")
      }
    }

  default:
    log.Fatalf("Unsupported output: %s", *output)
  }

  if *exitHigh {
    for _, f := range findings {
      if f.Severity == "HIGH" {
        os.Exit(1)
      }
    }
  }
}
