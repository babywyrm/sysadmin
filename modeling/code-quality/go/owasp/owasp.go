package main

import (
  "bufio"
  "bytes"
  "context"
  "encoding/json"
  "flag"
  "fmt"
  "io"
  "io/ioutil"        // <<< added
  "log"
  "net/http"
  "os"
  "os/exec"
  "path/filepath"
  "regexp"           // <<< added
  "strings"
  "time"

  "github.com/bmatcuk/doublestar/v4"
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

var supportedExtensions = map[string]bool{
  ".go": true, ".js": true, ".py": true, ".java": true, ".html": true,
}

// ruleMap lets us look up full Rule metadata by name
var ruleMap = map[string]Rule{}

// --------------------------------------------------------------------------
// JSON‐loader for external rules.json
// --------------------------------------------------------------------------
func loadRulesFromFile(path string) ([]Rule, error) {
  data, err := ioutil.ReadFile(path)
  if err != nil {
    return nil, err
  }
  // intermediate shape matching JSON
  var jr []struct {
    Name        string `json:"name"`
    Pattern     string `json:"pattern"`
    Severity    string `json:"severity"`
    Category    string `json:"category"`
    Description string `json:"description"`
    Remediation string `json:"remediation"`
  }
  if err := json.Unmarshal(data, &jr); err != nil {
    return nil, err
  }
  out := make([]Rule, len(jr))
  for i, r := range jr {
    out[i] = Rule{
      Name:        r.Name,
      Regex:       r.Pattern,
      Pattern:     regexp.MustCompile(r.Pattern),
      Severity:    r.Severity,
      Category:    r.Category,
      Description: r.Description,
      Remediation: r.Remediation,
    }
  }
  return out, nil
}

func init() {
  // this will be overridden in main() if -rules is passed
  ruleMap = InitRules()
}

// --------------------------------------------------------------------------
// (rest of your code: runCommand, getGitChangedFiles, ignore logic, scanFile, scanDir…)
// --------------------------------------------------------------------------
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
      if !d.IsDir() &&
         supportedExtensions[filepath.Ext(path)] &&
         !shouldIgnore(path, ignorePatterns) {
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

func outputMarkdownBody(findings []Finding, verbose bool) string {
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
  if verbose {
    b.WriteString("\n---\n### 🛠 Remediation Brief\n\n")
    for _, f := range findings {
      r := ruleMap[f.RuleName]
      b.WriteString(fmt.Sprintf(
        "- **%s:%d** – %s\n    - %s\n\n",
        f.File, f.Line, r.Name, r.Remediation,
      ))
    }
  }
  // summary
  sevCount := map[string]int{}
  catCount := map[string]int{}
  for _, f := range findings {
    sevCount[f.Severity]++
    catCount[f.Category]++
  }
  b.WriteString("---\n\n**Severity Summary**\n\n")
  for _, lvl := range []string{"HIGH","MEDIUM","LOW"} {
    if c, ok := sevCount[lvl]; ok {
      b.WriteString(fmt.Sprintf("- **%s**: %d\n", lvl, c))
    }
  }
  b.WriteString("\n**OWASP Category Summary**\n\n")
  for _, cat := range []string{OWASP_A01,OWASP_A02,OWASP_A03,OWASP_A05,OWASP_A06,OWASP_A07,OWASP_A08,OWASP_A10} {
    if c, ok := catCount[cat]; ok {
      b.WriteString(fmt.Sprintf("- **%s**: %d\n", cat, c))
    }
  }
  return b.String()
}

func postGitHubComment(body string) error {
  repo := os.Getenv("GITHUB_REPOSITORY")
  pr   := os.Getenv("GITHUB_PR_NUMBER")
  tok  := os.Getenv("GITHUB_TOKEN")
  if repo == "" || pr == "" || tok == "" {
    return fmt.Errorf("GitHub environment variables not set")
  }
  url := fmt.Sprintf(
    "https://api.github.com/repos/%s/issues/%s/comments", repo, pr,
  )
  payload := map[string]string{"body": body}
  data, _ := json.Marshal(payload)
  req, _ := http.NewRequest("POST", url, bytes.NewReader(data))
  req.Header.Set("Authorization", "Bearer "+tok)
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

  dir          := flag.String("dir", ".", "Directory to scan")
  output       := flag.String("output", "text", "Output: text/json/markdown")
  debug        := flag.Bool("debug", false, "Debug mode")
  useGit       := flag.Bool("git-diff", false, "Scan changed files only")
  exitHigh     := flag.Bool("exit-high", false, "Exit 1 if any HIGH findings")
  ignoreFlag   := flag.String("ignore", "vendor,node_modules,dist,public,build",
                      "Ignore patterns")
  postToGitHub := flag.Bool("github-pr", false, "Post results to GitHub PR")
  verbose      := flag.Bool("verbose", false, "Show short remediation advice")
  ruleFile     := flag.String("rules", "",
                      "Path to external rules.json (overrides built-in)")
  flag.Parse()

  // 1) override built-in rules if json file provided
  if *ruleFile != "" {
    loaded, err := loadRulesFromFile(*ruleFile)
    if err != nil {
      log.Fatalf("failed to load rules from %s: %v", *ruleFile, err)
    }
    rules   = loaded
    ruleMap = make(map[string]Rule)
    for _, r := range rules {
      ruleMap[r.Name] = r
    }
  }

  if *debug {
    log.Println("Debug mode enabled")
  }
  ignorePatterns, err := loadIgnorePatterns(*ignoreFlag)
  if err != nil {
    log.Fatalf("Failed to load ignore patterns: %v", err)
  }

  findings, err := scanDir(
    context.Background(), *dir, *useGit, *debug, ignorePatterns,
  )
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
    // … unchanged …
  case "json":
    // … unchanged …
  case "markdown":
    body := outputMarkdownBody(findings, *verbose)
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
