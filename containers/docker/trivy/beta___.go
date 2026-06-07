// go run main.go bkimminich/juice-shop --clear-cache --severity CRITICAL,HIGH --ignore-unfixed --output=csv
// main.go
package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"sort"
	"strings"
)

var (
	defaultSeverities = []string{"CRITICAL", "HIGH", "MEDIUM"}
	headers           = []string{"Package Name", "Installed Version", "Fixed Version", "Severity", "CVE ID", "Description", "Link"}
)

// Vulnerability represents a single vulnerability entry from Trivy.
type Vulnerability struct {
	PkgName          string `json:"PkgName"`
	InstalledVersion string `json:"InstalledVersion"`
	FixedVersion     string `json:"FixedVersion"`
	Severity         string `json:"Severity"`
	VulnerabilityID  string `json:"VulnerabilityID"`
	Description      string `json:"Description"`
	PrimaryURL       string `json:"PrimaryURL"`
}

// Result represents one result entry in the Trivy report.
type Result struct {
	Vulnerabilities []Vulnerability `json:"Vulnerabilities"`
}

// TrivyReport is the top-level structure of the JSON output.
type TrivyReport struct {
	Results []Result `json:"Results"`
}

// resetTrivyCache runs "trivy clean --all" to clear the cache.
func resetTrivyCache() error {
	cmd := exec.Command("trivy", "clean", "--all")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// runTrivyScan executes the Trivy scan and writes JSON output to a file.
func runTrivyScan(imageName, severityLevels string) (string, error) {
	// Sanitize image name: replace "/" and ":" with underscores.
	sanitized := strings.ReplaceAll(imageName, "/", "_")
	sanitized = strings.ReplaceAll(sanitized, ":", "_")
	outputJSON := fmt.Sprintf("trivy_json_%s.json", sanitized)

	cmdArgs := []string{
		"image",
		"--format=json",
		"--severity", severityLevels,
		"--vuln-type", "os,library",
		"-o", outputJSON,
		imageName,
	}
	cmd := exec.Command("trivy", cmdArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("Trivy scan failed: %v", err)
	}
	return outputJSON, nil
}

// contains checks if a slice contains a given value.
func contains(slice []string, val string) bool {
	for _, s := range slice {
		if s == val {
			return true
		}
	}
	return false
}

// parseTrivyJSON reads and parses the Trivy JSON report.
// If ignoreUnfixed is true, vulnerabilities without a fixed version are skipped.
// Otherwise, vulnerabilities with no fixed version get "N/A" as fixed version.
func parseTrivyJSON(inputFile string, ignoreUnfixed bool) ([]string, [][]string, error) {
	bytes, err := ioutil.ReadFile(inputFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read JSON file: %v", err)
	}

	var report TrivyReport
	if err := json.Unmarshal(bytes, &report); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal JSON: %v", err)
	}

	var data [][]string
	for _, result := range report.Results {
		for _, vuln := range result.Vulnerabilities {
			fixed := vuln.FixedVersion
			if ignoreUnfixed {
				if fixed == "" || fixed == "N/A" {
					continue
				}
			} else {
				if fixed == "" {
					fixed = "N/A"
				}
			}
			if contains(defaultSeverities, vuln.Severity) {
				desc := vuln.Description
				if idx := strings.Index(desc, "\n"); idx != -1 {
					desc = desc[:idx]
				}
				row := []string{
					vuln.PkgName,
					vuln.InstalledVersion,
					fixed,
					vuln.Severity,
					vuln.VulnerabilityID,
					desc,
					vuln.PrimaryURL,
				}
				data = append(data, row)
			}
		}
	}

	// Sort by severity: CRITICAL < HIGH < MEDIUM.
	severityOrder := map[string]int{"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3}
	sort.Slice(data, func(i, j int) bool {
		return severityOrder[data[i][3]] < severityOrder[data[j][3]]
	})

	return headers, data, nil
}

// outputMarkdown writes data as a Markdown table.
func outputMarkdown(headers []string, data [][]string, outputFile string) error {
	f, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteString("| " + strings.Join(headers, " | ") + " |\n")
	if err != nil {
		return err
	}
	sep := make([]string, len(headers))
	for i := range headers {
		sep[i] = "---"
	}
	_, err = f.WriteString("| " + strings.Join(sep, " | ") + " |\n")
	if err != nil {
		return err
	}
	for _, row := range data {
		_, err = f.WriteString("| " + strings.Join(row, " | ") + " |\n")
		if err != nil {
			return err
		}
	}
	return nil
}

// outputCSV writes data as a CSV file.
func outputCSV(headers []string, data [][]string, outputFile string) error {
	f, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer f.Close()

	writer := csv.NewWriter(f)
	defer writer.Flush()

	if err := writer.Write(headers); err != nil {
		return err
	}
	return writer.WriteAll(data)
}

// outputJSON writes data as a JSON array of objects.
func outputJSON(headers []string, data [][]string, outputFile string) error {
	var records []map[string]string
	for _, row := range data {
		record := make(map[string]string)
		for i, h := range headers {
			record[h] = row[i]
		}
		records = append(records, record)
	}
	b, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(outputFile, b, 0644)
}

// outputTable prints a plain text table.
func outputTable(headers []string, data [][]string) {
	colWidths := make([]int, len(headers))
	for i, h := range headers {
		colWidths[i] = len(h)
	}
	for _, row := range data {
		for i, cell := range row {
			if len(cell) > colWidths[i] {
				colWidths[i] = len(cell)
			}
		}
	}

	for i, h := range headers {
		fmt.Printf("%-*s  ", colWidths[i], h)
	}
	fmt.Println()
	for _, w := range colWidths {
		fmt.Printf("%s  ", strings.Repeat("-", w))
	}
	fmt.Println()
	for _, row := range data {
		for i, cell := range row {
			fmt.Printf("%-*s  ", colWidths[i], cell)
		}
		fmt.Println()
	}
}

func main() {
	outputFormat := flag.String("output", "md", "Output format: md, csv, json, table")
	severityLevels := flag.String("severity", "CRITICAL,HIGH,MEDIUM", "Comma-separated severity levels")
	clearCache := flag.Bool("clear-cache", false, "Clear Trivy cache before scanning")
	ignoreUnfixed := flag.Bool("ignore-unfixed", false, "Ignore vulnerabilities without a fix")
	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Println("Usage: go run main.go <docker_image_name> [options]")
		flag.PrintDefaults()
		os.Exit(1)
	}

	imageName := flag.Arg(0)
	fmt.Printf("Running Trivy scan on image: %s\n", imageName)

	if *clearCache {
		fmt.Println("Clearing Trivy cache...")
		if err := resetTrivyCache(); err != nil {
			log.Fatalf("Error clearing cache: %v", err)
		}
	}

	jsonFile, err := runTrivyScan(imageName, *severityLevels)
	if err != nil {
		log.Fatalf("Error running Trivy scan: %v", err)
	}

	hdrs, data, err := parseTrivyJSON(jsonFile, *ignoreUnfixed)
	if err != nil {
		log.Fatalf("Error parsing JSON: %v", err)
	}

	// Sanitize image name for output filenames.
	sanitized := strings.ReplaceAll(imageName, "/", "_")
	sanitized = strings.ReplaceAll(sanitized, ":", "_")

	switch *outputFormat {
	case "md":
		outFile := fmt.Sprintf("trivy_vulns_%s.md", sanitized)
		if err := outputMarkdown(hdrs, data, outFile); err != nil {
			log.Fatalf("Error writing Markdown output: %v", err)
		}
		fmt.Printf("Data successfully written to %s\n", outFile)
	case "csv":
		outFile := fmt.Sprintf("trivy_vulns_%s.csv", sanitized)
		if err := outputCSV(hdrs, data, outFile); err != nil {
			log.Fatalf("Error writing CSV output: %v", err)
		}
		fmt.Printf("Data successfully written to %s\n", outFile)
	case "json":
		outFile := fmt.Sprintf("trivy_vulns_%s.json", sanitized)
		if err := outputJSON(hdrs, data, outFile); err != nil {
			log.Fatalf("Error writing JSON output: %v", err)
		}
		fmt.Printf("Data successfully written to %s\n", outFile)
	case "table":
		outputTable(hdrs, data)
	default:
		fmt.Println("Unknown output format. Please choose one of: md, csv, json, table")
	}
}
