package main

import (
	"context"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/miekg/dns"
)

// ── Config ────────────────────────────────────────────────────────────────────

var defaultResolvers = []string{
	"8.8.8.8:53",        // Google Primary
	"8.8.4.4:53",        // Google Secondary
	"1.1.1.1:53",        // Cloudflare Primary
	"1.0.0.1:53",        // Cloudflare Secondary
	"9.9.9.9:53",        // Quad9
	"208.67.222.222:53", // OpenDNS
}

// Common DKIM selectors to probe
var commonDKIMSelectors = []string{
	"default", "google", "mail", "email", "dkim",
	"k1", "k2", "s1", "s2", "selector1", "selector2",
	"mandrill", "sendgrid", "mailchimp", "amazonses",
}

const (
	queryTimeout = 5 * time.Second
	maxRetries   = 3
)

// ── Result types ─────────────────────────────────────────────────────────────

type Severity string

const (
	SeverityOK   Severity = "✅ OK"
	SeverityWarn Severity = "⚠️  WARN"
	SeverityFail Severity = "❌ FAIL"
	SeverityInfo Severity = "ℹ️  INFO"
)

type Finding struct {
	Category string
	Severity Severity
	Detail   string
}

type DomainReport struct {
	Domain   string
	MX       []MXRecord
	SPF      *SPFResult
	DMARC    *DMARCResult
	DKIM     []DKIMResult
	PTR      []string
	Findings []Finding
	mu       sync.Mutex
}

func (r *DomainReport) addFinding(f Finding) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Findings = append(r.Findings, f)
}

type MXRecord struct {
	Host       string
	Preference uint16
	IPs        []string
}

type SPFResult struct {
	Raw       string
	HasSPF    bool
	AllPolicy string // "+all", "-all", "~all", "?all"
	Includes  []string
	Redirects string
}

type DMARCResult struct {
	Raw      string
	HasDMARC bool
	Policy   string // none, quarantine, reject
	SubPolicy string
	PCT      string
	RUA      []string
	RUF      []string
	ADKIM    string
	ASPF     string
}

type DKIMResult struct {
	Selector string
	Raw      string
	KeyType  string
	Found    bool
}

// ── DNS Core ─────────────────────────────────────────────────────────────────

func randomResolver() string {
	return defaultResolvers[rand.Intn(len(defaultResolvers))]
}

func queryDNS(ctx context.Context, domain, recordType string) ([]dns.RR, error) {
	qtype, ok := dns.StringToType[recordType]
	if !ok {
		return nil, fmt.Errorf("unknown record type: %s", recordType)
	}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), qtype)
	m.RecursionDesired = true

	var (
		lastErr error
		r       *dns.Msg
	)

	for attempt := 0; attempt < maxRetries; attempt++ {
		resolver := randomResolver()
		c := &dns.Client{Timeout: queryTimeout, Net: "udp"}

		r, _, lastErr = c.ExchangeContext(ctx, m, resolver)
		if lastErr != nil {
			// Retry with TCP on truncation or error
			c.Net = "tcp"
			r, _, lastErr = c.ExchangeContext(ctx, m, resolver)
		}
		if lastErr == nil {
			break
		}
		time.Sleep(time.Duration(attempt+1) * 200 * time.Millisecond)
	}

	if lastErr != nil {
		return nil, fmt.Errorf("all retries failed for %s %s: %w", domain, recordType, lastErr)
	}
	if r.Rcode == dns.RcodeNameError {
		return nil, nil // NXDOMAIN — not an error, just no record
	}
	if r.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("rcode %s for %s %s", dns.RcodeToString[r.Rcode], domain, recordType)
	}

	return r.Answer, nil
}

func extractTXT(answers []dns.RR) []string {
	var out []string
	for _, rr := range answers {
		if txt, ok := rr.(*dns.TXT); ok {
			// TXT records can be split across multiple strings — join them
			out = append(out, strings.Join(txt.Txt, ""))
		}
	}
	return out
}

func extractA(answers []dns.RR) []string {
	var out []string
	for _, rr := range answers {
		if a, ok := rr.(*dns.A); ok {
			out = append(out, a.A.String())
		}
		if a, ok := rr.(*dns.AAAA); ok {
			out = append(out, a.AAAA.String())
		}
	}
	return out
}

// ── MX ───────────────────────────────────────────────────────────────────────

func checkMX(ctx context.Context, report *DomainReport) {
	answers, err := queryDNS(ctx, report.Domain, "MX")
	if err != nil {
		report.addFinding(Finding{"MX", SeverityFail, err.Error()})
		return
	}
	if len(answers) == 0 {
		report.addFinding(Finding{"MX", SeverityWarn, "No MX records found — domain cannot receive email"})
		return
	}

	for _, rr := range answers {
		mx, ok := rr.(*dns.MX)
		if !ok {
			continue
		}
		record := MXRecord{
			Host:       strings.TrimSuffix(mx.Mx, "."),
			Preference: mx.Preference,
		}
		// Resolve IPs for each MX host
		ips, err := net.LookupHost(record.Host)
		if err == nil {
			record.IPs = ips
		}
		report.MX = append(report.MX, record)
	}

	report.addFinding(Finding{"MX", SeverityOK, fmt.Sprintf("%d MX record(s) found", len(report.MX))})
}

// ── SPF ───────────────────────────────────────────────────────────────────────

func parseSPF(raw string) *SPFResult {
	result := &SPFResult{Raw: raw, HasSPF: true}
	parts := strings.Fields(raw)

	for _, p := range parts {
		lower := strings.ToLower(p)
		switch {
		case strings.HasPrefix(lower, "include:"):
			result.Includes = append(result.Includes, strings.TrimPrefix(p, "include:"))
		case strings.HasPrefix(lower, "redirect="):
			result.Redirects = strings.TrimPrefix(p, "redirect=")
		case lower == "+all" || lower == "-all" || lower == "~all" || lower == "?all":
			result.AllPolicy = lower
		}
	}
	return result
}

func checkSPF(ctx context.Context, report *DomainReport) {
	answers, err := queryDNS(ctx, report.Domain, "TXT")
	if err != nil {
		report.addFinding(Finding{"SPF", SeverityFail, err.Error()})
		return
	}

	txts := extractTXT(answers)
	var spfRecord string
	var count int
	for _, t := range txts {
		if strings.HasPrefix(t, "v=spf1") {
			spfRecord = t
			count++
		}
	}

	if count == 0 {
		report.SPF = &SPFResult{HasSPF: false}
		report.addFinding(Finding{"SPF", SeverityFail, "No SPF record found — domain is spoofable"})
		return
	}
	if count > 1 {
		report.addFinding(Finding{"SPF", SeverityFail, "Multiple SPF records found — RFC 7208 violation"})
		return
	}

	spf := parseSPF(spfRecord)
	report.SPF = spf

	switch spf.AllPolicy {
	case "-all":
		report.addFinding(Finding{"SPF", SeverityOK, "Policy: -all (hard fail — strict)"})
	case "~all":
		report.addFinding(Finding{"SPF", SeverityWarn, "Policy: ~all (soft fail — not enforced by all receivers)"})
	case "?all":
		report.addFinding(Finding{"SPF", SeverityFail, "Policy: ?all (neutral — effectively no protection)"})
	case "+all":
		report.addFinding(Finding{"SPF", SeverityFail, "Policy: +all (pass all — anyone can send as this domain)"})
	default:
		report.addFinding(Finding{"SPF", SeverityWarn, "No explicit all mechanism found"})
	}

	if len(spf.Includes) > 10 {
		report.addFinding(Finding{"SPF", SeverityWarn, fmt.Sprintf("%d includes — approaching DNS lookup limit (10)", len(spf.Includes))})
	}
}

// ── DMARC ─────────────────────────────────────────────────────────────────────

func parseDMARC(raw string) *DMARCResult {
	result := &DMARCResult{Raw: raw, HasDMARC: true}
	tags := strings.Split(raw, ";")

	for _, tag := range tags {
		tag = strings.TrimSpace(tag)
		kv := strings.SplitN(tag, "=", 2)
		if len(kv) != 2 {
			continue
		}
		k, v := strings.TrimSpace(strings.ToLower(kv[0])), strings.TrimSpace(kv[1])
		switch k {
		case "p":
			result.Policy = strings.ToLower(v)
		case "sp":
			result.SubPolicy = strings.ToLower(v)
		case "pct":
			result.PCT = v
		case "rua":
			result.RUA = strings.Split(v, ",")
		case "ruf":
			result.RUF = strings.Split(v, ",")
		case "adkim":
			result.ADKIM = v
		case "aspf":
			result.ASPF = v
		}
	}
	return result
}

func checkDMARC(ctx context.Context, report *DomainReport) {
	dmarcDomain := "_dmarc." + report.Domain
	answers, err := queryDNS(ctx, dmarcDomain, "TXT")
	if err != nil {
		report.addFinding(Finding{"DMARC", SeverityFail, err.Error()})
		return
	}

	txts := extractTXT(answers)
	var dmarcRaw string
	for _, t := range txts {
		if strings.HasPrefix(t, "v=DMARC1") {
			dmarcRaw = t
			break
		}
	}

	if dmarcRaw == "" {
		report.DMARC = &DMARCResult{HasDMARC: false}
		report.addFinding(Finding{"DMARC", SeverityFail, "No DMARC record found — phishing/spoofing not mitigated"})
		return
	}

	dmarc := parseDMARC(dmarcRaw)
	report.DMARC = dmarc

	switch dmarc.Policy {
	case "reject":
		report.addFinding(Finding{"DMARC", SeverityOK, "Policy: reject (strict — spoofed mail is rejected)"})
	case "quarantine":
		report.addFinding(Finding{"DMARC", SeverityWarn, "Policy: quarantine (moderate — spoofed mail goes to spam)"})
	case "none":
		report.addFinding(Finding{"DMARC", SeverityFail, "Policy: none (monitor only — no enforcement)"})
	default:
		report.addFinding(Finding{"DMARC", SeverityFail, fmt.Sprintf("Unknown policy: %q", dmarc.Policy)})
	}

	if dmarc.PCT != "" && dmarc.PCT != "100" {
		report.addFinding(Finding{"DMARC", SeverityWarn, fmt.Sprintf("pct=%s — policy only applied to %s%% of mail", dmarc.PCT, dmarc.PCT)})
	}
	if len(dmarc.RUA) == 0 {
		report.addFinding(Finding{"DMARC", SeverityWarn, "No rua= aggregate report URI — blind to abuse"})
	}
	if dmarc.SubPolicy != "" && dmarc.SubPolicy != dmarc.Policy {
		report.addFinding(Finding{"DMARC", SeverityWarn, fmt.Sprintf("Subdomain policy (sp=%s) differs from main policy", dmarc.SubPolicy)})
	}
}

// ── DKIM ─────────────────────────────────────────────────────────────────────

func probeDKIM(ctx context.Context, domain, selector string) DKIMResult {
	result := DKIMResult{Selector: selector}
	dkimDomain := fmt.Sprintf("%s._domainkey.%s", selector, domain)

	answers, err := queryDNS(ctx, dkimDomain, "TXT")
	if err != nil || len(answers) == 0 {
		return result
	}

	txts := extractTXT(answers)
	for _, t := range txts {
		if strings.Contains(t, "v=DKIM1") || strings.Contains(t, "k=") || strings.Contains(t, "p=") {
			result.Found = true
			result.Raw = t

			// Extract key type
			for _, part := range strings.Split(t, ";") {
				part = strings.TrimSpace(part)
				if strings.HasPrefix(strings.ToLower(part), "k=") {
					result.KeyType = strings.TrimPrefix(strings.ToLower(part), "k=")
				}
			}
			if result.KeyType == "" {
				result.KeyType = "rsa" // default per RFC 6376
			}
			break
		}
	}
	return result
}

func checkDKIM(ctx context.Context, report *DomainReport, extraSelectors []string) {
	selectors := append(commonDKIMSelectors, extraSelectors...)

	type job struct {
		selector string
	}
	jobs := make(chan job, len(selectors))
	results := make(chan DKIMResult, len(selectors))

	// Worker pool
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				results <- probeDKIM(ctx, report.Domain, j.selector)
			}
		}()
	}

	for _, s := range selectors {
		jobs <- job{s}
	}
	close(jobs)

	wg.Wait()
	close(results)

	for r := range results {
		if r.Found {
			report.DKIM = append(report.DKIM, r)
		}
	}

	if len(report.DKIM) == 0 {
		report.addFinding(Finding{"DKIM", SeverityWarn, "No DKIM records found for common selectors"})
	} else {
		for _, d := range report.DKIM {
			sev := SeverityOK
			detail := fmt.Sprintf("Selector %q found (key type: %s)", d.Selector, d.KeyType)
			if d.KeyType == "rsa" {
				detail += " — verify key length ≥ 2048 bits"
			}
			report.addFinding(Finding{"DKIM", sev, detail})
		}
	}
}

// ── PTR (Reverse DNS) ────────────────────────────────────────────────────────

func checkPTR(ctx context.Context, report *DomainReport) {
	// Resolve the domain's A records first, then reverse-lookup each IP
	answers, err := queryDNS(ctx, report.Domain, "A")
	if err != nil || len(answers) == 0 {
		return
	}

	ips := extractA(answers)
	for _, ip := range ips {
		hosts, err := net.LookupAddr(ip)
		if err != nil || len(hosts) == 0 {
			report.addFinding(Finding{"PTR", SeverityWarn, fmt.Sprintf("No PTR record for %s — may affect deliverability", ip)})
			continue
		}
		for _, h := range hosts {
			h = strings.TrimSuffix(h, ".")
			report.PTR = append(report.PTR, fmt.Sprintf("%s → %s", ip, h))
			// Check forward-confirmed reverse DNS
			fwd, err := net.LookupHost(h)
			if err != nil {
				report.addFinding(Finding{"PTR", SeverityWarn, fmt.Sprintf("FCrDNS failed for %s (PTR host %s not resolvable)", ip, h)})
				continue
			}
			confirmed := false
			for _, f := range fwd {
				if f == ip {
					confirmed = true
					break
				}
			}
			if confirmed {
				report.addFinding(Finding{"PTR", SeverityOK, fmt.Sprintf("FCrDNS confirmed: %s ↔ %s", ip, h)})
			} else {
				report.addFinding(Finding{"PTR", SeverityWarn, fmt.Sprintf("FCrDNS mismatch: %s PTR→%s but %s does not resolve back", ip, h, h)})
			}
		}
	}
}

// ── Report Rendering ──────────────────────────────────────────────────────────

func printReport(report *DomainReport, verbose bool) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	sep := strings.Repeat("─", 70)

	fmt.Printf("\n%s\n", sep)
	fmt.Printf("  DNS Email Security Report: %s\n", report.Domain)
	fmt.Printf("  Generated: %s\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Printf("%s\n\n", sep)

	// MX Records
	fmt.Println("📬 MX Records")
	if len(report.MX) == 0 {
		fmt.Println("  (none)")
	}
	for _, mx := range report.MX {
		fmt.Fprintf(w, "  [%d]\t%s\t%s\n", mx.Preference, mx.Host, strings.Join(mx.IPs, ", "))
	}
	w.Flush()

	// SPF
	fmt.Println("\n📧 SPF")
	if report.SPF != nil && report.SPF.HasSPF {
		fmt.Printf("  Raw:      %s\n", report.SPF.Raw)
		fmt.Printf("  Policy:   %s\n", report.SPF.AllPolicy)
		if len(report.SPF.Includes) > 0 {
			fmt.Printf("  Includes: %s\n", strings.Join(report.SPF.Includes, ", "))
		}
		if report.SPF.Redirects != "" {
			fmt.Printf("  Redirect: %s\n", report.SPF.Redirects)
		}
	} else {
		fmt.Println("  (not found)")
	}

	// DMARC
	fmt.Println("\n🛡️  DMARC")
	if report.DMARC != nil && report.DMARC.HasDMARC {
		fmt.Printf("  Raw:       %s\n", report.DMARC.Raw)
		fmt.Printf("  Policy:    %s\n", report.DMARC.Policy)
		if report.DMARC.SubPolicy != "" {
			fmt.Printf("  SubPolicy: %s\n", report.DMARC.SubPolicy)
		}
		if report.DMARC.PCT != "" {
			fmt.Printf("  PCT:       %s%%\n", report.DMARC.PCT)
		}
		if len(report.DMARC.RUA) > 0 {
			fmt.Printf("  RUA:       %s\n", strings.Join(report.DMARC.RUA, ", "))
		}
		if len(report.DMARC.RUF) > 0 {
			fmt.Printf("  RUF:       %s\n", strings.Join(report.DMARC.RUF, ", "))
		}
	} else {
		fmt.Println("  (not found)")
	}

	// DKIM
	fmt.Println("\n🔑 DKIM")
	if len(report.DKIM) == 0 {
		fmt.Println("  (none found for probed selectors)")
	}
	for _, d := range report.DKIM {
		fmt.Printf("  selector=%-20s key-type=%s\n", d.Selector, d.KeyType)
		if verbose {
			fmt.Printf("    %s\n", d.Raw)
		}
	}

	// PTR
	fmt.Println("\n🔄 PTR / FCrDNS")
	if len(report.PTR) == 0 {
		fmt.Println("  (none resolved)")
	}
	for _, p := range report.PTR {
		fmt.Printf("  %s\n", p)
	}

	// Findings summary
	fmt.Printf("\n%s\n", sep)
	fmt.Println("  Findings Summary")
	fmt.Printf("%s\n", sep)

	counts := map[Severity]int{}
	for _, f := range report.Findings {
		fmt.Fprintf(w, "  %s\t[%s]\t%s\n", f.Severity, f.Category, f.Detail)
		counts[f.Severity]++
	}
	w.Flush()

	fmt.Printf("\n  %s %d   %s %d   %s %d\n\n",
		SeverityOK, counts[SeverityOK],
		SeverityWarn, counts[SeverityWarn],
		SeverityFail, counts[SeverityFail],
	)
}

// ── Main ──────────────────────────────────────────────────────────────────────

func main() {
	var (
		domain          = flag.String("domain", "", "Target domain to check (required)")
		extraSelectors  = flag.String("selectors", "", "Comma-separated extra DKIM selectors to probe")
		verbose         = flag.Bool("verbose", false, "Print full DKIM record values")
		timeoutSecs     = flag.Int("timeout", 30, "Overall timeout in seconds")
	)
	flag.Parse()

	if *domain == "" {
		fmt.Fprintln(os.Stderr, "Usage: dns-email-checker -domain example.com [-selectors sel1,sel2] [-verbose]")
		os.Exit(1)
	}

	var extra []string
	if *extraSelectors != "" {
		for _, s := range strings.Split(*extraSelectors, ",") {
			if s = strings.TrimSpace(s); s != "" {
				extra = append(extra, s)
			}
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*timeoutSecs)*time.Second)
	defer cancel()

	report := &DomainReport{Domain: *domain}

	// Run all checks concurrently (except DKIM which manages its own pool)
	var wg sync.WaitGroup
	for _, fn := range []func(){
		func() { checkMX(ctx, report) },
		func() { checkSPF(ctx, report) },
		func() { checkDMARC(ctx, report) },
		func() { checkPTR(ctx, report) },
	} {
		wg.Add(1)
		go func(f func()) {
			defer wg.Done()
			f()
		}(fn)
	}
	wg.Wait()

	// DKIM runs after (manages its own goroutine pool)
	checkDKIM(ctx, report, extra)

	printReport(report, *verbose)
}
