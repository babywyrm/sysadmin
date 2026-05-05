package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// ── Config ────────────────────────────────────────────────────────────────────

var resolvers = []string{
	"8.8.8.8:53", "1.1.1.1:53", "9.9.9.9:53",
}

var dkimSelectors = []string{
	"default", "google", "mail", "dkim", "k1", "k2",
	"s1", "s2", "selector1", "selector2", "mandrill",
	"sendgrid", "mailchimp", "amazonses",
}

const timeout = 5 * time.Second

// ── DNS ───────────────────────────────────────────────────────────────────────

func query(ctx context.Context, domain, qtype string) ([]dns.RR, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.StringToType[qtype])
	m.RecursionDesired = true

	c := &dns.Client{Timeout: timeout}
	for _, res := range resolvers {
		r, _, err := c.ExchangeContext(ctx, m, res)
		if err != nil {
			continue
		}
		if r.Rcode == dns.RcodeNameError {
			return nil, nil // NXDOMAIN — record simply doesn't exist
		}
		if r.Rcode == dns.RcodeSuccess {
			return r.Answer, nil
		}
	}
	return nil, fmt.Errorf("all resolvers failed for %s %s", domain, qtype)
}

func txts(ctx context.Context, domain string) []string {
	answers, _ := query(ctx, domain, "TXT")
	var out []string
	for _, rr := range answers {
		if t, ok := rr.(*dns.TXT); ok {
			out = append(out, strings.Join(t.Txt, ""))
		}
	}
	return out
}

// ── Checks ────────────────────────────────────────────────────────────────────

func checkMX(ctx context.Context, domain string) {
	section("MX Records",
		"hint: missing MX = domain can't receive email",
		"hint: low-preference (lower number) = higher priority",
	)
	answers, err := query(ctx, domain, "MX")
	if err != nil || len(answers) == 0 {
		bad("no MX records found — domain cannot receive mail")
		return
	}
	for _, rr := range answers {
		if mx, ok := rr.(*dns.MX); ok {
			host := strings.TrimSuffix(mx.Mx, ".")
			ips, _ := net.LookupHost(host)
			ok("MX [prio %d] %s → %s", mx.Preference, host, strings.Join(ips, ", "))
		}
	}
}

func checkSPF(ctx context.Context, domain string) {
	section("SPF",
		"hint: -all = hard fail (strict, recommended)",
		"hint: ~all = soft fail (weak, common but not enforced)",
		"hint: +all = allow all senders (dangerous!)",
		"hint: >10 DNS lookups in includes will break SPF",
	)
	records := txts(ctx, domain)
	var spf string
	var count int
	for _, r := range records {
		if strings.HasPrefix(r, "v=spf1") {
			spf = r
			count++
		}
	}
	switch {
	case count == 0:
		bad("no SPF record — domain is spoofable via email")
		return
	case count > 1:
		bad("multiple SPF records found — RFC 7208 violation, only one allowed")
		return
	}
	info("raw: %s", spf)

	// Policy
	for _, policy := range []string{"-all", "~all", "?all", "+all"} {
		if strings.Contains(spf, policy) {
			switch policy {
			case "-all":
				ok("policy: -all (hard fail)")
			case "~all":
				warn("policy: ~all (soft fail — not enforced by all receivers)")
			case "?all":
				bad("policy: ?all (neutral — no real protection)")
			case "+all":
				bad("policy: +all (permits any sender — critical misconfiguration)")
			}
			break
		}
	}

	// Count includes for lookup limit hint
	includes := strings.Count(spf, "include:")
	if includes > 8 {
		warn("%d include: mechanisms — approaching 10-lookup DNS limit", includes)
	} else {
		info("%d include: mechanism(s)", includes)
	}
}

func checkDMARC(ctx context.Context, domain string) {
	section("DMARC",
		"hint: p=reject is the gold standard",
		"hint: p=none is monitoring only — no protection",
		"hint: rua= sets where aggregate reports go (blind without it)",
		"hint: pct= less than 100 means partial enforcement",
	)
	records := txts(ctx, "_dmarc."+domain)
	var raw string
	for _, r := range records {
		if strings.HasPrefix(r, "v=DMARC1") {
			raw = r
			break
		}
	}
	if raw == "" {
		bad("no DMARC record — phishing/spoofing not mitigated")
		return
	}
	info("raw: %s", raw)

	// Parse tags into a simple map
	tags := map[string]string{}
	for _, part := range strings.Split(raw, ";") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) == 2 {
			tags[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
		}
	}

	switch tags["p"] {
	case "reject":
		ok("policy: reject (strict)")
	case "quarantine":
		warn("policy: quarantine (moderate — spoofed mail goes to spam)")
	case "none":
		bad("policy: none (monitoring only — no enforcement)")
	default:
		bad("missing or unknown policy tag")
	}

	if sp, ok2 := tags["sp"]; ok2 && sp != tags["p"] {
		warn("subdomain policy (sp=%s) differs from main policy", sp)
	}
	if pct, ok2 := tags["pct"]; ok2 && pct != "100" {
		warn("pct=%s — policy only applied to %s%% of messages", pct, pct)
	}
	if tags["rua"] == "" {
		warn("no rua= tag — aggregate reports disabled, blind to abuse")
	} else {
		ok("aggregate reports → %s", tags["rua"])
	}
}

func checkDKIM(ctx context.Context, domain string, extra []string) {
	section("DKIM",
		"hint: multiple selectors = multiple signing keys (e.g. per-provider)",
		"hint: no records found doesn't mean DKIM is absent — selector names vary",
		"hint: pass -selectors=sel1,sel2 to probe additional selectors",
	)
	selectors := append(dkimSelectors, extra...)
	type hit struct{ sel, keytype, raw string }
	hits := make(chan hit, len(selectors))

	var wg sync.WaitGroup
	sem := make(chan struct{}, 8) // concurrency limit
	for _, sel := range selectors {
		wg.Add(1)
		go func(s string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			records := txts(ctx, s+"._domainkey."+domain)
			for _, r := range records {
				if strings.Contains(r, "p=") {
					kt := "rsa" // default per RFC 6376
					for _, part := range strings.Split(r, ";") {
						if strings.HasPrefix(strings.TrimSpace(part), "k=") {
							kt = strings.TrimPrefix(strings.TrimSpace(part), "k=")
						}
					}
					hits <- hit{s, kt, r}
					return
				}
			}
		}(sel)
	}
	wg.Wait()
	close(hits)

	var found int
	for h := range hits {
		found++
		ok("selector=%-18s key-type=%s", h.sel, h.keytype)
		info("  %s", h.raw)
	}
	if found == 0 {
		warn("no DKIM records found across %d probed selectors", len(selectors))
	}
}

func checkPTR(ctx context.Context, domain string) {
	section("PTR / FCrDNS",
		"hint: missing PTR = reverse DNS not set, hurts deliverability",
		"hint: FCrDNS = forward-confirmed reverse DNS (IP → name → IP must match)",
	)
	answers, err := query(ctx, domain, "A")
	if err != nil || len(answers) == 0 {
		warn("could not resolve A records for PTR lookup")
		return
	}
	for _, rr := range answers {
		a, ok2 := rr.(*dns.A)
		if !ok2 {
			continue
		}
		ip := a.A.String()
		hosts, err := net.LookupAddr(ip)
		if err != nil || len(hosts) == 0 {
			bad("no PTR for %s — may affect deliverability", ip)
			continue
		}
		for _, h := range hosts {
			h = strings.TrimSuffix(h, ".")
			fwd, err := net.LookupHost(h)
			if err != nil {
				warn("FCrDNS failed: %s → %s but %s won't resolve", ip, h, h)
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
				ok("FCrDNS confirmed: %s ↔ %s", ip, h)
			} else {
				warn("FCrDNS mismatch: %s → %s but forward lookup doesn't return original IP", ip, h)
			}
		}
	}
}

// ── Printer helpers ───────────────────────────────────────────────────────────

func section(title string, hints ...string) {
	fmt.Printf("\n%s\n", strings.Repeat("─", 60))
	fmt.Printf("  %s\n", title)
	for _, h := range hints {
		fmt.Printf("  \033[2m%s\033[0m\n", h) // dim text
	}
	fmt.Printf("%s\n", strings.Repeat("─", 60))
}

func ok(f string, a ...any)   { fmt.Printf("  ✅  "+f+"\n", a...) }
func warn(f string, a ...any) { fmt.Printf("  ⚠️   "+f+"\n", a...) }
func bad(f string, a ...any)  { fmt.Printf("  ❌  "+f+"\n", a...) }
func info(f string, a ...any) { fmt.Printf("  ℹ️   "+f+"\n", a...) }

// ── Main ──────────────────────────────────────────────────────────────────────

func main() {
	domain := flag.String("domain", "", "target domain (required)")
	extra := flag.String("selectors", "", "extra DKIM selectors, comma-separated")
	secs := flag.Int("timeout", 30, "overall timeout in seconds")
	flag.Parse()

	if *domain == "" {
		fmt.Fprintln(os.Stderr, "usage: dns-check -domain example.com [-selectors sel1,sel2] [-timeout 30]")
		os.Exit(1)
	}

	var extraSelectors []string
	for _, s := range strings.Split(*extra, ",") {
		if s = strings.TrimSpace(s); s != "" {
			extraSelectors = append(extraSelectors, s)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*secs)*time.Second)
	defer cancel()

	fmt.Printf("\n  🔍 DNS Email Security Check: %s\n", *domain)
	fmt.Printf("  %s\n", time.Now().UTC().Format(time.RFC3339))

	var wg sync.WaitGroup
	for _, fn := range []func(){
		func() { checkMX(ctx, *domain) },
		func() { checkSPF(ctx, *domain) },
		func() { checkDMARC(ctx, *domain) },
		func() { checkPTR(ctx, *domain) },
	} {
		wg.Add(1)
		go func(f func()) { defer wg.Done(); f() }(fn)
	}
	wg.Wait()

	checkDKIM(ctx, *domain, extraSelectors)
	fmt.Println()
}
