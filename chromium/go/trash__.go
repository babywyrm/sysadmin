#!/usr/bin/env -S go run .
// chromium_crawler.go – authenticated web crawler using chromedp
// Credentials are read from environment variables only — never hardcoded.

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/chromedp"
)

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

type Config struct {
	LoginURL      string
	Username      string
	Password      string
	StartURLs     []string
	AllowedHost   string // only crawl URLs on this host
	MaxDepth      int
	AJAXDelay     time.Duration
	NavTimeout    time.Duration
	LoginTimeout  time.Duration
	OutputFile    string
	Headless      bool
}

func configFromEnv() (Config, error) {
	required := map[string]string{
		"CRAWLER_LOGIN_URL": "",
		"CRAWLER_USERNAME":  "",
		"CRAWLER_PASSWORD":  "",
	}
	for k := range required {
		v := os.Getenv(k)
		if v == "" {
			return Config{}, fmt.Errorf("required env var %q is not set", k)
		}
		required[k] = v
	}

	loginURL := required["CRAWLER_LOGIN_URL"]
	parsed, err := url.Parse(loginURL)
	if err != nil || parsed.Scheme != "https" {
		return Config{}, fmt.Errorf("CRAWLER_LOGIN_URL must be a valid https URL, got: %q", loginURL)
	}

	startURLs := []string{loginURL}
	if extra := os.Getenv("CRAWLER_START_URLS"); extra != "" {
		for _, u := range strings.Split(extra, ",") {
			u = strings.TrimSpace(u)
			if u != "" {
				startURLs = append(startURLs, u)
			}
		}
	}

	maxDepth := 3
	ajaxDelay := 2 * time.Second
	navTimeout := 30 * time.Second
	loginTimeout := 30 * time.Second
	outputFile := "crawled_links.txt"
	headless := true

	return Config{
		LoginURL:     loginURL,
		Username:     required["CRAWLER_USERNAME"],
		Password:     required["CRAWLER_PASSWORD"],
		StartURLs:    startURLs,
		AllowedHost:  parsed.Host,
		MaxDepth:     maxDepth,
		AJAXDelay:    ajaxDelay,
		NavTimeout:   navTimeout,
		LoginTimeout: loginTimeout,
		OutputFile:   outputFile,
		Headless:     headless,
	}, nil
}

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

func newLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
}

// ---------------------------------------------------------------------------
// URL validation
// ---------------------------------------------------------------------------

// normalizeURL strips fragments, trailing slashes, and query strings
// and validates the URL is on the allowed host over HTTPS.
func normalizeURL(raw, allowedHost string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid URL %q: %w", raw, err)
	}
	if u.Scheme != "https" {
		return "", fmt.Errorf("non-https URL rejected: %q", raw)
	}
	if u.Host != allowedHost {
		return "", fmt.Errorf("off-domain URL rejected: %q (allowed: %q)", raw, allowedHost)
	}
	u.Fragment = ""
	u.RawQuery = ""
	path := strings.TrimRight(u.Path, "/")
	if path == "" {
		path = "/"
	}
	u.Path = path
	return u.String(), nil
}

// ---------------------------------------------------------------------------
// Visited set (thread-safe)
// ---------------------------------------------------------------------------

type visitedSet struct {
	mu   sync.Mutex
	seen map[string]bool
}

func newVisitedSet() *visitedSet {
	return &visitedSet{seen: make(map[string]bool)}
}

func (v *visitedSet) tryAdd(u string) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.seen[u] {
		return false
	}
	v.seen[u] = true
	return true
}

func (v *visitedSet) snapshot() []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	out := make([]string, 0, len(v.seen))
	for u := range v.seen {
		out = append(out, u)
	}
	return out
}

// ---------------------------------------------------------------------------
// Browser context
// ---------------------------------------------------------------------------

func newBrowserContext(
	parent context.Context,
	headless bool,
) (context.Context, context.CancelFunc) {
	opts := append(
		chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", headless),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", false), // keep sandbox enabled
		chromedp.Flag("disable-extensions", true),
		chromedp.Flag("disable-background-networking", true),
		chromedp.Flag("disable-sync", true),
		chromedp.Flag("metrics-recording-only", true),
		chromedp.Flag("safebrowsing-disable-auto-update", true),
		chromedp.UserAgent(
			"Mozilla/5.0 (compatible; InternalCrawler/1.0)",
		),
	)
	allocCtx, allocCancel := chromedp.NewExecAllocator(parent, opts...)
	ctx, ctxCancel := chromedp.NewContext(allocCtx)
	return ctx, func() {
		ctxCancel()
		allocCancel()
	}
}

// ---------------------------------------------------------------------------
// Login
// ---------------------------------------------------------------------------

func login(ctx context.Context, cfg Config, log *slog.Logger) error {
	log.Info("starting login", "url", cfg.LoginURL)

	loginCtx, cancel := context.WithTimeout(ctx, cfg.LoginTimeout)
	defer cancel()

	err := chromedp.Run(loginCtx,
		chromedp.Navigate(cfg.LoginURL),
		chromedp.WaitVisible(`#email`, chromedp.ByID),
		chromedp.SendKeys(`#email`, cfg.Username, chromedp.ByID),
		chromedp.SendKeys(`#password`, cfg.Password, chromedp.ByID),
		chromedp.Click(`button[type="submit"]`, chromedp.NodeVisible),
		chromedp.WaitTitleContains("Dashboard"),
	)
	if err != nil {
		return fmt.Errorf("login failed: %w", err)
	}

	log.Info("login successful")
	return nil
}

// ---------------------------------------------------------------------------
// Link extraction
// ---------------------------------------------------------------------------

// extractLinks pulls all <a href> values from the current page,
// normalizes them, and returns only those on the allowed host.
func extractLinks(
	ctx context.Context,
	allowedHost string,
	log *slog.Logger,
) ([]string, error) {
	var raw []string
	err := chromedp.Run(ctx,
		chromedp.Evaluate(
			`Array.from(document.querySelectorAll('a[href]'))
			  .map(a => a.href)
			  .filter(h => h.startsWith('https://'))`,
			&raw,
		),
	)
	if err != nil {
		return nil, fmt.Errorf("link extraction JS failed: %w", err)
	}

	var links []string
	for _, r := range raw {
		norm, err := normalizeURL(r, allowedHost)
		if err != nil {
			log.Debug("skipping URL", "reason", err)
			continue
		}
		links = append(links, norm)
	}

	log.Debug("extracted links", "count", len(links))
	return links, nil
}

// ---------------------------------------------------------------------------
// Crawler
// ---------------------------------------------------------------------------

type crawler struct {
	cfg     Config
	visited *visitedSet
	log     *slog.Logger
}

func (c *crawler) crawl(
	ctx context.Context,
	urls []string,
	depth int,
) {
	if depth > c.cfg.MaxDepth {
		return
	}

	for _, u := range urls {
		norm, err := normalizeURL(u, c.cfg.AllowedHost)
		if err != nil {
			c.log.Debug("invalid URL", "url", u, "err", err)
			continue
		}

		if !c.visited.tryAdd(norm) {
			c.log.Debug("already visited", "url", norm)
			continue
		}

		c.log.Info("visiting", "url", norm, "depth", depth)

		navCtx, cancel := context.WithTimeout(ctx, c.cfg.NavTimeout)
		err = chromedp.Run(navCtx,
			chromedp.Navigate(norm),
			chromedp.Sleep(c.cfg.AJAXDelay),
		)
		cancel()

		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				c.log.Warn("navigation timeout", "url", norm)
			} else {
				c.log.Warn("navigation failed", "url", norm, "err", err)
			}
			continue
		}

		newLinks, err := extractLinks(ctx, c.cfg.AllowedHost, c.log)
		if err != nil {
			c.log.Warn("link extraction failed", "url", norm, "err", err)
			continue
		}

		c.crawl(ctx, newLinks, depth+1)
	}
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

func saveLinks(links []string, path string, log *slog.Logger) error {
	// Sanitise output path — must be a plain filename or relative path,
	// no directory traversal.
	clean := filepath.Clean(path)
	if strings.Contains(clean, "..") {
		return fmt.Errorf("output path rejected (traversal): %q", path)
	}

	f, err := os.OpenFile(
		clean,
		os.O_CREATE|os.O_WRONLY|os.O_TRUNC,
		0o600, // owner read/write only
	)
	if err != nil {
		return fmt.Errorf("could not open output file: %w", err)
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	for _, link := range links {
		if _, err := fmt.Fprintln(w, link); err != nil {
			return fmt.Errorf("write error: %w", err)
		}
	}
	if err := w.Flush(); err != nil {
		return fmt.Errorf("flush error: %w", err)
	}

	log.Info("links saved", "file", clean, "count", len(links))
	return nil
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

func main() {
	log := newLogger()

	cfg, err := configFromEnv()
	if err != nil {
		log.Error("configuration error", "err", err)
		os.Exit(1)
	}

	ctx, cancel := newBrowserContext(context.Background(), cfg.Headless)
	defer cancel()

	if err := login(ctx, cfg, log); err != nil {
		log.Error("login error", "err", err)
		os.Exit(1)
	}

	c := &crawler{
		cfg:     cfg,
		visited: newVisitedSet(),
		log:     log,
	}
	c.crawl(ctx, cfg.StartURLs, 0)

	links := c.visited.snapshot()
	if err := saveLinks(links, cfg.OutputFile, log); err != nil {
		log.Error("failed to save links", "err", err)
		os.Exit(1)
	}
}
