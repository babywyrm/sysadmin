package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/fsnotify/fsnotify"
)

// RuleConfig represents a rule definition from config
type RuleConfig struct {
	Name        string `json:"name"`
	Regex       string `json:"regex"`
	Severity    string `json:"severity"`
	Category    string `json:"category"`
	Description string `json:"description"`
	Remediation string `json:"remediation"`
	Enabled     bool   `json:"enabled"`
}

// RuleSet represents a collection of rules
type RuleSet struct {
	Version string       `json:"version"`
	Rules   []RuleConfig `json:"rules"`
}

// RuleManager handles dynamic rule loading and hot reload
type RuleManager struct {
	rules       []Rule
	ruleMap     map[string]Rule
	configPaths []string
	watcher     *fsnotify.Watcher
	hotReload   bool
}

// NewRuleManager creates a new rule manager
func NewRuleManager(configPaths []string, hotReload bool) *RuleManager {
	rm := &RuleManager{
		rules:       make([]Rule, 0),
		ruleMap:     make(map[string]Rule),
		configPaths: configPaths,
		hotReload:   hotReload,
	}

	if hotReload {
		watcher, err := fsnotify.NewWatcher()
		if err != nil {
			log.Printf("Failed to create file watcher: %v", err)
		} else {
			rm.watcher = watcher
		}
	}

	return rm
}

// LoadRules loads rules from configuration files
func (rm *RuleManager) LoadRules() error {
	rm.rules = make([]Rule, 0)
	rm.ruleMap = make(map[string]Rule)

	// Try to load from config files
	rulesLoaded := false
	for _, configPath := range rm.configPaths {
		if err := rm.loadFromPath(configPath); err != nil {
			log.Printf("Warning: Failed to load rules from %s: %v", configPath, err)
		} else {
			rulesLoaded = true
		}
	}

	// If no rules loaded from config, fall back to hardcoded rules
	if !rulesLoaded || len(rm.rules) == 0 {
		log.Println("No rules loaded from config, using built-in rules")
		rm.loadBuiltinRules()
	}

	log.Printf("Loaded %d rules", len(rm.rules))

	// Set up file watching if enabled
	if rm.hotReload && rm.watcher != nil {
		rm.setupWatcher()
	}

	return nil
}

// loadFromPath loads rules from a file or directory
func (rm *RuleManager) loadFromPath(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}

	if info.IsDir() {
		return rm.loadFromDirectory(path)
	}
	return rm.loadFromFile(path)
}

// loadFromDirectory loads all JSON files from a directory
func (rm *RuleManager) loadFromDirectory(dir string) error {
	return filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && filepath.Ext(path) == ".json" {
			return rm.loadFromFile(path)
		}
		return nil
	})
}

// loadFromFile loads rules from a single JSON file
func (rm *RuleManager) loadFromFile(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	var ruleSet RuleSet
	if err := json.Unmarshal(data, &ruleSet); err != nil {
		return fmt.Errorf("failed to parse %s: %w", filename, err)
	}

	for _, rc := range ruleSet.Rules {
		if !rc.Enabled {
			continue
		}

		pattern, err := regexp.Compile(rc.Regex)
		if err != nil {
			log.Printf("Warning: Invalid regex in rule %s: %v", rc.Name, err)
			continue
		}

		rule := Rule{
			Name:        rc.Name,
			Regex:       rc.Regex,
			Pattern:     pattern,
			Severity:    rc.Severity,
			Category:    rc.Category,
			Description: rc.Description,
			Remediation: rc.Remediation,
		}

		rm.rules = append(rm.rules, rule)
		rm.ruleMap[rule.Name] = rule
	}

	log.Printf("Loaded %d rules from %s", len(ruleSet.Rules), filename)
	return nil
}

// setupWatcher sets up file system watching for hot reload
func (rm *RuleManager) setupWatcher() {
	for _, path := range rm.configPaths {
		if err := rm.watcher.Add(path); err != nil {
			log.Printf("Warning: Failed to watch %s: %v", path, err)
		}
	}

	go func() {
		for {
			select {
			case event, ok := <-rm.watcher.Events:
				if !ok {
					return
				}
				if event.Op&fsnotify.Write == fsnotify.Write {
					log.Printf("Config file changed: %s, reloading rules...", event.Name)
					time.Sleep(100 * time.Millisecond) // Brief delay to ensure write is complete
					if err := rm.LoadRules(); err != nil {
						log.Printf("Failed to reload rules: %v", err)
					}
				}
			case err, ok := <-rm.watcher.Errors:
				if !ok {
					return
				}
				log.Printf("Watcher error: %v", err)
			}
		}
	}()
}

// GetRules returns the current rules
func (rm *RuleManager) GetRules() []Rule {
	return rm.rules
}

// GetRuleMap returns the current rule map
func (rm *RuleManager) GetRuleMap() map[string]Rule {
	return rm.ruleMap
}

// Close closes the rule manager and file watcher
func (rm *RuleManager) Close() {
	if rm.watcher != nil {
		rm.watcher.Close()
	}
}

// loadBuiltinRules loads the original hardcoded rules as fallback
func (rm *RuleManager) loadBuiltinRules() {
	// Get the original rules from rules.go
	originalRules := GetAllRules()

	for _, rule := range originalRules {
		rm.rules = append(rm.rules, rule)
		rm.ruleMap[rule.Name] = rule
	}
}
