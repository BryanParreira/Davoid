package playbook

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/bryanparreira/davoid/internal/engagement"
	"github.com/bryanparreira/davoid/internal/modules/ui"
	"github.com/bryanparreira/davoid/internal/runner"
	"github.com/bryanparreira/davoid/internal/targets"
	"github.com/bryanparreira/davoid/internal/vault"
)

// Condition is a predicate that controls whether a playbook step runs.
// Supported types:
//
//	if_finding_module  — skip unless a finding with Module == Value exists
//	if_finding_severity — skip unless a finding with Severity >= Value exists
//	if_port_open       — skip unless host with port Value in Ports exists
//	if_creds_exist     — skip unless vault has at least one credential
//	if_hosts_exist     — skip unless target inventory has at least one host
type Condition struct {
	Type  string `yaml:"type"`
	Value string `yaml:"value"`
}

// Step is a single module execution within a playbook, with optional conditions.
type Step struct {
	Module     string      `yaml:"module"`
	Conditions []Condition `yaml:"conditions,omitempty"`
}

// Playbook is an ordered sequence of modules forming an attack chain.
type Playbook struct {
	Key         string
	Name        string
	Description string
	Category    string
	Modules     []string // legacy flat list (built-in playbooks)
	Steps       []Step   // rich steps with conditions (YAML playbooks)
}

// EffectiveSteps returns the playbook steps, falling back to Modules for built-in playbooks.
func (p *Playbook) EffectiveSteps() []Step {
	if len(p.Steps) > 0 {
		return p.Steps
	}
	steps := make([]Step, len(p.Modules))
	for i, m := range p.Modules {
		steps[i] = Step{Module: m}
	}
	return steps
}

// EvalConditions returns true if all conditions pass for the given engagement.
// An empty conditions list always passes.
func EvalConditions(conditions []Condition, engID string) bool {
	if len(conditions) == 0 {
		return true
	}
	for _, c := range conditions {
		if !evalCondition(c, engID) {
			return false
		}
	}
	return true
}

func evalCondition(c Condition, engID string) bool {
	switch c.Type {
	case "if_finding_module":
		findings, _ := engagement.Findings(engID)
		for _, f := range findings {
			if f.Module == c.Value {
				return true
			}
		}
		return false
	case "if_finding_severity":
		findings, _ := engagement.Findings(engID)
		order := map[string]int{"INFO": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
		want := order[strings.ToUpper(c.Value)]
		for _, f := range findings {
			if order[f.Severity] >= want {
				return true
			}
		}
		return false
	case "if_port_open":
		hosts, _ := targets.List(engID)
		for _, h := range hosts {
			for _, p := range h.Ports {
				if strings.TrimSpace(p) == c.Value {
					return true
				}
			}
		}
		return false
	case "if_creds_exist":
		creds, _ := vault.List(engID)
		return len(creds) > 0
	case "if_hosts_exist":
		hosts, _ := targets.List(engID)
		return len(hosts) > 0
	}
	return true // unknown condition type: pass
}

var Registry = []Playbook{
	{
		Key:         "external-recon",
		Name:        "External Recon",
		Description: "Full external recon — scanner → OSINT → web audit",
		Category:    "Recon",
		Modules:     []string{"scanner", "osint", "web_recon"},
	},
	{
		Key:         "phish-to-shell",
		Name:        "Phish to Shell",
		Description: "Clone login page → harvest creds → generate payload → catch shell",
		Category:    "Social Engineering",
		Modules:     []string{"phishing", "payloads"},
	},
	{
		Key:         "network-compromise",
		Name:        "Network Compromise",
		Description: "ARP poison → intercept traffic → crack hashes → spray creds",
		Category:    "Network",
		Modules:     []string{"mitm", "sniff", "credops"},
	},
	{
		Key:         "post-exploitation",
		Name:        "Post-Exploitation",
		Description: "Enumerate privesc → harvest loot → persist → spray creds across network",
		Category:    "Post-Ex",
		Modules:     []string{"looter", "persistence", "cred_tester"},
	},
	{
		Key:         "ad-attack",
		Name:        "Active Directory Attack",
		Description: "LDAP enum → AS-REP roast → Kerberoast → crack hashes → spray",
		Category:    "Active Directory",
		Modules:     []string{"ad_ops", "bruteforce", "cred_tester"},
	},
	{
		Key:         "wifi-full",
		Name:        "WiFi Full Attack",
		Description: "Enable monitor mode → scan → capture handshake → crack PSK",
		Category:    "WiFi",
		Modules:     []string{"wifi_monitor", "wifi_scan", "wifi_handshake", "wifi_crack"},
	},
	{
		Key:         "full-kill-chain",
		Name:        "Full Kill Chain",
		Description: "Recon → phishing → shell → post-ex → pivot → report",
		Category:    "Full Op",
		Modules:     []string{"scanner", "osint", "phishing", "catcher", "looter", "cred_tester", "persistence"},
	},
}

// Get returns a playbook by key, checking the built-in registry and then
// ~/.davoid/playbooks/<key>.yaml for custom YAML playbooks.
func Get(key string) *Playbook {
	for i := range Registry {
		if Registry[i].Key == key {
			return &Registry[i]
		}
	}
	return loadYAML(key)
}

// yamlPlaybook mirrors Playbook for YAML unmarshalling.
type yamlPlaybook struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	Category    string `yaml:"category"`
	Steps       []struct {
		Module     string      `yaml:"module"`
		Conditions []Condition `yaml:"conditions,omitempty"`
	} `yaml:"steps"`
}

// loadYAML tries to load a custom playbook from ~/.davoid/playbooks/<key>.yaml.
func loadYAML(key string) *Playbook {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	path := filepath.Join(home, ".davoid", "playbooks", key+".yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var yp yamlPlaybook
	if err := yaml.Unmarshal(data, &yp); err != nil {
		return nil
	}
	steps := make([]Step, 0, len(yp.Steps))
	for _, s := range yp.Steps {
		if s.Module != "" {
			steps = append(steps, Step{Module: s.Module, Conditions: s.Conditions})
		}
	}
	if len(steps) == 0 {
		return nil
	}
	cat := yp.Category
	if cat == "" {
		cat = "Custom"
	}
	pb := &Playbook{
		Key:         key,
		Name:        yp.Name,
		Description: yp.Description,
		Category:    cat,
		Steps:       steps,
	}
	// Populate Modules list for backward-compatible display.
	for _, s := range steps {
		pb.Modules = append(pb.Modules, s.Module)
	}
	return pb
}

// ListCustom returns all YAML playbooks found in ~/.davoid/playbooks/.
func ListCustom() []Playbook {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	dir := filepath.Join(home, ".davoid", "playbooks")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var customs []Playbook
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".yaml" {
			continue
		}
		key := strings.TrimSuffix(e.Name(), ".yaml")
		// skip if key matches a built-in
		if Get(key) != nil {
			pb := loadYAML(key)
			if pb != nil {
				customs = append(customs, *pb)
			}
			continue
		}
		if pb := loadYAML(key); pb != nil {
			customs = append(customs, *pb)
		}
	}
	return customs
}

// Run executes a playbook interactively, one module at a time.
// Steps with conditions are skipped when the predicate is not satisfied.
func Run(key string) error {
	pb := Get(key)
	if pb == nil {
		return fmt.Errorf("playbook not found: %s", key)
	}

	eng, _ := engagement.Active()
	engID := ""
	if eng != nil {
		engID = eng.ID
	}

	steps := pb.EffectiveSteps()

	ui.Header(fmt.Sprintf("Playbook: %s", pb.Name))
	fmt.Printf("\n  %s\n\n", pb.Description)

	width := 60
	fmt.Println("  " + strings.Repeat("─", width))
	for i, step := range steps {
		cond := ""
		if len(step.Conditions) > 0 {
			cond = "  [conditional]"
		}
		fmt.Printf("  %s %d. %s%s\n", stepIcon(i, len(steps)), i+1, moduleLabel(step.Module), cond)
	}
	fmt.Println("  " + strings.Repeat("─", width))
	fmt.Println()

	if !ui.Confirm("Start playbook?") {
		return nil
	}

	skipped := 0
	failed := 0

	for i, step := range steps {
		fmt.Println()
		fmt.Println("  " + strings.Repeat("═", width))
		ui.Info(fmt.Sprintf("Step %d/%d — %s", i+1, len(steps), moduleLabel(step.Module)))
		fmt.Println("  " + strings.Repeat("═", width))
		fmt.Println()

		if len(step.Conditions) > 0 && !EvalConditions(step.Conditions, engID) {
			ui.Warn(fmt.Sprintf("Conditions not met — skipping [%s]", step.Module))
			skipped++
			continue
		}

		if !ui.Confirm(fmt.Sprintf("Run [%s]?", step.Module)) {
			ui.Warn("Skipped.")
			skipped++
			continue
		}

		if err := runner.RunModule(step.Module); err != nil {
			ui.Fail(fmt.Sprintf("Module error: %v", err))
			failed++
			if !ui.Confirm("Continue to next step?") {
				break
			}
		}
	}

	fmt.Println()
	fmt.Println("  " + strings.Repeat("─", width))
	total := len(steps)
	ran := total - skipped - failed
	ui.Success(fmt.Sprintf("Playbook complete — %d/%d modules ran  (%d skipped  %d failed)", ran, total, skipped, failed))
	fmt.Println()

	return nil
}

func moduleLabel(key string) string {
	for _, m := range runner.Registry {
		if m.Key == key {
			return fmt.Sprintf("%-18s  %s", m.Name, runner.ShortDesc(m.Description, 45))
		}
	}
	return key
}

func stepIcon(i, total int) string {
	if i == total-1 {
		return "  \\--"
	}
	return "  +--"
}
