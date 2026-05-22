package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Config holds persistent Davoid operator configuration.
type Config struct {
	WebhookURL    string   `json:"webhook_url"`
	WebhookEvents []string `json:"webhook_events"`
}

func path() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".davoid", "config.json")
}

// Load reads config from disk, returning defaults if file is missing.
func Load() *Config {
	cfg := &Config{}
	data, err := os.ReadFile(path())
	if err != nil {
		return cfg
	}
	_ = json.Unmarshal(data, cfg)
	return cfg
}

// Save writes config to disk.
func Save(cfg *Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path(), data, 0600)
}

// Set updates a single config value by dot-notation key.
func Set(key, value string) error {
	cfg := Load()
	switch key {
	case "webhook.url":
		cfg.WebhookURL = value
	case "webhook.events":
		if value == "" {
			cfg.WebhookEvents = nil
		} else {
			cfg.WebhookEvents = strings.Split(value, ",")
		}
	default:
		return fmt.Errorf("unknown config key: %s\n\nValid keys:\n  webhook.url     Webhook URL (Discord, Slack, or ntfy.sh)\n  webhook.events  Comma-separated events: shell_connect,creds_captured,finding_critical,handshake_captured,hash_cracked", key)
	}
	return Save(cfg)
}

// Get retrieves a config value by dot-notation key.
func Get(key string) (string, error) {
	cfg := Load()
	switch key {
	case "webhook.url":
		return cfg.WebhookURL, nil
	case "webhook.events":
		return strings.Join(cfg.WebhookEvents, ","), nil
	default:
		return "", fmt.Errorf("unknown config key: %s", key)
	}
}

// All returns all config key=value pairs as strings.
func All() []string {
	cfg := Load()
	return []string{
		fmt.Sprintf("webhook.url     = %s", maskURL(cfg.WebhookURL)),
		fmt.Sprintf("webhook.events  = %s", strings.Join(cfg.WebhookEvents, ",")),
	}
}

func maskURL(u string) string {
	if u == "" {
		return "(not set)"
	}
	if len(u) > 20 {
		return u[:20] + "..."
	}
	return u
}
