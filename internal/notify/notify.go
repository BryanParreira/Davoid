// Package notify sends operator alerts to Discord, Slack, or ntfy.sh webhooks.
// Configure via: davoid config set webhook.url <url>
package notify

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/bryanparreira/davoid/internal/config"
)

// Events that can trigger notifications.
const (
	EventShellConnect       = "shell_connect"
	EventCredsCaptured      = "creds_captured"
	EventFindingCritical    = "finding_critical"
	EventHandshakeCaptured  = "handshake_captured"
	EventHashCracked        = "hash_cracked"
)

// Fire sends a notification for the given event. Silent on error — never blocks ops.
func Fire(event, title, message string) {
	cfg := config.Load()
	if cfg.WebhookURL == "" {
		return
	}
	if !isEnabled(event, cfg.WebhookEvents) {
		return
	}
	go func() {
		switch {
		case strings.Contains(cfg.WebhookURL, "discord.com/api/webhooks"):
			sendDiscord(cfg.WebhookURL, title, message)
		case strings.Contains(cfg.WebhookURL, "hooks.slack.com"):
			sendSlack(cfg.WebhookURL, title, message)
		default:
			sendNtfy(cfg.WebhookURL, title, message)
		}
	}()
}

func isEnabled(event string, events []string) bool {
	if len(events) == 0 {
		return true
	}
	for _, e := range events {
		if e == event || e == "*" {
			return true
		}
	}
	return false
}

func sendDiscord(url, title, message string) {
	body := map[string]interface{}{
		"embeds": []map[string]interface{}{
			{
				"title":       "🔴 Davoid — " + title,
				"description": message,
				"color":       16711680,
				"footer":      map[string]string{"text": "Davoid Red Team Platform"},
				"timestamp":   time.Now().UTC().Format(time.RFC3339),
			},
		},
	}
	postJSON(url, body)
}

func sendSlack(url, title, message string) {
	body := map[string]interface{}{
		"text": "*Davoid — " + title + "*\n" + message,
	}
	postJSON(url, body)
}

func sendNtfy(url, title, message string) {
	req, err := http.NewRequest("POST", url, strings.NewReader(message))
	if err != nil {
		return
	}
	req.Header.Set("Title", "Davoid: "+title)
	req.Header.Set("Priority", "high")
	req.Header.Set("Tags", "red_circle")
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}

func postJSON(url string, body interface{}) {
	data, err := json.Marshal(body)
	if err != nil {
		return
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return
	}
	resp.Body.Close()
}
