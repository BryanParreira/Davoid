package engagement

import (
	"net"
	"sort"
	"strings"
	"time"
)

// TimelineEvent is a unified chronological event for the engagement timeline.
type TimelineEvent struct {
	Time     time.Time
	Kind     string // "finding" | "note"
	Title    string
	Detail   string
	Severity string
	Module   string
}

// Timeline returns all findings and notes for an engagement merged and sorted newest-first.
func Timeline(engID string) ([]TimelineEvent, error) {
	var events []TimelineEvent

	findings, _ := Findings(engID)
	for _, f := range findings {
		events = append(events, TimelineEvent{
			Time:     f.CreatedAt,
			Kind:     "finding",
			Title:    f.Title,
			Detail:   f.Module + " → " + f.Target,
			Severity: f.Severity,
			Module:   f.Module,
		})
	}

	notes, _ := Notes(engID)
	for _, n := range notes {
		events = append(events, TimelineEvent{
			Time:  n.CreatedAt,
			Kind:  "note",
			Title: n.Content,
		})
	}

	sort.Slice(events, func(i, j int) bool {
		return events[i].Time.After(events[j].Time)
	})

	return events, nil
}

// InScope reports whether target is within the engagement's scope definition.
// Returns true when scope is empty (no restriction defined).
// Scope field supports comma-separated IPs, CIDRs, and domain suffixes.
func InScope(engID, target string) bool {
	eng, err := GetByID(engID)
	if err != nil || eng == nil || strings.TrimSpace(eng.Scope) == "" {
		return true
	}
	targetIP := net.ParseIP(target)
	for _, entry := range strings.Split(eng.Scope, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.EqualFold(entry, target) {
			return true
		}
		if _, network, err := net.ParseCIDR(entry); err == nil {
			if targetIP != nil && network.Contains(targetIP) {
				return true
			}
		}
		if strings.HasSuffix(target, "."+entry) || strings.EqualFold(target, entry) {
			return true
		}
	}
	return false
}
