package targets

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/bryanparreira/davoid/internal/engagement"
)

type Host struct {
	ID           string
	IP           string
	Hostname     string
	OS           string
	Ports        []string
	DiscoveredAt time.Time
}

// Save persists a discovered host. Upserts on (engagement_id, ip).
func Save(engagementID, ip, hostname, osName string, ports []string) error {
	db := engagement.DB()
	if db == nil {
		return fmt.Errorf("targets: db not initialized")
	}
	portStr := strings.Join(ports, ",")
	_, err := db.Exec(`INSERT INTO hosts (id, engagement_id, ip, hostname, os, ports, discovered_at)
		VALUES (?,?,?,?,?,?,?)
		ON CONFLICT(engagement_id, ip) DO UPDATE SET
			hostname=excluded.hostname,
			os=excluded.os,
			ports=excluded.ports,
			discovered_at=excluded.discovered_at`,
		uuid.New().String(), engagementID, ip, hostname, osName, portStr,
		time.Now().UTC().Format(time.RFC3339),
	)
	return err
}

// List returns all hosts for an engagement.
func List(engagementID string) ([]*Host, error) {
	db := engagement.DB()
	if db == nil {
		return nil, fmt.Errorf("targets: db not initialized")
	}
	rows, err := db.Query(`SELECT id, ip, hostname, os, ports, discovered_at
		FROM hosts WHERE engagement_id = ? ORDER BY ip`, engagementID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var hosts []*Host
	for rows.Next() {
		h := &Host{}
		var portStr, ts string
		if err := rows.Scan(&h.ID, &h.IP, &h.Hostname, &h.OS, &portStr, &ts); err != nil {
			continue
		}
		if portStr != "" {
			h.Ports = strings.Split(portStr, ",")
		}
		h.DiscoveredAt, _ = time.Parse(time.RFC3339, ts)
		hosts = append(hosts, h)
	}
	return hosts, nil
}

// IPs returns just the IP addresses for quick-select menus.
func IPs(engagementID string) []string {
	hosts, err := List(engagementID)
	if err != nil {
		return nil
	}
	ips := make([]string, len(hosts))
	for i, h := range hosts {
		label := h.IP
		if h.Hostname != "" {
			label = h.IP + " (" + h.Hostname + ")"
		}
		ips[i] = label
	}
	return ips
}

// ImportHost inserts a host by its original ID (upsert-ignore).
// Used by the snapshot import system.
func ImportHost(h *Host, engagementID string) error {
	db := engagement.DB()
	if db == nil {
		return fmt.Errorf("targets: db not initialized")
	}
	portStr := strings.Join(h.Ports, ",")
	_, err := db.Exec(`INSERT OR IGNORE INTO hosts
		(id, engagement_id, ip, hostname, os, ports, discovered_at)
		VALUES (?,?,?,?,?,?,?)`,
		h.ID, engagementID, h.IP, h.Hostname, h.OS, portStr,
		h.DiscoveredAt.Format(time.RFC3339),
	)
	return err
}

// Count returns how many hosts are saved for an engagement.
func Count(engagementID string) int {
	db := engagement.DB()
	if db == nil {
		return 0
	}
	var n int
	db.QueryRow(`SELECT COUNT(*) FROM hosts WHERE engagement_id = ?`, engagementID).Scan(&n)
	return n
}

// NetworkMap renders an ASCII topology of discovered hosts.
func NetworkMap(engagementID string) string {
	hosts, err := List(engagementID)
	if err != nil || len(hosts) == 0 {
		return "  No hosts discovered yet. Run Net-Mapper first.\n"
	}

	var sb strings.Builder
	sb.WriteString("\n  NETWORK MAP\n")
	sb.WriteString("  " + strings.Repeat("─", 50) + "\n\n")
	sb.WriteString("  [NETWORK]\n")

	// Group by /24 subnet
	subnets := map[string][]*Host{}
	for _, h := range hosts {
		parts := strings.Split(h.IP, ".")
		subnet := "unknown"
		if len(parts) == 4 {
			subnet = parts[0] + "." + parts[1] + "." + parts[2] + ".0/24"
		}
		subnets[subnet] = append(subnets[subnet], h)
	}

	for subnet, sHosts := range subnets {
		sb.WriteString(fmt.Sprintf("  │\n  ├── [%s]\n", subnet))
		for i, h := range sHosts {
			prefix := "  │   ├──"
			if i == len(sHosts)-1 {
				prefix = "  │   └──"
			}
			name := h.IP
			if h.Hostname != "" {
				name = h.IP + " / " + h.Hostname
			}
			sb.WriteString(fmt.Sprintf("%s %s\n", prefix, name))
			if h.OS != "" {
				sb.WriteString(fmt.Sprintf("  │       OS: %s\n", h.OS))
			}
			if len(h.Ports) > 0 && h.Ports[0] != "" {
				portDisplay := h.Ports
				if len(portDisplay) > 6 {
					portDisplay = append(portDisplay[:6], fmt.Sprintf("+%d more", len(h.Ports)-6))
				}
				sb.WriteString(fmt.Sprintf("  │       Ports: %s\n", strings.Join(portDisplay, ", ")))
			}
		}
	}
	sb.WriteString("\n")
	return sb.String()
}
