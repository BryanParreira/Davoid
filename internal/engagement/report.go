package engagement

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// GenerateMarkdown produces a professional Markdown engagement report.
func GenerateMarkdown(engID string) (string, string, error) {
	eng, err := GetByID(engID)
	if err != nil || eng == nil {
		return "", "", fmt.Errorf("engagement %s not found", engID)
	}

	findings, err := Findings(engID)
	if err != nil {
		return "", "", err
	}

	stats := FindingStats(engID)

	var sb strings.Builder

	sb.WriteString("# DAVOID — Red Team Engagement Report\n\n")
	sb.WriteString(fmt.Sprintf("**Generated:** %s  \n", time.Now().Format("2006-01-02 15:04:05 UTC")))
	sb.WriteString(fmt.Sprintf("**Tool Version:** Davoid v2.0.0 (Go Edition)  \n\n"))
	sb.WriteString("---\n\n")

	sb.WriteString("## Engagement Details\n\n")
	sb.WriteString(fmt.Sprintf("| Field | Value |\n|---|---|\n"))
	sb.WriteString(fmt.Sprintf("| **Name** | %s |\n", eng.Name))
	sb.WriteString(fmt.Sprintf("| **ID** | `%s` |\n", eng.ID))
	sb.WriteString(fmt.Sprintf("| **Target** | %s |\n", valueOrNA(eng.Target)))
	sb.WriteString(fmt.Sprintf("| **Scope** | %s |\n", valueOrNA(eng.Scope)))
	sb.WriteString(fmt.Sprintf("| **Status** | %s |\n", strings.ToUpper(eng.Status)))
	sb.WriteString(fmt.Sprintf("| **Started** | %s |\n", eng.CreatedAt.Format("2006-01-02 15:04 UTC")))
	sb.WriteString(fmt.Sprintf("| **Last Updated** | %s |\n\n", eng.UpdatedAt.Format("2006-01-02 15:04 UTC")))

	sb.WriteString("---\n\n")
	sb.WriteString("## Executive Summary\n\n")

	totalFindings := len(findings)
	sb.WriteString(fmt.Sprintf(
		"A total of **%d findings** were identified during this engagement. ",
		totalFindings,
	))

	critical := stats["CRITICAL"]
	high := stats["HIGH"]
	medium := stats["MEDIUM"]

	if critical > 0 || high > 0 {
		sb.WriteString(fmt.Sprintf(
			"**Immediate remediation is recommended** for the %d Critical and %d High severity issues.\n\n",
			critical, high,
		))
	} else if medium > 0 {
		sb.WriteString(fmt.Sprintf(
			"%d Medium severity issues were found and should be addressed in the next patch cycle.\n\n",
			medium,
		))
	} else {
		sb.WriteString("No critical or high severity issues were identified.\n\n")
	}

	sb.WriteString("### Finding Summary\n\n")
	sb.WriteString("| Severity | Count |\n|---|---|\n")
	for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "INFO"} {
		if stats[sev] > 0 {
			sb.WriteString(fmt.Sprintf("| %s | %d |\n", sev, stats[sev]))
		}
	}
	sb.WriteString("\n---\n\n")

	sb.WriteString("## Findings\n\n")

	if len(findings) == 0 {
		sb.WriteString("*No findings recorded for this engagement.*\n\n")
	} else {
		for i, f := range findings {
			sb.WriteString(fmt.Sprintf("### %d. %s\n\n", i+1, f.Title))
			sb.WriteString(fmt.Sprintf("| Field | Value |\n|---|---|\n"))
			sb.WriteString(fmt.Sprintf("| **Severity** | %s |\n", f.Severity))
			sb.WriteString(fmt.Sprintf("| **Module** | %s |\n", valueOrNA(f.Module)))
			sb.WriteString(fmt.Sprintf("| **Target** | %s |\n", valueOrNA(f.Target)))
			sb.WriteString(fmt.Sprintf("| **Discovered** | %s |\n\n", f.CreatedAt.Format("2006-01-02 15:04 UTC")))
			if f.Description != "" {
				sb.WriteString("**Description**\n\n")
				sb.WriteString(f.Description + "\n\n")
			}
			if f.Evidence != "" {
				sb.WriteString("**Evidence**\n\n")
				sb.WriteString("```\n" + f.Evidence + "\n```\n\n")
			}
			if i < len(findings)-1 {
				sb.WriteString("---\n\n")
			}
		}
	}

	sb.WriteString("\n---\n\n")
	sb.WriteString("## Methodology\n\n")
	sb.WriteString("This engagement was conducted using Davoid — an open-source operator-grade red team engagement platform. ")
	sb.WriteString("All findings were collected through authorized testing activities using integrated recon, offensive, and post-exploitation modules.\n\n")
	sb.WriteString("*This report was generated automatically by Davoid v2.0.0.*\n")

	content := sb.String()

	outDir, _ := os.UserHomeDir()
	outDir = filepath.Join(outDir, ".davoid", "reports")
	os.MkdirAll(outDir, 0700)
	filename := fmt.Sprintf("davoid-report-%s-%s.md",
		sanitizeFilename(eng.Name),
		time.Now().Format("20060102-150405"),
	)
	outPath := filepath.Join(outDir, filename)
	if err := os.WriteFile(outPath, []byte(content), 0600); err != nil {
		return content, "", err
	}

	return content, outPath, nil
}

func valueOrNA(s string) string {
	if s == "" {
		return "N/A"
	}
	return s
}

func sanitizeFilename(s string) string {
	var sb strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			sb.WriteRune(r)
		} else if r == ' ' {
			sb.WriteRune('-')
		}
	}
	return sb.String()
}
