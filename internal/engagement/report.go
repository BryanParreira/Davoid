package engagement

import (
	"fmt"
	"os"
	"os/exec"
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

// GeneratePDF converts the Markdown report to PDF using pandoc if available.
// Returns the PDF path or an error if pandoc is not installed.
func GeneratePDF(engID string) (string, error) {
	if _, err := exec.LookPath("pandoc"); err != nil {
		return "", fmt.Errorf("pandoc not found — install with: brew install pandoc")
	}
	_, mdPath, err := GenerateMarkdown(engID)
	if err != nil {
		return "", err
	}
	pdfPath := strings.TrimSuffix(mdPath, ".md") + ".pdf"
	cmd := exec.Command("pandoc", mdPath, "-o", pdfPath,
		"--pdf-engine=wkhtmltopdf",
		"--metadata", "title=Davoid Red Team Report",
	)
	if err := cmd.Run(); err != nil {
		// Fallback: try without pdf-engine flag
		cmd2 := exec.Command("pandoc", mdPath, "-o", pdfPath)
		if err2 := cmd2.Run(); err2 != nil {
			return "", fmt.Errorf("pandoc failed: %v", err2)
		}
	}
	return pdfPath, nil
}

// SaveNote adds a free-form note to an engagement.
func SaveNote(engID, content string) error {
	_, err := db.Exec(`INSERT INTO notes (id, engagement_id, content, created_at) VALUES (?,?,?,?)`,
		newID(), engID, content, now())
	return err
}

// Notes returns all notes for an engagement.
func Notes(engID string) ([]struct {
	Content   string
	CreatedAt time.Time
}, error) {
	rows, err := db.Query(`SELECT content, created_at FROM notes WHERE engagement_id = ? ORDER BY created_at DESC`, engID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var notes []struct {
		Content   string
		CreatedAt time.Time
	}
	for rows.Next() {
		var n struct {
			Content   string
			CreatedAt time.Time
		}
		var ts string
		rows.Scan(&n.Content, &ts)
		n.CreatedAt, _ = time.Parse(time.RFC3339, ts)
		notes = append(notes, n)
	}
	return notes, nil
}

func newID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

func now() string {
	return time.Now().UTC().Format(time.RFC3339)
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
