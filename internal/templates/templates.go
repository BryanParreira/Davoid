// Package templates provides pre-built finding templates with CVSS 3.1 metrics.
package templates

import (
	"fmt"
	"strings"

	"github.com/bryanparreira/davoid/internal/cvss"
)

// Template is a pre-built finding with suggested CVSS base metrics.
type Template struct {
	Key         string
	Name        string
	Title       string
	Severity    string
	Description string
	Remediation string
	CVSS        cvss.BaseMetrics
}

// Registry holds all built-in finding templates.
var Registry = []Template{
	{
		Key:         "default_creds",
		Name:        "Default Credentials",
		Title:       "Default credentials accepted on [TARGET]",
		Severity:    "CRITICAL",
		Description: "The target accepts factory-default or well-known vendor credentials. An unauthenticated attacker can gain full access without exploitation.",
		Remediation: "Change all default credentials immediately. Enforce a strong password policy. Audit all devices for vendor-default accounts. Enable MFA where supported.",
		CVSS:        cvss.BaseMetrics{AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "H"},
	},
	{
		Key:         "sqli",
		Name:        "SQL Injection",
		Title:       "SQL injection in [PARAMETER] on [TARGET]",
		Severity:    "CRITICAL",
		Description: "User-controlled input is passed to a SQL query without sanitization or parameterization, allowing an attacker to read, modify, or delete database contents and potentially achieve remote code execution.",
		Remediation: "Use parameterized queries or prepared statements exclusively. Apply allowlist input validation. Deploy a WAF as a compensating control. Audit all database query construction.",
		CVSS:        cvss.BaseMetrics{AV: "N", AC: "L", PR: "N", UI: "N", S: "C", C: "H", I: "H", A: "H"},
	},
	{
		Key:         "xss",
		Name:        "Cross-Site Scripting (XSS)",
		Title:       "XSS in [PARAMETER] on [TARGET]",
		Severity:    "HIGH",
		Description: "Unsanitized user input is reflected in the page HTML, allowing injection of arbitrary JavaScript executed in victim browsers. Enables session hijacking, credential theft, and defacement.",
		Remediation: "HTML-encode all output using a proven encoding library. Implement Content-Security-Policy headers. Validate and sanitize all input server-side. Use HttpOnly and Secure cookie flags.",
		CVSS:        cvss.BaseMetrics{AV: "N", AC: "L", PR: "N", UI: "R", S: "C", C: "L", I: "L", A: "N"},
	},
	{
		Key:         "weak_creds",
		Name:        "Weak Credentials",
		Title:       "Weak password accepted on [TARGET]",
		Severity:    "HIGH",
		Description: "Account credentials were successfully obtained via dictionary attack, indicating insufficient password complexity enforcement. Enables unauthorized access without exploitation.",
		Remediation: "Enforce minimum 12-character passwords with complexity requirements. Implement account lockout policies (5 attempts, 15-minute lockout). Require MFA for all privileged accounts.",
		CVSS:        cvss.BaseMetrics{AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "N"},
	},
	{
		Key:         "unauth_access",
		Name:        "Unauthenticated Access",
		Title:       "Unauthenticated access to sensitive resource on [TARGET]",
		Severity:    "CRITICAL",
		Description: "Sensitive functionality or data is accessible without authentication, exposing it to any network-reachable attacker without credentials.",
		Remediation: "Implement authentication for all sensitive endpoints. Apply the principle of least privilege. Audit access controls across all API routes and admin panels.",
		CVSS:        cvss.BaseMetrics{AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "N"},
	},
	{
		Key:         "outdated_software",
		Name:        "Outdated Software / Known CVE",
		Title:       "Outdated software with known vulnerability on [TARGET]",
		Severity:    "HIGH",
		Description: "The target runs software with publicly known vulnerabilities. Exploit code is likely publicly available, significantly lowering the attacker skill requirement.",
		Remediation: "Apply vendor patches immediately. Establish a regular patching cadence (maximum 30 days for HIGH/CRITICAL CVEs). Subscribe to CVE notification feeds for all deployed software.",
		CVSS:        cvss.BaseMetrics{AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "H"},
	},
	{
		Key:         "info_disclosure",
		Name:        "Information Disclosure",
		Title:       "Sensitive information disclosure on [TARGET]",
		Severity:    "MEDIUM",
		Description: "The application exposes sensitive data including stack traces, internal paths, version strings, or API keys that aid further attacks.",
		Remediation: "Suppress verbose error messages in production. Implement custom error pages. Audit API responses and HTTP headers for information leakage. Remove debugging endpoints.",
		CVSS:        cvss.BaseMetrics{AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "L", I: "N", A: "N"},
	},
	{
		Key:         "missing_tls",
		Name:        "Missing TLS / Cleartext Protocol",
		Title:       "Sensitive data transmitted in cleartext on [TARGET]",
		Severity:    "HIGH",
		Description: "Credentials, session tokens, or sensitive data are transmitted over unencrypted channels, allowing interception via network-level MITM attack.",
		Remediation: "Enforce TLS 1.2+ for all communications. Redirect all HTTP to HTTPS. Implement HTTP Strict Transport Security (HSTS). Disable SSL/TLS versions prior to 1.2.",
		CVSS:        cvss.BaseMetrics{AV: "A", AC: "H", PR: "N", UI: "N", S: "U", C: "H", I: "N", A: "N"},
	},
	{
		Key:         "privesc",
		Name:        "Privilege Escalation",
		Title:       "Local privilege escalation to root/SYSTEM on [TARGET]",
		Severity:    "HIGH",
		Description: "A low-privileged local user can escalate to root or SYSTEM through misconfigured SUID binaries, sudo rules, cron jobs, or writable service paths.",
		Remediation: "Audit all SUID binaries and remove unnecessary ones. Review sudo configuration (sudoers). Restrict cron job permissions. Enable audit logging (auditd/Sysmon). Apply principle of least privilege.",
		CVSS:        cvss.BaseMetrics{AV: "L", AC: "L", PR: "L", UI: "N", S: "U", C: "H", I: "H", A: "H"},
	},
	{
		Key:         "open_redirect",
		Name:        "Open Redirect",
		Title:       "Open redirect vulnerability on [TARGET]",
		Severity:    "MEDIUM",
		Description: "The application redirects users to attacker-controlled URLs without validation, enabling phishing, OAuth token theft, and bypass of referer-based security controls.",
		Remediation: "Validate redirect destinations against a strict allowlist. Reject external URLs or display an interstitial warning. Avoid passing redirect targets in URL parameters.",
		CVSS:        cvss.BaseMetrics{AV: "N", AC: "L", PR: "N", UI: "R", S: "U", C: "L", I: "N", A: "N"},
	},
}

// Get returns a template by key, or nil if not found.
func Get(key string) *Template {
	for i := range Registry {
		if Registry[i].Key == key {
			return &Registry[i]
		}
	}
	return nil
}

// Keys returns all template keys.
func Keys() []string {
	keys := make([]string, len(Registry))
	for i, t := range Registry {
		keys[i] = t.Key
	}
	return keys
}

// Render formats a template for display, substituting [TARGET] with the given target.
func Render(t *Template, target string) string {
	score := cvss.Calculate(t.CVSS)
	sev := cvss.Severity(score)
	vector := cvss.VectorString(t.CVSS)

	title := strings.ReplaceAll(t.Title, "[TARGET]", target)
	title = strings.ReplaceAll(title, "[PARAMETER]", "[parameter]")

	return fmt.Sprintf(`
  Template:    %s
  Title:       %s
  Severity:    %s
  CVSS Score:  %.1f (%s)
  Vector:      %s

  Description:
  %s

  Remediation:
  %s
`,
		t.Name, title, sev, score, sev, vector,
		wordWrap(t.Description, 70),
		wordWrap(t.Remediation, 70),
	)
}

func wordWrap(s string, width int) string {
	words := strings.Fields(s)
	var lines []string
	line := ""
	for _, w := range words {
		if len(line)+len(w)+1 > width {
			lines = append(lines, "  "+line)
			line = w
		} else {
			if line != "" {
				line += " "
			}
			line += w
		}
	}
	if line != "" {
		lines = append(lines, "  "+line)
	}
	return strings.Join(lines, "\n")
}
