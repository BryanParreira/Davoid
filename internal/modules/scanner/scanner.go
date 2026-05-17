package scanner

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/bryanparreira/davoid/internal/engagement"
	"github.com/bryanparreira/davoid/internal/modules/ui"
)

type nmapRun struct {
	Hosts []nmapHost `xml:"host"`
}

type nmapHost struct {
	Addresses []nmapAddr    `xml:"address"`
	Ports     nmapPorts     `xml:"ports"`
	OS        nmapOS        `xml:"os"`
	Status    nmapHostStatus `xml:"status"`
}

type nmapHostStatus struct {
	State string `xml:"state,attr"`
}

type nmapAddr struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type nmapPorts struct {
	Ports []nmapPort `xml:"port"`
}

type nmapPort struct {
	Protocol string      `xml:"protocol,attr"`
	PortID   int         `xml:"portid,attr"`
	State    nmapState   `xml:"state"`
	Service  nmapService `xml:"service"`
}

type nmapState struct {
	State string `xml:"state,attr"`
}

type nmapService struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
}

type nmapOS struct {
	Matches []nmapOSMatch `xml:"osmatch"`
}

type nmapOSMatch struct {
	Name     string `xml:"name,attr"`
	Accuracy string `xml:"accuracy,attr"`
}

type nvdResponse struct {
	Vulnerabilities []struct {
		Cve struct {
			ID          string `json:"id"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics struct {
				CvssMetricV31 []struct {
					CvssData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
			} `json:"metrics"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

func Run() error {
	ui.Header("Net-Mapper — Nmap Tactical Orchestrator")

	if _, err := exec.LookPath("nmap"); err != nil {
		ui.Fail("nmap not found. Install: brew install nmap (macOS) or apt install nmap (Linux)")
		return nil
	}

	target := ui.Prompt("Target (IP / CIDR / hostname)")
	if target == "" {
		ui.Fail("No target specified.")
		return nil
	}

	scanType := ui.Select("Scan Type", []string{
		"Quick Scan       (-sV -T4 top 1000 ports)",
		"Full Audit       (-sS -sV -sC -O all ports)",
		"Stealth SYN      (-sS -T2)",
		"UDP Scan         (-sU top 200 ports)",
		"Vuln Scripts     (-sV --script=vuln)",
	})
	if scanType < 0 {
		return nil
	}

	args := map[int][]string{
		0: {"-sV", "-T4", "--open"},
		1: {"-sS", "-sV", "-sC", "-O", "-p-", "--open"},
		2: {"-sS", "-T2", "--open"},
		3: {"-sU", "--top-ports", "200", "--open"},
		4: {"-sV", "--script=vuln", "--open"},
	}

	ui.Info(fmt.Sprintf("Scanning %s ...", target))
	fmt.Println()

	tmpFile := fmt.Sprintf("/tmp/davoid_scan_%d.xml", time.Now().Unix())
	defer os.Remove(tmpFile)

	cmdArgs := append(args[scanType], "-oX", tmpFile, target)
	cmd := exec.Command("nmap", cmdArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		ui.Fail(fmt.Sprintf("nmap error: %v", err))
		return nil
	}

	data, err := os.ReadFile(tmpFile)
	if err != nil {
		ui.Fail("Could not read scan output.")
		return nil
	}

	var run nmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		ui.Fail(fmt.Sprintf("XML parse error: %v", err))
		return nil
	}

	fmt.Println()
	ui.Divider()
	ui.Info("Scan Results + CVE Lookup")
	ui.Divider()

	eng, _ := engagement.Active()

	for _, host := range run.Hosts {
		if host.Status.State != "up" {
			continue
		}

		ip := ""
		for _, a := range host.Addresses {
			if a.AddrType == "ipv4" || a.AddrType == "ipv6" {
				ip = a.Addr
			}
		}

		fmt.Println()
		fmt.Printf("  %s  %s\n", ui.Green.Render("HOST"), ui.Bold.Render(ip))

		if len(host.OS.Matches) > 0 {
			fmt.Printf("  %s  %s\n", ui.Cyan.Render("OS  "), host.OS.Matches[0].Name)
		}

		for _, p := range host.Ports.Ports {
			if p.State.State != "open" {
				continue
			}
			svc := p.Service.Name
			if p.Service.Product != "" {
				svc = p.Service.Product
				if p.Service.Version != "" {
					svc += " " + p.Service.Version
				}
			}
			fmt.Printf("    %s/%s  %s  %s\n",
				ui.Yellow.Render(fmt.Sprintf("%d", p.PortID)),
				p.Protocol,
				ui.Green.Render("open"),
				svc,
			)

			// CVE lookup for versioned services
			if p.Service.Product != "" && p.Service.Version != "" {
				cves := lookupCVE(p.Service.Product, p.Service.Version)
				for _, c := range cves {
					fmt.Printf("      %s  %s  %s\n",
						ui.Red.Render(c.id),
						ui.Yellow.Render(fmt.Sprintf("[%.1f %s]", c.score, c.severity)),
						truncate(c.desc, 70),
					)
					if eng != nil {
						sev := "INFO"
						if c.score >= 9.0 {
							sev = "CRITICAL"
						} else if c.score >= 7.0 {
							sev = "HIGH"
						} else if c.score >= 4.0 {
							sev = "MEDIUM"
						}
						engagement.LogFinding(eng.ID, "scanner", ip,
							fmt.Sprintf("%s on port %d/%s — %s", c.id, p.PortID, p.Protocol, svc),
							c.desc, sev, c.id)
					}
				}
			}
		}
	}

	fmt.Println()
	ui.Divider()
	ui.Success("Scan complete.")
	if eng != nil {
		ui.Info("Findings logged to active engagement.")
	}
	ui.PressEnter()
	return nil
}

type cveResult struct {
	id       string
	score    float64
	severity string
	desc     string
}

func lookupCVE(product, version string) []cveResult {
	keyword := strings.ReplaceAll(product+" "+version, " ", "+")
	url := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=%s&resultsPerPage=3", keyword)

	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var nvd nvdResponse
	if err := json.Unmarshal(body, &nvd); err != nil {
		return nil
	}

	var results []cveResult
	for _, v := range nvd.Vulnerabilities {
		r := cveResult{id: v.Cve.ID}
		for _, d := range v.Cve.Descriptions {
			if d.Lang == "en" {
				r.desc = d.Value
			}
		}
		if len(v.Cve.Metrics.CvssMetricV31) > 0 {
			r.score = v.Cve.Metrics.CvssMetricV31[0].CvssData.BaseScore
			r.severity = v.Cve.Metrics.CvssMetricV31[0].CvssData.BaseSeverity
		}
		results = append(results, r)
	}
	return results
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
