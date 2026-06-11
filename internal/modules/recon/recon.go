package recon

import (
	"github.com/bryanparreira/davoid/internal/modules/osint"
	"github.com/bryanparreira/davoid/internal/modules/scanner"
	"github.com/bryanparreira/davoid/internal/modules/ui"
	"github.com/bryanparreira/davoid/internal/modules/webrecon"
)

func Run() error {
	ui.Header("Recon Suite — Intelligence Gathering Center")

	mode := ui.Select("Recon Mode", []string{
		"Net-Mapper       (Nmap port scan + live CVE lookup)",
		"OSINT Engine     (URL / domain / IP / username intelligence)",
		"Web Recon        (security headers, path fuzzing, data extraction)",
		"Full Recon       (all three in sequence — comprehensive)",
	})

	switch mode {
	case 0:
		return scanner.Run()
	case 1:
		return osint.Run()
	case 2:
		return webrecon.Run()
	case 3:
		return runFull()
	}
	return nil
}

func runFull() error {
	ui.Info("Running full recon suite: Net-Mapper → OSINT → Web Recon")

	ui.Divider()
	ui.Info("[1/3] Net-Mapper")
	ui.Divider()
	if err := scanner.Run(); err != nil {
		ui.Warn("Net-Mapper error — continuing to next module.")
	}

	ui.Divider()
	ui.Info("[2/3] OSINT Engine")
	ui.Divider()
	if err := osint.Run(); err != nil {
		ui.Warn("OSINT error — continuing to next module.")
	}

	ui.Divider()
	ui.Info("[3/3] Web Recon")
	ui.Divider()
	if err := webrecon.Run(); err != nil {
		ui.Warn("Web Recon error.")
	}

	ui.Success("Full recon suite complete.")
	return nil
}
