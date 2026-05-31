// Package attack maps Davoid module keys to MITRE ATT&CK technique IDs.
package attack

// TagsForModule returns ATT&CK technique IDs for a given module key.
func TagsForModule(key string) []string {
	switch key {
	case "scanner":
		return []string{"T1046", "T1018"} // Network Service Discovery, Remote System Discovery
	case "osint":
		return []string{"T1589", "T1598", "T1596"} // Gather Victim Identity Info, Phishing for Info, Search Open Tech DBs
	case "web_recon":
		return []string{"T1590", "T1595"} // Gather Victim Network Info, Active Scanning
	case "mitm":
		return []string{"T1557"} // Adversary-in-the-Middle
	case "sniff":
		return []string{"T1040"} // Network Sniffing
	case "phishing":
		return []string{"T1566", "T1598"} // Phishing, Phishing for Information
	case "ghost_hub":
		return []string{"T1090", "T1102", "T1132"} // Proxy, Web Service, Data Encoding
	case "payloads":
		return []string{"T1059", "T1027"} // Command and Scripting Interpreter, Obfuscated Files
	case "crypt_keeper":
		return []string{"T1027", "T1140"} // Obfuscated Files, Deobfuscate/Decode
	case "msf_engine":
		return []string{"T1190", "T1210"} // Exploit Public-Facing App, Exploitation of Remote Services
	case "catcher":
		return []string{"T1059", "T1071"} // Command and Scripting Interpreter, Application Layer Protocol
	case "looter":
		return []string{"T1087", "T1083", "T1552"} // Account Discovery, File/Dir Discovery, Unsecured Credentials
	case "cred_tester":
		return []string{"T1110", "T1078"} // Brute Force, Valid Accounts
	case "bruteforce":
		return []string{"T1110.002"} // Password Cracking
	case "persistence":
		return []string{"T1053", "T1543", "T1547"} // Scheduled Task, Create/Modify System Process, Boot Autostart
	case "ad_ops":
		return []string{"T1558", "T1069", "T1087.002", "T1482"} // Steal Kerberos Tickets, Permission Groups, Domain Account, Domain Trust
	case "wifi_monitor", "wifi_scan":
		return []string{"T1602", "T1040"} // Data from Network Devices, Network Sniffing
	case "wifi_deauth":
		return []string{"T1499"} // Endpoint Denial of Service
	case "wifi_handshake":
		return []string{"T1040", "T1556"} // Network Sniffing, Modify Auth Process
	case "wifi_crack":
		return []string{"T1110.002"} // Password Cracking
	case "wifi_eviltwin":
		return []string{"T1557", "T1565"} // Adversary-in-the-Middle, Data Manipulation
	case "cloud_ops":
		return []string{"T1552.005", "T1530", "T1619"} // Cloud Instance Metadata, Cloud Storage, Cloud Storage Object Discovery
	case "god_mode":
		return []string{"T1569", "T1210"} // System Services, Exploitation of Remote Services
	default:
		return nil
	}
}

// URL returns the ATT&CK web URL for a technique ID.
func URL(id string) string {
	return "https://attack.mitre.org/techniques/" + id
}
