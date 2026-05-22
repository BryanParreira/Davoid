// Package snapshot provides engagement export and import as portable encrypted archives.
package snapshot

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/bryanparreira/davoid/internal/engagement"
	"github.com/bryanparreira/davoid/internal/targets"
	"github.com/bryanparreira/davoid/internal/vault"
)

const version = "1"

// Snapshot is a portable, serializable engagement archive.
type Snapshot struct {
	Version     string                 `json:"version"`
	ExportedAt  time.Time              `json:"exported_at"`
	Engagement  engagement.Engagement  `json:"engagement"`
	Findings    []*engagement.Finding  `json:"findings"`
	Hosts       []*targets.Host        `json:"hosts"`
	Credentials []*vault.Credential    `json:"credentials"`
}

// Export writes a snapshot of the given engagement to path.
// If password is non-empty, the file is AES-256-GCM encrypted.
func Export(engID, path, password string) error {
	eng, err := engagement.GetByID(engID)
	if err != nil {
		return fmt.Errorf("lookup engagement: %w", err)
	}
	if eng == nil {
		return fmt.Errorf("engagement not found: %s", engID)
	}

	findings, _ := engagement.Findings(engID)
	hosts, _ := targets.List(engID)
	creds, _ := vault.List(engID)

	snap := Snapshot{
		Version:     version,
		ExportedAt:  time.Now().UTC(),
		Engagement:  *eng,
		Findings:    findings,
		Hosts:       hosts,
		Credentials: creds,
	}

	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return fmt.Errorf("serialize snapshot: %w", err)
	}

	if password != "" {
		data, err = encrypt(data, password)
		if err != nil {
			return fmt.Errorf("encrypt snapshot: %w", err)
		}
	}

	return os.WriteFile(path, data, 0600)
}

// Import reads a snapshot file and upserts its data into the engagement database.
// Returns the imported engagement.
func Import(path, password string) (*engagement.Engagement, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read snapshot: %w", err)
	}

	if password != "" {
		data, err = decrypt(data, password)
		if err != nil {
			return nil, fmt.Errorf("decrypt snapshot (wrong password?): %w", err)
		}
	}

	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("parse snapshot: %w", err)
	}

	if err := engagement.ImportEngagement(&snap.Engagement); err != nil {
		return nil, fmt.Errorf("import engagement: %w", err)
	}

	for _, f := range snap.Findings {
		_ = engagement.ImportFinding(f)
	}

	for _, h := range snap.Hosts {
		_ = targets.ImportHost(h, snap.Engagement.ID)
	}

	for _, c := range snap.Credentials {
		_ = vault.ImportCredential(c, snap.Engagement.ID)
	}

	eng := snap.Engagement
	return &eng, nil
}

func deriveKey(password string) []byte {
	h := sha256.Sum256([]byte(password))
	return h[:]
}

func encrypt(data []byte, password string) ([]byte, error) {
	key := deriveKey(password)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, data, nil), nil
}

func decrypt(data []byte, password string) ([]byte, error) {
	key := deriveKey(password)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("invalid ciphertext")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}
