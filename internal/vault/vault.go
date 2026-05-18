package vault

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

var db *sql.DB

func init() {
	home, _ := os.UserHomeDir()
	dbPath := filepath.Join(home, ".davoid", "engagements.db")
	var err error
	db, err = sql.Open("sqlite", dbPath)
	if err != nil {
		return
	}
}

type Credential struct {
	ID          string
	Source      string
	Host        string
	Username    string
	Secret      string
	Kind        string // "password", "hash", "token"
	CapturedAt  time.Time
}

// Save persists a captured credential to the vault.
func Save(engagementID, source, host, username, secret, kind string) error {
	if db == nil {
		return fmt.Errorf("vault: db not initialized")
	}
	if kind == "" {
		kind = "password"
	}
	_, err := db.Exec(`INSERT OR IGNORE INTO credentials
		(id, engagement_id, source, host, username, secret, kind, captured_at)
		VALUES (?,?,?,?,?,?,?,?)`,
		uuid.New().String(), engagementID, source, host, username, secret, kind,
		time.Now().UTC().Format(time.RFC3339),
	)
	return err
}

// List returns all credentials for an engagement.
func List(engagementID string) ([]*Credential, error) {
	if db == nil {
		return nil, fmt.Errorf("vault: db not initialized")
	}
	rows, err := db.Query(`SELECT id, source, host, username, secret, kind, captured_at
		FROM credentials WHERE engagement_id = ? ORDER BY captured_at DESC`, engagementID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var creds []*Credential
	for rows.Next() {
		c := &Credential{}
		var ts string
		if err := rows.Scan(&c.ID, &c.Source, &c.Host, &c.Username, &c.Secret, &c.Kind, &ts); err != nil {
			continue
		}
		c.CapturedAt, _ = time.Parse(time.RFC3339, ts)
		creds = append(creds, c)
	}
	return creds, nil
}

// Pairs returns username/password pairs as flat slices for use in modules.
func Pairs(engagementID string) (usernames, secrets []string) {
	creds, err := List(engagementID)
	if err != nil {
		return
	}
	seen := map[string]bool{}
	for _, c := range creds {
		key := c.Username + ":" + c.Secret
		if seen[key] {
			continue
		}
		seen[key] = true
		usernames = append(usernames, c.Username)
		secrets = append(secrets, c.Secret)
	}
	return
}

// Count returns how many creds are saved for an engagement.
func Count(engagementID string) int {
	if db == nil {
		return 0
	}
	var n int
	db.QueryRow(`SELECT COUNT(*) FROM credentials WHERE engagement_id = ?`, engagementID).Scan(&n)
	return n
}
