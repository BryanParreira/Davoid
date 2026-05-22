package engagement

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

var dbPath string
var db *sql.DB

func init() {
	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, ".davoid")
	os.MkdirAll(dir, 0700)
	dbPath = filepath.Join(dir, "engagements.db")

	var err error
	db, err = sql.Open("sqlite", dbPath)
	if err != nil {
		panic(fmt.Sprintf("davoid: cannot open engagement database: %v", err))
	}
	migrate()
}

func migrate() {
	db.Exec(`CREATE TABLE IF NOT EXISTS engagements (
		id         TEXT PRIMARY KEY,
		name       TEXT NOT NULL,
		target     TEXT NOT NULL DEFAULT '',
		scope      TEXT NOT NULL DEFAULT '',
		status     TEXT NOT NULL DEFAULT 'active',
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL
	)`)

	db.Exec(`CREATE TABLE IF NOT EXISTS findings (
		id            TEXT PRIMARY KEY,
		engagement_id TEXT NOT NULL,
		module        TEXT NOT NULL DEFAULT '',
		target        TEXT NOT NULL DEFAULT '',
		title         TEXT NOT NULL DEFAULT '',
		description   TEXT NOT NULL DEFAULT '',
		severity      TEXT NOT NULL DEFAULT 'INFO',
		evidence      TEXT NOT NULL DEFAULT '',
		created_at    TEXT NOT NULL,
		FOREIGN KEY(engagement_id) REFERENCES engagements(id)
	)`)

	db.Exec(`CREATE TABLE IF NOT EXISTS credentials (
		id            TEXT PRIMARY KEY,
		engagement_id TEXT NOT NULL,
		source        TEXT NOT NULL DEFAULT '',
		host          TEXT NOT NULL DEFAULT '',
		username      TEXT NOT NULL DEFAULT '',
		secret        TEXT NOT NULL DEFAULT '',
		kind          TEXT NOT NULL DEFAULT 'password',
		captured_at   TEXT NOT NULL
	)`)

	db.Exec(`CREATE TABLE IF NOT EXISTS hosts (
		id            TEXT PRIMARY KEY,
		engagement_id TEXT NOT NULL,
		ip            TEXT NOT NULL,
		hostname      TEXT NOT NULL DEFAULT '',
		os            TEXT NOT NULL DEFAULT '',
		ports         TEXT NOT NULL DEFAULT '',
		discovered_at TEXT NOT NULL,
		UNIQUE(engagement_id, ip)
	)`)

	db.Exec(`CREATE TABLE IF NOT EXISTS notes (
		id            TEXT PRIMARY KEY,
		engagement_id TEXT NOT NULL,
		content       TEXT NOT NULL DEFAULT '',
		created_at    TEXT NOT NULL
	)`)
}

// Engagement represents a red team engagement.
type Engagement struct {
	ID        string
	Name      string
	Target    string
	Scope     string
	Status    string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Finding is a discovered vulnerability or notable event within an engagement.
type Finding struct {
	ID           string
	EngagementID string
	Module       string
	Target       string
	Title        string
	Description  string
	Severity     string
	Evidence     string
	CreatedAt    time.Time
}

// Create starts a new engagement and persists it.
func Create(name, target, scope string) (*Engagement, error) {
	if name == "" {
		return nil, fmt.Errorf("engagement name cannot be empty")
	}
	now := time.Now().UTC()
	eng := &Engagement{
		ID:        uuid.New().String(),
		Name:      name,
		Target:    target,
		Scope:     scope,
		Status:    "active",
		CreatedAt: now,
		UpdatedAt: now,
	}
	_, err := db.Exec(
		`INSERT INTO engagements (id, name, target, scope, status, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		eng.ID, eng.Name, eng.Target, eng.Scope, eng.Status,
		eng.CreatedAt.Format(time.RFC3339),
		eng.UpdatedAt.Format(time.RFC3339),
	)
	if err != nil {
		return nil, fmt.Errorf("create engagement: %w", err)
	}
	setActive(eng.ID)
	return eng, nil
}

// All returns all engagements, newest first.
func All() ([]*Engagement, error) {
	rows, err := db.Query(
		`SELECT id, name, target, scope, status, created_at, updated_at
		 FROM engagements ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*Engagement
	for rows.Next() {
		e := &Engagement{}
		var ca, ua string
		if err := rows.Scan(&e.ID, &e.Name, &e.Target, &e.Scope, &e.Status, &ca, &ua); err != nil {
			continue
		}
		e.CreatedAt, _ = time.Parse(time.RFC3339, ca)
		e.UpdatedAt, _ = time.Parse(time.RFC3339, ua)
		out = append(out, e)
	}
	return out, nil
}

// GetByID returns a single engagement or nil.
func GetByID(id string) (*Engagement, error) {
	row := db.QueryRow(
		`SELECT id, name, target, scope, status, created_at, updated_at
		 FROM engagements WHERE id = ?`, id,
	)
	e := &Engagement{}
	var ca, ua string
	if err := row.Scan(&e.ID, &e.Name, &e.Target, &e.Scope, &e.Status, &ca, &ua); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	e.CreatedAt, _ = time.Parse(time.RFC3339, ca)
	e.UpdatedAt, _ = time.Parse(time.RFC3339, ua)
	return e, nil
}

// Active returns the currently active engagement, or nil.
func Active() (*Engagement, error) {
	home, _ := os.UserHomeDir()
	activeFile := filepath.Join(home, ".davoid", "active_engagement")
	data, err := os.ReadFile(activeFile)
	if err != nil {
		return nil, nil
	}
	id := string(data)
	if id == "" {
		return nil, nil
	}
	return GetByID(id)
}

func setActive(id string) {
	home, _ := os.UserHomeDir()
	activeFile := filepath.Join(home, ".davoid", "active_engagement")
	os.WriteFile(activeFile, []byte(id), 0600)
}

// SetActive switches the active engagement.
func SetActive(id string) error {
	eng, err := GetByID(id)
	if err != nil {
		return err
	}
	if eng == nil {
		return fmt.Errorf("engagement %s not found", id)
	}
	setActive(id)
	return nil
}

// ClearActive deactivates the current engagement without deleting it.
func ClearActive() {
	home, _ := os.UserHomeDir()
	activeFile := filepath.Join(home, ".davoid", "active_engagement")
	os.WriteFile(activeFile, []byte(""), 0600)
}

// Close marks an engagement as closed.
func Close(id string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := db.Exec(
		`UPDATE engagements SET status='closed', updated_at=? WHERE id=?`,
		now, id,
	)
	return err
}

// LogFinding adds a finding to an engagement.
func LogFinding(engID, module, target, title, description, severity, evidence string) (*Finding, error) {
	if engID == "" {
		eng, err := Active()
		if err != nil || eng == nil {
			return nil, fmt.Errorf("no active engagement — run 'davoid new <name>' first")
		}
		engID = eng.ID
	}
	now := time.Now().UTC()
	f := &Finding{
		ID:           uuid.New().String(),
		EngagementID: engID,
		Module:       module,
		Target:       target,
		Title:        title,
		Description:  description,
		Severity:     severity,
		Evidence:     evidence,
		CreatedAt:    now,
	}
	_, err := db.Exec(
		`INSERT INTO findings
		 (id, engagement_id, module, target, title, description, severity, evidence, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		f.ID, f.EngagementID, f.Module, f.Target, f.Title,
		f.Description, f.Severity, f.Evidence,
		f.CreatedAt.Format(time.RFC3339),
	)
	if err != nil {
		return nil, fmt.Errorf("log finding: %w", err)
	}
	db.Exec(
		`UPDATE engagements SET updated_at=? WHERE id=?`,
		now.Format(time.RFC3339), engID,
	)
	return f, nil
}

// Findings returns all findings for an engagement, newest first.
func Findings(engID string) ([]*Finding, error) {
	rows, err := db.Query(
		`SELECT id, engagement_id, module, target, title, description, severity, evidence, created_at
		 FROM findings WHERE engagement_id = ? ORDER BY created_at DESC`,
		engID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*Finding
	for rows.Next() {
		f := &Finding{}
		var ca string
		if err := rows.Scan(&f.ID, &f.EngagementID, &f.Module, &f.Target,
			&f.Title, &f.Description, &f.Severity, &f.Evidence, &ca); err != nil {
			continue
		}
		f.CreatedAt, _ = time.Parse(time.RFC3339, ca)
		out = append(out, f)
	}
	return out, nil
}

// FindingStats returns severity counts for an engagement.
func FindingStats(engID string) map[string]int {
	stats := map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "INFO": 0}
	rows, err := db.Query(
		`SELECT severity, COUNT(*) FROM findings WHERE engagement_id=? GROUP BY severity`,
		engID,
	)
	if err != nil {
		return stats
	}
	defer rows.Close()
	for rows.Next() {
		var sev string
		var count int
		if err := rows.Scan(&sev, &count); err == nil {
			stats[sev] = count
		}
	}
	return stats
}

// RecentFindings returns the N most recent findings across all engagements.
func RecentFindings(limit int) ([]*Finding, error) {
	rows, err := db.Query(
		`SELECT id, engagement_id, module, target, title, description, severity, evidence, created_at
		 FROM findings ORDER BY created_at DESC LIMIT ?`,
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*Finding
	for rows.Next() {
		f := &Finding{}
		var ca string
		if err := rows.Scan(&f.ID, &f.EngagementID, &f.Module, &f.Target,
			&f.Title, &f.Description, &f.Severity, &f.Evidence, &ca); err != nil {
			continue
		}
		f.CreatedAt, _ = time.Parse(time.RFC3339, ca)
		out = append(out, f)
	}
	return out, nil
}

// ImportEngagement inserts an engagement by its original ID (upsert-ignore).
// Used by the snapshot import system.
func ImportEngagement(eng *Engagement) error {
	_, err := db.Exec(
		`INSERT OR IGNORE INTO engagements (id, name, target, scope, status, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		eng.ID, eng.Name, eng.Target, eng.Scope, eng.Status,
		eng.CreatedAt.Format(time.RFC3339),
		eng.UpdatedAt.Format(time.RFC3339),
	)
	return err
}

// ImportFinding inserts a finding by its original ID (upsert-ignore).
// Used by the snapshot import system.
func ImportFinding(f *Finding) error {
	_, err := db.Exec(
		`INSERT OR IGNORE INTO findings
		 (id, engagement_id, module, target, title, description, severity, evidence, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		f.ID, f.EngagementID, f.Module, f.Target, f.Title,
		f.Description, f.Severity, f.Evidence,
		f.CreatedAt.Format(time.RFC3339),
	)
	return err
}

// DB returns the underlying database handle for advanced use.
func DB() *sql.DB { return db }
