package logger

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// DB wraps the SQLite connection and provides all database operations.
type DB struct {
	conn *sql.DB
}

// Session represents a full attacker session.
type Session struct {
	ID           int64
	IP           string
	Port         int
	Country      string
	City         string
	ASN          string
	ISP          string
	StartTime    time.Time
	EndTime      *time.Time
	ThreatScore  int
	TotalCreds   int
	TotalCmds    int
	Disconnected bool
}

// Credential represents a login attempt.
type Credential struct {
	ID        int64
	SessionID int64
	Username  string
	Password  string
	Attempt   int
	Timestamp time.Time
	Success   bool // always false — honeypot never grants real access
}

// Command represents a shell command entered by the attacker.
type Command struct {
	ID        int64
	SessionID int64
	Command   string
	Response  string
	Timestamp time.Time
}

// AttackPattern tracks repeated behaviour across sessions.
type AttackPattern struct {
	IP          string
	PatternType string // brute_force | credential_stuffing | scanner
	FirstSeen   time.Time
	LastSeen    time.Time
	Count       int
}

// Open opens (or creates) the SQLite database and runs migrations.
func Open(path string) (*DB, error) {
	conn, err := sql.Open("sqlite", path+"?_journal=WAL&_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	db := &DB{conn: conn}
	if err := db.migrate(); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return db, nil
}

// Close closes the database connection.
func (db *DB) Close() error {
	return db.conn.Close()
}

// migrate creates all tables if they don't exist.
func (db *DB) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS sessions (
		id           INTEGER PRIMARY KEY AUTOINCREMENT,
		ip           TEXT    NOT NULL,
		port         INTEGER NOT NULL,
		country      TEXT    DEFAULT '',
		city         TEXT    DEFAULT '',
		asn          TEXT    DEFAULT '',
		isp          TEXT    DEFAULT '',
		start_time   DATETIME NOT NULL,
		end_time     DATETIME,
		threat_score INTEGER DEFAULT 0,
		total_creds  INTEGER DEFAULT 0,
		total_cmds   INTEGER DEFAULT 0,
		disconnected INTEGER DEFAULT 0
	);

	CREATE TABLE IF NOT EXISTS credentials (
		id         INTEGER PRIMARY KEY AUTOINCREMENT,
		session_id INTEGER NOT NULL REFERENCES sessions(id),
		username   TEXT    NOT NULL,
		password   TEXT    NOT NULL,
		attempt    INTEGER NOT NULL,
		timestamp  DATETIME NOT NULL,
		success    INTEGER DEFAULT 0
	);

	CREATE TABLE IF NOT EXISTS commands (
		id         INTEGER PRIMARY KEY AUTOINCREMENT,
		session_id INTEGER NOT NULL REFERENCES sessions(id),
		command    TEXT    NOT NULL,
		response   TEXT    NOT NULL,
		timestamp  DATETIME NOT NULL
	);

	CREATE TABLE IF NOT EXISTS patterns (
		ip           TEXT    NOT NULL,
		pattern_type TEXT    NOT NULL,
		first_seen   DATETIME NOT NULL,
		last_seen    DATETIME NOT NULL,
		count        INTEGER  DEFAULT 1,
		PRIMARY KEY (ip, pattern_type)
	);

	CREATE INDEX IF NOT EXISTS idx_sessions_ip        ON sessions(ip);
	CREATE INDEX IF NOT EXISTS idx_sessions_start     ON sessions(start_time);
	CREATE INDEX IF NOT EXISTS idx_credentials_user   ON credentials(username);
	CREATE INDEX IF NOT EXISTS idx_credentials_pass   ON credentials(password);
	CREATE INDEX IF NOT EXISTS idx_commands_session   ON commands(session_id);
	`
	_, err := db.conn.Exec(schema)
	return err
}

// ── Session operations ────────────────────────────────────────────────────────

// CreateSession inserts a new session and returns its ID.
func (db *DB) CreateSession(ip string, port int) (int64, error) {
	res, err := db.conn.Exec(
		`INSERT INTO sessions (ip, port, start_time) VALUES (?, ?, ?)`,
		ip, port, time.Now().UTC(),
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// UpdateSessionGeo fills in GeoIP fields after lookup.
func (db *DB) UpdateSessionGeo(id int64, country, city, asn, isp string) error {
	_, err := db.conn.Exec(
		`UPDATE sessions SET country=?, city=?, asn=?, isp=? WHERE id=?`,
		country, city, asn, isp, id,
	)
	return err
}

// CloseSession marks a session as ended with final stats.
func (db *DB) CloseSession(id int64, threatScore, totalCreds, totalCmds int) error {
	_, err := db.conn.Exec(
		`UPDATE sessions SET end_time=?, threat_score=?, total_creds=?,
		 total_cmds=?, disconnected=1 WHERE id=?`,
		time.Now().UTC(), threatScore, totalCreds, totalCmds, id,
	)
	return err
}

// ── Credential operations ─────────────────────────────────────────────────────

// LogCredential records a login attempt.
func (db *DB) LogCredential(sessionID int64, username, password string, attempt int) error {
	_, err := db.conn.Exec(
		`INSERT INTO credentials (session_id, username, password, attempt, timestamp)
		 VALUES (?, ?, ?, ?, ?)`,
		sessionID, username, password, attempt, time.Now().UTC(),
	)
	return err
}

// ── Command operations ────────────────────────────────────────────────────────

// LogCommand records a shell command and the fake response given.
func (db *DB) LogCommand(sessionID int64, command, response string) error {
	_, err := db.conn.Exec(
		`INSERT INTO commands (session_id, command, response, timestamp)
		 VALUES (?, ?, ?, ?)`,
		sessionID, command, response, time.Now().UTC(),
	)
	return err
}

// ── Pattern operations ────────────────────────────────────────────────────────

// UpsertPattern updates or inserts an attack pattern for an IP.
func (db *DB) UpsertPattern(ip, patternType string) error {
	now := time.Now().UTC()
	_, err := db.conn.Exec(`
		INSERT INTO patterns (ip, pattern_type, first_seen, last_seen, count)
		VALUES (?, ?, ?, ?, 1)
		ON CONFLICT(ip, pattern_type) DO UPDATE SET
			last_seen = excluded.last_seen,
			count     = count + 1
	`, ip, patternType, now, now)
	return err
}

// ── Stats queries ─────────────────────────────────────────────────────────────

// Stats holds aggregated honeypot statistics.
type Stats struct {
	TotalSessions    int
	ActiveSessions   int
	TotalCredentials int
	TotalCommands    int
	UniqueIPs        int
	TopPasswords     []TopEntry
	TopUsernames     []TopEntry
	TopCountries     []TopEntry
	RecentSessions   []Session
}

// TopEntry is a ranked item with count.
type TopEntry struct {
	Value string
	Count int
}

// GetStats returns aggregated statistics for the dashboard.
func (db *DB) GetStats() (*Stats, error) {
	s := &Stats{}

	// Totals
	db.conn.QueryRow(`SELECT COUNT(*) FROM sessions`).Scan(&s.TotalSessions)
	db.conn.QueryRow(`SELECT COUNT(*) FROM sessions WHERE end_time IS NULL`).Scan(&s.ActiveSessions)
	db.conn.QueryRow(`SELECT COUNT(*) FROM credentials`).Scan(&s.TotalCredentials)
	db.conn.QueryRow(`SELECT COUNT(*) FROM commands`).Scan(&s.TotalCommands)
	db.conn.QueryRow(`SELECT COUNT(DISTINCT ip) FROM sessions`).Scan(&s.UniqueIPs)

	// Top passwords
	s.TopPasswords, _ = db.topEntries(`
		SELECT password, COUNT(*) as c FROM credentials
		GROUP BY password ORDER BY c DESC LIMIT 10`)

	// Top usernames
	s.TopUsernames, _ = db.topEntries(`
		SELECT username, COUNT(*) as c FROM credentials
		GROUP BY username ORDER BY c DESC LIMIT 10`)

	// Top countries
	s.TopCountries, _ = db.topEntries(`
		SELECT COALESCE(NULLIF(country,''), 'Unknown'), COUNT(*) as c
		FROM sessions GROUP BY country ORDER BY c DESC LIMIT 10`)

	// Recent sessions
	rows, err := db.conn.Query(`
		SELECT id, ip, port, country, city, asn, isp,
		       start_time, end_time, threat_score, total_creds, total_cmds, disconnected
		FROM sessions ORDER BY start_time DESC LIMIT 20`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var sess Session
			var endTime sql.NullTime
			var disconnected int
			rows.Scan(
				&sess.ID, &sess.IP, &sess.Port, &sess.Country, &sess.City,
				&sess.ASN, &sess.ISP, &sess.StartTime, &endTime,
				&sess.ThreatScore, &sess.TotalCreds, &sess.TotalCmds, &disconnected,
			)
			if endTime.Valid {
				sess.EndTime = &endTime.Time
			}
			sess.Disconnected = disconnected == 1
			s.RecentSessions = append(s.RecentSessions, sess)
		}
	}

	return s, nil
}

func (db *DB) topEntries(query string) ([]TopEntry, error) {
	rows, err := db.conn.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var entries []TopEntry
	for rows.Next() {
		var e TopEntry
		rows.Scan(&e.Value, &e.Count)
		entries = append(entries, e)
	}
	return entries, nil
}

// GetSessionCredentials returns all credentials for a session.
func (db *DB) GetSessionCredentials(sessionID int64) ([]Credential, error) {
	rows, err := db.conn.Query(
		`SELECT id, session_id, username, password, attempt, timestamp
		 FROM credentials WHERE session_id=? ORDER BY attempt`,
		sessionID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var creds []Credential
	for rows.Next() {
		var c Credential
		rows.Scan(&c.ID, &c.SessionID, &c.Username, &c.Password, &c.Attempt, &c.Timestamp)
		creds = append(creds, c)
	}
	return creds, nil
}

// GetSessionCommands returns all commands for a session.
func (db *DB) GetSessionCommands(sessionID int64) ([]Command, error) {
	rows, err := db.conn.Query(
		`SELECT id, session_id, command, response, timestamp
		 FROM commands WHERE session_id=? ORDER BY timestamp`,
		sessionID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var cmds []Command
	for rows.Next() {
		var c Command
		rows.Scan(&c.ID, &c.SessionID, &c.Command, &c.Response, &c.Timestamp)
		cmds = append(cmds, c)
	}
	return cmds, nil
}
