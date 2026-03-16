package logger

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// DB wraps the SQLite connection and provides all database operations.
type DB struct {
	conn *sql.DB
	path string
}

// Session represents a full attacker session.
type Session struct {
	ID           int64      `json:"id"`
	IP           string     `json:"ip"`
	Port         int        `json:"port"`
	Country      string     `json:"country"`
	City         string     `json:"city"`
	ASN          string     `json:"asn"`
	ISP          string     `json:"isp"`
	StartTime    time.Time  `json:"start_time"`
	EndTime      *time.Time `json:"end_time"`
	ThreatScore  int        `json:"threat_score"`
	TotalCreds   int        `json:"total_creds"`
	TotalCmds    int        `json:"total_cmds"`
	Disconnected bool       `json:"disconnected"`
	Lat          float64    `json:"lat"`
	Lon          float64    `json:"lon"`
}

// Credential represents a login attempt.
type Credential struct {
	ID        int64     `json:"id"`
	SessionID int64     `json:"session_id"`
	Username  string    `json:"username"`
	Password  string    `json:"password"`
	Attempt   int       `json:"attempt"`
	Timestamp time.Time `json:"timestamp"`
	Success   bool      `json:"success"` // always false — honeypot never grants real access
}

// Command represents a shell command entered by the attacker.
type Command struct {
	ID        int64     `json:"id"`
	SessionID int64     `json:"session_id"`
	Command   string    `json:"command"`
	Response  string    `json:"response"`
	Timestamp time.Time `json:"timestamp"`
}

// CommandIntel represents a ranked and categorized command pattern.
type CommandIntel struct {
	Command  string `json:"command"`
	Count    int    `json:"count"`
	Risk     string `json:"risk"`     // LOW | MEDIUM | HIGH
	Category string `json:"category"` // Reconnaissance | Malware | Destructive | etc
}

func (db *DB) withRetry(fn func() error) error {
	var err error
	for i := 0; i < 5; i++ {
		err = fn()
		if err == nil {
			return nil
		}
		if !isLocked(err) {
			return err
		}
		time.Sleep(time.Duration(100*(i+1)) * time.Millisecond)
	}
	return err
}

func isLocked(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "database is locked") || strings.Contains(err.Error(), "SQLITE_BUSY")
}

func Open(path string) (*DB, error) {
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	// Standard SQLite optimization for high concurrency
	// With WAL mode, we can have multiple concurrent readers
	conn.SetMaxOpenConns(10)
	conn.SetMaxIdleConns(10)
	conn.SetConnMaxLifetime(time.Hour)

	_, err = conn.Exec("PRAGMA journal_mode=WAL;")
	if err != nil {
		return nil, fmt.Errorf("set WAL mode: %w", err)
	}
	_, err = conn.Exec("PRAGMA busy_timeout=5000;")
	if err != nil {
		return nil, fmt.Errorf("set busy timeout: %w", err)
	}
	_, err = conn.Exec("PRAGMA synchronous=NORMAL;")
	if err != nil {
		return nil, fmt.Errorf("set synchronous normal: %w", err)
	}

	db := &DB{conn: conn, path: path}
	if err := db.migrate(); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return db, nil
}

func (db *DB) Path() string {
	return db.path
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
		disconnected INTEGER DEFAULT 0,
		latitude     REAL    DEFAULT 0,
		longitude    REAL    DEFAULT 0
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

	CREATE TABLE IF NOT EXISTS settings (
		key   TEXT PRIMARY KEY,
		value TEXT NOT NULL
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
	var id int64
	err := db.withRetry(func() error {
		ts := time.Now().UTC().Format("2006-01-02 15:04:05")
		res, err := db.conn.Exec(
			`INSERT INTO sessions (ip, port, start_time) VALUES (?, ?, ?)`,
			ip, port, ts,
		)
		if err != nil {
			return err
		}
		id, _ = res.LastInsertId()
		fmt.Printf("[DB DEBUG] Created Session %d for IP %s at %s\n", id, ip, ts)
		return nil
	})
	return id, err
}

// UpdateSessionGeo fills in GeoIP fields including coordinates.
func (db *DB) UpdateSessionGeo(id int64, country, city, asn, isp string, lat, lon float64) error {
	_, err := db.conn.Exec(
		`UPDATE sessions SET country=?, city=?, asn=?, isp=?, latitude=?, longitude=? WHERE id=?`,
		country, city, asn, isp, lat, lon, id,
	)
	return err
}

// CloseSession marks a session as ended with final stats.
func (db *DB) CloseSession(id int64, threatScore, totalCreds, totalCmds int) error {
	_, err := db.conn.Exec(
		`UPDATE sessions SET end_time=?, threat_score=?, total_creds=?, total_cmds=?, disconnected=? WHERE id=?`,
		time.Now().UTC().Format("2006-01-02 15:04:05"), threatScore, totalCreds, totalCmds, 1, id,
	)
	return err
}

// ── Credential operations ─────────────────────────────────────────────────────

// LogCredential records a login attempt.
func (db *DB) LogCredential(sessionID int64, username, password string, attempt int) error {
	_, err := db.conn.Exec(
		`INSERT INTO credentials (session_id, username, password, attempt, timestamp) VALUES (?, ?, ?, ?, ?)`,
		sessionID, username, password, attempt, time.Now().UTC().Format("2006-01-02 15:04:05"),
	)
	return err
}

// ── Command operations ────────────────────────────────────────────────────────

// LogCommand records a shell command and the fake response given.
func (db *DB) LogCommand(sessionID int64, command, response string) error {
	return db.withRetry(func() error {
		_, err := db.conn.Exec(
			`INSERT INTO commands (session_id, command, response, timestamp) VALUES (?, ?, ?, ?)`,
			sessionID, command, response, time.Now().UTC().Format("2006-01-02 15:04:05"),
		)
		return err
	})
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
	TotalSessions    int        `json:"total_sessions"`
	ActiveSessions   int        `json:"active_sessions"`
	TotalCredentials int        `json:"total_credentials"`
	TotalCommands    int        `json:"total_commands"`
	UniqueIPs        int        `json:"unique_ips"`
	TopPasswords     []TopEntry `json:"top_passwords"`      // Full U:P
	TopPasswordsOnly []TopEntry `json:"top_passwords_only"` // Passwords only
	TopUsernames     []TopEntry `json:"top_usernames"`
	TopCountries     []TopEntry `json:"top_countries"`
	RecentSessions   []Session  `json:"recent_sessions"`
	RangeStart       time.Time  `json:"range_start,omitempty"`
	RangeEnd         time.Time  `json:"range_end,omitempty"`
}

// TimelineData holds labels and values for a time-series chart.
type TimelineData struct {
	Labels        []string `json:"labels"`
	Counts        []int    `json:"counts"`         // Bruteforce attempts
	CommandCounts []int    `json:"command_counts"` // Commands
}

// GetTimeline returns attack counts grouped by time intervals.
func (db *DB) GetTimeline(period string) (*TimelineData, error) {
	var interval string
	var duration time.Duration
	var timeFormat string
	var queryFormat string

	switch period {
	case "24h":
		interval = "-24 hours"
		duration = time.Hour
		timeFormat = "2006-01-02 15:00"
		queryFormat = "%Y-%m-%d %H:00"
	case "3d":
		interval = "-3 days"
		duration = 24 * time.Hour
		timeFormat = "2006-01-02"
		queryFormat = "%Y-%m-%d"
	case "7d":
		interval = "-7 days"
		duration = 24 * time.Hour
		timeFormat = "2006-01-02"
		queryFormat = "%Y-%m-%d"
	case "30d":
		interval = "-30 days"
		duration = 24 * time.Hour
		timeFormat = "2006-01-02"
		queryFormat = "%Y-%m-%d"
	default:
		return nil, fmt.Errorf("invalid period: %s", period)
	}

	data := &TimelineData{
		Labels:        []string{},
		Counts:        []int{},
		CommandCounts: []int{},
	}

	err := db.withRetry(func() error {
		// 1. Query Bruteforce Attempts (Credentials)
		rows, err := db.conn.Query(`
			SELECT strftime(?, timestamp) as p, COUNT(*) 
			FROM credentials 
			WHERE timestamp > (SELECT datetime('now', ?))
			GROUP BY p`, queryFormat, interval)
		if err != nil {
			return err
		}
		defer rows.Close()

		counts := make(map[string]int)
		for rows.Next() {
			var p string
			var count int
			if err := rows.Scan(&p, &count); err == nil {
				counts[p] = count
			}
		}

		// 2. Query Commands
		cmdRows, err := db.conn.Query(`
			SELECT strftime(?, timestamp) as p, COUNT(*) 
			FROM commands 
			WHERE timestamp > (SELECT datetime('now', ?))
			GROUP BY p`, queryFormat, interval)
		if err != nil {
			return err
		}
		defer cmdRows.Close()
		
		cmdCounts := make(map[string]int)
		for cmdRows.Next() {
			var p string
			var count int
			if err := cmdRows.Scan(&p, &count); err == nil {
				cmdCounts[p] = count
			}
		}

		// 3. Fill gaps and generate labels
		now := time.Now().UTC()
		start := now.Add(parseInterval(interval)).Truncate(duration)
		
		// Reset data for the retry
		data.Labels = []string{}
		data.Counts = []int{}
		data.CommandCounts = []int{}

		for t := start; t.Before(now) || t.Equal(now); t = t.Add(duration) {
			label := t.Format(timeFormat)
			data.Labels = append(data.Labels, label)
			data.Counts = append(data.Counts, counts[label])
			data.CommandCounts = append(data.CommandCounts, cmdCounts[label])
		}
		return nil
	})

	return data, err
}

func parseInterval(s string) time.Duration {
	switch s {
	case "-24 hours": return -24 * time.Hour
	case "-3 days":   return -3 * 24 * time.Hour
	case "-7 days":   return -7 * 24 * time.Hour
	case "-30 days":  return -30 * 24 * time.Hour
	}
	return 0
}

// TopEntry is a ranked item with count.
type TopEntry struct {
	Value string `json:"value"`
	Count int    `json:"count"`
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

	// Top credentials (U:P)
	s.TopPasswords, _ = db.topEntries(`
		SELECT username || ':' || password, COUNT(*) as c FROM credentials
		GROUP BY username, password ORDER BY c DESC LIMIT 50`)

	// Top Passwords (Passwords only)
	s.TopPasswordsOnly, _ = db.topEntries(`
		SELECT password, COUNT(*) as c FROM credentials
		GROUP BY password ORDER BY c DESC LIMIT 50`)

	// Top usernames
	s.TopUsernames, _ = db.topEntries(`
		SELECT username, COUNT(*) as c FROM credentials
		GROUP BY username ORDER BY c DESC LIMIT 50`)

	// Top countries
	s.TopCountries, _ = db.topEntries(`
		SELECT COALESCE(NULLIF(country,''), 'Unknown'), COUNT(*) as c
		FROM sessions GROUP BY country ORDER BY c DESC LIMIT 50`)

	// Recent sessions
	rows, err := db.conn.Query(`
		SELECT id, ip, port, country, city, asn, isp,
		       start_time, end_time, threat_score, total_creds, total_cmds, disconnected,
		       latitude, longitude
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
				&sess.Lat, &sess.Lon,
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

func (db *DB) topEntries(query string, args ...interface{}) ([]TopEntry, error) {
	rows, err := db.conn.Query(query, args...)
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

// GetStatsRange returns stats for a specific time window.
func (db *DB) GetStatsRange(start, end time.Time) (*Stats, error) {
	s := &Stats{}
	s.RangeStart = start
	s.RangeEnd = end

	// USE STANDARDIZED ISO STRINGS FOR RELIABLE SQLITE COMPARISON
	startStr := start.Format("2006-01-02 15:04:05")
	endStr := end.Format("2006-01-02 15:04:05")

	// Totals
	db.conn.QueryRow(`SELECT COUNT(*) FROM sessions WHERE start_time >= ? AND start_time <= ?`, startStr, endStr).Scan(&s.TotalSessions)
	db.conn.QueryRow(`SELECT COUNT(*) FROM credentials WHERE timestamp >= ? AND timestamp <= ?`, startStr, endStr).Scan(&s.TotalCredentials)
	db.conn.QueryRow(`SELECT COUNT(*) FROM commands WHERE timestamp >= ? AND timestamp <= ?`, startStr, endStr).Scan(&s.TotalCommands)
	db.conn.QueryRow(`SELECT COUNT(DISTINCT ip) FROM sessions WHERE start_time >= ? AND start_time <= ?`, startStr, endStr).Scan(&s.UniqueIPs)

	// Top Passwords
	s.TopPasswordsOnly, _ = db.topEntries(`
		SELECT password, COUNT(*) as c FROM credentials
		WHERE timestamp >= ? AND timestamp <= ?
		GROUP BY password ORDER BY c DESC LIMIT 20`, startStr, endStr)

	// Top usernames
	s.TopUsernames, _ = db.topEntries(`
		SELECT username, COUNT(*) as c FROM credentials
		WHERE timestamp >= ? AND timestamp <= ?
		GROUP BY username ORDER BY c DESC LIMIT 20`, startStr, endStr)

	// Top countries
	s.TopCountries, _ = db.topEntries(`
		SELECT COALESCE(NULLIF(country,''), 'Unknown'), COUNT(*) as c
		FROM sessions WHERE start_time >= ? AND start_time <= ?
		GROUP BY country ORDER BY c DESC LIMIT 10`, startStr, endStr)

	return s, nil
}

// GetDetailedReportData returns all sessions and their details for a range.
func (db *DB) GetDetailedReportData(start, end time.Time) ([]Session, error) {
	startStr := start.Format("2006-01-02 15:04:05")
	endStr := end.Format("2006-01-02 15:04:05")

	rows, err := db.conn.Query(`
		SELECT id, ip, port, country, city, asn, isp,
		       start_time, end_time, threat_score, total_creds, total_cmds, disconnected,
		       latitude, longitude
		FROM sessions 
		WHERE start_time >= ? AND start_time <= ? 
		ORDER BY start_time ASC`, startStr, endStr)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var results []Session
	for rows.Next() {
		var sess Session
		var endTime sql.NullTime
		var disconnected int
		rows.Scan(
			&sess.ID, &sess.IP, &sess.Port, &sess.Country, &sess.City,
			&sess.ASN, &sess.ISP, &sess.StartTime, &endTime,
			&sess.ThreatScore, &sess.TotalCreds, &sess.TotalCmds, &disconnected,
			&sess.Lat, &sess.Lon,
		)
		if endTime.Valid {
			sess.EndTime = &endTime.Time
		}
		sess.Disconnected = disconnected == 1
		results = append(results, sess)
	}
	return results, nil
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
// GetCommandIntelligence aggregates and classifies attacker commands.
func (db *DB) GetCommandIntelligence() ([]CommandIntel, error) {
	rows, err := db.conn.Query(`
		SELECT command, COUNT(*) as c 
		FROM commands 
		GROUP BY command 
		ORDER BY c DESC 
		LIMIT 100`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var intel []CommandIntel
	for rows.Next() {
		var c string
		var count int
		if err := rows.Scan(&c, &count); err == nil {
			risk, cat := classifyCommand(c)
			intel = append(intel, CommandIntel{
				Command:  c,
				Count:    count,
				Risk:     risk,
				Category: cat,
			})
		}
	}
	return intel, nil
}

func classifyCommand(cmd string) (string, string) {
	low := strings.ToLower(cmd)
	if strings.Contains(low, "rm -rf") || strings.Contains(low, "mkfs") || strings.Contains(low, "dd if=/dev/zero") {
		return "HIGH", "Destructive Action"
	}
	if strings.Contains(low, "wget") || strings.Contains(low, "curl") || strings.Contains(low, "python -c") {
		return "HIGH", "Malware Dropper"
	}
	if strings.Contains(low, "/etc/shadow") || strings.Contains(low, "/etc/passwd") || strings.Contains(low, ".ssh/") {
		return "HIGH", "Credential Harvest"
	}
	if strings.Contains(low, "uname -a") || strings.Contains(low, "whoami") || strings.Contains(low, "ls -la") || strings.Contains(low, "df -h") {
		return "MEDIUM", "Reconnaissance"
	}
	if strings.Contains(low, "ps aux") || strings.Contains(low, "netstat") || strings.Contains(low, "ip addr") {
		return "MEDIUM", "Network Enumeration"
	}
	return "LOW", "Unknown / Generic"
}
func (db *DB) Vacuum() error {
	_, err := db.conn.Exec("VACUUM")
	return err
}

func (db *DB) ClearAll() error {
	queries := []string{
		"DELETE FROM sessions",
		"DELETE FROM credentials",
		"DELETE FROM commands",
		"DELETE FROM patterns",
	}
	return db.withRetry(func() error {
		for _, q := range queries {
			if _, err := db.conn.Exec(q); err != nil {
				return err
			}
		}
		return nil
	})
}

func (db *DB) GetDBStats() (int64, int, error) {
	var rows int
	err := db.conn.QueryRow("SELECT (SELECT COUNT(*) FROM sessions) + (SELECT COUNT(*) FROM credentials) + (SELECT COUNT(*) FROM commands)").Scan(&rows)
	if err != nil {
		return 0, 0, err
	}
	
	// Get file size
	// Note: We need the path. Let's assume we can get it from the connection if needed, 
	// but it's easier if we just use os.Stat on the path provided in Open. 
	// For now, return 0 for size, handle in server.go or add path to DB struct.
	return 0, rows, nil
}

type SysSettings struct {
	AlertOnLogin    bool   `json:"alert_on_login"`
	AlertOnHighRisk bool   `json:"alert_on_high_risk"`
	RiskThreshold   int    `json:"risk_threshold"`
	DiscordWebhook  string `json:"discord_webhook"`
	EmailAlias      string `json:"email_alias"`
	AdminUser       string `json:"admin_user"`
	AdminPass       string `json:"admin_pass"`
	TelegramToken   string `json:"telegram_token"`
	TelegramChatID  string `json:"telegram_chat_id"`
}

func (db *DB) GetSettings() (SysSettings, error) {
	s := SysSettings{
		RiskThreshold: 75,
		AdminUser:     "root",
		AdminPass:     "root",
	} // Defaults
	rows, err := db.conn.Query("SELECT key, value FROM settings")
	if err != nil {
		return s, err
	}
	defer rows.Close()

	for rows.Next() {
		var k, v string
		rows.Scan(&k, &v)
		switch k {
		case "alert_on_login": s.AlertOnLogin = v == "true"
		case "alert_on_high_risk": s.AlertOnHighRisk = v == "true"
		case "risk_threshold": fmt.Sscanf(v, "%d", &s.RiskThreshold)
		case "discord_webhook": s.DiscordWebhook = v
		case "email_alias": s.EmailAlias = v
		case "admin_user": s.AdminUser = v
		case "admin_pass": s.AdminPass = v
		case "telegram_token": s.TelegramToken = v
		case "telegram_chat_id": s.TelegramChatID = v
		}
	}
	return s, nil
}

func (db *DB) SaveSettings(s SysSettings) error {
	settings := map[string]string{
		"alert_on_login":    fmt.Sprintf("%v", s.AlertOnLogin),
		"alert_on_high_risk": fmt.Sprintf("%v", s.AlertOnHighRisk),
		"risk_threshold":    fmt.Sprintf("%d", s.RiskThreshold),
		"discord_webhook":   s.DiscordWebhook,
		"email_alias":       s.EmailAlias,
		"admin_user":        s.AdminUser,
		"admin_pass":        s.AdminPass,
		"telegram_token":    s.TelegramToken,
		"telegram_chat_id":   s.TelegramChatID,
	}

	return db.withRetry(func() error {
		for k, v := range settings {
			_, err := db.conn.Exec("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", k, v)
			if err != nil {
				return err
			}
		}
		return nil
	})
}
