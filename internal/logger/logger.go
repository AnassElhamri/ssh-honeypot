package logger

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Level represents log severity.
type Level int

const (
	DEBUG Level = iota
	INFO
	WARN
	ERROR
)

func (l Level) String() string {
	return [...]string{"DEBUG", "INFO", "WARN", "ERROR"}[l]
}

// Event is a structured log event written to session files.
type Event struct {
	Time      time.Time         `json:"time"`
	Type      string            `json:"type"`
	SessionID int64             `json:"session_id,omitempty"`
	IP        string            `json:"ip,omitempty"`
	Data      map[string]any    `json:"data,omitempty"`
}

// Logger handles both console and file logging.
type Logger struct {
	mu          sync.Mutex
	level       Level
	sessionsDir string
	console     *log.Logger
	DB          *DB
	callbacks   []func(string)
	Alerts      *AlertHandler
}

// New creates a Logger.
func New(level Level, sessionsDir string, db *DB, alerts *AlertHandler) *Logger {
	return &Logger{
		level:       level,
		sessionsDir: sessionsDir,
		console:     log.New(os.Stdout, "", 0),
		DB:          db,
		Alerts:      alerts,
		callbacks:   make([]func(string), 0),
	}
}

// AddCallback adds a custom logging callback (e.g., for dashboards).
func (l *Logger) AddCallback(cb func(string)) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.callbacks = append(l.callbacks, cb)
}

// log writes a formatted line to stdout and all registered callbacks.
func (l *Logger) log(level Level, format string, args ...any) {
	if level < l.level {
		return
	}
	ts := time.Now().Format("2006-01-02 15:04:05")
	msg := fmt.Sprintf(format, args...)

	colors := map[Level]string{
		DEBUG: "\033[90m",
		INFO:  "\033[92m",
		WARN:  "\033[93m",
		ERROR: "\033[91m",
	}
	reset := "\033[0m"

	l.mu.Lock()
	callbacks := make([]func(string), len(l.callbacks))
	copy(callbacks, l.callbacks)
	l.mu.Unlock()

	line := fmt.Sprintf("%s [%s] %s", ts, level, msg)
	for _, cb := range callbacks {
		cb(line)
	}

	// Always print ERROR and WARN to console for easier debugging
	// Unless it's INFO/DEBUG and a callback is active (dashboard mode)
	if len(callbacks) == 0 || level >= WARN {
		l.console.Printf("%s%s [%s] %s%s", colors[level], ts, level, msg, reset)
	}
}

func (l *Logger) Debug(format string, args ...any) { l.log(DEBUG, format, args...) }
func (l *Logger) Info(format string, args ...any)  { l.log(INFO, format, args...) }
func (l *Logger) Warn(format string, args ...any)  { l.log(WARN, format, args...) }
func (l *Logger) Error(format string, args ...any) { l.log(ERROR, format, args...) }

// LogEvent writes a structured JSON event to a per-session file.
func (l *Logger) LogEvent(event Event) {
	if l.sessionsDir == "" {
		return
	}
	event.Time = time.Now().UTC()

	l.mu.Lock()
	defer l.mu.Unlock()

	// One file per session: data/sessions/session_<id>.jsonl
	filename := filepath.Join(l.sessionsDir,
		fmt.Sprintf("session_%d.jsonl", event.SessionID))

	f, err := os.OpenFile(filename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		l.Error("failed to open session log: %v", err)
		return
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.Encode(event) //nolint:errcheck
}

// LogConnect logs a new connection event.
func (l *Logger) LogConnect(sessionID int64, ip string, port int) {
	l.Info("NEW CONNECTION  ip=%-16s  session=%d", ip, sessionID)
	l.LogEvent(Event{
		Type:      "connect",
		SessionID: sessionID,
		IP:        ip,
		Data:      map[string]any{"port": port},
	})
}

// LogCredential logs an authentication attempt.
func (l *Logger) LogCredential(sessionID int64, ip, user, pass string, attempt int) {
	l.Info("AUTH ATTEMPT    ip=%-16s  user=%-20s  pass=%s", ip, user, pass)
	l.LogEvent(Event{
		Type:      "credential",
		SessionID: sessionID,
		IP:        ip,
		Data: map[string]any{
			"username": user,
			"password": pass,
			"attempt":  attempt,
		},
	})
}

// LogCommand logs a shell command.
func (l *Logger) LogCommand(sessionID int64, ip, command string) {
	l.Info("COMMAND         ip=%-16s  cmd=%s", ip, command)
	l.LogEvent(Event{
		Type:      "command",
		SessionID: sessionID,
		IP:        ip,
		Data:      map[string]any{"command": command},
	})
}

// LogDisconnect logs a session end.
func (l *Logger) LogDisconnect(sessionID int64, ip string, duration time.Duration, creds, cmds int) {
	l.Info("DISCONNECT      ip=%-16s  duration=%-10s  creds=%d  cmds=%d",
		ip, duration.Round(time.Second), creds, cmds)
	l.LogEvent(Event{
		Type:      "disconnect",
		SessionID: sessionID,
		IP:        ip,
		Data: map[string]any{
			"duration_sec": duration.Seconds(),
			"credentials":  creds,
			"commands":     cmds,
		},
	})
}
