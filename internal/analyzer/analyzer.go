package analyzer

import (
	"sync"
	"time"
)

// ThreatLevel classifies the severity of an attacker session.
type ThreatLevel int

const (
	ThreatLow ThreatLevel = iota
	ThreatMedium
	ThreatHigh
	ThreatCritical
)

func (t ThreatLevel) String() string {
	return [...]string{"LOW", "MEDIUM", "HIGH", "CRITICAL"}[t]
}

func (t ThreatLevel) Color() string {
	return [...]string{"green", "yellow", "red", "red"}[t]
}

// SessionStats tracks live stats for an active session.
type SessionStats struct {
	mu            sync.Mutex
	IP            string
	Country       string
	StartTime     time.Time
	CredAttempts  int
	Commands      int
	UniqueUsers   map[string]int
	UniquePasswd  map[string]int
	LastActivity  time.Time
}

// NewSessionStats creates a new tracker for a session.
func NewSessionStats(ip string) *SessionStats {
	return &SessionStats{
		IP:           ip,
		Country:      "resolving...",
		StartTime:    time.Now(),
		UniqueUsers:  make(map[string]int),
		UniquePasswd: make(map[string]int),
		LastActivity: time.Now(),
	}
}

// SetCountry updates the session country after GeoIP lookup.
func (s *SessionStats) SetCountry(country string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Country = country
}

// GetCountry returns the resolved country string.
func (s *SessionStats) GetCountry() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Country
}

// RecordCredential records an auth attempt and returns updated threat score.
func (s *SessionStats) RecordCredential(username, password string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.CredAttempts++
	s.UniqueUsers[username]++
	s.UniquePasswd[password]++
	s.LastActivity = time.Now()
}

// RecordCommand records a shell command.
func (s *SessionStats) RecordCommand() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Commands++
	s.LastActivity = time.Now()
}

// ThreatScore calculates a 0-100 threat score for this session.
func (s *SessionStats) ThreatScore() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	score := 0

	// Credential attempts
	switch {
	case s.CredAttempts >= 50:
		score += 40
	case s.CredAttempts >= 20:
		score += 25
	case s.CredAttempts >= 5:
		score += 15
	default:
		score += 5
	}

	// Many unique usernames = credential stuffing
	if len(s.UniqueUsers) >= 10 {
		score += 20
	} else if len(s.UniqueUsers) >= 3 {
		score += 10
	}

	// Commands entered = active attacker, not just scanner
	switch {
	case s.Commands >= 20:
		score += 30
	case s.Commands >= 5:
		score += 20
	case s.Commands >= 1:
		score += 10
	}

	// Fast brute force (many attempts in short time)
	elapsed := time.Since(s.StartTime).Seconds()
	if elapsed > 0 && float64(s.CredAttempts)/elapsed > 2 {
		score += 10 // more than 2 attempts/sec = automated
	}

	if score > 100 {
		score = 100
	}
	return score
}

// ThreatLevel returns the threat classification.
func (s *SessionStats) Level() ThreatLevel {
	score := s.ThreatScore()
	switch {
	case score >= 75:
		return ThreatCritical
	case score >= 50:
		return ThreatHigh
	case score >= 25:
		return ThreatMedium
	default:
		return ThreatLow
	}
}

// PatternType classifies the attack pattern.
func (s *SessionStats) PatternType() string {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.Commands >= 3 {
		return "interactive_session"
	}
	if len(s.UniqueUsers) >= 5 {
		return "credential_stuffing"
	}
	if s.CredAttempts >= 10 {
		return "brute_force"
	}
	return "scanner"
}

// Duration returns how long this session has been active.
func (s *SessionStats) Duration() time.Duration {
	return time.Since(s.StartTime)
}

// IsIdle returns true if no activity for over 30 seconds.
func (s *SessionStats) IsIdle() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return time.Since(s.LastActivity) > 30*time.Second
}

// ── Global tracker ────────────────────────────────────────────────────────────

// Tracker manages all active sessions globally.
type Tracker struct {
	mu         sync.RWMutex
	sessions   map[int64]*SessionStats
	closers    map[int64]func()
}

// NewTracker creates a global session tracker.
func NewTracker() *Tracker {
	return &Tracker{
		sessions: make(map[int64]*SessionStats),
		closers:  make(map[int64]func()),
	}
}

// Add registers a new session.
func (t *Tracker) Add(id int64, ip string, closer func()) *SessionStats {
	stats := NewSessionStats(ip)
	t.mu.Lock()
	t.sessions[id] = stats
	t.closers[id] = closer
	t.mu.Unlock()
	return stats
}

// Get returns stats for a session.
func (t *Tracker) Get(id int64) *SessionStats {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.sessions[id]
}

// Remove removes a session from tracking.
func (t *Tracker) Remove(id int64) {
	t.mu.Lock()
	delete(t.sessions, id)
	delete(t.closers, id)
	t.mu.Unlock()
}

// ActiveCount returns the number of active sessions.
func (t *Tracker) ActiveCount() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.sessions)
}

// ActiveSessions returns a snapshot of all active sessions.
func (t *Tracker) ActiveSessions() map[int64]*SessionStats {
	t.mu.RLock()
	defer t.mu.RUnlock()
	snap := make(map[int64]*SessionStats, len(t.sessions))
	for k, v := range t.sessions {
		snap[k] = v
	}
	return snap
}

// TerminateIP closes all active sessions for a specific IP.
func (t *Tracker) TerminateIP(ip string) {
	t.mu.RLock()
	var toClose []func()
	for id, stats := range t.sessions {
		if stats.IP == ip {
			if closer, ok := t.closers[id]; ok {
				toClose = append(toClose, closer)
			}
		}
	}
	t.mu.RUnlock()

	for _, closeFunc := range toClose {
		closeFunc()
	}
}
