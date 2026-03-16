package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/AnassElhamri/ssh-honeypot/internal/analyzer"
	"github.com/AnassElhamri/ssh-honeypot/internal/geoip"
	"github.com/AnassElhamri/ssh-honeypot/internal/logger"
)

// Config holds SSH server configuration.
type Config struct {
	Host              string
	Port              int
	MaxConnections    int
	ConnectionTimeout time.Duration
	Banner            string
	ShellHostname     string
	ShellUsername     string
	FakeOS            string
	ShellPrompt       string
	ResponseDelayMs   int
	HostKeyPath       string
}

// Server is the SSH honeypot server.
type Server struct {
	cfg       *Config
	hostKey   ssh.Signer
	log       *logger.Logger
	db        *logger.DB
	geo       *geoip.Resolver
	tracker   *analyzer.Tracker
	semaphore chan struct{}
	blacklist sync.Map
	fw        *Firewall
	onPing    func(string, float64, float64)
}

// New creates and configures a new SSH honeypot server.
func New(cfg *Config, log *logger.Logger, db *logger.DB, geo *geoip.Resolver) (*Server, error) {
	s := &Server{
		cfg:       cfg,
		log:       log,
		db:        db,
		geo:       geo,
		tracker:   analyzer.NewTracker(),
		semaphore: make(chan struct{}, cfg.MaxConnections),
		fw:        NewFirewall(),
	}
	hostKey, err := s.loadOrGenerateHostKey()
	if err != nil {
		return nil, fmt.Errorf("host key: %w", err)
	}
	s.hostKey = hostKey
	return s, nil
}

// SetOnPing registers a callback for real-time map pings.
func (s *Server) SetOnPing(cb func(string, float64, float64)) {
	s.onPing = cb
}

// Tracker returns the session tracker.
func (s *Server) Tracker() *analyzer.Tracker {
	return s.tracker
}

// Geo returns the geo resolver.
func (s *Server) Geo() *geoip.Resolver {
	return s.geo
}

// Listen starts the TCP listener and accepts connections.
func (s *Server) Listen() error {
	addr := fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", addr, err)
	}
	defer listener.Close()

	s.log.Info("SSH Honeypot listening on %s", addr)
	s.log.Info("Banner: %s", s.cfg.Banner)

	for {
		conn, err := listener.Accept()
		if err != nil {
			s.log.Error("accept: %v", err)
			continue
		}
		select {
		case s.semaphore <- struct{}{}:
			go s.handleConn(conn)
		default:
			s.log.Warn("max connections reached, rejecting %s", conn.RemoteAddr())
			conn.Close()
		}
	}
}

// handleConn manages one attacker TCP connection.
func (s *Server) handleConn(conn net.Conn) {
	defer func() { <-s.semaphore }()

	var ip string
	var port int
	if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		ip   = tcpAddr.IP.String()
		port = tcpAddr.Port
	} else {
		host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		ip = host
	}

	if _, blacklisted := s.blacklist.Load(ip); blacklisted {
		s.log.Warn("REJECTED BLACKLISTED IP: %s", ip)
		conn.Close()
		return
	}

	conn.SetDeadline(time.Now().Add(s.cfg.ConnectionTimeout))

	// Removed spoofing logic

	sessionID, err := s.db.CreateSession(ip, port)
	if err != nil {
		s.log.Error("create session: %v", err)
		conn.Close()
		return
	}

	s.log.LogConnect(sessionID, ip, port)
	stats := s.tracker.Add(sessionID, ip, func() { conn.Close() })

	sshConn, chans, reqs, err := ssh.NewServerConn(conn, s.buildSSHConfig(sessionID, ip, stats))
	if err != nil {
		s.db.CloseSession(sessionID, stats.ThreatScore(), stats.CredAttempts, stats.Commands)
		s.tracker.Remove(sessionID)
		return
	}

	go ssh.DiscardRequests(reqs)

	shell := NewShell(
		s.cfg.ShellHostname,
		s.cfg.ShellUsername,
		s.cfg.FakeOS,
		s.cfg.ShellPrompt,
		s.cfg.ResponseDelayMs,
	)

	sess := &Session{
		id:      sessionID,
		ip:      ip,
		port:    port,
		conn:    sshConn,
		chans:   chans,
		shell:   shell,
		log:     s.log,
		db:      s.db,
		geo:     s.geo,
		stats:   stats,
		tracker: s.tracker,
		timeout: s.cfg.ConnectionTimeout,
		onPing:  s.onPing,
	}
	sess.handle()
}

// buildSSHConfig creates a per-connection SSH config that logs all auth attempts.
func (s *Server) buildSSHConfig(sessionID int64, ip string, stats *analyzer.SessionStats) *ssh.ServerConfig {
	attempt := 0
	cfg := &ssh.ServerConfig{
		ServerVersion: s.cfg.Banner,
		MaxAuthTries:  99,
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			attempt++
			user := conn.User()
			pass := string(password)
			clientVer := string(conn.ClientVersion())

			stats.RecordCredential(user, pass)
			s.db.LogCredential(sessionID, user, pass, attempt)
			s.log.Info("AUTH ATTEMPT    ip=%-16s  user=%-20s  pass=%s  ver=%s", ip, user, pass, clientVer)
			s.log.LogCredential(sessionID, ip, user, pass, attempt)

			if s.shouldAccept(user, pass) {
				s.log.Info("AUTH ACCEPTED   ip=%-16s  user=%-20s  (honeypot shell)", ip, user)
				return &ssh.Permissions{}, nil
			}
			time.Sleep(300 * time.Millisecond)
			return nil, fmt.Errorf("permission denied")
		},
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			s.log.Info("PUBKEY ATTEMPT  ip=%-16s  user=%-20s  fp=%s",
				ip, conn.User(), ssh.FingerprintSHA256(key))
			return nil, fmt.Errorf("public key not accepted")
		},
	}
	cfg.AddHostKey(s.hostKey)
	return cfg
}

// shouldAccept returns true for well-known default credentials.
func (s *Server) shouldAccept(username, password string) bool {
	defaults := [][2]string{
		{"root", "root"}, {"root", "toor"}, {"root", "password"},
		{"root", "123456"}, {"root", "admin"}, {"root", ""},
		{"admin", "admin"}, {"admin", "password"}, {"admin", "123456"},
		{"ubuntu", "ubuntu"}, {"pi", "raspberry"},
		{"user", "user"}, {"test", "test"}, {"guest", "guest"},
	}
	for _, pair := range defaults {
		if strings.EqualFold(username, pair[0]) && password == pair[1] {
			return true
		}
	}
	return false
}

// loadOrGenerateHostKey loads or creates the RSA host key.
func (s *Server) loadOrGenerateHostKey() (ssh.Signer, error) {
	keyPath := s.cfg.HostKeyPath
	if keyPath == "" {
		keyPath = "data/host_key"
	}

	if data, err := os.ReadFile(keyPath); err == nil {
		if block, _ := pem.Decode(data); block != nil {
			if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
				return ssh.NewSignerFromKey(key)
			}
		}
	}

	s.log.Info("Generating RSA host key at %s ...", keyPath)
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	os.MkdirAll("data", 0700)
	f, err := os.OpenFile(keyPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return nil, fmt.Errorf("save host key: %w", err)
	}
	defer f.Close()

	pem.Encode(f, &pem.Block{ //nolint:errcheck
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	s.log.Info("Host key generated.")
	return ssh.NewSignerFromKey(privateKey)
}

// BlockIP adds an IP to the blacklist and runs firewall commands.
func (s *Server) BlockIP(ip string) {
	s.blacklist.Store(ip, true)
	s.log.Warn("IP BLACKLISTED: %s", ip)

	// Terminate active sessions for this IP
	s.tracker.TerminateIP(ip)

	// Try OS-level block
	if err := s.fw.BlockIP(ip); err != nil {
		s.log.Error("firewall block failed for %s: %v", ip, err)
	} else {
		s.log.Info("FIREWALL RULE ADDED: Blocked %s", ip)
	}
}

// End of file
