package server

import (
	"fmt"
	"io"
	"math/rand"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/AnassElhamri/ssh-honeypot/internal/analyzer"
	"github.com/AnassElhamri/ssh-honeypot/internal/geoip"
	"github.com/AnassElhamri/ssh-honeypot/internal/logger"
)

// Session manages a single attacker SSH connection.
type Session struct {
	id      int64
	ip      string
	port    int
	conn    *ssh.ServerConn
	chans   <-chan ssh.NewChannel
	shell   *Shell
	log     *logger.Logger
	db      *logger.DB
	geo     *geoip.Resolver
	stats   *analyzer.SessionStats
	tracker *analyzer.Tracker
	timeout time.Duration
}

// handle runs the full lifecycle of an SSH session.
func (s *Session) handle() {
	defer s.cleanup()

	// GeoIP lookup in background
	go func() {
		loc := s.geo.Lookup(s.ip)
		if loc != nil {
			s.db.UpdateSessionGeo(s.id, loc.Country, loc.City, loc.ASN, loc.ISP)
			s.stats.SetCountry(loc.Country)
			flag := geoip.FlagEmoji(loc.Country)
			s.log.Info("GEOIP           ip=%-16s  %s %s  %s  %s",
				s.ip, flag, loc.Country, loc.City, loc.ISP)
		}
	}()

	// Process incoming channels (each channel = PTY or exec request)
	for newChan := range s.chans {
		if newChan.ChannelType() != "session" {
			newChan.Reject(ssh.UnknownChannelType, "unsupported channel type")
			continue
		}
		ch, reqs, err := newChan.Accept()
		if err != nil {
			return
		}
		go s.handleChannel(ch, reqs)
	}
}

// handleChannel handles an SSH channel (PTY / exec / shell).
func (s *Session) handleChannel(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()

	// Send MOTD with randomized last-login IP (realistic, not traceable)
	lastLoginIPs := []string{
		"85.214.132.117", "45.33.32.156", "178.62.194.101",
		"104.236.179.241", "139.59.173.249", "167.172.53.89",
		"159.65.120.214", "138.197.148.152", "165.227.42.33",
	}
	lastIP := lastLoginIPs[rand.Intn(len(lastLoginIPs))]
	motd := fmt.Sprintf("\r\nWelcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n\r\n"+
		" * Documentation:  https://help.ubuntu.com\r\n"+
		" * Management:     https://landscape.canonical.com\r\n\r\n"+
		"Last login: %s from %s\r\n\r\n",
		time.Now().Add(-24*time.Hour).Format("Mon Jan  2 15:04:05 2006"), lastIP)
	ch.Write([]byte(motd))

	for req := range reqs {
		switch req.Type {
		case "pty-req":
			if req.WantReply {
				req.Reply(true, nil)
			}
		case "shell":
			if req.WantReply {
				req.Reply(true, nil)
			}
			s.runShell(ch)
			return
		case "exec":
			if req.WantReply {
				req.Reply(true, nil)
			}
			// Extract the command from exec payload
			if len(req.Payload) > 4 {
				cmdLen := int(req.Payload[0])<<24 | int(req.Payload[1])<<16 |
					int(req.Payload[2])<<8 | int(req.Payload[3])
				if cmdLen <= len(req.Payload)-4 {
					cmd := string(req.Payload[4 : 4+cmdLen])
					s.runCommand(ch, cmd)
				}
			}
			return
		case "window-change":
			if req.WantReply {
				req.Reply(true, nil)
			}
		default:
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}
}

// runShell runs an interactive shell session.
func (s *Session) runShell(ch ssh.Channel) {
	ch.Write([]byte(s.shell.Prompt()))

	var buf strings.Builder
	b := make([]byte, 1)

	for {
		// Set read deadline for timeout
		n, err := ch.Read(b)
		if err != nil || n == 0 {
			if err != io.EOF {
				s.log.Debug("shell read error: %v", err)
			}
			return
		}

		char := b[0]

		switch char {
		case '\r', '\n':
			// Execute command on Enter
			ch.Write([]byte("\r\n"))
			cmd := strings.TrimSpace(buf.String())
			buf.Reset()

			if cmd == "" {
				ch.Write([]byte(s.shell.Prompt()))
				continue
			}

			// Log the command
			s.log.LogCommand(s.id, s.ip, cmd)
			s.stats.RecordCommand()

			// Execute and send response
			response := s.shell.Execute(cmd)
			if response == "__EXIT__" {
				ch.Write([]byte("logout\r\n"))
				return
			}

			if response != "" {
				// Normalize newlines for SSH terminal
				resp := strings.ReplaceAll(response, "\n", "\r\n")
				ch.Write([]byte(resp + "\r\n"))
			}

			// Log to DB
			s.db.LogCommand(s.id, cmd, response)

			ch.Write([]byte(s.shell.Prompt()))

		case 127, 8: // Backspace / DEL
			if buf.Len() > 0 {
				str := buf.String()
				buf.Reset()
				buf.WriteString(str[:len(str)-1])
				ch.Write([]byte("\b \b"))
			}

		case 3: // Ctrl+C
			ch.Write([]byte("^C\r\n"))
			buf.Reset()
			ch.Write([]byte(s.shell.Prompt()))

		case 4: // Ctrl+D
			ch.Write([]byte("logout\r\n"))
			return

		default:
			if char >= 32 && char < 127 { // Printable ASCII
				buf.WriteByte(char)
				ch.Write(b[:n]) // Echo back
			}
		}
	}
}

// runCommand runs a single non-interactive command.
func (s *Session) runCommand(ch ssh.Channel, cmd string) {
	s.log.LogCommand(s.id, s.ip, cmd)
	s.stats.RecordCommand()

	response := s.shell.Execute(cmd)
	if response != "" && response != "__EXIT__" {
		ch.Write([]byte(response + "\n"))
	}
	s.db.LogCommand(s.id, cmd, response)

	// Send exit status
	exitStatus := []byte{0, 0, 0, 0}
	ch.SendRequest("exit-status", false, exitStatus)
}

// cleanup closes the session and saves final stats.
func (s *Session) cleanup() {
	s.conn.Close()

	score    := s.stats.ThreatScore()
	creds    := s.stats.CredAttempts
	cmds     := s.stats.Commands
	duration := s.stats.Duration()
	pattern  := s.stats.PatternType()

	s.log.LogDisconnect(s.id, s.ip, duration, creds, cmds)
	s.db.CloseSession(s.id, score, creds, cmds)
	s.db.UpsertPattern(s.ip, pattern)
	
	if s.stats.Level() == analyzer.ThreatCritical && s.log.Alerts != nil {
		country := "Unknown"
		loc := s.geo.Lookup(s.ip)
		if loc != nil { country = loc.Country }
		s.log.Alerts.SendCriticalAlert(s.id, s.ip, country, score, pattern)
	}

	s.tracker.Remove(s.id)
}
