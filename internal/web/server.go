package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"
	"github.com/AnassElhamri/ssh-honeypot/internal/analyzer"
	"github.com/AnassElhamri/ssh-honeypot/internal/logger"
)

// Server is the web dashboard server.
type Server struct {
	db      *logger.DB
	tracker *analyzer.Tracker
	port    int
	onBlock func(string)
}

// New creates a new web dashboard server.
func New(db *logger.DB, tracker *analyzer.Tracker, port int, onBlock func(string)) *Server {
	return &Server{
		db:      db,
		tracker: tracker,
		port:    port,
		onBlock: onBlock,
	}
}

// Start launches the web server.
func (s *Server) Start() error {
	mux := http.NewServeMux()

	// Static files
	staticDir := "web/static"
	mux.Handle("/", http.FileServer(http.Dir(staticDir)))

	// API Endpoints
	mux.HandleFunc("/api/stats", s.handleStats)
	mux.HandleFunc("/api/sessions", s.handleSessions)
	mux.HandleFunc("/api/block", s.handleBlock)
	mux.HandleFunc("/api/reports", s.handleReports)
	mux.HandleFunc("/api/download/", s.handleDownload)

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", s.port),
		Handler: mux,
	}

	return server.ListenAndServe()
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	stats, err := s.db.GetStats()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(stats)
}

func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	active := s.tracker.ActiveSessions()
	// Map to list for JSON
	list := make([]interface{}, 0, len(active))
	for id, s := range active {
		list = append(list, map[string]interface{}{
			"id":        id,
			"ip":        s.IP,
			"country":   s.GetCountry(),
			"creds":     s.CredAttempts,
			"cmds":      s.Commands,
			"threat":    s.Level().String(),
			"score":     s.ThreatScore(),
			"duration":  s.Duration().Round(1 * time.Second).String(),
		})
	}
	json.NewEncoder(w).Encode(list)
}

func (s *Server) handleBlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	if s.onBlock != nil {
		s.onBlock(req.IP)
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleReports(w http.ResponseWriter, r *http.Request) {
	reports, _ := filepath.Glob("data/reports/*")
	list := make([]string, 0, len(reports))
	for _, path := range reports {
		list = append(list, filepath.Base(path))
	}
	json.NewEncoder(w).Encode(list)
}

func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
	filename := filepath.Base(r.URL.Path)
	path := filepath.Join("data/reports", filename)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}
	http.ServeFile(w, r, path)
}
