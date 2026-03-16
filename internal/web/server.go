package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/AnassElhamri/ssh-honeypot/internal/analyzer"
	"github.com/AnassElhamri/ssh-honeypot/internal/geoip"
	"github.com/AnassElhamri/ssh-honeypot/internal/logger"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/process"
	"github.com/xuri/excelize/v2"
)

// Server is the web dashboard server.
type Server struct {
	db          *logger.DB
	geo         *geoip.Resolver
	tracker     *analyzer.Tracker
	port        int
	user        string
	pass        string
	onBlock     func(string)
	hub         *Hub
	dbPath      string
	sessionsDir string
	startTime   time.Time
	client      *http.Client
}

// New creates a new web dashboard server.
func New(db *logger.DB, geo *geoip.Resolver, tracker *analyzer.Tracker, port int, user, pass string, sessionsDir string, onBlock func(string)) *Server {
	return &Server{
		db:          db,
		geo:         geo,
		tracker:     tracker,
		port:        port,
		user:        user,
		pass:        pass,
		sessionsDir: sessionsDir,
		onBlock:     onBlock,
		hub:         NewHub(),
		dbPath:      db.Path(),
		startTime:   time.Now(),
		client:      &http.Client{Timeout: 10 * time.Second},
	}
}

// Start launches the web server.
func (s *Server) Start() error {
	mux := http.NewServeMux()
	staticDir := "web/static"

	// Static files
	// WebSocket (Public for now, or auth check inside if needed)
	go s.hub.Run()
	mux.HandleFunc("/ws", s.hub.ServeWebSocket)

	// Auth routes
	mux.HandleFunc("/login", s.handleLogin)
	mux.HandleFunc("/logout", s.handleLogout)

	// API Endpoints (Protected)
	mux.Handle("/api/", s.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimSuffix(r.URL.Path, "/")
		switch path {
		case "/api/stats":
			s.handleStats(w, r)
		case "/api/sessions":
			s.handleSessions(w, r)
		case "/api/timeline":
			s.handleTimeline(w, r)
		case "/api/hub-location":
			s.handleHubLocation(w, r)
		case "/api/block":
			s.handleBlock(w, r)
		case "/api/reports":
			s.handleReports(w, r)
		case "/api/commands":
			s.handleCommandIntel(w, r)
		case "/api/settings":
			s.handleSettings(w, r)
		case "/api/system/stats":
			s.handleSystemStats(w, r)
		case "/api/db/maintenance":
			s.handleMaintenance(w, r)
		case "/api/generate-report":
			s.handleGenerateReport(w, r)
		case "/api/test/discord":
			s.handleTestDiscord(w, r)
		case "/api/test/telegram":
			s.handleTestTelegram(w, r)
		case "/api/clear-reports":
			s.handleClearReports(w, r)
		default:
			if strings.HasPrefix(r.URL.Path, "/api/download/") {
				s.handleDownload(w, r)
			} else {
				http.NotFound(w, r)
			}
		}
	})))

	// Main Dashboard (Protected)
	mux.Handle("/index.html", s.authMiddleware(http.FileServer(http.Dir(staticDir))))
	mux.Handle("/settings.html", s.authMiddleware(http.FileServer(http.Dir(staticDir))))
	mux.Handle("/", s.rootHandler(staticDir))

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

func (s *Server) handleTimeline(w http.ResponseWriter, r *http.Request) {
	period := r.URL.Query().Get("period")
	if period == "" {
		period = "24h"
	}
	data, err := s.db.GetTimeline(period)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(data)
}

func (s *Server) handleHubLocation(w http.ResponseWriter, r *http.Request) {
	loc := s.geo.LookupSelf()
	if loc == nil {
		// Fallback to a default if resolution fails
		json.NewEncoder(w).Encode(map[string]float64{"lat": 0, "lon": 0})
		return
	}
	json.NewEncoder(w).Encode(map[string]float64{"lat": loc.Lat, "lon": loc.Lon})
}

func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	active := s.tracker.ActiveSessions()
	// Map to list for JSON
	list := make([]interface{}, 0, len(active))
	for id, s := range active {
		list = append(list, map[string]interface{}{
			"id":       id,
			"ip":       s.IP,
			"country":  s.GetCountry(),
			"creds":    s.CredAttempts,
			"cmds":     s.Commands,
			"threat":   s.Level().String(),
			"score":    s.ThreatScore(),
			"duration": s.Duration().Round(1 * time.Second).String(),
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

func (s *Server) rootHandler(staticDir string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.FileServer(http.Dir(staticDir)).ServeHTTP(w, r)
			return
		}
		// If authenticated, serve index.html, else redirect to login
		if s.isAuthenticated(r) {
			http.ServeFile(w, r, filepath.Join(staticDir, "index.html"))
		} else {
			http.ServeFile(w, r, filepath.Join(staticDir, "login.html"))
		}
	})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		http.ServeFile(w, r, "web/static/login.html")
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	// Check DB settings first
	settings, _ := s.db.GetSettings()
	validUser := settings.AdminUser
	validPass := settings.AdminPass

	// Fallback to startup credentials if DB is empty or explicitly root/root
	if validUser == "" {
		validUser = s.user
		validPass = s.pass
	}

	if username == validUser && password == validPass {
		cookie := &http.Cookie{
			Name:     "honey_session",
			Value:    "authenticated",
			Path:     "/",
			HttpOnly: true,
			MaxAge:   86400, // 24h
		}
		http.SetCookie(w, cookie)
		http.Redirect(w, r, "/", http.StatusFound)
	} else {
		http.Redirect(w, r, "/login?error=1", http.StatusFound)
	}
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie := &http.Cookie{
		Name:     "honey_session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	}
	http.SetCookie(w, cookie)
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.isAuthenticated(r) {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
			} else {
				http.Redirect(w, r, "/login", http.StatusFound)
			}
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) isAuthenticated(r *http.Request) bool {
	cookie, err := r.Cookie("honey_session")
	return err == nil && cookie.Value == "authenticated"
}

func (s *Server) handleCommandIntel(w http.ResponseWriter, r *http.Request) {
	intel, err := s.db.GetCommandIntelligence()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(intel)
}

// BroadcastLog sends a log message to all connected web clients.
func (s *Server) BroadcastLog(msg string) {
	if s.hub != nil {
		s.hub.BroadcastLog(msg)
	}
}

// BroadcastPing sends coordinate data for a real-time map ping.
func (s *Server) BroadcastPing(ip string, lat, lon float64) {
	if s.hub != nil {
		s.hub.BroadcastPing(ip, lat, lon)
	}
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		settings, err := s.db.GetSettings()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Mask sensitive keys for UI
		mask := "__SNAKESEC_SET__"
		if settings.DiscordWebhook != "" {
			settings.DiscordWebhook = mask
		}
		if settings.TelegramToken != "" {
			settings.TelegramToken = mask
		}
		if settings.TelegramChatID != "" {
			settings.TelegramChatID = mask
		}
		if settings.AdminPass != "" {
			settings.AdminPass = mask
		}

		json.NewEncoder(w).Encode(settings)
		return
	}

	if r.Method == http.MethodPost {
		var req logger.SysSettings
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		// Handle masked keys from UI
		current, _ := s.db.GetSettings()
		mask := "__SNAKESEC_SET__"
		if req.DiscordWebhook == mask {
			req.DiscordWebhook = current.DiscordWebhook
		}
		if req.TelegramToken == mask {
			req.TelegramToken = current.TelegramToken
		}
		if req.TelegramChatID == mask {
			req.TelegramChatID = current.TelegramChatID
		}
		if req.AdminPass == mask {
			req.AdminPass = current.AdminPass
		}

		if err := s.db.SaveSettings(req); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

func (s *Server) handleSystemStats(w http.ResponseWriter, r *http.Request) {
	uptime := time.Since(s.startTime).Truncate(time.Second).String()
	_, rows, _ := s.db.GetDBStats()
	var dbSize int64
	if info, err := os.Stat(s.dbPath); err == nil {
		dbSize = info.Size()
	}

	// Real Metrics
	cpuPercent, _ := cpu.Percent(0, false)
	vMem, _ := mem.VirtualMemory()

	currentProcess, _ := process.NewProcess(int32(os.Getpid()))
	procName, _ := currentProcess.Name()
	isRunning, _ := currentProcess.IsRunning()

	cpuVal := 0.0
	if len(cpuPercent) > 0 {
		cpuVal = cpuPercent[0]
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"uptime":      uptime,
		"pid":         os.Getpid(),
		"proc_name":   procName,
		"is_running":  isRunning,
		"cpu_usage":   cpuVal,
		"ram_usage":   vMem.Used / 1024 / 1024,
		"ram_total":   vMem.Total / 1024 / 1024,
		"ram_percent": vMem.UsedPercent,
		"db_size":     dbSize,
		"db_rows":     rows,
	})
}

func (s *Server) handleMaintenance(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	action := r.URL.Query().Get("action")
	var err error
	switch action {
	case "vacuum":
		err = s.db.Vacuum()
	case "clear":
		// Clear Database
		err = s.db.ClearAll()
		if err == nil {
			// Clear Filesystem Logs
			files, _ := filepath.Glob(filepath.Join(s.sessionsDir, "*.jsonl"))
			for _, f := range files {
				os.Remove(f)
			}
			// Shrink DB file size immediately
			s.db.Vacuum()
		}
	case "backup":
		backupPath := filepath.Join("data", fmt.Sprintf("backup_%d.db", time.Now().Unix()))
		data, errRead := os.ReadFile(s.dbPath)
		if errRead != nil {
			err = errRead
		} else {
			err = os.WriteFile(backupPath, data, 0644)
		}
	default:
		http.Error(w, "Unknown action", http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleTestDiscord(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	url := req.URL
	if url == "__SNAKESEC_SET__" {
		settings, _ := s.db.GetSettings()
		url = settings.DiscordWebhook
	}

	payload := map[string]string{
		"content": "🛡️ **SnakeSec Threat Intelligence**\nSuccessful connection test! Dashboard integration is live.",
	}
	body, _ := json.Marshal(payload)

	resp, err := s.client.Post(req.URL, "application/json", strings.NewReader(string(body)))
	if err != nil || resp.StatusCode >= 400 {
		http.Error(w, "Discord connection failed", http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleTestTelegram(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token  string `json:"token"`
		ChatID string `json:"chat_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	token := strings.TrimSpace(req.Token)
	chatID := strings.TrimSpace(req.ChatID)

	if token == "__SNAKESEC_SET__" || chatID == "__SNAKESEC_SET__" {
		settings, _ := s.db.GetSettings()
		if token == "__SNAKESEC_SET__" {
			token = settings.TelegramToken
		}
		if chatID == "__SNAKESEC_SET__" {
			chatID = settings.TelegramChatID
		}
	}

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", token)
	payload := map[string]string{
		"chat_id": chatID,
		"text":    "🛡️ SnakeSec Threat Intelligence\nSuccessful connection test! Dashboard integration is live.",
	}
	body, _ := json.Marshal(payload)

	resp, err := s.client.Post(url, "application/json", strings.NewReader(string(body)))
	if err != nil {
		fmt.Printf("TELEGRAM ERROR: %v\n", err)
		http.Error(w, "Telegram request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		var errorResponse map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&errorResponse)
		fmt.Printf("TELEGRAM API ERROR [%d]: %v\n", resp.StatusCode, errorResponse)
		http.Error(w, fmt.Sprintf("Telegram error: %v", errorResponse["description"]), http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleClearReports(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	reportDir := filepath.Join("data", "reports")
	files, err := os.ReadDir(reportDir)
	if err != nil {
		w.WriteHeader(http.StatusOK)
		return
	}

	for _, f := range files {
		if !f.IsDir() {
			os.Remove(filepath.Join(reportDir, f.Name()))
		}
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Reports cleared")
}

func (s *Server) handleGenerateReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Start    string `json:"start"`  // RFC3339
		End      string `json:"end"`    // RFC3339
		Format   string `json:"format"` // html | excel
		Includes struct {
			Creds    bool `json:"creds"`
			Commands bool `json:"commands"`
			Geo      bool `json:"geo"`
			Threat   bool `json:"threat"`
		} `json:"includes"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	startTime, errS := time.Parse(time.RFC3339, req.Start)
	endTime, errE := time.Parse(time.RFC3339, req.End)
	if errS != nil || errE != nil {
		http.Error(w, "Invalid timestamp format", http.StatusBadRequest)
		return
	}

	// Fetch Data
	stats, err := s.db.GetStatsRange(startTime, endTime)
	if err != nil {
		http.Error(w, "Statistical data retrieval failed", http.StatusInternalServerError)
		return
	}

	sessions, err := s.db.GetDetailedReportData(startTime, endTime)
	if err != nil {
		http.Error(w, "Session data retrieval failed", http.StatusInternalServerError)
		return
	}

	// Generate Report according to format
	var reportContent []byte
	var extension string
	var genErr error

	if req.Format == "excel" {
		extension = ".xlsx"
		reportContent, genErr = s.generateExcelReport(stats, sessions, req.Includes.Creds, req.Includes.Commands, req.Includes.Geo, req.Includes.Threat)
	} else {
		// Default to HTML
		extension = ".html"
		reportContentStr := s.generateProfessionalHTML(stats, sessions, req.Includes.Creds, req.Includes.Commands, req.Includes.Geo, req.Includes.Threat)
		reportContent = []byte(reportContentStr)
	}

	if genErr != nil {
		http.Error(w, "Report generation failed: "+genErr.Error(), http.StatusInternalServerError)
		return
	}

	filename := fmt.Sprintf("Security_Audit_%s%s", time.Now().Format("20060102_150405"), extension)
	reportPath := filepath.Join("data", "reports", filename)

	if err := os.MkdirAll(filepath.Join("data", "reports"), 0755); err != nil {
		http.Error(w, "Failed to create reports directory", http.StatusInternalServerError)
		return
	}

	if err := os.WriteFile(reportPath, reportContent, 0644); err != nil {
		http.Error(w, "Failed to save report", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"filename": filename,
		"url":      "/api/download/" + filename,
	})
}

func (s *Server) generateProfessionalHTML(stats *logger.Stats, sessions []logger.Session, includeCreds, includeCmds, includeGeo, includeThreat bool) string {
	var sb strings.Builder

	sb.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>SnakeSec Security Intelligence Audit</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0d1117; color: #e6edf3; padding: 40px; margin: 0; }
        .container { max-width: 1000px; margin: 0 auto; background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 40px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }
        .header { border-bottom: 2px solid #3fb950; padding-bottom: 20px; margin-bottom: 30px; }
        .logo { font-size: 24px; font-weight: 800; color: #3fb950; letter-spacing: 2px; }
        h1 { margin: 10px 0; font-size: 28px; }
        .meta { color: #8b949e; font-size: 14px; margin-bottom: 30px; }
        .stats-grid { display: grid; grid-cols: 4; gap: 20px; margin-bottom: 40px; }
        .stat-card { background: #0d1117; border: 1px solid #30363d; padding: 20px; border-radius: 8px; text-align: center; }
        .stat-value { font-size: 24px; font-weight: bold; color: #3fb950; margin-bottom: 5px; }
        .stat-label { font-size: 10px; color: #8b949e; text-transform: uppercase; letter-spacing: 1px; }
        table { width: 100%; border-collapse: collapse; margin-bottom: 30px; }
        th { text-align: left; padding: 12px; border-bottom: 1px solid #30363d; color: #8b949e; font-size: 12px; text-transform: uppercase; }
        td { padding: 12px; border-bottom: 1px solid #21262d; font-size: 14px; }
        .risk-high { color: #f85149; font-weight: bold; }
        .risk-med { color: #d29922; font-weight: bold; }
        .section-title { font-size: 18px; font-weight: bold; margin: 40px 0 20px; border-left: 4px solid #3fb950; padding-left: 15px; }
        .appendix { background: #0d1117; border-radius: 8px; padding: 20px; margin-top: 20px; border: 1px solid #30363d; }
        .session-id { color: #58a6ff; font-family: monospace; }
        pre { background: #161b22; padding: 10px; border-radius: 4px; font-size: 12px; color: #58a6ff; overflow-x: auto; border: 0.5px solid #30363d; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">SNAKESEC</div>
            <h1>Security Intelligence Audit</h1>
            <div class="meta">
                Period: <b>` + stats.RangeStart.Format("2006-01-02 15:04") + ` — ` + stats.RangeEnd.Format("2006-01-02 15:04") + `</b><br>
                Generated: ` + time.Now().Format("2006-01-02 15:04:05") + `
            </div>
        </div>

        <div class="section-title">Executive Summary</div>
        <div class="summary-grid">
            <div class="summary-card">
                <div class="card-label">Total Audit Sessions</div>
                <div class="card-value">` + fmt.Sprintf("%d", stats.TotalSessions) + `</div>
            </div>
            <div class="summary-card">
                <div class="card-label">Unique Attack Vectors (IP)</div>
                <div class="card-value">` + fmt.Sprintf("%d", stats.UniqueIPs) + `</div>
            </div>
            <div class="summary-card">
                <div class="card-label">Credentials Harvested</div>
                <div class="card-value">` + fmt.Sprintf("%d", stats.TotalCredentials) + `</div>
            </div>
            <div class="summary-card">
                <div class="card-label">Command Injections</div>
                <div class="card-value">` + fmt.Sprintf("%d", stats.TotalCommands) + `</div>
            </div>
        </div>

        <div class="section-title">Global Threat Origin</div>
        <table>
            <thead><tr><th>Region</th><th>Incident Count</th></tr></thead>
            <tbody>`)
	for _, c := range stats.TopCountries {
		sb.WriteString("<tr><td>" + c.Value + "</td><td>" + fmt.Sprintf("%d", c.Count) + "</td></tr>")
	}
	sb.WriteString(`</tbody>
        </table>

        <div class="section-title">Modular Forensic Audit</div>
        <table>
            <thead><tr>
                <th>IP Address</th>
                <th>Audit Time</th>
                ` + func() string {
		if includeGeo {
			return "<th>Location</th>"
		}
		return ""
	}() + `
                ` + func() string {
		if includeThreat {
			return "<th>Risk %</th>"
		}
		return ""
	}() + `
                <th>Creds</th>
                <th>Cmds</th>
            </tr></thead>
            <tbody>`)
	for _, sess := range sessions {
		riskClass := ""
		riskVal := ""
		if includeThreat {
			if sess.ThreatScore > 70 {
				riskClass = "risk-high"
			} else if sess.ThreatScore > 40 {
				riskClass = "risk-med"
			}
			riskVal = fmt.Sprintf("<td class='%s'>%d</td>", riskClass, sess.ThreatScore)
		}

		geoVal := ""
		if includeGeo {
			geoVal = fmt.Sprintf("<td>%s, %s</td>", sess.City, sess.Country)
		}

		sb.WriteString(fmt.Sprintf("<tr><td>%s</td><td>%s</td>%s%s<td>%d</td><td>%d</td></tr>",
			sess.IP, sess.StartTime.Format("15:04:05"), geoVal, riskVal, sess.TotalCreds, sess.TotalCmds))
	}
	sb.WriteString(`</tbody>
        </table>`)

	if includeCreds || includeCmds {
		sb.WriteString("<div class='section-title'>Forensic Appendix</div>")
		for _, sess := range sessions {
			if (includeCreds && sess.TotalCreds > 0) || (includeCmds && sess.TotalCmds > 0) {
				sb.WriteString("<div class='appendix'>")
				sb.WriteString(fmt.Sprintf("<div style='margin-bottom:10px;'><b>Session <span class='session-id'>#%d</span></b> &mdash; %s</div>", sess.ID, sess.IP))

				if includeCreds {
					creds, _ := s.db.GetSessionCredentials(sess.ID)
					if len(creds) > 0 {
						sb.WriteString("<div style='font-size:12px; color:#8b949e; margin-bottom:5px; text-transform:uppercase;'>Credential Infiltration:</div>")
						sb.WriteString("<pre>")
						for _, c := range creds {
							sb.WriteString(fmt.Sprintf("%s:%s\n", c.Username, c.Password))
						}
						sb.WriteString("</pre>")
					}
				}

				if includeCmds {
					cmds, _ := s.db.GetSessionCommands(sess.ID)
					if len(cmds) > 0 {
						sb.WriteString("<div style='font-size:12px; color:#8b949e; margin-bottom:5px; margin-top:10px; text-transform:uppercase;'>Shell Interaction:</div>")
						sb.WriteString("<pre>")
						for _, c := range cmds {
							sb.WriteString(fmt.Sprintf("$ %s\n", c.Command))
						}
						sb.WriteString("</pre>")
					}
				}
				sb.WriteString("</div>")
			}
		}
	}

	sb.WriteString(`<div style="margin-top: 50px; text-align: center; color: #8b949e; font-size: 11px; border-top: 1px solid #30363d; padding-top: 20px;">
            Honeypot Logic by SnakeSec &mdash; Proprietary Intelligence Output
        </div>
    </div>
</body>
</html>`)
	return sb.String()
}

func (s *Server) generateExcelReport(stats *logger.Stats, sessions []logger.Session, includeCreds, includeCmds, includeGeo, includeThreat bool) ([]byte, error) {
	f := excelize.NewFile()
	defer f.Close()

	// 1. Summary Sheet
	sheetName := "Audit Summary"
	f.SetSheetName("Sheet1", sheetName)

	// Headers and Style
	style, _ := f.NewStyle(&excelize.Style{
		Font: &excelize.Font{Bold: true, Color: "3fb950"},
		Fill: excelize.Fill{Type: "pattern", Color: []string{"0d1117"}, Pattern: 1},
	})

	f.SetCellValue(sheetName, "A1", "SNAKESEC SECURITY AUDIT")
	f.MergeCell(sheetName, "A1", "B1")
	f.SetCellStyle(sheetName, "A1", "B1", style)

	f.SetCellValue(sheetName, "A3", "Audit Period Start")
	f.SetCellValue(sheetName, "B3", stats.RangeStart.Format("2006-01-02 15:04"))
	f.SetCellValue(sheetName, "A4", "Audit Period End")
	f.SetCellValue(sheetName, "B4", stats.RangeEnd.Format("2006-01-02 15:04"))

	f.SetCellValue(sheetName, "A6", "METRIC")
	f.SetCellValue(sheetName, "B6", "VALUE")

	f.SetCellValue(sheetName, "A7", "Total Sessions")
	f.SetCellValue(sheetName, "B7", stats.TotalSessions)
	f.SetCellValue(sheetName, "A8", "Unique IPs")
	f.SetCellValue(sheetName, "B8", stats.UniqueIPs)
	f.SetCellValue(sheetName, "A9", "Credential Attempts")
	f.SetCellValue(sheetName, "B9", stats.TotalCredentials)
	f.SetCellValue(sheetName, "A10", "Commands Run")
	f.SetCellValue(sheetName, "B10", stats.TotalCommands)

	// 2. Sessions Sheet (Flexible Columnar Audit)
	sessSheet := "Threat Logs"
	f.NewSheet(sessSheet)

	columns := []string{"SESSION ID", "TIMESTAMP", "SOURCE IP"}
	if includeGeo {
		columns = append(columns, "ISP")
	}
	if includeThreat {
		columns = append(columns, "RISK SCORE")
	}
	columns = append(columns, "CREDENTIALS", "COMMANDS")
	if includeGeo {
		columns = append(columns, "COUNTRY", "CITY")
	}

	for i, col := range columns {
		cell, _ := excelize.CoordinatesToCellName(i+1, 1)
		f.SetCellValue(sessSheet, cell, col)
		f.SetCellStyle(sessSheet, cell, cell, style)
	}

	for i, sess := range sessions {
		row := i + 2

		f.SetCellValue(sessSheet, fmt.Sprintf("%s%d", "A", row), sess.ID)
		f.SetCellValue(sessSheet, fmt.Sprintf("%s%d", "B", row), sess.StartTime.Local().Format("2006-01-02 15:04:05"))
		f.SetCellValue(sessSheet, fmt.Sprintf("%s%d", "C", row), sess.IP)
		colIdx := 4

		if includeGeo {
			f.SetCellValue(sessSheet, fmt.Sprintf("%s%d", "D", row), sess.ISP)
			colIdx++
		}

		if includeThreat {
			cell, _ := excelize.CoordinatesToCellName(colIdx, row)
			f.SetCellValue(sessSheet, cell, sess.ThreatScore)
			colIdx++
		}

		cellCred, _ := excelize.CoordinatesToCellName(colIdx, row)
		f.SetCellValue(sessSheet, cellCred, sess.TotalCreds)

		cellCmd, _ := excelize.CoordinatesToCellName(colIdx+1, row)
		f.SetCellValue(sessSheet, cellCmd, sess.TotalCmds)
		colIdx += 2

		if includeGeo {
			cellCountry, _ := excelize.CoordinatesToCellName(colIdx, row)
			f.SetCellValue(sessSheet, cellCountry, sess.Country)
			cellCity, _ := excelize.CoordinatesToCellName(colIdx+1, row)
			f.SetCellValue(sessSheet, cellCity, sess.City)
		}
	}

	// Auto-Filter for flexibility
	lastCol, _ := excelize.CoordinatesToCellName(len(columns), len(sessions)+1)
	f.AutoFilter(sessSheet, "A1:"+lastCol, nil)

	// 3. Optional Detailed Sheets
	if includeCreds {
		credSheet := "Adversary Creds"
		f.NewSheet(credSheet)
		headers := []string{"SESSION ID", "TIMESTAMP", "SOURCE IP", "USERNAME", "PASSWORD", "COUNTRY", "CITY"}
		for i, h := range headers {
			cell, _ := excelize.CoordinatesToCellName(i+1, 1)
			f.SetCellValue(credSheet, cell, h)
			f.SetCellStyle(credSheet, cell, cell, style)
		}

		row := 2
		for _, sess := range sessions {
			creds, _ := s.db.GetSessionCredentials(sess.ID)
			for _, c := range creds {
				f.SetCellValue(credSheet, fmt.Sprintf("A%d", row), sess.ID)
				f.SetCellValue(credSheet, fmt.Sprintf("B%d", row), c.Timestamp.Local().Format("2006-01-02 15:04:05"))
				f.SetCellValue(credSheet, fmt.Sprintf("C%d", row), sess.IP)
				f.SetCellValue(credSheet, fmt.Sprintf("D%d", row), c.Username)
				f.SetCellValue(credSheet, fmt.Sprintf("E%d", row), c.Password)
				f.SetCellValue(credSheet, fmt.Sprintf("F%d", row), sess.Country)
				f.SetCellValue(credSheet, fmt.Sprintf("G%d", row), sess.City)
				row++
			}
		}
		lastCol, _ := excelize.CoordinatesToCellName(len(headers), row)
		f.AutoFilter(credSheet, "A1:"+lastCol, nil)
	}

	if includeCmds {
		cmdSheet := "Forensic Shell"
		f.NewSheet(cmdSheet)
		headers := []string{"SESSION ID", "TIMESTAMP", "SOURCE IP", "COMMAND", "COUNTRY", "CITY"}
		for i, h := range headers {
			cell, _ := excelize.CoordinatesToCellName(i+1, 1)
			f.SetCellValue(cmdSheet, cell, h)
			f.SetCellStyle(cmdSheet, cell, cell, style)
		}

		row := 2
		for _, sess := range sessions {
			cmds, _ := s.db.GetSessionCommands(sess.ID)
			for _, c := range cmds {
				f.SetCellValue(cmdSheet, fmt.Sprintf("A%d", row), sess.ID)
				f.SetCellValue(cmdSheet, fmt.Sprintf("B%d", row), c.Timestamp.Local().Format("2006-01-02 15:04:05"))
				f.SetCellValue(cmdSheet, fmt.Sprintf("C%d", row), sess.IP)
				f.SetCellValue(cmdSheet, fmt.Sprintf("D%d", row), c.Command)
				f.SetCellValue(cmdSheet, fmt.Sprintf("E%d", row), sess.Country)
				f.SetCellValue(cmdSheet, fmt.Sprintf("F%d", row), sess.City)
				row++
			}
		}
		lastCol, _ := excelize.CoordinatesToCellName(len(headers), row)
		f.AutoFilter(cmdSheet, "A1:"+lastCol, nil)
	}

	// Auto-width for all sheets
	for _, name := range f.GetSheetList() {
		f.SetColWidth(name, "A", "Z", 20)
	}

	var buf bytes.Buffer
	if err := f.Write(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
