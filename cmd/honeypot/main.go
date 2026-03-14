package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/AnassElhamri/ssh-honeypot/internal/dashboard"
	"github.com/AnassElhamri/ssh-honeypot/internal/geoip"
	"github.com/AnassElhamri/ssh-honeypot/internal/logger"
	"github.com/AnassElhamri/ssh-honeypot/internal/reporter"
	"github.com/AnassElhamri/ssh-honeypot/internal/server"
)

// appConfig mirrors config.yaml structure.
type appConfig struct {
	Server struct {
		Host              string `yaml:"host"`
		Port              int    `yaml:"port"`
		MaxConnections    int    `yaml:"max_connections"`
		ConnectionTimeout int    `yaml:"connection_timeout"`
		Banner            string `yaml:"banner"`
	} `yaml:"server"`
	Shell struct {
		Hostname        string `yaml:"hostname"`
		Username        string `yaml:"username"`
		FakeOS          string `yaml:"fake_os"`
		Prompt          string `yaml:"prompt"`
		ResponseDelayMs int    `yaml:"response_delay_ms"`
	} `yaml:"shell"`
	Database struct {
		Path string `yaml:"path"`
	} `yaml:"database"`
	GeoIP struct {
		DatabasePath string `yaml:"database_path"`
	} `yaml:"geoip"`
	Logging struct {
		Level       string `yaml:"level"`
		SessionsDir string `yaml:"sessions_dir"`
	} `yaml:"logging"`
	Dashboard struct {
		Enabled   bool `yaml:"enabled"`
		RefreshMs int  `yaml:"refresh_ms"`
	} `yaml:"dashboard"`
	Reporter struct {
		Enabled   bool   `yaml:"enabled"`
		OutputDir string `yaml:"output_dir"`
		Schedule  string `yaml:"schedule"`
	} `yaml:"reporter"`
	Alerts struct {
		DiscordWebhook string `yaml:"discord_webhook"`
	} `yaml:"alerts"`
}

func main() {
	configPath  := flag.String("config", "config.yaml", "Path to config file")
	reportOnly  := flag.Bool("report", false, "Generate a report and exit")
	noDashboard := flag.Bool("no-dashboard", false, "Disable live dashboard")
	flag.Parse()

	printBanner()

	// ── Load config ───────────────────────────────────────────────────────────
	cfg, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	// ── Ensure data directories exist ─────────────────────────────────────────
	os.MkdirAll("data/sessions", 0755)
	os.MkdirAll("data/reports", 0755)

	// ── Open database ─────────────────────────────────────────────────────────
	db, err := logger.Open(cfg.Database.Path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	// ── Alerts & Logger ───────────────────────────────────────────────────────
	alerts := logger.NewAlertHandler(cfg.Alerts.DiscordWebhook)

	logLevel := logger.INFO
	if cfg.Logging.Level == "debug" {
		logLevel = logger.DEBUG
	}
	log := logger.New(logLevel, cfg.Logging.SessionsDir, db, alerts)

	// ── GeoIP ─────────────────────────────────────────────────────────────────
	geo := geoip.New(cfg.GeoIP.DatabasePath)
	defer geo.Close()

	// ── Reporter ──────────────────────────────────────────────────────────────
	rep := reporter.New(db, cfg.Reporter.OutputDir)

	if *reportOnly {
		fmt.Println("Generating report...")
		if err := rep.GenerateReport(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	// ── Build SSH server ──────────────────────────────────────────────────────
	srvCfg := &server.Config{
		Host:              cfg.Server.Host,
		Port:              cfg.Server.Port,
		MaxConnections:    cfg.Server.MaxConnections,
		ConnectionTimeout: time.Duration(cfg.Server.ConnectionTimeout) * time.Second,
		Banner:            cfg.Server.Banner,
		ShellHostname:     cfg.Shell.Hostname,
		ShellUsername:     cfg.Shell.Username,
		FakeOS:            cfg.Shell.FakeOS,
		ShellPrompt:       cfg.Shell.Prompt,
		ResponseDelayMs:   cfg.Shell.ResponseDelayMs,
		HostKeyPath:       "data/host_key",
	}

	srv, err := server.New(srvCfg, log, db, geo)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating server: %v\n", err)
		os.Exit(1)
	}

	// ── Graceful shutdown logic ───────────────────────────────────────────────
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	shutdown := make(chan struct{})

	// ── Dashboard — uses the server's own tracker ─────────────────────────────
	var dash *dashboard.Dashboard
	if cfg.Dashboard.Enabled && !*noDashboard {
		dash = dashboard.New(db, srv.Tracker(), cfg.Dashboard.RefreshMs)
		log.SetCallback(dash.AddLogLine)
		dash.Start(func() {
			close(shutdown)
		})
		log.Info("Dashboard started — press Q to quit")
	}

	// ── Reporter scheduler ────────────────────────────────────────────────────
	if cfg.Reporter.Enabled {
		rep.StartScheduler(cfg.Reporter.Schedule)
		log.Info("Reporter scheduled: %s", cfg.Reporter.Schedule)
	}

	// ── Start server ──────────────────────────────────────────────────────────
	go func() {
		if err := srv.Listen(); err != nil {
			log.Error("Server error: %v", err)
			os.Exit(1)
		}
	}()

	// Wait for either Ctrl+C or Dashboard closing
	select {
	case <-quit:
	case <-shutdown:
	}

	fmt.Println("\nShutting down...")
	if dash != nil {
		dash.Stop()
	}
	fmt.Println("Generating final report...")
	rep.GenerateReport()
	fmt.Println("Done.")
	os.Exit(0)
}

func loadConfig(path string) (*appConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg appConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	// Apply defaults
	if cfg.Server.Port == 0              { cfg.Server.Port = 2222 }
	if cfg.Server.MaxConnections == 0    { cfg.Server.MaxConnections = 100 }
	if cfg.Server.ConnectionTimeout == 0 { cfg.Server.ConnectionTimeout = 120 }
	if cfg.Server.Banner == ""           { cfg.Server.Banner = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6" }
	if cfg.Server.Host == ""             { cfg.Server.Host = "0.0.0.0" }
	if cfg.Shell.Hostname == ""          { cfg.Shell.Hostname = "ubuntu-server" }
	if cfg.Shell.Username == ""          { cfg.Shell.Username = "root" }
	if cfg.Shell.ResponseDelayMs == 0    { cfg.Shell.ResponseDelayMs = 80 }
	if cfg.Database.Path == ""           { cfg.Database.Path = "data/honeypot.db" }
	if cfg.Dashboard.RefreshMs == 0      { cfg.Dashboard.RefreshMs = 1000 }
	if cfg.Reporter.OutputDir == ""      { cfg.Reporter.OutputDir = "data/reports" }
	if cfg.Reporter.Schedule == ""       { cfg.Reporter.Schedule = "daily" }
	if cfg.Logging.SessionsDir == ""     { cfg.Logging.SessionsDir = "data/sessions" }
	return &cfg, nil
}

func printBanner() {
	fmt.Print(`
 ███████╗███████╗██╗  ██╗    ██╗  ██╗ ██████╗ ███╗   ██╗███████╗██╗   ██╗██████╗  ██████╗ ████████╗
 ██╔════╝██╔════╝██║  ██║    ██║  ██║██╔═══██╗████╗  ██║██╔════╝╚██╗ ██╔╝██╔══██╗██╔═══██╗╚══██╔══╝
 ███████╗███████╗███████║    ███████║██║   ██║██╔██╗ ██║█████╗   ╚████╔╝ ██████╔╝██║   ██║   ██║
 ╚════██║╚════██║██╔══██║    ██╔══██║██║   ██║██║╚██╗██║██╔══╝    ╚██╔╝  ██╔═══╝ ██║   ██║   ██║
 ███████║███████║██║  ██║    ██║  ██║╚██████╔╝██║ ╚████║███████╗   ██║   ██║     ╚██████╔╝   ██║
 ╚══════╝╚══════╝╚═╝  ╚═╝    ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝      ╚═════╝    ╚═╝

 Deception Technology  |  Threat Intelligence  |  Real-time Monitoring
 github.com/AnassElhamri/ssh-honeypot

`)
}
