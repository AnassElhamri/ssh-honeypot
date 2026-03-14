package server

import (
	"fmt"
	"math/rand"
	"strings"
	"time"
)

// Shell simulates a realistic Linux shell for attackers.
type Shell struct {
	hostname string
	username string
	fakeOS   string
	prompt   string
	cwd      string
	delayMs  int
}

// NewShell creates a fake shell with the given config.
func NewShell(hostname, username, fakeOS, prompt string, delayMs int) *Shell {
	return &Shell{
		hostname: hostname,
		username: username,
		fakeOS:   fakeOS,
		prompt:   prompt,
		cwd:      "/root",
		delayMs:  delayMs,
	}
}

// Execute processes a command and returns the fake response.
// It also simulates realistic processing delay.
func (s *Shell) Execute(input string) string {
	// Simulate processing delay — makes it feel real
	delay := time.Duration(s.delayMs+rand.Intn(40)) * time.Millisecond
	time.Sleep(delay)

	cmd := strings.TrimSpace(input)
	if cmd == "" {
		return ""
	}

	// Parse command and args
	parts := strings.Fields(cmd)
	base := parts[0]
	args := parts[1:]

	switch base {
	case "whoami":
		return s.username

	case "id":
		return fmt.Sprintf("uid=0(%s) gid=0(%s) groups=0(%s)", s.username, s.username, s.username)

	case "uname":
		if len(args) > 0 && args[0] == "-a" {
			return s.fakeOS
		}
		return "Linux"

	case "hostname":
		return s.hostname

	case "pwd":
		return s.cwd

	case "cd":
		return s.handleCd(args)

	case "ls":
		return s.handleLs(args)

	case "cat":
		return s.handleCat(args)

	case "echo":
		return strings.Join(args, " ")

	case "ps":
		return s.fakeProcList()

	case "w", "who":
		return s.fakeWho()

	case "uptime":
		return s.fakeUptime()

	case "df":
		return s.fakeDf()

	case "free":
		return s.fakeFree()

	case "ifconfig", "ip":
		return s.fakeIfconfig()

	case "netstat", "ss":
		return s.fakeNetstat()

	case "history":
		return "" // Good opsec — no history

	case "env", "printenv":
		return s.fakeEnv()

	case "wget":
		// Hang briefly then fail — attackers trying to download tools
		time.Sleep(3 * time.Second)
		return fmt.Sprintf("--2026-03-13 12:00:00--  %s\nResolving %s... failed: Name or service not known.",
			strings.Join(args, " "), strings.Join(args, " "))

	case "curl":
		time.Sleep(2 * time.Second)
		return "curl: (6) Could not resolve host"

	case "python", "python3":
		if len(args) == 0 {
			// Interactive python — just hang briefly
			time.Sleep(500 * time.Millisecond)
			return "Python 3.10.12 (main) [GCC 11.4.0] on linux\nType \"help\" for more information.\n>>>"
		}
		return ""

	case "bash", "sh":
		return "" // Just a new prompt

	case "passwd":
		return "passwd: Authentication token manipulation error"

	case "sudo":
		return fmt.Sprintf("[sudo] password for %s: \nSorry, try again.", s.username)

	case "apt", "apt-get", "yum", "dnf":
		return "E: Could not open lock file /var/lib/dpkg/lock-frontend - open (13: Permission denied)"

	case "chmod", "chown":
		if len(args) > 0 {
			return ""
		}
		return "missing operand"

	case "rm":
		// Log this — they're trying to delete things
		return ""

	case "find":
		return s.handleFind(args)

	case "grep":
		return ""

	case "iptables":
		return "iptables: No chain/target/match by that name."

	case "crontab":
		return ""

	case "systemctl":
		if len(args) > 0 && args[0] == "status" {
			return "● " + strings.Join(args[1:], " ") + "\n   Loaded: not-found (Reason: No such file or directory)"
		}
		return "System has not been booted with systemd as init system (PID 1). Can't operate."

	case "service":
		return "service: command not found"

	case "exit", "logout", "quit":
		return "__EXIT__" // Signal to close the session

	case "clear":
		return "\033[2J\033[H" // ANSI clear screen

	case "help":
		return "GNU bash, version 5.1.16(1)-release\nType 'man bash' for help."

	default:
		// For unknown commands, sometimes pretend it worked, sometimes say not found
		if rand.Intn(3) == 0 {
			return ""
		}
		return fmt.Sprintf("%s: command not found", base)
	}
}

// Prompt returns the current shell prompt string.
func (s *Shell) Prompt() string {
	return fmt.Sprintf("%s@%s:%s# ", s.username, s.hostname, s.cwdDisplay())
}

func (s *Shell) cwdDisplay() string {
	if s.cwd == "/root" {
		return "~"
	}
	return s.cwd
}

func (s *Shell) handleCd(args []string) string {
	if len(args) == 0 || args[0] == "~" {
		s.cwd = "/root"
		return ""
	}
	target := args[0]
	if strings.HasPrefix(target, "/") {
		s.cwd = target
	} else {
		s.cwd = s.cwd + "/" + target
	}
	return ""
}

func (s *Shell) handleLs(args []string) string {
	path := s.cwd
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			path = a
		}
	}

	listings := map[string]string{
		"/":        "bin   boot  dev  etc  home  lib  lib64  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var",
		"/var":     "backups  cache  lib  local  lock  log  mail  opt  run  spool  tmp",
		"/tmp":     ".ICE-unix  .Test-unix  systemd-private-5829-01",
		"/home":    "ubuntu",
		"/home/ubuntu": ".bash_logout  .bashrc  .profile  .ssh",
		"/root":    ".bash_history  .bash_logout  .bashrc  .profile  .ssh  .env  db_config.json  backups",
		"/root/backups": "db_dump_20230510.sql.gz  prod_config_backup.yaml",
		"/bin":     "bash  cat  chmod  chown  cp  curl  date  df  du  echo  find  grep  gzip  hostname  kill  less  ln  ls  mkdir  more  mount  mv  ping  ps  pwd  rm  sed  sh  sort  su  tail  tar  touch  uname  unzip  wget  which",
		"/usr/bin": "awk  base64  curl  env  find  git  head  htop  id  less  nano  nmap  perl  python3  ssh  tail  top  vi  vim  wget  who  whoami",
	}

	if content, ok := listings[path]; ok {
		if content == "" {
			return ""
		}
		return content
	}
	return fmt.Sprintf("ls: cannot access '%s': No such file or directory", path)
}

func (s *Shell) handleCat(args []string) string {
	if len(args) == 0 {
		return ""
	}
	files := map[string]string{
		"/etc/passwd": `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
ubuntu:x:1000:1000:ubuntu:/home/ubuntu:/bin/bash
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin`,

		"/etc/shadow": "cat: /etc/shadow: Permission denied",

		"/etc/hosts": `127.0.0.1   localhost
127.0.1.1   ` + s.hostname + `
::1         localhost ip6-localhost ip6-loopback`,

		"/etc/hostname": s.hostname,

		"/etc/issue": "Ubuntu 22.04.3 LTS \\n \\l\n",

		"/etc/os-release": `PRETTY_NAME="Ubuntu 22.04.3 LTS"
NAME="Ubuntu"
VERSION_ID="22.04"
VERSION="22.04.3 LTS (Jammy Jellyfish)"
ID=ubuntu
ID_LIKE=debian`,

		"/proc/version": "Linux version 5.15.0-91-generic (buildd@lcy02-amd64-032) " +
			"(gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0) #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023",

		"/proc/cpuinfo": `processor       : 0
vendor_id       : GenuineIntel
cpu family      : 6
model name      : Intel(R) Xeon(R) CPU E5-2676 v3 @ 2.40GHz
cpu MHz         : 2399.982
cache size      : 30720 KB
bogomips        : 4800.08`,

		"/root/.bash_history": "",
		"/root/.bashrc": `# ~/.bashrc: executed by bash(1) for non-login shells.
export PS1='\u@\h:\w\$ '
alias ll='ls -alF'
alias la='ls -A'`,
		"/root/.env": `STRIPE_API_KEY=sk_test_FAKE_Mv1qHJksE9vJk0m0z1q2w3e4r5t6y7u8i9o0p
AWS_ACCESS_KEY_ID=AKIA_MOCK_Y78P9O0I1U2Y
AWS_SECRET_ACCESS_KEY=FAKE_u8i9o0p0z1q2w3e4r5t6y7u8i9o0p0z1q2w3e4r
GITHUB_TOKEN=ghp_FAKE_0m0z1q2w3e4r5t6y7u8i9o0p0z1q2w3e4r5
DB_PASSWORD=SuperSecretPass123!`,
		"/root/db_config.json": `{
  "database": {
    "host": "production-db.internal",
    "port": 5432,
    "user": "admin",
    "password": "ProductionDatabaseStaticPassword!123",
    "ssl_mode": "require"
  }
}`,
		"/home/ubuntu/.bashrc": "# ~/.bashrc contents for ubuntu user...",
		"/etc/ssh/sshd_config": `Port 22
PermitRootLogin yes
PasswordAuthentication yes
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server`,
	}

	path := args[0]
	if content, ok := files[path]; ok {
		return content
	}
	return fmt.Sprintf("cat: %s: No such file or directory", path)
}

func (s *Shell) handleFind(args []string) string {
	// Simulate finding things but slowly
	time.Sleep(800 * time.Millisecond)
	joinedArgs := strings.Join(args, " ")
	if strings.Contains(joinedArgs, "passwd") || strings.Contains(joinedArgs, "shadow") {
		return "/etc/passwd\n/etc/pam.d/passwd"
	}
	if strings.Contains(joinedArgs, "ssh") {
		return "/etc/ssh\n/etc/ssh/sshd_config\n/root/.ssh"
	}
	return ""
}

func (s *Shell) fakeProcList() string {
	return `  PID TTY          TIME CMD
    1 ?        00:00:02 systemd
    2 ?        00:00:00 kthreadd
  432 ?        00:00:00 sshd
  891 ?        00:00:00 cron
 1024 pts/0    00:00:00 bash
 1156 pts/0    00:00:00 ps`
}

func (s *Shell) fakeWho() string {
	return fmt.Sprintf("root     pts/0        2026-03-13 08:%02d GMT", rand.Intn(60))
}

func (s *Shell) fakeUptime() string {
	days := rand.Intn(30) + 1
	hours := rand.Intn(24)
	users := rand.Intn(3) + 1
	return fmt.Sprintf(" 12:00:00 up %d days, %2d:%02d,  %d user,  load average: 0.0%d, 0.0%d, 0.0%d",
		days, hours, rand.Intn(60), users,
		rand.Intn(9), rand.Intn(9), rand.Intn(9))
}

func (s *Shell) fakeDf() string {
	return `Filesystem      Size  Used Avail Use% Mounted on
/dev/xvda1       20G  3.2G   16G  17% /
tmpfs           491M     0  491M   0% /dev/shm
tmpfs           5.0M     0  5.0M   0% /run/lock`
}

func (s *Shell) fakeFree() string {
	return `               total        used        free      shared  buff/cache   available
Mem:         1003316      456820      102444        1116      444052      398836
Swap:              0           0           0`
}

func (s *Shell) fakeIfconfig() string {
	return `eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 9001
        inet 172.31.42.100  netmask 255.255.240.0  broadcast 172.31.47.255
        inet6 fe80::878:b2ff:fe6a:1234  prefixlen 64  scopeid 0x20<link>
        ether 0a:78:b2:6a:12:34  txqueuelen 1000  (Ethernet)

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>`
}

func (s *Shell) fakeNetstat() string {
	return `Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN
tcp6       0      0 :::80                   :::*                    LISTEN`
}

func (s *Shell) fakeEnv() string {
	return fmt.Sprintf(`SHELL=/bin/bash
HOME=/root
LOGNAME=%s
USER=%s
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
LANG=en_US.UTF-8
TERM=xterm-256color`, s.username, s.username)
}
