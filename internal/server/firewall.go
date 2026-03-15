package server

import (
	"fmt"
	"os/exec"
	"runtime"
)

// Firewall handles OS-level blocking.
type Firewall struct {
	enabled bool
}

// NewFirewall creates a new firewall controller.
func NewFirewall() *Firewall {
	// Only enable if we have sudo or are on Linux
	return &Firewall{
		enabled: runtime.GOOS == "linux",
	}
}

// BlockIP runs the OS command to block an IP address.
func (f *Firewall) BlockIP(ip string) error {
	if !f.enabled {
		return fmt.Errorf("ip blocking not supported on this OS")
	}

	// Try UFW first (common on Ubuntu)
	if _, err := exec.LookPath("ufw"); err == nil {
		cmd := exec.Command("sudo", "ufw", "deny", "from", ip)
		if err := cmd.Run(); err == nil {
			return nil
		}
	}

	// Fallback to iptables
	if _, err := exec.LookPath("iptables"); err == nil {
		cmd := exec.Command("sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP")
		return cmd.Run()
	}

	return fmt.Errorf("no supported firewall (ufw/iptables) found")
}
