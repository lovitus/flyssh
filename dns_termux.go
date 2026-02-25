package main

import (
	"context"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

// On Android/Termux, Go's pure-Go DNS resolver fails because there is no
// /etc/resolv.conf and no local DNS listener on :53. Android uses getprop
// to discover DNS servers. This init() detects Termux at runtime and
// configures net.DefaultResolver to use the system DNS servers directly,
// falling back to public DNS (8.8.8.8, 1.1.1.1) if getprop fails.
func init() {
	if !isTermux() {
		return
	}
	servers := getAndroidDNS()
	if len(servers) == 0 {
		servers = []string{"8.8.8.8:53", "1.1.1.1:53"}
	}
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			var lastErr error
			for _, server := range servers {
				conn, err := d.DialContext(ctx, "udp", server)
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			return nil, lastErr
		},
	}
}

func isTermux() bool {
	if os.Getenv("TERMUX_VERSION") != "" {
		return true
	}
	if strings.HasPrefix(os.Getenv("PREFIX"), "/data/data/com.termux") {
		return true
	}
	return false
}

func getAndroidDNS() []string {
	var servers []string
	for _, prop := range []string{"net.dns1", "net.dns2", "net.dns3", "net.dns4"} {
		out, err := exec.Command("getprop", prop).Output()
		if err != nil {
			continue
		}
		s := strings.TrimSpace(string(out))
		if s != "" && s != "0.0.0.0" {
			if !strings.Contains(s, ":") {
				s += ":53"
			}
			servers = append(servers, s)
		}
	}
	return servers
}
