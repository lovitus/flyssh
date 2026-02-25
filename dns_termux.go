package main

import (
	"bufio"
	"context"
	"net"
	"os"
	"strings"
	"time"
)

// On Android/Termux, Go's pure-Go DNS resolver fails because there is no
// /etc/resolv.conf and no local DNS listener on :53. This init() detects
// Termux at runtime and configures net.DefaultResolver to use discovered
// or well-known public DNS servers directly.
//
// NOTE: We intentionally avoid os/exec.Command here because Go 1.20+'s
// exec.LookPath calls faccessat2 (syscall 439), which Android's seccomp
// filter blocks with SIGSYS. Instead we parse resolv.conf files directly.
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

// getAndroidDNS tries to discover DNS servers by parsing resolv.conf files.
// We avoid exec.Command("getprop") because Android's seccomp blocks
// the faccessat2 syscall that Go's os/exec.LookPath uses internally.
func getAndroidDNS() []string {
	paths := []string{
		"/etc/resolv.conf",
		os.Getenv("PREFIX") + "/etc/resolv.conf",
	}
	for _, path := range paths {
		if servers := parseResolvConf(path); len(servers) > 0 {
			return servers
		}
	}
	return nil
}

func parseResolvConf(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var servers []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "nameserver") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ip := fields[1]
		if ip == "" || ip == "0.0.0.0" {
			continue
		}
		if !strings.Contains(ip, ":") || net.ParseIP(ip) != nil {
			// IPv4 or valid IPv6 — append port
			if !strings.Contains(ip, ":") {
				ip += ":53"
			} else {
				ip = "[" + ip + "]:53"
			}
			servers = append(servers, ip)
		}
	}
	return servers
}
