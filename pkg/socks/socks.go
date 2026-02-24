package socks

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

// DialViaSocks5 establishes a TCP connection to target through a SOCKS5 proxy.
// Supports optional username/password authentication (RFC 1928/1929).
func DialViaSocks5(proxyAddr, targetAddr, username, password string) (net.Conn, error) {
	// Parse target
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid target address %q: %w", targetAddr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid port in %q: %w", targetAddr, err)
	}

	// Connect to proxy
	conn, err := net.DialTimeout("tcp", proxyAddr, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connect to SOCKS5 proxy %s: %w", proxyAddr, err)
	}

	// SOCKS5 greeting
	needAuth := username != ""
	var authMethods []byte
	if needAuth {
		authMethods = []byte{0x00, 0x02} // NO AUTH + USERNAME/PASSWORD
	} else {
		authMethods = []byte{0x00} // NO AUTH
	}

	greeting := make([]byte, 0, 3+len(authMethods))
	greeting = append(greeting, 0x05)                // VER
	greeting = append(greeting, byte(len(authMethods))) // NMETHODS
	greeting = append(greeting, authMethods...)

	if _, err := conn.Write(greeting); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 greeting: %w", err)
	}

	// Read server choice
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 greeting response: %w", err)
	}
	if resp[0] != 0x05 {
		conn.Close()
		return nil, errors.New("socks5: server returned invalid version")
	}

	chosenMethod := resp[1]
	switch chosenMethod {
	case 0x00:
		// No auth required
	case 0x02:
		// Username/password auth (RFC 1929)
		if err := doUsernamePasswordAuth(conn, username, password); err != nil {
			conn.Close()
			return nil, err
		}
	case 0xFF:
		conn.Close()
		return nil, errors.New("socks5: no acceptable auth method")
	default:
		conn.Close()
		return nil, fmt.Errorf("socks5: unsupported auth method 0x%02x", chosenMethod)
	}

	// CONNECT request
	req := buildConnectRequest(host, port)
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 connect request: %w", err)
	}

	// Read reply
	if err := readConnectReply(conn); err != nil {
		conn.Close()
		return nil, err
	}

	return conn, nil
}

func doUsernamePasswordAuth(conn net.Conn, username, password string) error {
	// VER=0x01, ULEN, UNAME, PLEN, PASSWD
	uLen := len(username)
	pLen := len(password)
	if uLen > 255 || pLen > 255 {
		return errors.New("socks5: username or password too long")
	}

	buf := make([]byte, 0, 3+uLen+pLen)
	buf = append(buf, 0x01)
	buf = append(buf, byte(uLen))
	buf = append(buf, []byte(username)...)
	buf = append(buf, byte(pLen))
	buf = append(buf, []byte(password)...)

	if _, err := conn.Write(buf); err != nil {
		return fmt.Errorf("socks5 auth write: %w", err)
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("socks5 auth response: %w", err)
	}
	if resp[1] != 0x00 {
		return errors.New("socks5: authentication failed")
	}
	return nil
}

func buildConnectRequest(host string, port int) []byte {
	// VER=5, CMD=CONNECT(1), RSV=0, ATYP, DST.ADDR, DST.PORT
	buf := []byte{0x05, 0x01, 0x00}

	// Try IP first
	ip := net.ParseIP(host)
	if ip4 := ip.To4(); ip4 != nil {
		buf = append(buf, 0x01) // IPv4
		buf = append(buf, ip4...)
	} else if ip16 := ip.To16(); ip16 != nil {
		buf = append(buf, 0x04) // IPv6
		buf = append(buf, ip16...)
	} else {
		// Domain name
		buf = append(buf, 0x03) // DOMAINNAME
		buf = append(buf, byte(len(host)))
		buf = append(buf, []byte(host)...)
	}

	// Port (big-endian)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))
	buf = append(buf, portBytes...)

	return buf
}

func readConnectReply(conn net.Conn) error {
	// VER, REP, RSV, ATYP
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return fmt.Errorf("socks5 reply: %w", err)
	}
	if header[0] != 0x05 {
		return errors.New("socks5: invalid reply version")
	}
	if header[1] != 0x00 {
		return fmt.Errorf("socks5: connect failed with code 0x%02x (%s)", header[1], replyCodeString(header[1]))
	}

	// Read bound address
	switch header[3] {
	case 0x01: // IPv4
		addr := make([]byte, 4+2)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return fmt.Errorf("socks5 reply addr: %w", err)
		}
	case 0x03: // Domain
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return fmt.Errorf("socks5 reply domain len: %w", err)
		}
		addr := make([]byte, int(lenBuf[0])+2)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return fmt.Errorf("socks5 reply domain: %w", err)
		}
	case 0x04: // IPv6
		addr := make([]byte, 16+2)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return fmt.Errorf("socks5 reply addr: %w", err)
		}
	default:
		return fmt.Errorf("socks5: unknown address type 0x%02x", header[3])
	}

	return nil
}

func replyCodeString(code byte) string {
	switch code {
	case 0x00:
		return "succeeded"
	case 0x01:
		return "general SOCKS server failure"
	case 0x02:
		return "connection not allowed by ruleset"
	case 0x03:
		return "network unreachable"
	case 0x04:
		return "host unreachable"
	case 0x05:
		return "connection refused"
	case 0x06:
		return "TTL expired"
	case 0x07:
		return "command not supported"
	case 0x08:
		return "address type not supported"
	default:
		return "unknown"
	}
}
