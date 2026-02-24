package forwarding

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
)

// StartLocalForward starts local port forwarding: -L [bind_address:]port:host:hostport
func StartLocalForward(client *ssh.Client, spec string, verbose bool) error {
	bindAddr, remoteAddr, err := parseForwardSpec(spec)
	if err != nil {
		return fmt.Errorf("invalid local forward spec %q: %w", spec, err)
	}

	listener, err := net.Listen("tcp", bindAddr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", bindAddr, err)
	}
	defer listener.Close()

	if verbose {
		log.Printf("Local forward: listening on %s -> %s", bindAddr, remoteAddr)
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			return fmt.Errorf("accept: %w", err)
		}
		go func() {
			defer conn.Close()
			remote, err := client.Dial("tcp", remoteAddr)
			if err != nil {
				if verbose {
					log.Printf("Local forward: dial %s failed: %v", remoteAddr, err)
				}
				return
			}
			defer remote.Close()
			biCopy(conn, remote)
		}()
	}
}

// StartRemoteForward starts remote port forwarding: -R [bind_address:]port:host:hostport
func StartRemoteForward(client *ssh.Client, spec string, verbose bool) error {
	bindAddr, localAddr, err := parseForwardSpec(spec)
	if err != nil {
		return fmt.Errorf("invalid remote forward spec %q: %w", spec, err)
	}

	listener, err := client.Listen("tcp", bindAddr)
	if err != nil {
		return fmt.Errorf("remote listen on %s: %w", bindAddr, err)
	}
	defer listener.Close()

	if verbose {
		log.Printf("Remote forward: remote %s -> local %s", bindAddr, localAddr)
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			return fmt.Errorf("remote accept: %w", err)
		}
		go func() {
			defer conn.Close()
			local, err := net.Dial("tcp", localAddr)
			if err != nil {
				if verbose {
					log.Printf("Remote forward: dial local %s failed: %v", localAddr, err)
				}
				return
			}
			defer local.Close()
			biCopy(conn, local)
		}()
	}
}

// StartDynamicForward starts dynamic port forwarding (SOCKS5 server): -D [bind_address:]port
func StartDynamicForward(client *ssh.Client, spec string, verbose bool) error {
	bindAddr := spec
	if !strings.Contains(bindAddr, ":") {
		bindAddr = "127.0.0.1:" + bindAddr
	}

	listener, err := net.Listen("tcp", bindAddr)
	if err != nil {
		return fmt.Errorf("dynamic forward listen on %s: %w", bindAddr, err)
	}
	defer listener.Close()

	if verbose {
		log.Printf("Dynamic forward (SOCKS5): listening on %s", bindAddr)
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			if verbose {
				log.Printf("Dynamic forward accept error: %v", err)
			}
			continue
		}
		go handleSocks5Client(client, conn, verbose)
	}
}

func handleSocks5Client(client *ssh.Client, conn net.Conn, verbose bool) {
	defer conn.Close()

	// SOCKS5 handshake
	// Read version and auth methods
	buf := make([]byte, 258)
	n, err := conn.Read(buf)
	if err != nil || n < 2 {
		return
	}
	if buf[0] != 0x05 {
		return
	}

	// We only support no-auth for local SOCKS5 server
	conn.Write([]byte{0x05, 0x00})

	// Read connect request
	n, err = conn.Read(buf)
	if err != nil || n < 7 {
		return
	}
	if buf[0] != 0x05 || buf[1] != 0x01 {
		// Only CONNECT supported
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	var targetHost string
	var targetPort int
	addrType := buf[3]
	var addrEnd int

	switch addrType {
	case 0x01: // IPv4
		if n < 10 {
			return
		}
		targetHost = net.IP(buf[4:8]).String()
		targetPort = int(binary.BigEndian.Uint16(buf[8:10]))
		addrEnd = 10
	case 0x03: // Domain
		domainLen := int(buf[4])
		if n < 5+domainLen+2 {
			return
		}
		targetHost = string(buf[5 : 5+domainLen])
		targetPort = int(binary.BigEndian.Uint16(buf[5+domainLen : 5+domainLen+2]))
		addrEnd = 5 + domainLen + 2
	case 0x04: // IPv6
		if n < 22 {
			return
		}
		targetHost = net.IP(buf[4:20]).String()
		targetPort = int(binary.BigEndian.Uint16(buf[20:22]))
		addrEnd = 22
	default:
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	_ = addrEnd

	targetAddr := net.JoinHostPort(targetHost, strconv.Itoa(targetPort))

	if verbose {
		log.Printf("Dynamic forward: CONNECT %s", targetAddr)
	}

	// Dial through SSH
	remote, err := client.Dial("tcp", targetAddr)
	if err != nil {
		if verbose {
			log.Printf("Dynamic forward: dial %s failed: %v", targetAddr, err)
		}
		conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer remote.Close()

	// Success reply
	reply := []byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	conn.Write(reply)

	// Bidirectional copy
	biCopy(conn, remote)
}

func biCopy(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(b, a)
		if tc, ok := b.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		io.Copy(a, b)
		if tc, ok := a.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()
	wg.Wait()
}

// parseForwardSpec parses "[bind_address:]port:host:hostport" into bind and remote addresses
func parseForwardSpec(spec string) (bindAddr, remoteAddr string, err error) {
	parts := strings.Split(spec, ":")
	switch len(parts) {
	case 3:
		// port:host:hostport
		bindAddr = "127.0.0.1:" + parts[0]
		remoteAddr = net.JoinHostPort(parts[1], parts[2])
	case 4:
		// bind_address:port:host:hostport
		bindAddr = net.JoinHostPort(parts[0], parts[1])
		remoteAddr = net.JoinHostPort(parts[2], parts[3])
	default:
		err = fmt.Errorf("expected [bind_address:]port:host:hostport, got %q", spec)
	}
	return
}
