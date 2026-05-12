package gateway

import (
	"fmt"
	"io"
	"log"
	"net"
	"sync"

	"github.com/flyssh/flyssh/pkg/forwarding"
	"golang.org/x/crypto/ssh"
)

// Directional request allowlists.
var (
	// downstreamToUpstream: requests the client sends that we forward to the real server.
	downstreamToUpstream = map[string]bool{
		"pty-req":         true,
		"window-change":   true,
		"env":             true,
		"shell":           true,
		"exec":            true,
		"subsystem":       true,
		"signal":          true,
		"eow@openssh.com": true,
	}

	// upstreamToDownstream: requests the real server sends that we forward to the client.
	upstreamToDownstream = map[string]bool{
		"exit-status":     true,
		"exit-signal":     true,
		"eow@openssh.com": true,
	}
)

// handleChannels processes new channel requests from a downstream SSH client.
func handleChannels(chans <-chan ssh.NewChannel, upstream *ssh.Client, verbose bool) {
	for newCh := range chans {
		switch newCh.ChannelType() {
		case "session":
			go handleSession(newCh, upstream, verbose)
		case "direct-tcpip":
			go handleDirectTCPIP(newCh, upstream, verbose)
		default:
			newCh.Reject(ssh.UnknownChannelType, fmt.Sprintf("unsupported channel type: %s", newCh.ChannelType()))
		}
	}
}

// handleSession proxies a session channel between downstream and upstream.
func handleSession(newCh ssh.NewChannel, upstream *ssh.Client, verbose bool) {
	// Open upstream first — if server rejects (e.g. MaxSessions), reject downstream.
	upCh, upReqs, err := upstream.OpenChannel("session", nil)
	if err != nil {
		newCh.Reject(ssh.ResourceShortage, fmt.Sprintf("upstream session: %v", err))
		return
	}

	downCh, downReqs, err := newCh.Accept()
	if err != nil {
		upCh.Close()
		return
	}

	// Stderr and request proxy run in the background; closing the channels
	// (below) will unblock them once data transfer is done.
	go io.Copy(upCh.Stderr(), downCh.Stderr())
	go io.Copy(downCh.Stderr(), upCh.Stderr())
	go proxyRequests(downReqs, upCh, downstreamToUpstream, verbose, "down→up")
	go proxyRequests(upReqs, downCh, upstreamToDownstream, verbose, "up→down")

	// Wait only for bidirectional stdout to finish, then close both channels.
	// This unblocks the stderr and request goroutines immediately, preventing
	// the session from hanging after SCP completes or the user types exit.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(upCh, downCh)
		upCh.CloseWrite()
	}()
	go func() {
		defer wg.Done()
		io.Copy(downCh, upCh)
		downCh.CloseWrite()
	}()
	wg.Wait()

	downCh.Close()
	upCh.Close()
}

// proxyRequests forwards SSH channel requests according to the given allowlist.
func proxyRequests(reqs <-chan *ssh.Request, target ssh.Channel, allowed map[string]bool, verbose bool, direction string) {
	for req := range reqs {
		if req == nil {
			return
		}
		if !allowed[req.Type] {
			if verbose {
				log.Printf("[gateway] %s: denied request %q", direction, req.Type)
			}
			if req.WantReply {
				req.Reply(false, nil)
			}
			continue
		}
		ok, err := target.SendRequest(req.Type, req.WantReply, req.Payload)
		if err != nil {
			if req.WantReply {
				req.Reply(false, nil)
			}
			continue
		}
		if req.WantReply {
			req.Reply(ok, nil)
		}
	}
}

// directTCPIPData matches the SSH direct-tcpip channel open extra data.
type directTCPIPData struct {
	DestHost   string
	DestPort   uint32
	OriginHost string
	OriginPort uint32
}

type closeWriter interface {
	CloseWrite() error
}

func closeWrite(v any) {
	if cw, ok := v.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
}

// handleDirectTCPIP proxies a direct-tcpip channel to the upstream network.
func handleDirectTCPIP(newCh ssh.NewChannel, upstream *ssh.Client, verbose bool) {
	var reqData directTCPIPData
	if err := ssh.Unmarshal(newCh.ExtraData(), &reqData); err != nil {
		newCh.Reject(ssh.ConnectionFailed, "invalid direct-tcpip data")
		return
	}

	addr := net.JoinHostPort(reqData.DestHost, fmt.Sprintf("%d", reqData.DestPort))

	// Dial upstream first — reject downstream if dial fails.
	conn, err := forwarding.DialTCP(upstream, addr, verbose)
	if err != nil {
		newCh.Reject(ssh.ConnectionFailed, fmt.Sprintf("dial %s: %v", addr, err))
		return
	}

	downCh, _, err := newCh.Accept()
	if err != nil {
		conn.Close()
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(conn, downCh)
		closeWrite(conn)
	}()
	go func() {
		defer wg.Done()
		io.Copy(downCh, conn)
		closeWrite(downCh)
	}()
	wg.Wait()

	downCh.Close()
	conn.Close()
}
