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

	// Stderr and down→up request proxy run fully in the background; closing
	// the channels below will unblock them once the session ends.
	go io.Copy(upCh.Stderr(), downCh.Stderr())
	go io.Copy(downCh.Stderr(), upCh.Stderr())
	go proxyRequests(downReqs, upCh, downstreamToUpstream, verbose, "down→up")

	// up→down request proxy carries exit-status and must be drained before
	// we close the downstream channel.  upReqs is closed by the SSH library
	// when the upstream sends SSH_MSG_CHANNEL_CLOSE (which arrives right
	// after exit-status + EOF in the normal SSH protocol sequence).
	var upReqWg sync.WaitGroup
	upReqWg.Add(1)
	go func() {
		defer upReqWg.Done()
		proxyRequests(upReqs, downCh, upstreamToDownstream, verbose, "up→down")
	}()

	// done is closed after the downstream channel is fully shut down.
	done := make(chan struct{})

	// Upstream→downstream goroutine: when upstream closes, first drain
	// exit-status (upReqWg), then send a full SSH_MSG_CHANNEL_CLOSE to the
	// downstream client.  Sending CLOSE (not just EOF/CloseWrite) is
	// required for clients such as rsync that hold their write side open
	// until they see the server's CLOSE message.
	go func() {
		io.Copy(downCh, upCh)
		upReqWg.Wait()
		downCh.Close()
		close(done)
	}()

	// Downstream→upstream goroutine: runs until either the client closes
	// its write side or downCh.Close() above makes reads return an error.
	go func() {
		io.Copy(upCh, downCh)
		upCh.CloseWrite()
		upCh.Close()
	}()

	<-done
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
