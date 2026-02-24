package forwarding

import (
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/flyssh/flyssh/pkg/muxproto"
	"golang.org/x/crypto/ssh"
)

// MuxDialer multiplexes many TCP connections over a single SSH exec session
// running the relay binary in -mux mode. Only 1 SSH session is used for all
// forwarded connections, avoiding MaxSessions exhaustion.
type MuxDialer struct {
	writer  *muxproto.SafeWriter
	session *ssh.Session
	stdin   io.WriteCloser
	nextID  atomic.Uint32

	mu      sync.Mutex
	streams map[uint32]*muxStream
	closed  bool
	closeCh chan struct{}
}

type muxStream struct {
	id        uint32
	dialer    *MuxDialer
	connectCh chan error    // CONNECT_OK (nil) or CONNECT_FAIL (error)
	dataCh    chan []byte   // incoming DATA payloads
	current   []byte       // partial read leftover
	closeCh   chan struct{} // closed when stream ends
	closeOnce sync.Once
}

// NewMuxDialer uploads the relay if needed, starts it in -mux mode, and
// returns a dialer that can open unlimited TCP connections through it.
func NewMuxDialer(client *ssh.Client, relayPath string, verbose bool) (*MuxDialer, error) {
	sess, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("mux session: %w", err)
	}

	stdin, err := sess.StdinPipe()
	if err != nil {
		sess.Close()
		return nil, err
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		sess.Close()
		return nil, err
	}

	cmd := relayPath + " -mux"
	if err := sess.Start(cmd); err != nil {
		sess.Close()
		return nil, fmt.Errorf("start mux relay: %w", err)
	}

	d := &MuxDialer{
		writer:  muxproto.NewSafeWriter(stdin),
		session: sess,
		stdin:   stdin,
		streams: make(map[uint32]*muxStream),
		closeCh: make(chan struct{}),
	}

	go d.readLoop(stdout)

	if verbose {
		log.Printf("Mux relay started (1 SSH session for all forwarded connections)")
	}
	return d, nil
}

func (d *MuxDialer) readLoop(r io.Reader) {
	defer func() {
		d.mu.Lock()
		d.closed = true
		for _, s := range d.streams {
			s.closeLocal()
		}
		d.mu.Unlock()
		close(d.closeCh)
	}()

	for {
		frame, err := muxproto.ReadFrame(r)
		if err != nil {
			return
		}

		d.mu.Lock()
		s := d.streams[frame.StreamID]
		d.mu.Unlock()
		if s == nil {
			continue
		}

		switch frame.Type {
		case muxproto.TypeConnectOK:
			select {
			case s.connectCh <- nil:
			default:
			}

		case muxproto.TypeConnectFail:
			select {
			case s.connectCh <- fmt.Errorf("%s", string(frame.Payload)):
			default:
			}
			s.closeLocal()

		case muxproto.TypeData:
			select {
			case s.dataCh <- frame.Payload:
			case <-s.closeCh:
			}

		case muxproto.TypeClose:
			s.closeLocal()
		}
	}
}

// Dial opens a new multiplexed TCP connection to addr (host:port) through the relay.
func (d *MuxDialer) Dial(addr string) (net.Conn, error) {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil, fmt.Errorf("mux dialer closed")
	}

	id := d.nextID.Add(1)
	s := &muxStream{
		id:        id,
		dialer:    d,
		connectCh: make(chan error, 1),
		dataCh:    make(chan []byte, 256),
		closeCh:   make(chan struct{}),
	}
	d.streams[id] = s
	d.mu.Unlock()

	// Send CONNECT request
	err := d.writer.WriteFrame(&muxproto.Frame{
		Type:     muxproto.TypeConnect,
		StreamID: id,
		Payload:  []byte(addr),
	})
	if err != nil {
		d.removeStream(id)
		return nil, err
	}

	// Wait for CONNECT_OK or CONNECT_FAIL
	select {
	case connErr := <-s.connectCh:
		if connErr != nil {
			d.removeStream(id)
			return nil, connErr
		}
		return s, nil
	case <-time.After(15 * time.Second):
		d.removeStream(id)
		return nil, fmt.Errorf("mux connect timeout")
	case <-d.closeCh:
		return nil, fmt.Errorf("mux dialer closed")
	}
}

// IsClosed returns true if the mux session has been closed.
func (d *MuxDialer) IsClosed() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.closed
}

func (d *MuxDialer) removeStream(id uint32) {
	d.mu.Lock()
	delete(d.streams, id)
	d.mu.Unlock()
}

// Close shuts down the mux session and all streams.
func (d *MuxDialer) Close() error {
	d.mu.Lock()
	d.closed = true
	for _, s := range d.streams {
		s.closeLocal()
	}
	d.mu.Unlock()
	d.stdin.Close()
	return d.session.Close()
}

// --- muxStream implements net.Conn ---

func (s *muxStream) Read(b []byte) (int, error) {
	if len(s.current) > 0 {
		n := copy(b, s.current)
		s.current = s.current[n:]
		return n, nil
	}

	select {
	case data, ok := <-s.dataCh:
		if !ok {
			return 0, io.EOF
		}
		n := copy(b, data)
		if n < len(data) {
			s.current = data[n:]
		}
		return n, nil
	case <-s.closeCh:
		return 0, io.EOF
	}
}

func (s *muxStream) Write(b []byte) (int, error) {
	total := 0
	for len(b) > 0 {
		chunk := b
		if len(chunk) > muxproto.MaxPayload {
			chunk = chunk[:muxproto.MaxPayload]
		}
		err := s.dialer.writer.WriteFrame(&muxproto.Frame{
			Type:     muxproto.TypeData,
			StreamID: s.id,
			Payload:  chunk,
		})
		if err != nil {
			return total, err
		}
		total += len(chunk)
		b = b[len(chunk):]
	}
	return total, nil
}

func (s *muxStream) Close() error {
	s.dialer.writer.WriteFrame(&muxproto.Frame{
		Type:     muxproto.TypeClose,
		StreamID: s.id,
	})
	s.closeLocal()
	s.dialer.removeStream(s.id)
	return nil
}

func (s *muxStream) closeLocal() {
	s.closeOnce.Do(func() {
		close(s.closeCh)
	})
}

func (s *muxStream) LocalAddr() net.Addr                { return nil }
func (s *muxStream) RemoteAddr() net.Addr               { return nil }
func (s *muxStream) SetDeadline(t time.Time) error      { return nil }
func (s *muxStream) SetReadDeadline(t time.Time) error  { return nil }
func (s *muxStream) SetWriteDeadline(t time.Time) error { return nil }
