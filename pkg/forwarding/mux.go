package forwarding

import (
	"encoding/binary"
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

	mu        sync.Mutex
	streams   map[uint32]*muxStream
	listeners map[uint32]*muxListener
	closed    bool
	closeCh   chan struct{}
	closeOnce sync.Once
	waitCh    chan error
}

type muxStream struct {
	id        uint32
	dialer    *MuxDialer
	connectCh chan error    // CONNECT_OK (nil) or CONNECT_FAIL (error)
	dataCh    chan []byte   // incoming DATA payloads
	current   []byte        // partial read leftover
	closeCh   chan struct{} // closed when stream ends
	closeOnce sync.Once
}

type muxListener struct {
	id       uint32
	dialer   *MuxDialer
	acceptCh chan net.Conn
	readyCh  chan error
	closeCh  chan struct{}
	addr     net.Addr
	closed   bool
}

type muxAddr string

func (a muxAddr) Network() string { return "tcp" }
func (a muxAddr) String() string  { return string(a) }

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
		writer:    muxproto.NewSafeWriter(stdin),
		session:   sess,
		stdin:     stdin,
		streams:   make(map[uint32]*muxStream),
		listeners: make(map[uint32]*muxListener),
		closeCh:   make(chan struct{}),
		waitCh:    make(chan error, 1),
	}

	go d.readLoop(stdout)
	go func() {
		d.waitCh <- sess.Wait()
		close(d.waitCh)
	}()

	if verbose {
		log.Printf("Mux relay started (1 SSH session for all forwarded connections)")
	}
	return d, nil
}

func (d *MuxDialer) readLoop(r io.Reader) {
	defer func() {
		var queued []net.Conn
		d.mu.Lock()
		d.closed = true
		for _, s := range d.streams {
			s.closeLocal()
		}
		for _, l := range d.listeners {
			queued = append(queued, l.closeLocalLocked()...)
		}
		d.mu.Unlock()
		closeAcceptedConns(queued)
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

		switch frame.Type {
		case muxproto.TypeConnectOK:
			if s == nil {
				continue
			}
			select {
			case s.connectCh <- nil:
			default:
			}

		case muxproto.TypeConnectFail:
			if s == nil {
				continue
			}
			select {
			case s.connectCh <- fmt.Errorf("%s", string(frame.Payload)):
			default:
			}
			s.closeLocal()

		case muxproto.TypeData:
			if s == nil {
				continue
			}
			select {
			case s.dataCh <- frame.Payload:
			case <-s.closeCh:
			}

		case muxproto.TypeClose:
			if s != nil {
				s.closeLocal()
			}

		case muxproto.TypeListenOK:
			d.mu.Lock()
			l := d.listeners[frame.StreamID]
			d.mu.Unlock()
			if l == nil {
				continue
			}
			l.addr = muxAddr(string(frame.Payload))
			select {
			case l.readyCh <- nil:
			default:
			}

		case muxproto.TypeListenFail:
			d.mu.Lock()
			l := d.listeners[frame.StreamID]
			delete(d.listeners, frame.StreamID)
			d.mu.Unlock()
			if l == nil {
				continue
			}
			select {
			case l.readyCh <- fmt.Errorf("%s", string(frame.Payload)):
			default:
			}
			l.closeLocal()

		case muxproto.TypeAccepted:
			if len(frame.Payload) < 4 {
				continue
			}
			listenerID := binary.BigEndian.Uint32(frame.Payload[:4])
			d.mu.Lock()
			l := d.listeners[listenerID]
			if l == nil || l.closed || d.closed {
				d.mu.Unlock()
				_ = d.writer.WriteFrame(&muxproto.Frame{Type: muxproto.TypeClose, StreamID: frame.StreamID})
				continue
			}
			s := &muxStream{
				id:        frame.StreamID,
				dialer:    d,
				connectCh: make(chan error, 1),
				dataCh:    make(chan []byte, 256),
				closeCh:   make(chan struct{}),
			}
			accepted := false
			select {
			case l.acceptCh <- s:
				d.streams[frame.StreamID] = s
				accepted = true
			default:
				s.closeLocal()
			}
			d.mu.Unlock()
			if !accepted {
				_ = d.writer.WriteFrame(&muxproto.Frame{Type: muxproto.TypeClose, StreamID: frame.StreamID})
			}
		}
	}
}

func (d *MuxDialer) nextLocalStreamID() uint32 {
	return d.nextID.Add(2) - 1
}

// Dial opens a new multiplexed TCP connection to addr (host:port) through the relay.
func (d *MuxDialer) Dial(addr string) (net.Conn, error) {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil, fmt.Errorf("mux dialer closed")
	}

	id := d.nextLocalStreamID()
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

func (d *MuxDialer) Listen(addr string) (net.Listener, error) {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil, fmt.Errorf("mux dialer closed")
	}
	id := d.nextLocalStreamID()
	l := &muxListener{
		id:       id,
		dialer:   d,
		acceptCh: make(chan net.Conn, 128),
		readyCh:  make(chan error, 1),
		closeCh:  make(chan struct{}),
		addr:     muxAddr(addr),
	}
	d.listeners[id] = l
	d.mu.Unlock()

	if err := d.writer.WriteFrame(&muxproto.Frame{
		Type:     muxproto.TypeListen,
		StreamID: id,
		Payload:  []byte(addr),
	}); err != nil {
		d.removeListener(id)
		l.closeLocal()
		return nil, err
	}

	select {
	case err := <-l.readyCh:
		if err != nil {
			return nil, err
		}
		return l, nil
	case <-time.After(15 * time.Second):
		_ = l.Close()
		return nil, fmt.Errorf("mux listen timeout")
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

func (d *MuxDialer) removeListener(id uint32) {
	d.mu.Lock()
	delete(d.listeners, id)
	d.mu.Unlock()
}

// Close shuts down the mux session and all streams.
func (d *MuxDialer) Close() error {
	var closeErr error
	d.closeOnce.Do(func() {
		closeErr = d.close()
	})
	return closeErr
}

func (d *MuxDialer) close() error {
	var queued []net.Conn
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil
	}
	d.closed = true
	listenerIDs := make([]uint32, 0, len(d.listeners))
	for id := range d.listeners {
		listenerIDs = append(listenerIDs, id)
	}
	for _, s := range d.streams {
		s.closeLocal()
	}
	for _, l := range d.listeners {
		queued = append(queued, l.closeLocalLocked()...)
	}
	d.mu.Unlock()
	closeAcceptedConns(queued)

	for _, id := range listenerIDs {
		_ = d.writer.WriteFrame(&muxproto.Frame{Type: muxproto.TypeListenClose, StreamID: id})
	}
	d.stdin.Close()
	select {
	case err := <-d.waitCh:
		return err
	case <-time.After(3 * time.Second):
		return d.session.Close()
	}
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

func (l *muxListener) Accept() (net.Conn, error) {
	select {
	case conn, ok := <-l.acceptCh:
		if !ok {
			return nil, io.ErrClosedPipe
		}
		return conn, nil
	case <-l.closeCh:
		return nil, io.ErrClosedPipe
	}
}

func (l *muxListener) Close() error {
	l.dialer.mu.Lock()
	if l.closed {
		l.dialer.mu.Unlock()
		return nil
	}
	delete(l.dialer.listeners, l.id)
	queued := l.closeLocalLocked()
	l.dialer.mu.Unlock()

	_ = l.dialer.writer.WriteFrame(&muxproto.Frame{Type: muxproto.TypeListenClose, StreamID: l.id})
	closeAcceptedConns(queued)
	return nil
}

func (l *muxListener) closeLocal() {
	l.dialer.mu.Lock()
	queued := l.closeLocalLocked()
	l.dialer.mu.Unlock()
	closeAcceptedConns(queued)
}

func (l *muxListener) closeLocalLocked() []net.Conn {
	if l.closed {
		return nil
	}
	l.closed = true
	close(l.closeCh)

	var queued []net.Conn
	for {
		select {
		case conn := <-l.acceptCh:
			queued = append(queued, conn)
		default:
			return queued
		}
	}
}

func closeAcceptedConns(conns []net.Conn) {
	for _, conn := range conns {
		_ = conn.Close()
	}
}

func (l *muxListener) Addr() net.Addr {
	return l.addr
}
