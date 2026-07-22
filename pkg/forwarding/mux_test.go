package forwarding

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/flyssh/flyssh/pkg/muxproto"
)

func TestMuxDialerLocalStreamIDsAreOdd(t *testing.T) {
	d := &MuxDialer{}
	for _, want := range []uint32{1, 3, 5, 7} {
		if got := d.nextLocalStreamID(); got != want {
			t.Fatalf("nextLocalStreamID: got %d want %d", got, want)
		}
		if got := want % 2; got != 1 {
			t.Fatalf("local stream id %d is not odd", want)
		}
	}
}

func TestMuxDialerReadLoopRejectsAcceptedWhenAcceptQueueFull(t *testing.T) {
	pr, pw := io.Pipe()
	var out bytes.Buffer
	d := &MuxDialer{
		writer:    muxproto.NewSafeWriter(&out),
		streams:   make(map[uint32]*muxStream),
		listeners: make(map[uint32]*muxListener),
		closeCh:   make(chan struct{}),
	}
	l := &muxListener{
		id:       1,
		dialer:   d,
		acceptCh: make(chan net.Conn),
		closeCh:  make(chan struct{}),
	}
	d.listeners[l.id] = l

	done := make(chan struct{})
	go func() {
		d.readLoop(pr)
		close(done)
	}()

	var payload [4]byte
	binary.BigEndian.PutUint32(payload[:], l.id)
	if err := muxproto.WriteFrame(pw, &muxproto.Frame{
		Type:     muxproto.TypeAccepted,
		StreamID: 2,
		Payload:  payload[:],
	}); err != nil {
		t.Fatalf("write accepted frame: %v", err)
	}
	_ = pw.Close()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("readLoop blocked on full accept queue")
	}
	if _, ok := d.streams[2]; ok {
		t.Fatal("rejected accepted stream was not removed")
	}
}

func TestMuxListenerCloseDrainsQueuedAcceptedStreams(t *testing.T) {
	var out bytes.Buffer
	d := &MuxDialer{
		writer:    muxproto.NewSafeWriter(&out),
		streams:   make(map[uint32]*muxStream),
		listeners: make(map[uint32]*muxListener),
	}
	l := &muxListener{
		id:       1,
		dialer:   d,
		acceptCh: make(chan net.Conn, 1),
		closeCh:  make(chan struct{}),
	}
	s := &muxStream{
		id:      2,
		dialer:  d,
		dataCh:  make(chan []byte, 1),
		closeCh: make(chan struct{}),
	}
	d.listeners[l.id] = l
	d.streams[s.id] = s
	l.acceptCh <- s

	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case <-s.closeCh:
	default:
		t.Fatal("queued accepted stream was not closed")
	}
	if _, ok := d.streams[s.id]; ok {
		t.Fatal("queued accepted stream was not removed")
	}
}
