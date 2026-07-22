package muxproto

import (
	"bytes"
	"testing"
)

func TestReverseListenFramesRoundTrip(t *testing.T) {
	frames := []*Frame{
		{Type: TypeListen, StreamID: 1, Payload: []byte("127.0.0.1:3333")},
		{Type: TypeListenOK, StreamID: 1, Payload: []byte("127.0.0.1:3333")},
		{Type: TypeListenFail, StreamID: 1, Payload: []byte("bind: address already in use")},
		{Type: TypeAccepted, StreamID: 2, Payload: []byte{0, 0, 0, 1}},
		{Type: TypeListenClose, StreamID: 1},
	}

	var buf bytes.Buffer
	for _, frame := range frames {
		if err := WriteFrame(&buf, frame); err != nil {
			t.Fatalf("WriteFrame(%#v): %v", frame, err)
		}
	}

	for i, want := range frames {
		got, err := ReadFrame(&buf)
		if err != nil {
			t.Fatalf("ReadFrame #%d: %v", i, err)
		}
		if got.Type != want.Type || got.StreamID != want.StreamID || !bytes.Equal(got.Payload, want.Payload) {
			t.Fatalf("frame #%d: got %#v want %#v", i, got, want)
		}
	}
}
