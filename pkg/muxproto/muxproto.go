package muxproto

import (
	"encoding/binary"
	"fmt"
	"io"
	"sync"
)

const (
	TypeConnect     byte = 0x01
	TypeConnectOK   byte = 0x02
	TypeConnectFail byte = 0x03
	TypeData        byte = 0x04
	TypeClose       byte = 0x05

	HeaderSize = 9     // 1 type + 4 stream_id + 4 length
	MaxPayload = 65536 // 64KB per frame
)

type Frame struct {
	Type     byte
	StreamID uint32
	Payload  []byte
}

func WriteFrame(w io.Writer, f *Frame) error {
	var hdr [HeaderSize]byte
	hdr[0] = f.Type
	binary.BigEndian.PutUint32(hdr[1:5], f.StreamID)
	binary.BigEndian.PutUint32(hdr[5:9], uint32(len(f.Payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(f.Payload) > 0 {
		_, err := w.Write(f.Payload)
		return err
	}
	return nil
}

func ReadFrame(r io.Reader) (*Frame, error) {
	var hdr [HeaderSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	f := &Frame{
		Type:     hdr[0],
		StreamID: binary.BigEndian.Uint32(hdr[1:5]),
	}
	length := binary.BigEndian.Uint32(hdr[5:9])
	if length > MaxPayload {
		return nil, fmt.Errorf("frame too large: %d", length)
	}
	if length > 0 {
		f.Payload = make([]byte, length)
		if _, err := io.ReadFull(r, f.Payload); err != nil {
			return nil, err
		}
	}
	return f, nil
}

// SafeWriter wraps an io.Writer with a mutex for concurrent frame writes.
type SafeWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func NewSafeWriter(w io.Writer) *SafeWriter {
	return &SafeWriter{w: w}
}

func (sw *SafeWriter) WriteFrame(f *Frame) error {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	return WriteFrame(sw.w, f)
}
