package moshframe

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	got, err := Read(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Fatalf("payload = %q", got)
	}
}

func TestFrameRejectsOversize(t *testing.T) {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], MaxPayload+1)
	_, err := Read(bytes.NewReader(hdr[:]))
	if err == nil {
		t.Fatal("expected oversize frame error")
	}
	if err := Write(io.Discard, make([]byte, MaxPayload+1)); err == nil {
		t.Fatal("expected oversize write error")
	}
}

func TestFrameTruncatedPayload(t *testing.T) {
	var buf bytes.Buffer
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], 10)
	buf.Write(hdr[:])
	buf.WriteString("short")
	if _, err := Read(&buf); err == nil {
		t.Fatal("expected truncated payload error")
	}
}
