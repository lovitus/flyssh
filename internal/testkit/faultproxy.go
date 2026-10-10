package testkit

import (
	"bytes"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// FaultProxy forwards real TCP traffic and can interrupt an established route
// without changing the address used by clients.
type FaultProxy struct {
	listener    net.Listener
	target      string
	mu          sync.Mutex
	connections map[net.Conn]struct{}
	closed      bool
	blackhole   atomic.Bool
	cutAfter    atomic.Int64
	bytes       atomic.Int64
	Connections atomic.Int64
	CutDone     chan struct{}
	cutOnce     sync.Once
}

func StartFaultProxy(t *testing.T, target string) *FaultProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &FaultProxy{listener: ln, target: target, connections: make(map[net.Conn]struct{}), CutDone: make(chan struct{})}
	t.Cleanup(p.Close)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			p.mu.Lock()
			if p.closed {
				p.mu.Unlock()
				conn.Close()
				return
			}
			p.connections[conn] = struct{}{}
			p.mu.Unlock()
			p.Connections.Add(1)
			go p.forward(conn)
		}
	}()
	return p
}

func (p *FaultProxy) Addr() string           { return p.listener.Addr().String() }
func (p *FaultProxy) Transferred() int64     { return p.bytes.Load() }
func (p *FaultProxy) Blackhole(enabled bool) { p.blackhole.Store(enabled) }
func (p *FaultProxy) CutAfter(n int64)       { p.cutAfter.Store(p.bytes.Load() + n) }

func (p *FaultProxy) forward(down net.Conn) {
	defer func() {
		down.Close()
		p.mu.Lock()
		delete(p.connections, down)
		p.mu.Unlock()
	}()
	up, err := net.DialTimeout("tcp", p.target, 3*time.Second)
	if err != nil {
		return
	}
	defer up.Close()
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.connections[up] = struct{}{}
	p.mu.Unlock()
	defer func() { p.mu.Lock(); delete(p.connections, up); p.mu.Unlock() }()
	done := make(chan struct{}, 2)
	copyTraffic := func(dst, src net.Conn) {
		defer func() { dst.Close(); src.Close(); done <- struct{}{} }()
		buf := make([]byte, 32*1024)
		for {
			n, err := src.Read(buf)
			if n > 0 && !p.blackhole.Load() {
				if _, writeErr := io.Copy(dst, bytes.NewReader(buf[:n])); writeErr != nil {
					return
				}
				total := p.bytes.Add(int64(n))
				if limit := p.cutAfter.Load(); limit > 0 && total >= limit {
					if p.cutAfter.CompareAndSwap(limit, 0) {
						p.Cut()
						p.cutOnce.Do(func() { close(p.CutDone) })
					}
				}
			}
			if err != nil {
				return
			}
		}
	}
	go copyTraffic(up, down)
	go copyTraffic(down, up)
	<-done
	<-done
}

func (p *FaultProxy) Cut() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for conn := range p.connections {
		_ = conn.Close()
	}
}

func (p *FaultProxy) Close() {
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
	_ = p.listener.Close()
	p.Cut()
}
