package main

import (
	"encoding/binary"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"

	"github.com/flyssh/flyssh/pkg/muxproto"
)

func main() {
	if len(os.Args) == 3 && os.Args[1] == "-mosh-start" {
		runMoshStart(os.Args[2])
		return
	}
	if (len(os.Args) == 3 || len(os.Args) == 4) && os.Args[1] == "-mosh-attach" {
		token := ""
		if len(os.Args) == 4 {
			token = os.Args[3]
		}
		runMoshAttach(os.Args[2], token)
		return
	}
	if len(os.Args) == 3 && os.Args[1] == "-mosh-daemon" {
		runMoshDaemon(os.Args[2])
		return
	}

	if len(os.Args) == 2 && os.Args[1] == "-mux" {
		runMux()
		return
	}

	// Simple single-connection relay mode
	if len(os.Args) != 2 {
		os.Exit(2)
	}
	conn, err := net.Dial("tcp", os.Args[1])
	if err != nil {
		os.Exit(1)
	}
	defer conn.Close()

	done := make(chan struct{})
	go func() {
		io.Copy(conn, os.Stdin)
		if tc, ok := conn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		close(done)
	}()
	io.Copy(os.Stdout, conn)
	<-done
}

// runMux runs the relay in multiplexed mode.
// Protocol: binary frames on stdin/stdout, each with stream_id.
// Multiple TCP connections are multiplexed over this single pipe.
func runMux() {
	writer := muxproto.NewSafeWriter(os.Stdout)

	var mu sync.Mutex
	streams := make(map[uint32]net.Conn)
	listeners := make(map[uint32]net.Listener)
	pendingConnects := make(map[uint32]struct{})
	canceledStreams := make(map[uint32]struct{})
	var nextAccepted atomic.Uint32

	closeStream := func(sid uint32) {
		mu.Lock()
		if c, ok := streams[sid]; ok {
			c.Close()
			delete(streams, sid)
		} else if _, pending := pendingConnects[sid]; pending {
			// A TypeClose can arrive while a TypeConnect goroutine is still
			// dialing. Remember it so a later successful dial is closed instead
			// of being added to streams with no local peer left to consume it.
			canceledStreams[sid] = struct{}{}
		}
		mu.Unlock()
	}

	closeListener := func(lid uint32) {
		mu.Lock()
		if ln, ok := listeners[lid]; ok {
			ln.Close()
			delete(listeners, lid)
		}
		mu.Unlock()
	}

	closeAll := func() {
		mu.Lock()
		for _, c := range streams {
			c.Close()
		}
		for _, ln := range listeners {
			ln.Close()
		}
		streams = make(map[uint32]net.Conn)
		listeners = make(map[uint32]net.Listener)
		pendingConnects = make(map[uint32]struct{})
		canceledStreams = make(map[uint32]struct{})
		mu.Unlock()
	}

	for {
		frame, err := muxproto.ReadFrame(os.Stdin)
		if err != nil {
			// stdin closed — parent SSH session ended
			closeAll()
			os.Exit(0)
		}

		switch frame.Type {
		case muxproto.TypeConnect:
			addr := string(frame.Payload)
			sid := frame.StreamID
			mu.Lock()
			pendingConnects[sid] = struct{}{}
			mu.Unlock()
			go func() {
				conn, err := net.Dial("tcp", addr)
				if err != nil {
					mu.Lock()
					_, canceled := canceledStreams[sid]
					delete(pendingConnects, sid)
					delete(canceledStreams, sid)
					mu.Unlock()
					if canceled {
						return
					}
					writer.WriteFrame(&muxproto.Frame{
						Type:     muxproto.TypeConnectFail,
						StreamID: sid,
						Payload:  []byte(err.Error()),
					})
					return
				}

				mu.Lock()
				delete(pendingConnects, sid)
				if _, canceled := canceledStreams[sid]; canceled {
					delete(canceledStreams, sid)
					mu.Unlock()
					conn.Close()
					return
				}
				streams[sid] = conn
				mu.Unlock()

				if err := writer.WriteFrame(&muxproto.Frame{
					Type:     muxproto.TypeConnectOK,
					StreamID: sid,
				}); err != nil {
					closeStream(sid)
					return
				}

				// Read from TCP → send DATA frames
				buf := make([]byte, 32768)
				for {
					n, err := conn.Read(buf)
					if n > 0 {
						writer.WriteFrame(&muxproto.Frame{
							Type:     muxproto.TypeData,
							StreamID: sid,
							Payload:  buf[:n],
						})
					}
					if err != nil {
						writer.WriteFrame(&muxproto.Frame{
							Type:     muxproto.TypeClose,
							StreamID: sid,
						})
						closeStream(sid)
						return
					}
				}
			}()

		case muxproto.TypeListen:
			listenerID := frame.StreamID
			bindAddr := string(frame.Payload)
			ln, err := net.Listen("tcp", bindAddr)
			if err != nil {
				writer.WriteFrame(&muxproto.Frame{
					Type:     muxproto.TypeListenFail,
					StreamID: listenerID,
					Payload:  []byte(err.Error()),
				})
				continue
			}

			mu.Lock()
			listeners[listenerID] = ln
			mu.Unlock()

			writer.WriteFrame(&muxproto.Frame{
				Type:     muxproto.TypeListenOK,
				StreamID: listenerID,
				Payload:  []byte(ln.Addr().String()),
			})

			go func(listenerID uint32, ln net.Listener) {
				for {
					conn, err := ln.Accept()
					if err != nil {
						closeListener(listenerID)
						return
					}

					sid := nextAccepted.Add(2)
					mu.Lock()
					streams[sid] = conn
					mu.Unlock()

					var payload [4]byte
					binary.BigEndian.PutUint32(payload[:], listenerID)
					if err := writer.WriteFrame(&muxproto.Frame{
						Type:     muxproto.TypeAccepted,
						StreamID: sid,
						Payload:  payload[:],
					}); err != nil {
						closeStream(sid)
						continue
					}

					go func(sid uint32, conn net.Conn) {
						buf := make([]byte, 32768)
						for {
							n, err := conn.Read(buf)
							if n > 0 {
								writer.WriteFrame(&muxproto.Frame{
									Type:     muxproto.TypeData,
									StreamID: sid,
									Payload:  buf[:n],
								})
							}
							if err != nil {
								writer.WriteFrame(&muxproto.Frame{
									Type:     muxproto.TypeClose,
									StreamID: sid,
								})
								closeStream(sid)
								return
							}
						}
					}(sid, conn)
				}
			}(listenerID, ln)

		case muxproto.TypeData:
			mu.Lock()
			conn := streams[frame.StreamID]
			mu.Unlock()
			if conn != nil {
				conn.Write(frame.Payload)
			}

		case muxproto.TypeClose:
			closeStream(frame.StreamID)

		case muxproto.TypeListenClose:
			closeListener(frame.StreamID)
		}
	}
}
