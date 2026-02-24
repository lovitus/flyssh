package main

import (
	"io"
	"net"
	"os"
	"sync"

	"github.com/flyssh/flyssh/pkg/muxproto"
)

func main() {
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

	closeStream := func(sid uint32) {
		mu.Lock()
		if c, ok := streams[sid]; ok {
			c.Close()
			delete(streams, sid)
		}
		mu.Unlock()
	}

	for {
		frame, err := muxproto.ReadFrame(os.Stdin)
		if err != nil {
			// stdin closed — parent SSH session ended
			mu.Lock()
			for _, c := range streams {
				c.Close()
			}
			mu.Unlock()
			os.Exit(0)
		}

		switch frame.Type {
		case muxproto.TypeConnect:
			addr := string(frame.Payload)
			sid := frame.StreamID
			go func() {
				conn, err := net.Dial("tcp", addr)
				if err != nil {
					writer.WriteFrame(&muxproto.Frame{
						Type:     muxproto.TypeConnectFail,
						StreamID: sid,
						Payload:  []byte(err.Error()),
					})
					return
				}

				mu.Lock()
				streams[sid] = conn
				mu.Unlock()

				writer.WriteFrame(&muxproto.Frame{
					Type:     muxproto.TypeConnectOK,
					StreamID: sid,
				})

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

		case muxproto.TypeData:
			mu.Lock()
			conn := streams[frame.StreamID]
			mu.Unlock()
			if conn != nil {
				conn.Write(frame.Payload)
			}

		case muxproto.TypeClose:
			closeStream(frame.StreamID)
		}
	}
}
