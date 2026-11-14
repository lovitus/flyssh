package auth

import (
	"encoding/json"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type observedBrokerConn struct {
	net.Conn
	readStarted chan struct{}
	once        sync.Once
}

func (c *observedBrokerConn) Read(p []byte) (int, error) {
	c.once.Do(func() { close(c.readStarted) })
	return c.Conn.Read(p)
}

func brokerTestWait(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("broker did not finish")
	}
}

func TestPromptBrokerCleanupClosesIncompleteRequest(t *testing.T) {
	for _, request := range []string{"", `{"token":`} {
		t.Run(request, func(t *testing.T) {
			server, client := net.Pipe()
			defer client.Close()
			observed := &observedBrokerConn{Conn: server, readStarted: make(chan struct{})}
			old := promptBrokerListenerFactory
			promptBrokerListenerFactory = func() (string, net.Listener, func(), error) {
				return "pipe", &singleConnListener{connCh: chanWithConn(observed), closeCh: make(chan struct{}), addr: dummyAddr("test")}, func() {}, nil
			}
			defer func() { promptBrokerListenerFactory = old }()
			_, cleanup, err := StartPromptBroker()
			if err != nil {
				t.Fatal(err)
			}
			brokerTestWait(t, observed.readStarted)
			if request != "" {
				if _, err := io.WriteString(client, request); err != nil {
					t.Fatal(err)
				}
			}
			done := make(chan struct{})
			go func() {
				var wg sync.WaitGroup
				for i := 0; i < 4; i++ {
					wg.Add(1)
					go func() { defer wg.Done(); cleanup() }()
				}
				wg.Wait()
				close(done)
			}()
			brokerTestWait(t, done)
			if _, err := client.Write([]byte("x")); err == nil {
				t.Fatal("accepted connection survived cleanup")
			}
		})
	}
}

// This listener intentionally returns a connection after Close, modelling an
// Accept already in flight while shutdown takes its connection snapshot.
type lateBrokerListener struct {
	conn    net.Conn
	closed  chan struct{}
	release chan struct{}
	once    sync.Once
}

func (l *lateBrokerListener) Accept() (net.Conn, error) { <-l.release; return l.conn, nil }
func (l *lateBrokerListener) Close() error              { l.once.Do(func() { close(l.closed) }); return nil }
func (l *lateBrokerListener) Addr() net.Addr            { return dummyAddr("late") }

func TestPromptBrokerCleanupJoinsInFlightAccept(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	listener := &lateBrokerListener{conn: server, closed: make(chan struct{}), release: make(chan struct{})}
	old := promptBrokerListenerFactory
	promptBrokerListenerFactory = func() (string, net.Listener, func(), error) { return "pipe", listener, func() {}, nil }
	defer func() { promptBrokerListenerFactory = old }()
	_, cleanup, err := StartPromptBroker()
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { cleanup(); close(done) }()
	brokerTestWait(t, listener.closed)
	close(listener.release)
	brokerTestWait(t, done)
	if _, err := client.Write([]byte("x")); err == nil {
		t.Fatal("late accepted connection survived cleanup")
	}
}

func TestPromptBrokerCancelledQueuedPromptDoesNotOpenTTY(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	slot := make(chan struct{}, 1)
	slot <- struct{}{}
	stopped := make(chan struct{})
	var opened atomic.Int32
	old := brokerPromptLineReader
	brokerPromptLineReader = func(<-chan struct{}) (string, error) { opened.Add(1); return "", nil }
	defer func() { brokerPromptLineReader = old }()
	done := make(chan struct{})
	go func() { handlePromptBrokerConn(server, "token", slot, stopped); close(done) }()
	if err := json.NewEncoder(client).Encode(promptBrokerRequest{Token: "token", Op: "line"}); err != nil {
		t.Fatal(err)
	}
	close(stopped)
	brokerTestWait(t, done)
	<-slot
	if opened.Load() != 0 {
		t.Fatal("cancelled queued prompt opened input")
	}
}

func TestPromptBrokerCleanupClosesUnreadResponse(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	oldFactory, oldReader := promptBrokerListenerFactory, brokerPromptLineReader
	prompted := make(chan struct{})
	promptBrokerListenerFactory = func() (string, net.Listener, func(), error) {
		return "pipe", &singleConnListener{connCh: chanWithConn(server), closeCh: make(chan struct{}), addr: dummyAddr("test")}, func() {}, nil
	}
	brokerPromptLineReader = func(<-chan struct{}) (string, error) { close(prompted); return "answer", nil }
	defer func() { promptBrokerListenerFactory = oldFactory; brokerPromptLineReader = oldReader }()
	env, cleanup, err := StartPromptBroker()
	if err != nil {
		t.Fatal(err)
	}
	var token string
	for _, kv := range env {
		if strings.HasPrefix(kv, PromptBrokerTokenEnv+"=") {
			token = strings.TrimPrefix(kv, PromptBrokerTokenEnv+"=")
		}
	}
	if err := json.NewEncoder(client).Encode(promptBrokerRequest{Token: token, Op: "line"}); err != nil {
		t.Fatal(err)
	}
	brokerTestWait(t, prompted)
	done := make(chan struct{})
	go func() { cleanup(); close(done) }()
	brokerTestWait(t, done)
}
