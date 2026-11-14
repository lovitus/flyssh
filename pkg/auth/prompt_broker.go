package auth

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/term"
)

const (
	PromptBrokerNetworkEnv = "FLYSSH_PROMPT_BROKER_NETWORK"
	PromptBrokerAddrEnv    = "FLYSSH_PROMPT_BROKER_ADDR"
	PromptBrokerTokenEnv   = "FLYSSH_PROMPT_BROKER_TOKEN"
)

type promptBrokerRequest struct {
	Token string `json:"token"`
	Op    string `json:"op"`
}

type promptBrokerResponse struct {
	Value string `json:"value,omitempty"`
	Error string `json:"error,omitempty"`
}

var promptBrokerListenerFactory = startPromptBrokerListener
var brokerPromptLineReader = readBrokerPromptLine
var brokerPromptPasswordReader = readBrokerPromptPassword

func StartPromptBroker() (env []string, cleanup func(), err error) {
	network, listener, cleanupListener, err := promptBrokerListenerFactory()
	if err != nil {
		return nil, nil, fmt.Errorf("start prompt broker: %w", err)
	}

	token, err := randomPromptToken()
	if err != nil {
		_ = listener.Close()
		cleanupListener()
		return nil, nil, err
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	var once sync.Once
	connections := make(map[net.Conn]struct{})
	closing := false
	promptSlot := make(chan struct{}, 1)
	stopped := make(chan struct{})
	acceptDone := make(chan struct{})

	go func() {
		defer close(acceptDone)
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				select {
				case <-stopped:
					return
				default:
					continue
				}
			}
			mu.Lock()
			if closing {
				mu.Unlock()
				_ = conn.Close()
				return
			}
			connections[conn] = struct{}{}
			wg.Add(1)
			mu.Unlock()
			go func(c net.Conn) {
				defer wg.Done()
				defer func() {
					_ = c.Close()
					mu.Lock()
					delete(connections, c)
					mu.Unlock()
				}()
				handlePromptBrokerConn(c, token, promptSlot, stopped)
			}(conn)
		}
	}()

	cleanup = func() {
		once.Do(func() {
			mu.Lock()
			closing = true
			close(stopped)
			active := make([]net.Conn, 0, len(connections))
			for conn := range connections {
				active = append(active, conn)
			}
			mu.Unlock()
			_ = listener.Close()
			for _, conn := range active {
				_ = conn.Close()
			}
			// No Add can race Wait after the accept loop has exited.
			<-acceptDone
			wg.Wait()
			cleanupListener()
		})
	}

	env = []string{
		PromptBrokerNetworkEnv + "=" + network,
		PromptBrokerAddrEnv + "=" + listener.Addr().String(),
		PromptBrokerTokenEnv + "=" + token,
	}
	return env, cleanup, nil
}

func startPromptBrokerListener() (string, net.Listener, func(), error) {
	if runtime.GOOS != "windows" {
		dir, err := os.MkdirTemp("", "flyssh-prompt-broker-*")
		if err != nil {
			return "", nil, nil, err
		}
		socketPath := filepath.Join(dir, "broker.sock")
		listener, err := net.Listen("unix", socketPath)
		if err == nil {
			return "unix", listener, func() { _ = os.RemoveAll(dir) }, nil
		}
		_ = os.RemoveAll(dir)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, nil, err
	}
	return "tcp", listener, func() {}, nil
}

const promptBrokerIOTimeout = 10 * time.Second

func writePromptBrokerResponse(conn net.Conn, resp promptBrokerResponse) {
	_ = conn.SetWriteDeadline(time.Now().Add(promptBrokerIOTimeout))
	_ = json.NewEncoder(conn).Encode(resp)
}

func handlePromptBrokerConn(conn net.Conn, token string, promptSlot chan struct{}, stopped <-chan struct{}) {
	var req promptBrokerRequest
	_ = conn.SetReadDeadline(time.Now().Add(promptBrokerIOTimeout))
	if err := json.NewDecoder(io.LimitReader(conn, 4096)).Decode(&req); err != nil {
		writePromptBrokerResponse(conn, promptBrokerResponse{Error: err.Error()})
		return
	}
	_ = conn.SetReadDeadline(time.Time{}) // User input has no short network deadline.
	if req.Token != token {
		writePromptBrokerResponse(conn, promptBrokerResponse{Error: "invalid prompt broker token"})
		return
	}

	respCh := make(chan promptBrokerResponse, 1)
	cancel := make(chan struct{})
	promptDone := make(chan struct{})
	go func() {
		defer close(promptDone)
		select {
		case promptSlot <- struct{}{}:
			defer func() { <-promptSlot }()
		case <-cancel:
			return
		case <-stopped:
			return
		}
		// Acquiring a slot and cancellation may become ready together.
		select {
		case <-cancel:
			return
		case <-stopped:
			return
		default:
		}

		var (
			value string
			err   error
		)
		switch req.Op {
		case "line":
			value, err = brokerPromptLineReader(cancel)
		case "password":
			value, err = brokerPromptPasswordReader(cancel)
		default:
			err = fmt.Errorf("unsupported prompt op: %s", req.Op)
		}
		if err != nil {
			respCh <- promptBrokerResponse{Error: err.Error()}
			return
		}
		respCh <- promptBrokerResponse{Value: value}
	}()

	peerGone := make(chan struct{})
	go func() {
		var buf [1]byte
		_, _ = conn.Read(buf[:])
		close(peerGone)
	}()

	defer func() {
		close(cancel)
		_ = conn.Close()
		<-promptDone
		<-peerGone
	}()
	select {
	case resp := <-respCh:
		writePromptBrokerResponse(conn, resp)
	case <-peerGone:
	case <-stopped:
	}
}

func requestPromptBroker(op string) (string, bool, error) {
	network := os.Getenv(PromptBrokerNetworkEnv)
	addr := os.Getenv(PromptBrokerAddrEnv)
	token := os.Getenv(PromptBrokerTokenEnv)
	if addr == "" || token == "" {
		return "", false, nil
	}
	if network == "" {
		network = "tcp"
	}

	conn, err := net.DialTimeout(network, addr, promptBrokerIOTimeout)
	if err != nil {
		return "", true, fmt.Errorf("connect prompt broker: %w", err)
	}
	defer conn.Close()

	if err := json.NewEncoder(conn).Encode(promptBrokerRequest{Token: token, Op: op}); err != nil {
		return "", true, fmt.Errorf("send prompt broker request: %w", err)
	}

	var resp promptBrokerResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return "", true, fmt.Errorf("read prompt broker response: %w", err)
	}
	if resp.Error != "" {
		return "", true, fmt.Errorf("prompt broker: %s", resp.Error)
	}
	return resp.Value, true, nil
}

func randomPromptToken() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("generate prompt broker token: %w", err)
	}
	return hex.EncodeToString(buf[:]), nil
}

func readBrokerPromptLine(cancel <-chan struct{}) (string, error) {
	file, err := openPromptTTY()
	if err != nil {
		return "", err
	}
	return readCancelablePromptTTY(file, cancel, func() (string, error) {
		line, err := bufio.NewReader(file).ReadString('\n')
		if err != nil && err != io.EOF {
			return "", err
		}
		return strings.TrimSpace(line), nil
	})
}

func readBrokerPromptPassword(cancel <-chan struct{}) (string, error) {
	file, err := openPromptTTY()
	if err != nil {
		return "", err
	}
	return readCancelablePromptTTY(file, cancel, func() (string, error) {
		pass, err := term.ReadPassword(int(file.Fd()))
		return string(pass), err
	})
}

func openPromptTTY() (*os.File, error) {
	device := "/dev/tty"
	if runtime.GOOS == "windows" {
		// ReadPassword changes/restores console mode; a read-only CONIN$
		// handle rejects that operation with ERROR_ACCESS_DENIED.
		return os.OpenFile("CONIN$", os.O_RDWR, 0)
	}
	return os.Open(device)
}
