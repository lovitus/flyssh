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
	var promptMu sync.Mutex
	stopped := make(chan struct{})

	go func() {
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

			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				defer c.Close()
				handlePromptBrokerConn(c, token, &promptMu, stopped)
			}(conn)
		}
	}()

	cleanup = func() {
		close(stopped)
		_ = listener.Close()
		wg.Wait()
		cleanupListener()
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

func handlePromptBrokerConn(conn net.Conn, token string, promptMu *sync.Mutex, stopped <-chan struct{}) {
	var req promptBrokerRequest
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		_ = json.NewEncoder(conn).Encode(promptBrokerResponse{Error: err.Error()})
		return
	}
	if req.Token != token {
		_ = json.NewEncoder(conn).Encode(promptBrokerResponse{Error: "invalid prompt broker token"})
		return
	}

	respCh := make(chan promptBrokerResponse, 1)
	cancel := make(chan struct{})
	go func() {
		promptMu.Lock()
		defer promptMu.Unlock()

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

	select {
	case resp := <-respCh:
		_ = json.NewEncoder(conn).Encode(resp)
	case <-peerGone:
		close(cancel)
	case <-stopped:
		close(cancel)
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

	conn, err := net.Dial(network, addr)
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
	defer func() { _ = file.Close() }()

	resultCh := make(chan struct {
		value string
		err   error
	}, 1)
	go func() {
		line, readErr := bufio.NewReader(file).ReadString('\n')
		if readErr != nil && readErr != io.EOF {
			resultCh <- struct {
				value string
				err   error
			}{"", readErr}
			return
		}
		resultCh <- struct {
			value string
			err   error
		}{strings.TrimSpace(line), nil}
	}()

	select {
	case result := <-resultCh:
		return result.value, result.err
	case <-cancel:
		_ = file.Close()
		return "", fmt.Errorf("prompt cancelled")
	}
}

func readBrokerPromptPassword(cancel <-chan struct{}) (string, error) {
	file, err := openPromptTTY()
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()

	resultCh := make(chan struct {
		value string
		err   error
	}, 1)
	go func() {
		pass, readErr := term.ReadPassword(int(file.Fd()))
		if readErr != nil {
			resultCh <- struct {
				value string
				err   error
			}{"", readErr}
			return
		}
		resultCh <- struct {
			value string
			err   error
		}{string(pass), nil}
	}()

	select {
	case result := <-resultCh:
		return result.value, result.err
	case <-cancel:
		_ = file.Close()
		return "", fmt.Errorf("prompt cancelled")
	}
}

func openPromptTTY() (*os.File, error) {
	device := "/dev/tty"
	if runtime.GOOS == "windows" {
		device = "CONIN$"
	}
	return os.Open(device)
}
