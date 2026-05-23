package moshsession

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/flyssh/flyssh/pkg/moshframe"
)

func TestDecodeMoshKeyAcceptsUnpaddedKey(t *testing.T) {
	raw, err := decodeMoshKey("AAAAAAAAAAAAAAAAAAAAAA")
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 16 {
		t.Fatalf("key length = %d, want 16", len(raw))
	}
}

func TestRandomSessionNameUsesSafePrefix(t *testing.T) {
	name, err := randomSessionName()
	if err != nil {
		t.Fatal(err)
	}
	if len(name) != len("flyssh-")+16 {
		t.Fatalf("name = %q", name)
	}
}

func TestConsumeAttachOKLeavesFramesReadable(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString("OK\n")
	if err := moshframe.Write(&buf, []byte("payload")); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(&buf)
	if err := consumeAttachOK(br); err != nil {
		t.Fatalf("consumeAttachOK returned error: %v", err)
	}
	got, err := moshframe.Read(br)
	if err != nil {
		t.Fatalf("frame read failed after OK: %v", err)
	}
	if string(got) != "payload" {
		t.Fatalf("payload = %q", got)
	}
}

func TestConsumeAttachOKRejectsNonOK(t *testing.T) {
	err := consumeAttachOK(bufio.NewReader(strings.NewReader("NOPE\n")))
	if err == nil {
		t.Fatal("expected rejection")
	}
	if !strings.Contains(err.Error(), "attach rejected") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMoshAttachCommandIncludesTakeoverTokenOnlyWhenPresent(t *testing.T) {
	if got := moshAttachCommand("/tmp/flyssh relay", "work", ""); got != "'/tmp/flyssh relay' -mosh-attach 'work'" {
		t.Fatalf("command without token = %q", got)
	}
	got := moshAttachCommand("/tmp/flyssh relay", "work", "tok'en")
	want := "'/tmp/flyssh relay' -mosh-attach 'work' 'tok'\"'\"'en'"
	if got != want {
		t.Fatalf("command with token = %q, want %q", got, want)
	}
}

func TestWaitAttachCleanExitDoesNotRetry(t *testing.T) {
	closed := false
	err, retry := waitAttach(context.Background(), make(chan os.Signal), func() error {
		return nil
	}, func() {
		closed = true
	})
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if retry {
		t.Fatal("clean exit should not retry")
	}
	if !closed {
		t.Fatal("closeAttach was not called")
	}
}

func TestWaitAttachErrorRetries(t *testing.T) {
	want := errors.New("attach lost")
	closed := false
	err, retry := waitAttach(context.Background(), make(chan os.Signal), func() error {
		return want
	}, func() {
		closed = true
	})
	if !errors.Is(err, want) {
		t.Fatalf("err = %v, want %v", err, want)
	}
	if !retry {
		t.Fatal("attach error should retry")
	}
	if !closed {
		t.Fatal("closeAttach was not called")
	}
}

func TestWaitAttachSignalClosesAndDoesNotRetry(t *testing.T) {
	sigCh := make(chan os.Signal, 1)
	sigCh <- syscall.SIGTERM
	waitReleased := make(chan struct{})
	closeCalled := make(chan struct{})
	var once sync.Once
	err, retry := waitAttach(context.Background(), sigCh, func() error {
		<-waitReleased
		return nil
	}, func() {
		once.Do(func() {
			close(closeCalled)
			close(waitReleased)
		})
	})
	if err == nil || !strings.Contains(err.Error(), "interrupted by") {
		t.Fatalf("err = %v, want interrupted error", err)
	}
	if retry {
		t.Fatal("signal should not retry")
	}
	select {
	case <-closeCalled:
	default:
		t.Fatal("closeAttach was not called")
	}
}

func TestWaitReconnectCanBeInterrupted(t *testing.T) {
	sigCh := make(chan os.Signal, 1)
	sigCh <- syscall.SIGTERM
	err := waitReconnect(context.Background(), sigCh, time.Hour)
	if err == nil || !strings.Contains(err.Error(), "interrupted by") {
		t.Fatalf("err = %v, want interrupted error", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := waitReconnect(ctx, make(chan os.Signal), time.Hour); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context canceled", err)
	}
}
