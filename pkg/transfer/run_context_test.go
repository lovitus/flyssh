package transfer

import (
	"context"
	"errors"
	"testing"
)

func TestRunContextAlreadyCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	code, err := RunContext(ctx, nil, nil)
	if code != 1 || !errors.Is(err, context.Canceled) {
		t.Fatalf("code=%d err=%v", code, err)
	}
}
