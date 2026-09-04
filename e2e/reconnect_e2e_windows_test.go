//go:build windows

package e2e_test

import "testing"

func TestReconnectE2ERequiresUnixPTY(t *testing.T) {
	t.Skip("reconnect subprocess E2E runs in the Linux CI job")
}
