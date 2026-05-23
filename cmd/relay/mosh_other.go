//go:build !(linux || darwin || freebsd)

package main

import (
	"fmt"
	"os"
)

func runMoshStart(session string) {
	fmt.Fprintln(os.Stderr, "mosh relay is not supported on this platform")
	os.Exit(2)
}

func runMoshAttach(session, takeoverToken string) {
	fmt.Fprintln(os.Stderr, "mosh relay is not supported on this platform")
	os.Exit(2)
}

func runMoshDaemon(session string) {
	fmt.Fprintln(os.Stderr, "mosh relay is not supported on this platform")
	os.Exit(2)
}
