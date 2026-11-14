//go:build !windows

package main

import (
	"io"
	"os"
)

func rawStdinReader() (io.ReadCloser, error) {
	// The inherited process handle belongs to os.Stdin.
	return io.NopCloser(os.Stdin), nil
}
