//go:build !windows

package main

import (
	"io"
	"os"
)

func rawStdinReader() io.Reader {
	return os.Stdin
}
