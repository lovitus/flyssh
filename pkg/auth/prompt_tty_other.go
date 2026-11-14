//go:build !windows

package auth

import (
	"fmt"
	"os"
)

func readCancelablePromptTTY(file *os.File, cancel <-chan struct{}, read func() (string, error)) (string, error) {
	defer file.Close()
	type result struct {
		value string
		err   error
	}
	done := make(chan result, 1)
	go func() { value, err := read(); done <- result{value, err} }()
	select {
	case result := <-done:
		return result.value, result.err
	case <-cancel:
		_ = file.Close()
		return "", fmt.Errorf("prompt cancelled")
	}
}
