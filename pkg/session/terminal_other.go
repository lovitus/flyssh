//go:build !windows

package session

// enableVTProcessing is a no-op on non-Windows platforms.
func enableVTProcessing() func() {
	return func() {}
}
