//go:build !windows

package transfer

// resolveRsyncBinary returns the path to rsync via PATH lookup.
// On non-Windows platforms users are expected to manage their own rsync installation.
func resolveRsyncBinary() (string, error) {
	return lookPath("rsync")
}
