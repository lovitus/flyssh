package wingui

import "strings"

// Only transport failures are retryable. Rsync also uses 12/255 when its SSH
// transport fails before startup, so retain stderr to distinguish permanent
// authentication, host-key, command and filesystem errors.
func retryableRsyncFailure(code int, stderr string) bool {
	message := strings.ToLower(stderr)
	for _, permanent := range []string{
		"permission denied", "authentication failed", "unable to authenticate",
		"host key", "hostkey", "no such file", "not found", "no space left",
		"disk quota", "read-only file system", "unknown option", "invalid argument",
		"syntax or usage error", "protocol version mismatch",
	} {
		if strings.Contains(message, permanent) {
			return false
		}
	}
	switch code {
	case 10, 12, 30, 35:
		return true
	case 255:
		for _, network := range []string{"connection refused", "connection reset", "connection closed", "connection lost", "broken pipe", "unexpected eof", "i/o timeout", "timed out", "no route to host", "network is unreachable"} {
			if strings.Contains(message, network) {
				return true
			}
		}
		return false
	default:
		return false
	}
}
