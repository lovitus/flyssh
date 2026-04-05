package transfer

import (
	"fmt"

	"golang.org/x/crypto/ssh"
)

func Run(client *ssh.Client, spec *Spec) (int, error) {
	if spec == nil {
		return 0, nil
	}
	switch spec.Mode {
	case ModeSCP:
		return runSCP(client, spec)
	case ModeRsync:
		return 1, fmt.Errorf("rsync transfer mode is not implemented in SSH-session mode")
	default:
		return 1, fmt.Errorf("unsupported transfer mode: %s", spec.Mode)
	}
}
