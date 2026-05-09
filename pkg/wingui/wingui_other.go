//go:build !windows

package wingui

import (
	"fmt"

	"github.com/flyssh/flyssh/pkg/cli"
)

func Run(opts *cli.Options, rawArgs []string) error {
	return fmt.Errorf("--wingui is only available on Windows")
}
