//go:build !windows

package moshsession

func enableVTProcessing() func() {
	return func() {}
}
