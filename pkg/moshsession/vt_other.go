//go:build !windows

package moshsession

func enableVTProcessing() func() {
	return func() {}
}

func enableVTInput() func() {
	return func() {}
}
