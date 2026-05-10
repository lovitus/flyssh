//go:build windows

package wingui

import "testing"

func TestEntryDisplaysAvoidsEmptyModel(t *testing.T) {
	got := entryDisplays(nil)
	if len(got) != 1 || got[0] != "(empty)" {
		t.Fatalf("unexpected empty display model: %#v", got)
	}
}
