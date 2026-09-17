//go:build windows

package wingui

import (
	"bytes"
	"fmt"
	"os"
	"reflect"
	"testing"
)

func TestHashSelectionEnabled(t *testing.T) {
	file := selectionState{Side: sideLocal, Files: map[string]bool{"a": true}}
	multi := selectionState{Side: sideRemote, Files: map[string]bool{"a": true, "b": true}}
	mixed := selectionState{Side: sideLocal, Files: map[string]bool{"a": true}, Dirs: map[string]bool{"dir": true}}
	folder := selectionState{Side: sideLocal, Dirs: map[string]bool{"dir": true}}
	for _, tt := range []struct {
		name      string
		sel       selectionState
		requested side
		busy      bool
		dir       string
		want      bool
	}{
		{"none", newSelectionState(), sideLocal, false, `C:\data`, false},
		{"local file", file, sideLocal, false, `C:\data`, true},
		{"remote files", multi, sideRemote, false, "/data", true},
		{"wrong pane", multi, sideLocal, false, `C:\data`, false},
		{"folder", folder, sideLocal, false, `C:\data`, false},
		{"mixed", mixed, sideLocal, false, `C:\data`, false},
		{"busy", file, sideLocal, true, `C:\data`, false},
		{"not ready", multi, sideRemote, false, "", false},
		{"invalid side", file, sideNone, false, `C:\data`, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := hashSelectionEnabled(tt.sel, tt.requested, tt.busy, tt.dir); got != tt.want {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHashSelectionTargetsAreSortedSnapshot(t *testing.T) {
	sel := selectionState{Side: sideLocal, Files: map[string]bool{"b 'quote'.bin": true, "a.txt": true}}
	local, err := hashSelectionTargets(sel, sideLocal, `C:data`, "/remote")
	wantLocal := []string{`C:\data\a.txt`, `C:\data\b 'quote'.bin`}
	if err != nil || !reflect.DeepEqual(local, wantLocal) {
		t.Fatalf("local targets: %q, %v", local, err)
	}
	sel.Side = sideRemote
	remote, err := hashSelectionTargets(sel, sideRemote, `C:data`, "/remote")
	wantRemote := []string{"/remote/a.txt", "/remote/b 'quote'.bin"}
	if err != nil || !reflect.DeepEqual(remote, wantRemote) {
		t.Fatalf("remote targets: %q, %v", remote, err)
	}
	delete(sel.Files, "a.txt")
	sel.Files["new.txt"] = true
	if !reflect.DeepEqual(remote, wantRemote) {
		t.Fatal("selection mutation changed an already resolved hash snapshot")
	}
	for _, name := range []string{"..", "x/y", "bad\x00name"} {
		sel.Files = map[string]bool{name: true}
		if _, err := hashSelectionTargets(sel, sideRemote, "", "/remote"); err == nil {
			t.Fatalf("accepted invalid selection %q", name)
		}
	}
}

func TestHashChildOutputHelper(t *testing.T) {
	if os.Getenv("FLYSSH_HASH_TEST_CHILD") != "1" {
		return
	}
	_, _ = fmt.Fprint(os.Stdout, string(bytes.Repeat([]byte("checksum output\n"), 100000)))
	os.Exit(0)
}

func TestRunChildDrainsCompleteHashOutput(t *testing.T) {
	t.Setenv("FLYSSH_HASH_TEST_CHILD", "1")
	a := &app{exe: os.Args[0]}
	got, code, err := a.runChild([]string{"-test.run=^TestHashChildOutputHelper$"}, true)
	want := bytes.Repeat([]byte("checksum output\n"), 100000)
	if err != nil || code != 0 || !bytes.Equal(got, want) {
		t.Fatalf("stdout truncated: got %d bytes, want %d; code=%d err=%v", len(got), len(want), code, err)
	}
}
