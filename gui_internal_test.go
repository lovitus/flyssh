package main

import (
	"strings"
	"testing"
)

func TestRawArgSnapshotPreservesValues(t *testing.T) {
	args := []string{"user@host", "--password", "secret", "--passwords=one,two", "--wingui"}
	got := rawArgSnapshot(args)
	args[2] = "******"
	args[3] = "--passwords=******"
	if got[2] != "secret" || got[3] != "--passwords=one,two" {
		t.Fatalf("snapshot was mutated: %#v", got)
	}
}

func TestParseGUIRemoteListAndSort(t *testing.T) {
	data := []byte("0\x0010\x00100\x00z.txt\x001\x000\x0099\x00dir\x000\x001\x00101\x00.hidden\x00")
	entries, err := parseGUIRemoteList(data)
	if err != nil {
		t.Fatalf("parseGUIRemoteList returned error: %v", err)
	}
	sortGUIRemoteEntries(entries)
	got := []string{entries[0].Name, entries[1].Name, entries[2].Name}
	want := []string{"dir", ".hidden", "z.txt"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unexpected order: got %#v want %#v", got, want)
		}
	}
	if !entries[0].IsDir || entries[1].Size != 1 || entries[1].MTime != 101 {
		t.Fatalf("unexpected parsed entries: %+v", entries)
	}
}

func TestGUIInternalListCommandQuotesPathAsShellArgument(t *testing.T) {
	cmd := guiInternalListCommand(`/tmp/a 'b' $HOME ` + "`x`")
	for _, want := range []string{`cd "$dir"`, "'/tmp/a '\"'\"'b'\"'\"' $HOME `x`'"} {
		if !strings.Contains(cmd, want) {
			t.Fatalf("command %q does not contain %q", cmd, want)
		}
	}
}
