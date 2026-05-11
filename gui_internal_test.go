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
	data := []byte("0\x0010\x00100\x00-rw-r--r--\x00alice\x00staff\x00z.txt\x001\x000\x0099\x00drwxr-xr-x\x00root\x00root\x00dir\x000\x001\x00101\x00\x00\x00\x00.hidden\x00")
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
	if entries[2].Mode != "-rw-r--r--" || entries[2].User != "alice" || entries[2].Group != "staff" {
		t.Fatalf("unexpected metadata: %+v", entries[2])
	}
}

func TestParseGUIRemoteListUnknownSizeAndMTime(t *testing.T) {
	data := []byte("0\x00\x00\x00-rw-r--r--\x00alice\x00staff\x00unknown.txt\x00")
	entries, err := parseGUIRemoteList(data)
	if err != nil {
		t.Fatalf("parseGUIRemoteList returned error: %v", err)
	}
	if len(entries) != 1 || entries[0].Size != -1 || entries[0].MTime != -1 {
		t.Fatalf("unexpected unknown fields: %+v", entries)
	}
}

func TestParseGUIRemoteListRejectsMalformedFields(t *testing.T) {
	if _, err := parseGUIRemoteList([]byte("0\x001\x002\x00name\x00")); err == nil {
		t.Fatal("expected malformed field count error")
	}
	if _, err := parseGUIRemoteList([]byte("0\x00bad\x002\x00\x00\x00\x00name\x00")); err == nil {
		t.Fatal("expected malformed size error")
	}
	if _, err := parseGUIRemoteList([]byte("0\x001\x00bad\x00\x00\x00\x00name\x00")); err == nil {
		t.Fatal("expected malformed mtime error")
	}
}

func TestGUIInternalListCommandQuotesPathAsShellArgument(t *testing.T) {
	cmd := guiInternalListCommand(`/tmp/a 'b' $HOME ` + "`x`")
	for _, want := range []string{`cd "$dir"`, "'/tmp/a '\"'\"'b'\"'\"' $HOME `x`'"} {
		if !strings.Contains(cmd, want) {
			t.Fatalf("command %q does not contain %q", cmd, want)
		}
	}
	for _, want := range []string{"%A", "%U", "%G", `\0`} {
		if !strings.Contains(cmd, want) {
			t.Fatalf("command %q does not contain %q", cmd, want)
		}
	}
	if strings.Contains(cmd, "%n") {
		t.Fatalf("command should not use stat %%n for names: %q", cmd)
	}
}
