//go:build windows

package wingui

import (
	"reflect"
	"testing"
)

func TestEntryDisplaysAvoidsEmptyModel(t *testing.T) {
	got := entryDisplays(nil)
	if len(got) != 1 || got[0] != "(empty)" {
		t.Fatalf("unexpected empty display model: %#v", got)
	}
}

func TestTransferButtonTextDefaultsToProtocol(t *testing.T) {
	empty := newSelectionState()
	if got := transferButtonText("scp", empty); got != "SCP" {
		t.Fatalf("unexpected empty scp label: %q", got)
	}
	if got := transferButtonText("rsync", empty); got != "RSYNC" {
		t.Fatalf("unexpected empty rsync label: %q", got)
	}
}

func TestSortEntriesKeepsDirectoriesFirst(t *testing.T) {
	entries := []fileEntry{
		{Name: "b.txt", Size: 20, MTime: 20},
		{Name: "z-dir", IsDir: true, Size: 1, MTime: 1},
		{Name: "a.txt", Size: 10, MTime: 30},
	}
	sortEntries(entries, sortByName)
	got := entryNames(entries)
	want := []string{"z-dir", "a.txt", "b.txt"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected name sort: got %#v want %#v", got, want)
	}
}

func TestSortEntriesByTimeAndSizeDescending(t *testing.T) {
	byTime := []fileEntry{
		{Name: "old", MTime: 10, Size: 10},
		{Name: "new", MTime: 30, Size: 1},
		{Name: "mid", MTime: 20, Size: 30},
	}
	sortEntries(byTime, sortByTime)
	if got, want := entryNames(byTime), []string{"new", "mid", "old"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected time sort: got %#v want %#v", got, want)
	}

	bySize := []fileEntry{
		{Name: "small", MTime: 30, Size: 1},
		{Name: "large", MTime: 10, Size: 30},
		{Name: "mid", MTime: 20, Size: 20},
	}
	sortEntries(bySize, sortBySize)
	if got, want := entryNames(bySize), []string{"large", "mid", "small"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected size sort: got %#v want %#v", got, want)
	}
}

func TestSortEntriesUnknownTimeAndSizeLast(t *testing.T) {
	byTime := []fileEntry{
		{Name: "unknown", MTime: -1, Size: 10},
		{Name: "new", MTime: 30, Size: 1},
		{Name: "old", MTime: 10, Size: 30},
	}
	sortEntries(byTime, sortByTime)
	if got, want := entryNames(byTime), []string{"new", "old", "unknown"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected time sort: got %#v want %#v", got, want)
	}

	bySize := []fileEntry{
		{Name: "unknown", MTime: 30, Size: -1},
		{Name: "large", MTime: 10, Size: 30},
		{Name: "small", MTime: 20, Size: 1},
	}
	sortEntries(bySize, sortBySize)
	if got, want := entryNames(bySize), []string{"large", "small", "unknown"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected size sort: got %#v want %#v", got, want)
	}
}

func TestDeleteTargets(t *testing.T) {
	localSel := newSelectionState()
	localSel.Side = sideLocal
	localSel.Files["a.txt"] = true
	localSel.Files["b.txt"] = true
	got, err := deleteTargets(localSel, `D:work`, "/remote")
	if err != nil {
		t.Fatalf("deleteTargets local returned error: %v", err)
	}
	want := []string{`D:\work\a.txt`, `D:\work\b.txt`}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected local targets: got %#v want %#v", got, want)
	}

	remoteSel := newSelectionState()
	remoteSel.Side = sideRemote
	remoteSel.Dir = "folder"
	got, err = deleteTargets(remoteSel, `D:\work`, "/remote")
	if err != nil {
		t.Fatalf("deleteTargets remote returned error: %v", err)
	}
	want = []string{"/remote/folder"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected remote targets: got %#v want %#v", got, want)
	}
}

func TestRenameTargetRequiresSingleSelection(t *testing.T) {
	multi := newSelectionState()
	multi.Side = sideLocal
	multi.Files["a.txt"] = true
	multi.Files["b.txt"] = true
	if _, err := renameTarget(multi, `D:\work`, "/remote"); err == nil {
		t.Fatal("expected multi-select rename error")
	}

	one := newSelectionState()
	one.Side = sideRemote
	one.Files["a.txt"] = true
	got, err := renameTarget(one, `D:\work`, "/remote")
	if err != nil {
		t.Fatalf("renameTarget returned error: %v", err)
	}
	if want := "/remote/a.txt"; got != want {
		t.Fatalf("unexpected rename target: got %q want %q", got, want)
	}
}

func TestSelectionSingle(t *testing.T) {
	empty := newSelectionState()
	if selectionSingle(empty) {
		t.Fatal("empty selection should not be single")
	}
	dir := newSelectionState()
	dir.Side = sideLocal
	dir.Dir = "folder"
	if !selectionSingle(dir) {
		t.Fatal("directory selection should be single")
	}
	files := newSelectionState()
	files.Side = sideLocal
	files.Files["a.txt"] = true
	files.Files["b.txt"] = true
	if selectionSingle(files) {
		t.Fatal("multi-file selection should not be single")
	}
}

func TestChildDescriptionDetectsRemoteDelete(t *testing.T) {
	command, err := buildRemoteDeleteCommand([]string{"/tmp/a"})
	if err != nil {
		t.Fatalf("buildRemoteDeleteCommand returned error: %v", err)
	}
	if got, want := childDescription([]string{"user@host", command}), "remote delete"; got != want {
		t.Fatalf("unexpected child description: got %q want %q", got, want)
	}
}

func TestChildDescriptionDetectsRemoteRename(t *testing.T) {
	command, err := buildRemoteRenameCommand("/tmp/a", "/tmp/b")
	if err != nil {
		t.Fatalf("buildRemoteRenameCommand returned error: %v", err)
	}
	if got, want := childDescription([]string{"user@host", command}), "remote rename"; got != want {
		t.Fatalf("unexpected child description: got %q want %q", got, want)
	}
}

func entryNames(entries []fileEntry) []string {
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name)
	}
	return names
}
