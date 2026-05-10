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

func entryNames(entries []fileEntry) []string {
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name)
	}
	return names
}
