package wingui

import (
	"math"
	"reflect"
	"testing"
)

func TestSortChoicesAndDefaults(t *testing.T) {
	if got := sortModeLabels(); !reflect.DeepEqual(got, []string{"Name", "Size", "Date"}) {
		t.Fatalf("sort choices: %v", got)
	}
	for i, want := range []sortMode{sortByName, sortBySize, sortByTime} {
		if got := sortModeFromIndex(i); got != want {
			t.Fatalf("index %d: %s, want %s", i, got, want)
		}
		if got := defaultSortDescending(want); got != (i != 0) {
			t.Fatalf("default direction for %s: %v", want, got)
		}
	}
	for _, index := range []int{-1, 3, 99} {
		if sortModeFromIndex(index) != sortByName {
			t.Fatal("invalid index must fall back to Name")
		}
	}
	if sortDirectionText(false) != "Asc" || sortDirectionText(true) != "Desc" {
		t.Fatal("unexpected direction labels")
	}
	for _, mode := range []sortMode{sortByName, sortBySize, sortByTime} {
		if sortDirectionToolTip(mode, false) == sortDirectionToolTip(mode, true) {
			t.Fatalf("tooltip must describe direction for %s", mode)
		}
	}
}

func TestSortEveryKeyAndDirection(t *testing.T) {
	original := []fileEntry{
		{Name: "a.txt", Size: 2, MTime: 300, Display: "z"},
		{Name: "z-folder", IsDir: true, Size: 1, MTime: 10},
		{Name: "B.txt", Size: 1024 * 1024, MTime: 100, Display: "a"},
		{Name: "c.txt", Size: 100, MTime: 200},
		{Name: "a-folder", IsDir: true, Size: 20, MTime: 20},
	}
	for _, tt := range []struct {
		mode sortMode
		desc bool
		want []string
	}{
		{sortByName, false, []string{"a-folder", "z-folder", "a.txt", "B.txt", "c.txt"}},
		{sortByName, true, []string{"z-folder", "a-folder", "c.txt", "B.txt", "a.txt"}},
		{sortBySize, false, []string{"z-folder", "a-folder", "a.txt", "c.txt", "B.txt"}},
		{sortBySize, true, []string{"a-folder", "z-folder", "B.txt", "c.txt", "a.txt"}},
		{sortByTime, false, []string{"z-folder", "a-folder", "B.txt", "c.txt", "a.txt"}},
		{sortByTime, true, []string{"a-folder", "z-folder", "a.txt", "c.txt", "B.txt"}},
	} {
		t.Run(string(tt.mode)+sortDirectionText(tt.desc), func(t *testing.T) {
			items := append([]fileEntry(nil), original...)
			sortEntriesWithDirection(items, tt.mode, tt.desc)
			assertSortedNames(t, items, tt.want)
			sortEntriesWithDirection(items, tt.mode, tt.desc)
			assertSortedNames(t, items, tt.want)
		})
	}
}

func TestSortUnknownAndZeroValues(t *testing.T) {
	for _, mode := range []sortMode{sortBySize, sortByTime} {
		for _, desc := range []bool{false, true} {
			items := []fileEntry{
				{Name: "unknown", Size: -1, MTime: -1},
				{Name: "zero", Size: 0, MTime: 0},
				{Name: "max", Size: math.MaxInt64, MTime: math.MaxInt64},
				{Name: "unknown-folder", IsDir: true, Size: -1, MTime: -1},
				{Name: "zero-folder", IsDir: true},
			}
			want := []string{"zero-folder", "unknown-folder", "zero", "max", "unknown"}
			if desc {
				want[2], want[3] = want[3], want[2]
			}
			sortEntriesWithDirection(items, mode, desc)
			assertSortedNames(t, items, want)
		}
	}
}

func TestSortTiesAreDeterministic(t *testing.T) {
	for _, mode := range []sortMode{sortByName, sortBySize, sortByTime} {
		for _, desc := range []bool{false, true} {
			items := []fileEntry{{Name: "a"}, {Name: "A"}, {Name: "b"}, {Name: "B"}}
			want := []string{"A", "a", "B", "b"}
			if mode == sortByName && desc {
				want = []string{"b", "B", "a", "A"}
			}
			sortEntriesWithDirection(items, mode, desc)
			assertSortedNames(t, items, want)
		}
	}
}

func TestSortedSelectionTracksNamesNotOldIndexes(t *testing.T) {
	items := []fileEntry{{Name: "z.txt"}, {Name: "a.txt"}, {Name: "folder", IsDir: true}}
	files, dirs := map[string]bool{"z.txt": true}, map[string]bool{"folder": true}
	sortEntriesWithDirection(items, sortByName, false)
	if got := sortedSelectionIndexes(items, files, dirs); !reflect.DeepEqual(got, []int{0, 2}) {
		t.Fatalf("selection after sorting: %v", got)
	}
	// Deleted names and a name that changed kind must not select another item.
	if got := sortedSelectionIndexes(items, map[string]bool{"missing": true, "folder": true}, nil); len(got) != 0 {
		t.Fatalf("restored absent or wrong-kind selection: %v", got)
	}
	sortEntriesWithDirection(nil, sortByName, true)
	if got := sortedSelectionIndexes(nil, files, dirs); len(got) != 0 {
		t.Fatalf("empty selection: %v", got)
	}
}

func assertSortedNames(t *testing.T, items []fileEntry, want []string) {
	t.Helper()
	got := make([]string, len(items))
	for i, item := range items {
		got[i] = item.Name
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}
