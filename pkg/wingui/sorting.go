package wingui

import (
	"sort"
	"strings"
)

type sortMode string

const (
	sortByName sortMode = "name"
	sortByTime sortMode = "time" // Modification date, labelled Date in the GUI.
	sortBySize sortMode = "size"
)

type fileEntry struct {
	Name    string
	IsDir   bool
	Size    int64
	MTime   int64
	Mode    string
	User    string
	Group   string
	Display string
}

func sortModeLabels() []string { return []string{"Name", "Size", "Date"} }

func sortModeFromIndex(index int) sortMode {
	switch index {
	case 1:
		return sortBySize
	case 2:
		return sortByTime
	default:
		return sortByName
	}
}

func defaultSortDescending(mode sortMode) bool {
	return mode == sortBySize || mode == sortByTime
}

func sortDirectionText(descending bool) string {
	if descending {
		return "Desc"
	}
	return "Asc"
}

func sortDirectionToolTip(mode sortMode, descending bool) string {
	order := "A to Z"
	switch mode {
	case sortBySize:
		order = "smallest first"
		if descending {
			order = "largest first"
		}
	case sortByTime:
		order = "oldest first"
		if descending {
			order = "newest first"
		}
	default:
		if descending {
			order = "Z to A"
		}
	}
	return "Sort " + order + "; click to reverse. Folders stay first."
}

func sortEntries(entries []fileEntry, mode sortMode) {
	sortEntriesWithDirection(entries, mode, defaultSortDescending(mode))
}

// Compare the underlying byte counts and modification timestamps, not their
// formatted display text. Keep folders first and unknown metadata last in
// either direction, with a deterministic alphabetical tie-break.
func sortEntriesWithDirection(entries []fileEntry, mode sortMode, descending bool) {
	sort.SliceStable(entries, func(i, j int) bool {
		left, right := entries[i], entries[j]
		if left.IsDir != right.IsDir {
			return left.IsDir
		}
		switch mode {
		case sortBySize:
			if less, decided := sortValueUnknownLast(left.Size, right.Size, descending); decided {
				return less
			}
		case sortByTime:
			if less, decided := sortValueUnknownLast(left.MTime, right.MTime, descending); decided {
				return less
			}
		}
		order := strings.Compare(strings.ToLower(left.Name), strings.ToLower(right.Name))
		if order == 0 {
			order = strings.Compare(left.Name, right.Name)
		}
		if mode != sortBySize && mode != sortByTime && descending {
			return order > 0
		}
		return order < 0
	})
}

func sortValueUnknownLast(left, right int64, descending bool) (less, decided bool) {
	if left < 0 || right < 0 {
		if (left < 0) != (right < 0) {
			return left >= 0, true
		}
		return false, false
	}
	if left == right {
		return false, false
	}
	if descending {
		return left > right, true
	}
	return left < right, true
}

// Restore selection by filename AND kind after replacing a sorted list model;
// indexes from the previous order must never select different files.
func sortedSelectionIndexes(entries []fileEntry, files, dirs map[string]bool) []int {
	var indexes []int
	for i, entry := range entries {
		if (entry.IsDir && dirs[entry.Name]) || (!entry.IsDir && files[entry.Name]) {
			indexes = append(indexes, i)
		}
	}
	return indexes
}
