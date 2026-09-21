//go:build windows

package wingui

func (a *app) localSortChanged() {
	if a.localSort != nil {
		mode := sortModeFromIndex(a.localSort.CurrentIndex())
		a.changePaneSort(sideLocal, mode, defaultSortDescending(mode))
	}
}

func (a *app) remoteSortChanged() {
	if a.remoteSort != nil {
		mode := sortModeFromIndex(a.remoteSort.CurrentIndex())
		a.changePaneSort(sideRemote, mode, defaultSortDescending(mode))
	}
}

func (a *app) reversePaneSort(which side) {
	a.mu.Lock()
	mode, descending := a.localSortMode, a.localSortDescending
	if which == sideRemote {
		mode, descending = a.remoteSortMode, a.remoteSortDescending
	}
	a.mu.Unlock()
	a.changePaneSort(which, mode, !descending)
}

func (a *app) changePaneSort(which side, mode sortMode, descending bool) {
	// Initialization callbacks can precede the list widgets. The initial sort
	// is already Name/ascending; defer user changes to the UI thread so list
	// data and native controls cannot temporarily disagree during a reload.
	if a.localLB == nil || a.remoteLB == nil {
		return
	}
	a.ui(func() {
		a.mu.Lock()
		items, list, orderButton := a.localItems, a.localLB, a.localSortDirection
		if which == sideRemote {
			a.remoteSortMode, a.remoteSortDescending = mode, descending
			items, list, orderButton = a.remoteItems, a.remoteLB, a.remoteSortDirection
		} else {
			a.localSortMode, a.localSortDescending = mode, descending
		}
		items = append([]fileEntry(nil), items...)
		sortEntriesWithDirection(items, mode, descending)
		if which == sideRemote {
			a.remoteItems = items
		} else {
			a.localItems = items
		}
		var indexes []int
		if a.selection.Side == which {
			indexes = sortedSelectionIndexes(items, a.selection.Files, a.selection.Dirs)
		}
		a.suppressSelection = true
		a.mu.Unlock()

		// SetModel emits selection events; suppress them while restoring the
		// same names. Sorting the inactive pane leaves the other pane alone.
		_ = list.SetModel(entryDisplays(items))
		list.SetSelectedIndexes(indexes)
		_ = orderButton.SetText(sortDirectionText(descending))
		_ = orderButton.SetToolTipText(sortDirectionToolTip(mode, descending))
		a.mu.Lock()
		a.suppressSelection = false
		a.mu.Unlock()
		a.setButtons()
	})
}

// Publish listings on the same UI queue as sort changes. In particular, a
// background remote refresh must use the latest sort settings when displayed,
// not a stale ordering captured before the user changed the dropdown.
func (a *app) replacePaneItems(which side, dir string, entries []fileEntry) {
	a.ui(func() {
		a.mu.Lock()
		list, pathEdit := a.localLB, a.localPath
		if which == sideRemote {
			sortEntriesWithDirection(entries, a.remoteSortMode, a.remoteSortDescending)
			a.remoteItems = entries
			list, pathEdit = a.remoteLB, a.remotePath
		} else {
			sortEntriesWithDirection(entries, a.localSortMode, a.localSortDescending)
			a.localItems = entries
		}
		a.selection = newSelectionState()
		a.suppressSelection = true
		a.mu.Unlock()
		_ = pathEdit.SetText(dir)
		_ = list.SetModel(entryDisplays(entries))
		a.localLB.SetSelectedIndexes(nil)
		a.remoteLB.SetSelectedIndexes(nil)
		a.mu.Lock()
		a.suppressSelection = false
		a.mu.Unlock()
		a.setButtons()
	})
}
