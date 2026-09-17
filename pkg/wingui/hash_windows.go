//go:build windows

package wingui

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
)

func hashSelectionEnabled(sel selectionState, requested side, busy bool, directory string) bool {
	return !busy && directory != "" && (requested == sideLocal || requested == sideRemote) &&
		sel.Side == requested && len(sel.Files) > 0 && !sel.hasDir()
}

func hashSelectionTargets(sel selectionState, requested side, localDir, remoteDir string) ([]string, error) {
	directory := localDir
	if requested == sideRemote {
		directory = remoteDir
	}
	if !hashSelectionEnabled(sel, requested, false, directory) {
		return nil, fmt.Errorf("hash requires one or more selected files (no folders) in the current pane")
	}
	names, err := sel.names()
	if err != nil {
		return nil, err
	}
	targets := make([]string, 0, len(names))
	for _, name := range names {
		if strings.ContainsRune(name, '\x00') {
			return nil, fmt.Errorf("invalid selected name: %q", name)
		}
		if requested == sideRemote {
			targets = append(targets, remoteJoin(directory, name))
		} else {
			targets = append(targets, normalizeLocalTransferPath(filepath.Join(normalizeLocalTransferPath(directory), name)))
		}
	}
	return targets, nil
}

func (a *app) hashSelection(requested side) {
	// Resolve a snapshot now, not after the dialog or inside the worker: later
	// navigation/selection changes must not change which files get hashed.
	a.mu.Lock()
	busy := a.busy
	targets, err := hashSelectionTargets(a.selection, requested, a.localNav.Current, a.remoteNav.Current)
	a.mu.Unlock()
	if busy {
		return
	}
	if err != nil {
		a.setStatus(err.Error())
		return
	}
	// Reserve the operation before opening a modal dialog. Other remote work
	// cannot start while the user is choosing an algorithm.
	if !a.startOperationWithStatus("choose a hash method") {
		return
	}
	method, err := a.promptHashMethod(requested, len(targets))
	if err != nil || method == "" {
		if err != nil {
			a.setStatus("hash dialog failed: " + err.Error())
		} else {
			a.setStatus("hash cancelled")
		}
		a.endOperation()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.mu.Lock()
	a.hashCancel = cancel
	a.mu.Unlock()
	a.setStatus(fmt.Sprintf("hashing %d %s file(s) with %s", len(targets), requested, method))
	go func() {
		defer func() {
			cancel()
			a.mu.Lock()
			a.hashCancel = nil
			a.mu.Unlock()
			a.endOperation()
		}()
		failed := false
		if requested == sideRemote {
			commands, err := buildRemoteHashCommands(method, targets)
			if err != nil {
				a.setStatus("hash failed: " + err.Error())
				return
			}
			for _, command := range commands {
				if ctx.Err() != nil {
					break
				}
				args := buildChildArgs(a.rawArgs, "--no-reconnect", "--", command)
				if _, code, err := a.runChild(args, false); err != nil {
					failed = true
					a.appendLogLine(fmt.Sprintf("hash batch failed (%d): %v", code, err))
				}
			}
		} else {
			for _, target := range targets {
				if ctx.Err() != nil {
					break
				}
				digest, err := hashLocalFile(ctx, method, target)
				if err != nil {
					failed = true
					a.appendLogLine(fmt.Sprintf("hash failed for %q: %v", target, err))
					continue
				}
				a.appendLogLine(formatHashResult(digest, target))
			}
		}
		switch {
		case ctx.Err() != nil:
			a.setStatus("hash cancelled")
		case failed:
			a.setStatus("hash complete with errors; see Log for individual results")
		default:
			a.setStatus(fmt.Sprintf("hash complete: %d file(s), %s", len(targets), method))
		}
	}()
}

func (a *app) promptHashMethod(selectedSide side, count int) (string, error) {
	methods := hashMethods()
	labels := make([]string, len(methods))
	defaultIndex := 0
	for i, method := range methods {
		labels[i] = method.label
		if method.name == "sha256" {
			defaultIndex = i
		}
	}
	var dlg *walk.Dialog
	var choice *walk.ComboBox
	var calculateButton, cancelButton *walk.PushButton
	selectedIndex := -1
	err := (Dialog{
		AssignTo:      &dlg,
		Title:         "Calculate file hashes",
		MinSize:       Size{Width: 460, Height: 210},
		Font:          appFont(),
		Layout:        VBox{Margins: Margins{Left: 10, Top: 10, Right: 10, Bottom: 10}, Spacing: 8},
		DefaultButton: &calculateButton,
		CancelButton:  &cancelButton,
		Children: []Widget{
			Label{Text: fmt.Sprintf("Hash method for %d selected %s file(s):", count, selectedSide)},
			ComboBox{AssignTo: &choice, Model: labels, CurrentIndex: defaultIndex},
			Label{Text: "MD5 / SHA-1 are for compatibility. SHA-256 is recommended."},
			Label{Text: "Each checksum and filename will be printed in the Log and terminal."},
			Composite{Layout: HBox{MarginsZero: true, Spacing: 8}, Children: []Widget{
				HSpacer{},
				PushButton{AssignTo: &calculateButton, Text: "Calculate", Font: buttonFont(), MinSize: Size{Width: 110, Height: buttonHeight}, OnClicked: func() { selectedIndex = choice.CurrentIndex(); dlg.Accept() }},
				PushButton{AssignTo: &cancelButton, Text: "Cancel", Font: buttonFont(), MinSize: Size{Width: 96, Height: buttonHeight}, OnClicked: func() { dlg.Cancel() }},
			}},
		},
	}).Create(a.mw)
	if err != nil {
		return "", err
	}
	defer dlg.Dispose()
	_ = choice.SetFocus()
	if dlg.Run() != walk.DlgCmdOK {
		return "", nil
	}
	if selectedIndex < 0 || selectedIndex >= len(methods) {
		return "", fmt.Errorf("select a hash method")
	}
	return methods[selectedIndex].name, nil
}
