//go:build windows

package wingui

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/flyssh/flyssh/pkg/cli"
	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
	"golang.org/x/sys/windows"
)

var terminalLogMu sync.Mutex

type side string

const (
	sideNone   side = ""
	sideLocal  side = "local"
	sideRemote side = "remote"
)

type sortMode string

const (
	sortByName sortMode = "name"
	sortByTime sortMode = "time"
	sortBySize sortMode = "size"
)

const (
	buttonHeight         = 44
	transferButtonHeight = 56
	transferTopGap       = 12
	logMinHeight         = 46
	logMaxHeight         = 86
)

const (
	dropUploadCancel = walk.DlgCmdCancel
	dropUploadRsync  = 1001
	dropUploadSCP    = 1002
	deleteConfirm    = 1003
	renameConfirm    = 1004
	newDirConfirm    = 1005
)

func appFont() Font {
	return Font{PointSize: 10}
}

func buttonFont() Font {
	return Font{PointSize: 11, Bold: true}
}

func listFont() Font {
	return Font{Family: "Consolas", PointSize: 10}
}

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

type navState struct {
	Current string
	Back    []string
	Forward []string
}

func (n *navState) commit(next string) {
	if next == "" || next == n.Current {
		return
	}
	if n.Current != "" {
		n.Back = append(n.Back, n.Current)
	}
	n.Current = next
	n.Forward = nil
}

func (n *navState) goBack() string {
	if len(n.Back) == 0 {
		return n.Current
	}
	prev := n.Back[len(n.Back)-1]
	n.Back = n.Back[:len(n.Back)-1]
	if n.Current != "" {
		n.Forward = append(n.Forward, n.Current)
	}
	n.Current = prev
	return n.Current
}

func (n *navState) goForward() string {
	if len(n.Forward) == 0 {
		return n.Current
	}
	next := n.Forward[len(n.Forward)-1]
	n.Forward = n.Forward[:len(n.Forward)-1]
	if n.Current != "" {
		n.Back = append(n.Back, n.Current)
	}
	n.Current = next
	return n.Current
}

type selectionState struct {
	Side  side
	Files map[string]bool
	Dirs  map[string]bool
}

func newSelectionState() selectionState {
	return selectionState{
		Files: make(map[string]bool),
		Dirs:  make(map[string]bool),
	}
}

func (s selectionState) valid() bool {
	return s.Side != sideNone && s.count() > 0
}

func (s selectionState) count() int {
	seen := make(map[string]bool, len(s.Files)+len(s.Dirs))
	for name := range s.Files {
		seen[name] = true
	}
	for name := range s.Dirs {
		seen[name] = true
	}
	return len(seen)
}

func (s selectionState) hasDir() bool {
	return len(s.Dirs) > 0
}

func (s selectionState) names() ([]string, error) {
	seen := make(map[string]bool, len(s.Files)+len(s.Dirs))
	names := make([]string, 0, len(s.Files)+len(s.Dirs))
	add := func(name string) error {
		if seen[name] {
			return nil
		}
		if err := validateSelectedName(name); err != nil {
			return err
		}
		seen[name] = true
		names = append(names, name)
		return nil
	}
	for name := range s.Files {
		if err := add(name); err != nil {
			return nil, err
		}
	}
	for name := range s.Dirs {
		if err := add(name); err != nil {
			return nil, err
		}
	}
	sort.Strings(names)
	return names, nil
}

type childProcess struct {
	cmd  *exec.Cmd
	job  windows.Handle
	once sync.Once
}

func (c *childProcess) wait() error {
	err := c.cmd.Wait()
	c.closeJob()
	return err
}

func (c *childProcess) kill() {
	c.closeJob()
	if c.cmd.Process != nil {
		_ = c.cmd.Process.Kill()
	}
}

func (c *childProcess) closeJob() {
	c.once.Do(func() {
		if c.job != 0 {
			_ = windows.CloseHandle(c.job)
		}
	})
}

type app struct {
	opts    *cli.Options
	rawArgs []string
	exe     string

	mw           *walk.MainWindow
	status       *walk.LineEdit
	summary      *walk.LineEdit
	localPath    *walk.LineEdit
	remotePath   *walk.LineEdit
	localLB      *walk.ListBox
	remoteLB     *walk.ListBox
	localSort    *walk.ComboBox
	remoteSort   *walk.ComboBox
	scpButton    *walk.PushButton
	rsyncButton  *walk.PushButton
	localNewDir  *walk.PushButton
	remoteNewDir *walk.PushButton
	localRename  *walk.PushButton
	remoteRename *walk.PushButton
	localDelete  *walk.PushButton
	remoteDelete *walk.PushButton
	log          *walk.TextEdit

	mu                sync.Mutex
	localNav          navState
	remoteNav         navState
	localItems        []fileEntry
	remoteItems       []fileEntry
	localSortMode     sortMode
	remoteSortMode    sortMode
	selection         selectionState
	busy              bool
	rsyncAvailable    bool
	current           *childProcess
	suppressSelection bool
}

func Run(opts *cli.Options, rawArgs []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cwd, err := os.Getwd()
	if err != nil {
		cwd = "."
	}
	cwd = normalizeLocalTransferPath(cwd)
	_, rsyncErr := resolveRsyncBinary()
	a := &app{
		opts:           opts,
		rawArgs:        append([]string(nil), rawArgs...),
		exe:            exe,
		localNav:       navState{Current: cwd},
		selection:      newSelectionState(),
		rsyncAvailable: rsyncErr == nil,
		localSortMode:  sortByName,
		remoteSortMode: sortByName,
	}
	return a.run()
}

func (a *app) run() error {
	if err := (MainWindow{
		AssignTo: &a.mw,
		Title:    "FlySSH Transfer",
		MinSize:  Size{Width: 980, Height: 680},
		Font:     appFont(),
		Layout:   VBox{Margins: Margins{Left: 8, Top: 6, Right: 8, Bottom: 6}, Spacing: 4},
		Children: []Widget{
			Composite{Layout: Grid{Columns: 2, MarginsZero: true, Spacing: 4}, Children: []Widget{
				Label{Text: "Connection"},
				LineEdit{AssignTo: &a.summary, ReadOnly: true},
				Label{Text: "Status"},
				LineEdit{AssignTo: &a.status, ReadOnly: true},
			}},
			Composite{Layout: HBox{MarginsZero: true, Spacing: 6}, StretchFactor: 8, Children: []Widget{
				Composite{Layout: VBox{MarginsZero: true, Spacing: 4}, StretchFactor: 1, Children: []Widget{
					Composite{Layout: HBox{MarginsZero: true, Spacing: 4}, Children: []Widget{
						Label{Text: "Local"},
						PushButton{Text: "Back", Font: buttonFont(), MinSize: Size{Width: 64, Height: buttonHeight}, MaxSize: Size{Width: 64}, OnClicked: a.localBack},
						PushButton{Text: "Forward", Font: buttonFont(), MinSize: Size{Width: 82, Height: buttonHeight}, MaxSize: Size{Width: 82}, OnClicked: a.localForward},
						PushButton{Text: "Up", Font: buttonFont(), MinSize: Size{Width: 52, Height: buttonHeight}, MaxSize: Size{Width: 52}, OnClicked: a.localUp},
						PushButton{Text: "Refresh", Font: buttonFont(), MinSize: Size{Width: 82, Height: buttonHeight}, MaxSize: Size{Width: 82}, OnClicked: a.refreshLocal},
						Label{Text: "Sort"},
						ComboBox{AssignTo: &a.localSort, Model: sortModeLabels(), CurrentIndex: 0, MaxSize: Size{Width: 92}, OnCurrentIndexChanged: a.localSortChanged},
					}},
					Composite{Layout: HBox{MarginsZero: true, Spacing: 4}, Children: []Widget{
						LineEdit{AssignTo: &a.localPath, StretchFactor: 1, OnKeyDown: func(key walk.Key) {
							if key == walk.KeyReturn {
								a.gotoLocalPath(a.localPath.Text())
							}
						}},
						PushButton{AssignTo: &a.localNewDir, Text: "+Dir", Font: buttonFont(), MinSize: Size{Width: 64, Height: buttonHeight}, MaxSize: Size{Width: 64}, OnClicked: func() { a.newDirectory(sideLocal) }},
						PushButton{AssignTo: &a.localRename, Text: "MV", Font: buttonFont(), MinSize: Size{Width: 48, Height: buttonHeight}, MaxSize: Size{Width: 48}, OnClicked: func() { a.renameSelection(sideLocal) }},
						PushButton{AssignTo: &a.localDelete, Text: "Del", Font: buttonFont(), MinSize: Size{Width: 48, Height: buttonHeight}, MaxSize: Size{Width: 48}, OnClicked: func() { a.deleteSelection(sideLocal) }},
					}},
					ListBox{AssignTo: &a.localLB, Font: listFont(), MultiSelection: true, StretchFactor: 1,
						OnSelectedIndexesChanged: a.localSelectionChanged,
						OnItemActivated:          a.localActivate},
				}},
				Composite{Layout: VBox{MarginsZero: true, Spacing: 8}, MinSize: Size{Width: 150}, MaxSize: Size{Width: 150}, Children: []Widget{
					VSpacer{Size: transferTopGap},
					VSpacer{},
					PushButton{AssignTo: &a.scpButton, Text: "SCP Transfer", Font: buttonFont(), MinSize: Size{Width: 140, Height: transferButtonHeight}, OnClicked: func() { a.startTransfer("scp") }},
					PushButton{AssignTo: &a.rsyncButton, Text: "rsync Transfer", Font: buttonFont(), MinSize: Size{Width: 140, Height: transferButtonHeight}, OnClicked: func() { a.startTransfer("rsync") }},
					VSpacer{},
				}},
				Composite{Layout: VBox{MarginsZero: true, Spacing: 4}, StretchFactor: 1, Children: []Widget{
					Composite{Layout: HBox{MarginsZero: true, Spacing: 4}, Children: []Widget{
						Label{Text: "Remote"},
						PushButton{Text: "Back", Font: buttonFont(), MinSize: Size{Width: 64, Height: buttonHeight}, MaxSize: Size{Width: 64}, OnClicked: a.remoteBack},
						PushButton{Text: "Forward", Font: buttonFont(), MinSize: Size{Width: 82, Height: buttonHeight}, MaxSize: Size{Width: 82}, OnClicked: a.remoteForward},
						PushButton{Text: "Up", Font: buttonFont(), MinSize: Size{Width: 52, Height: buttonHeight}, MaxSize: Size{Width: 52}, OnClicked: a.remoteUp},
						PushButton{Text: "Refresh", Font: buttonFont(), MinSize: Size{Width: 82, Height: buttonHeight}, MaxSize: Size{Width: 82}, OnClicked: a.refreshRemote},
						Label{Text: "Sort"},
						ComboBox{AssignTo: &a.remoteSort, Model: sortModeLabels(), CurrentIndex: 0, MaxSize: Size{Width: 92}, OnCurrentIndexChanged: a.remoteSortChanged},
					}},
					Composite{Layout: HBox{MarginsZero: true, Spacing: 4}, Children: []Widget{
						LineEdit{AssignTo: &a.remotePath, StretchFactor: 1, OnKeyDown: func(key walk.Key) {
							if key == walk.KeyReturn {
								a.gotoRemotePath(a.remotePath.Text())
							}
						}},
						PushButton{AssignTo: &a.remoteNewDir, Text: "+Dir", Font: buttonFont(), MinSize: Size{Width: 64, Height: buttonHeight}, MaxSize: Size{Width: 64}, OnClicked: func() { a.newDirectory(sideRemote) }},
						PushButton{AssignTo: &a.remoteRename, Text: "MV", Font: buttonFont(), MinSize: Size{Width: 48, Height: buttonHeight}, MaxSize: Size{Width: 48}, OnClicked: func() { a.renameSelection(sideRemote) }},
						PushButton{AssignTo: &a.remoteDelete, Text: "Del", Font: buttonFont(), MinSize: Size{Width: 48, Height: buttonHeight}, MaxSize: Size{Width: 48}, OnClicked: func() { a.deleteSelection(sideRemote) }},
					}},
					ListBox{AssignTo: &a.remoteLB, Font: listFont(), MultiSelection: true, StretchFactor: 1,
						OnSelectedIndexesChanged: a.remoteSelectionChanged,
						OnItemActivated:          a.remoteActivate},
				}},
			}},
			Composite{Layout: HBox{MarginsZero: true, Spacing: 4}, Children: []Widget{
				Label{Text: "Log"},
				PushButton{Text: "Clear", Font: buttonFont(), MinSize: Size{Width: 64, Height: buttonHeight}, MaxSize: Size{Width: 64}, OnClicked: a.clearLog},
			}},
			TextEdit{AssignTo: &a.log, ReadOnly: true, VScroll: true, HScroll: true, MinSize: Size{Height: logMinHeight}, MaxSize: Size{Height: logMaxHeight}},
		},
	}).Create(); err != nil {
		return err
	}
	a.mw.Closing().Attach(func(canceled *bool, reason walk.CloseReason) {
		a.killCurrent()
	})
	a.remoteLB.DropFiles().Attach(a.remoteDropFiles)
	a.summary.SetText(connectionSummary(a.opts))
	a.localPath.SetText(a.localNav.Current)
	if !a.rsyncAvailable {
		a.appendLogLine("rsync disabled: local rsync binary was not found in supported locations")
	}
	a.refreshLocal()
	a.setButtons()
	go a.initializeRemote()
	a.mw.Run()
	return nil
}

func (a *app) initializeRemote() {
	if !a.startOperation() {
		return
	}
	defer a.endOperation()
	home, err := a.runBrowseHome()
	target := strings.TrimSpace(home)
	if err != nil || target == "" {
		if err != nil {
			a.appendLogLine("remote HOME failed: " + err.Error())
		}
		target = "/tmp"
	}
	if err := a.loadRemoteUnderOperation(target); err != nil {
		a.setStatus("remote list failed: " + err.Error())
		return
	}
	a.mu.Lock()
	a.remoteNav = navState{Current: target}
	a.mu.Unlock()
	a.setStatus("ready")
}

func (a *app) refreshLocal() {
	a.mu.Lock()
	dir := normalizeLocalTransferPath(a.localNav.Current)
	a.localNav.Current = dir
	a.mu.Unlock()
	items, err := listLocal(dir)
	if err != nil {
		a.setStatus("local list failed: " + err.Error())
		return
	}
	a.mu.Lock()
	sortEntries(items, a.localSortMode)
	a.localItems = items
	a.selection = newSelectionState()
	a.mu.Unlock()
	a.ui(func() {
		a.localPath.SetText(dir)
		a.localLB.SetModel(entryDisplays(items))
		a.localLB.SetSelectedIndexes(nil)
		a.remoteLB.SetSelectedIndexes(nil)
	})
	a.setButtons()
}

func (a *app) refreshRemote() {
	go func() {
		if !a.startOperation() {
			return
		}
		defer a.endOperation()
		a.mu.Lock()
		dir := a.remoteNav.Current
		a.mu.Unlock()
		if err := a.loadRemoteUnderOperation(dir); err != nil {
			a.setStatus("remote list failed: " + err.Error())
		}
	}()
}

func (a *app) loadRemoteUnderOperation(dir string) error {
	if dir == "" {
		return fmt.Errorf("empty remote directory")
	}
	items, err := a.runBrowseList(dir)
	if err != nil {
		return err
	}
	entries := make([]fileEntry, 0, len(items))
	for _, item := range items {
		entries = append(entries, fileEntry{
			Name:    item.Name,
			IsDir:   item.IsDir,
			Size:    item.Size,
			MTime:   item.MTime,
			Mode:    item.Mode,
			User:    item.User,
			Group:   item.Group,
			Display: formatEntryDisplay(item.Name, item.IsDir, item.Size, item.MTime, item.Mode, item.User, item.Group),
		})
	}
	a.mu.Lock()
	sortEntries(entries, a.remoteSortMode)
	a.remoteItems = entries
	a.selection = newSelectionState()
	a.mu.Unlock()
	a.ui(func() {
		a.remotePath.SetText(dir)
		a.remoteLB.SetModel(entryDisplays(entries))
		a.localLB.SetSelectedIndexes(nil)
		a.remoteLB.SetSelectedIndexes(nil)
	})
	a.setButtons()
	return nil
}

func (a *app) runBrowseHome() (string, error) {
	out, _, err := a.runChild(buildChildArgs(a.rawArgs, "--gui-internal-home"), true)
	return string(out), err
}

func (a *app) runBrowseList(dir string) ([]remoteEntry, error) {
	out, _, err := a.runChild(buildChildArgs(a.rawArgs, "--gui-internal-list", dir), true)
	if err != nil {
		return nil, err
	}
	var entries []remoteEntry
	if err := json.Unmarshal(out, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

func (a *app) gotoLocalPath(dir string) {
	dir = normalizeLocalTransferPath(dir)
	a.mu.Lock()
	next := a.localNav
	a.mu.Unlock()
	next.commit(dir)
	if err := validateLocalDir(dir); err != nil {
		a.setStatus("local path failed: " + err.Error())
		return
	}
	a.mu.Lock()
	a.localNav = next
	a.mu.Unlock()
	a.refreshLocal()
}

func (a *app) gotoRemotePath(dir string) {
	a.mu.Lock()
	next := a.remoteNav
	current := a.remoteNav.Current
	a.mu.Unlock()
	next.commit(dir)
	go func() {
		if !a.startOperation() {
			return
		}
		defer a.endOperation()
		if err := a.loadRemoteUnderOperation(dir); err != nil {
			a.setStatus("remote path failed: " + err.Error())
			a.ui(func() { a.remotePath.SetText(current) })
			return
		}
		a.mu.Lock()
		a.remoteNav = next
		a.mu.Unlock()
	}()
}

func (a *app) localBack() {
	a.mu.Lock()
	next := a.localNav
	a.mu.Unlock()
	dir := normalizeLocalTransferPath(next.goBack())
	next.Current = dir
	if err := validateLocalDir(dir); err != nil {
		a.setStatus("local path failed: " + err.Error())
		return
	}
	a.mu.Lock()
	a.localNav = next
	a.mu.Unlock()
	a.refreshLocal()
}

func (a *app) localForward() {
	a.mu.Lock()
	next := a.localNav
	a.mu.Unlock()
	dir := normalizeLocalTransferPath(next.goForward())
	next.Current = dir
	if err := validateLocalDir(dir); err != nil {
		a.setStatus("local path failed: " + err.Error())
		return
	}
	a.mu.Lock()
	a.localNav = next
	a.mu.Unlock()
	a.refreshLocal()
}

func (a *app) localUp() {
	a.mu.Lock()
	current := a.localNav.Current
	a.mu.Unlock()
	a.gotoLocalPath(filepath.Dir(current))
}

func (a *app) remoteBack() {
	a.mu.Lock()
	next := a.remoteNav
	current := a.remoteNav.Current
	a.mu.Unlock()
	dir := next.goBack()
	if dir == current {
		return
	}
	a.tryRemoteNav(next, dir, current)
}

func (a *app) remoteForward() {
	a.mu.Lock()
	next := a.remoteNav
	current := a.remoteNav.Current
	a.mu.Unlock()
	dir := next.goForward()
	if dir == current {
		return
	}
	a.tryRemoteNav(next, dir, current)
}

func (a *app) remoteUp() {
	a.mu.Lock()
	current := a.remoteNav.Current
	a.mu.Unlock()
	a.gotoRemotePath(remoteParent(current))
}

func (a *app) tryRemoteNav(next navState, dir, previous string) {
	go func() {
		if !a.startOperation() {
			return
		}
		defer a.endOperation()
		if err := a.loadRemoteUnderOperation(dir); err != nil {
			a.setStatus("remote path failed: " + err.Error())
			a.ui(func() { a.remotePath.SetText(previous) })
			return
		}
		a.mu.Lock()
		a.remoteNav = next
		a.mu.Unlock()
	}()
}

func (a *app) localActivate() {
	a.mu.Lock()
	items := append([]fileEntry(nil), a.localItems...)
	dir := a.localNav.Current
	a.mu.Unlock()
	idx := a.localLB.CurrentIndex()
	if idx >= 0 && idx < len(items) && items[idx].IsDir {
		a.gotoLocalPath(filepath.Join(dir, items[idx].Name))
	}
}

func (a *app) remoteActivate() {
	a.mu.Lock()
	items := append([]fileEntry(nil), a.remoteItems...)
	dir := a.remoteNav.Current
	a.mu.Unlock()
	idx := a.remoteLB.CurrentIndex()
	if idx >= 0 && idx < len(items) && items[idx].IsDir {
		a.gotoRemotePath(remoteJoin(dir, items[idx].Name))
	}
}

func (a *app) localSelectionChanged() {
	a.mu.Lock()
	if a.suppressSelection {
		a.mu.Unlock()
		return
	}
	items := append([]fileEntry(nil), a.localItems...)
	a.mu.Unlock()
	normalized := a.applySelection(sideLocal, a.localLB.SelectedIndexes(), items)
	a.mu.Lock()
	a.suppressSelection = true
	a.mu.Unlock()
	a.localLB.SetSelectedIndexes(normalized)
	a.remoteLB.SetSelectedIndexes(nil)
	a.mu.Lock()
	a.suppressSelection = false
	a.mu.Unlock()
}

func (a *app) remoteSelectionChanged() {
	a.mu.Lock()
	if a.suppressSelection {
		a.mu.Unlock()
		return
	}
	items := append([]fileEntry(nil), a.remoteItems...)
	a.mu.Unlock()
	normalized := a.applySelection(sideRemote, a.remoteLB.SelectedIndexes(), items)
	a.mu.Lock()
	a.suppressSelection = true
	a.mu.Unlock()
	a.remoteLB.SetSelectedIndexes(normalized)
	a.localLB.SetSelectedIndexes(nil)
	a.mu.Lock()
	a.suppressSelection = false
	a.mu.Unlock()
}

func (a *app) applySelection(selectedSide side, indexes []int, entries []fileEntry) []int {
	sel, normalized, err := selectionFromIndexes(selectedSide, indexes, entries)
	a.mu.Lock()
	a.selection = sel
	a.mu.Unlock()
	if err != nil {
		a.setStatus(err.Error())
	}
	a.setButtons()
	return normalized
}

func selectionFromIndexes(selectedSide side, indexes []int, entries []fileEntry) (selectionState, []int, error) {
	sel := newSelectionState()
	normalized := make([]int, 0, len(indexes))
	seenIndexes := make(map[int]bool, len(indexes))
	for _, idx := range indexes {
		if idx < 0 || idx >= len(entries) || seenIndexes[idx] {
			continue
		}
		seenIndexes[idx] = true
		entry := entries[idx]
		if err := validateSelectedName(entry.Name); err != nil {
			return newSelectionState(), nil, err
		}
		sel.Side = selectedSide
		if entry.IsDir {
			sel.Dirs[entry.Name] = true
		} else {
			sel.Files[entry.Name] = true
		}
		normalized = append(normalized, idx)
	}
	return sel, normalized, nil
}

func validateSelectedName(name string) error {
	switch name {
	case "", ".", "..", "~":
		return fmt.Errorf("invalid selected name: %q", name)
	}
	if strings.HasPrefix(name, "~/") || strings.HasPrefix(name, `~\`) {
		return fmt.Errorf("invalid selected name: %q", name)
	}
	if len(name) >= 2 && name[1] == ':' && isASCIIAlpha(name[0]) {
		return fmt.Errorf("invalid selected name: %q", name)
	}
	if strings.ContainsAny(name, `/\`) {
		return fmt.Errorf("invalid selected name: %q", name)
	}
	return nil
}

func normalizeNewDirName(input string) (string, error) {
	name := strings.TrimSpace(input)
	if err := validateSelectedName(name); err != nil {
		return "", err
	}
	return name, nil
}

func isASCIIAlpha(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

func (a *app) localSortChanged() {
	if a.localSort == nil {
		return
	}
	mode := sortModeFromIndex(a.localSort.CurrentIndex())
	a.mu.Lock()
	a.localSortMode = mode
	if a.localLB == nil || a.remoteLB == nil {
		a.mu.Unlock()
		return
	}
	items := append([]fileEntry(nil), a.localItems...)
	sortEntries(items, mode)
	a.localItems = items
	a.selection = newSelectionState()
	a.mu.Unlock()
	a.ui(func() {
		a.localLB.SetModel(entryDisplays(items))
		a.localLB.SetSelectedIndexes(nil)
		a.remoteLB.SetSelectedIndexes(nil)
	})
	a.setButtons()
}

func (a *app) remoteSortChanged() {
	if a.remoteSort == nil {
		return
	}
	mode := sortModeFromIndex(a.remoteSort.CurrentIndex())
	a.mu.Lock()
	a.remoteSortMode = mode
	if a.localLB == nil || a.remoteLB == nil {
		a.mu.Unlock()
		return
	}
	items := append([]fileEntry(nil), a.remoteItems...)
	sortEntries(items, mode)
	a.remoteItems = items
	a.selection = newSelectionState()
	a.mu.Unlock()
	a.ui(func() {
		a.remoteLB.SetModel(entryDisplays(items))
		a.localLB.SetSelectedIndexes(nil)
		a.remoteLB.SetSelectedIndexes(nil)
	})
	a.setButtons()
}

func (a *app) startTransfer(protocol string) {
	a.mu.Lock()
	selection := a.selection
	localDir := a.localNav.Current
	remoteDir := a.remoteNav.Current
	a.mu.Unlock()

	upload := selection.Side == sideLocal
	sources, target, err := transferPaths(selection, localDir, remoteDir)
	if err != nil {
		a.setStatus(err.Error())
		return
	}
	flag, raw, err := buildTransferArgs(protocol, upload, selection.hasDir(), sources, target)
	if err != nil {
		a.setStatus(err.Error())
		return
	}
	args := buildChildArgs(a.rawArgs, flag, raw)
	a.runTransferArgs(args)
}

func (a *app) startUpload(protocol string, sources []string, hasDir bool, remoteDir string) {
	flag, raw, err := buildTransferArgs(protocol, true, hasDir, sources, remoteDir)
	if err != nil {
		a.setStatus(err.Error())
		return
	}
	args := buildChildArgs(a.rawArgs, flag, raw)
	a.runTransferArgs(args)
}

func (a *app) runTransferArgs(args []string) {
	go func() {
		if !a.startOperation() {
			return
		}
		defer a.endOperation()
		_, code, err := a.runChild(args, false)
		if err != nil {
			a.setStatus(fmt.Sprintf("transfer failed (%d): %v", code, err))
			return
		}
		a.setStatus("transfer complete")
		a.refreshLocal()
		a.mu.Lock()
		currentRemote := a.remoteNav.Current
		a.mu.Unlock()
		_ = a.loadRemoteUnderOperation(currentRemote)
	}()
}

func (a *app) remoteDropFiles(paths []string) {
	a.mu.Lock()
	busy := a.busy
	remoteDir := a.remoteNav.Current
	rsyncAvailable := a.rsyncAvailable
	a.mu.Unlock()
	if busy {
		a.setDropStatus("drop ignored: operation already running")
		return
	}
	if remoteDir == "" {
		a.setDropStatus("drop ignored: remote directory is not ready")
		return
	}

	sources, hasDir, summary, err := classifyDroppedPaths(paths)
	if err != nil {
		a.setDropStatus("drop rejected: " + err.Error())
		return
	}
	protocol := a.promptDropUploadProtocol(summary, remoteDir, rsyncAvailable)
	if protocol == "" {
		a.appendLogLine("drop upload cancelled")
		return
	}
	a.startUpload(protocol, sources, hasDir, remoteDir)
}

func (a *app) setDropStatus(message string) {
	a.setStatus(message)
}

func (a *app) promptDropUploadProtocol(summary, remoteDir string, rsyncAvailable bool) string {
	var dlg *walk.Dialog
	var cancelButton *walk.PushButton
	message := "Upload dropped items to:\r\n" + remoteDir + "\r\n\r\n" + summary
	if !rsyncAvailable {
		message += "\r\n\r\nrsync is unavailable; use SCP or cancel."
	}

	err := (Dialog{
		AssignTo:      &dlg,
		Title:         "Upload dropped items",
		MinSize:       Size{Width: 560, Height: 320},
		Font:          appFont(),
		Layout:        VBox{Margins: Margins{Left: 10, Top: 10, Right: 10, Bottom: 10}, Spacing: 8},
		CancelButton:  &cancelButton,
		DefaultButton: &cancelButton,
		Children: []Widget{
			Label{Text: "Choose upload protocol"},
			TextEdit{Text: message, ReadOnly: true, VScroll: true, MinSize: Size{Height: 170}},
			Composite{Layout: HBox{MarginsZero: true, Spacing: 8}, Children: []Widget{
				HSpacer{},
				PushButton{Text: "rsync", Font: buttonFont(), Enabled: rsyncAvailable, MinSize: Size{Width: 96, Height: buttonHeight}, OnClicked: func() {
					dlg.Close(dropUploadRsync)
				}},
				PushButton{Text: "SCP", Font: buttonFont(), MinSize: Size{Width: 96, Height: buttonHeight}, OnClicked: func() {
					dlg.Close(dropUploadSCP)
				}},
				PushButton{AssignTo: &cancelButton, Text: "Cancel", Font: buttonFont(), MinSize: Size{Width: 96, Height: buttonHeight}, OnClicked: func() {
					dlg.Close(dropUploadCancel)
				}},
			}},
		},
	}).Create(a.mw)
	if err != nil {
		a.setStatus("drop confirm failed: " + err.Error())
		return ""
	}
	defer dlg.Dispose()

	switch dlg.Run() {
	case dropUploadRsync:
		return "rsync"
	case dropUploadSCP:
		return "scp"
	default:
		return ""
	}
}

func (a *app) newDirectory(requestedSide side) {
	a.mu.Lock()
	localDir := a.localNav.Current
	remoteDir := a.remoteNav.Current
	a.mu.Unlock()

	currentDir := localDir
	if requestedSide == sideRemote {
		currentDir = remoteDir
	}
	if currentDir == "" {
		a.setStatus("new folder requires a current directory")
		return
	}
	name, ok := a.promptNewDirName(requestedSide, currentDir)
	if !ok {
		a.appendLogLine("new folder cancelled")
		return
	}
	if requestedSide == sideLocal {
		target, err := newLocalDirTarget(localDir, name)
		if err != nil {
			a.setStatus(err.Error())
			return
		}
		a.runLocalNewDir(target)
		return
	}
	target, err := newRemoteDirTarget(remoteDir, name)
	if err != nil {
		a.setStatus(err.Error())
		return
	}
	a.runRemoteNewDir(target)
}

func (a *app) promptNewDirName(selectedSide side, currentDir string) (string, bool) {
	var dlg *walk.Dialog
	var nameEdit *walk.LineEdit
	var createButton *walk.PushButton
	var cancelButton *walk.PushButton
	var name string
	scope := "local"
	if selectedSide == sideRemote {
		scope = "remote"
	}
	confirmCreate := func() {
		name = nameEdit.Text()
		dlg.Close(newDirConfirm)
	}

	err := (Dialog{
		AssignTo:      &dlg,
		Title:         "New folder",
		MinSize:       Size{Width: 520, Height: 180},
		Font:          appFont(),
		Layout:        VBox{Margins: Margins{Left: 10, Top: 10, Right: 10, Bottom: 10}, Spacing: 8},
		CancelButton:  &cancelButton,
		DefaultButton: &createButton,
		Children: []Widget{
			Label{Text: "Create a new " + scope + " folder under:"},
			LineEdit{Text: currentDir, ReadOnly: true},
			LineEdit{AssignTo: &nameEdit, OnKeyDown: func(key walk.Key) {
				if key == walk.KeyReturn {
					confirmCreate()
				}
			}},
			Composite{Layout: HBox{MarginsZero: true, Spacing: 8}, Children: []Widget{
				HSpacer{},
				PushButton{AssignTo: &createButton, Text: "Create", Font: buttonFont(), MinSize: Size{Width: 96, Height: buttonHeight}, OnClicked: confirmCreate},
				PushButton{AssignTo: &cancelButton, Text: "Cancel", Font: buttonFont(), MinSize: Size{Width: 96, Height: buttonHeight}, OnClicked: func() {
					dlg.Close(walk.DlgCmdCancel)
				}},
			}},
		},
	}).Create(a.mw)
	if err != nil {
		a.setStatus("new folder dialog failed: " + err.Error())
		return "", false
	}
	defer dlg.Dispose()
	_ = nameEdit.SetFocus()
	if dlg.Run() != newDirConfirm {
		return "", false
	}
	name, err = normalizeNewDirName(name)
	if err != nil {
		a.setStatus(err.Error())
		return "", false
	}
	return name, true
}

func (a *app) runLocalNewDir(target string) {
	go func() {
		if !a.startOperationWithStatus("creating local folder") {
			return
		}
		defer a.endOperation()
		a.appendLogLine("mkdir local: " + target)
		if err := os.Mkdir(target, 0755); err != nil {
			a.setStatus("create folder failed: " + err.Error())
			return
		}
		a.setStatus("create folder complete")
		a.refreshLocal()
	}()
}

func (a *app) runRemoteNewDir(target string) {
	command, err := buildRemoteMkdirCommand(target)
	if err != nil {
		a.setStatus(err.Error())
		return
	}
	args := buildChildArgs(a.rawArgs, "--no-reconnect", "--", command)
	go func() {
		if !a.startOperation() {
			return
		}
		defer a.endOperation()
		_, code, err := a.runChild(args, false)
		if err != nil {
			a.setStatus(fmt.Sprintf("create folder failed (%d): %v", code, err))
			return
		}
		a.setStatus("create folder complete")
		a.mu.Lock()
		currentRemote := a.remoteNav.Current
		a.mu.Unlock()
		_ = a.loadRemoteUnderOperation(currentRemote)
	}()
}

func (a *app) deleteSelection(requestedSide side) {
	a.mu.Lock()
	selection := a.selection
	localDir := a.localNav.Current
	remoteDir := a.remoteNav.Current
	a.mu.Unlock()
	if selection.Side != requestedSide || !selection.valid() {
		a.setStatus("delete requires a selection")
		return
	}
	targets, err := deleteTargets(selection, localDir, remoteDir)
	if err != nil {
		a.setStatus(err.Error())
		return
	}
	if !a.promptDeleteConfirm(requestedSide, targets) {
		a.appendLogLine("delete cancelled")
		return
	}
	if requestedSide == sideLocal {
		a.runLocalDelete(targets)
		return
	}
	a.runRemoteDelete(targets)
}

func (a *app) promptDeleteConfirm(selectedSide side, targets []string) bool {
	var dlg *walk.Dialog
	var cancelButton *walk.PushButton
	scope := "local"
	if selectedSide == sideRemote {
		scope = "remote"
	}
	message := "Delete selected " + scope + " item(s)?\r\n\r\n" + selectionSummary(targets) + "\r\n\r\nThis cannot be undone."

	err := (Dialog{
		AssignTo:      &dlg,
		Title:         "Confirm delete",
		MinSize:       Size{Width: 560, Height: 320},
		Font:          appFont(),
		Layout:        VBox{Margins: Margins{Left: 10, Top: 10, Right: 10, Bottom: 10}, Spacing: 8},
		CancelButton:  &cancelButton,
		DefaultButton: &cancelButton,
		Children: []Widget{
			Label{Text: "Confirm delete"},
			TextEdit{Text: message, ReadOnly: true, VScroll: true, MinSize: Size{Height: 170}},
			Composite{Layout: HBox{MarginsZero: true, Spacing: 8}, Children: []Widget{
				HSpacer{},
				PushButton{Text: "Delete", Font: buttonFont(), MinSize: Size{Width: 96, Height: buttonHeight}, OnClicked: func() {
					dlg.Close(deleteConfirm)
				}},
				PushButton{AssignTo: &cancelButton, Text: "Cancel", Font: buttonFont(), MinSize: Size{Width: 96, Height: buttonHeight}, OnClicked: func() {
					dlg.Close(walk.DlgCmdCancel)
				}},
			}},
		},
	}).Create(a.mw)
	if err != nil {
		a.setStatus("delete confirm failed: " + err.Error())
		return false
	}
	defer dlg.Dispose()
	return dlg.Run() == deleteConfirm
}

func (a *app) runLocalDelete(targets []string) {
	go func() {
		if !a.startOperationWithStatus("deleting local selection") {
			return
		}
		defer a.endOperation()
		for _, target := range targets {
			a.appendLogLine("delete local: " + target)
			if err := os.RemoveAll(target); err != nil {
				a.setStatus("delete failed: " + err.Error())
				return
			}
		}
		a.setStatus("delete complete")
		a.refreshLocal()
	}()
}

func (a *app) runRemoteDelete(targets []string) {
	command, err := buildRemoteDeleteCommand(targets)
	if err != nil {
		a.setStatus(err.Error())
		return
	}
	args := buildChildArgs(a.rawArgs, "--no-reconnect", "--", command)
	go func() {
		if !a.startOperation() {
			return
		}
		defer a.endOperation()
		_, code, err := a.runChild(args, false)
		if err != nil {
			a.setStatus(fmt.Sprintf("delete failed (%d): %v", code, err))
			return
		}
		a.setStatus("delete complete")
		a.mu.Lock()
		currentRemote := a.remoteNav.Current
		a.mu.Unlock()
		_ = a.loadRemoteUnderOperation(currentRemote)
	}()
}

func (a *app) renameSelection(requestedSide side) {
	a.mu.Lock()
	selection := a.selection
	localDir := a.localNav.Current
	remoteDir := a.remoteNav.Current
	a.mu.Unlock()
	if selection.Side != requestedSide || !selection.valid() {
		a.setStatus("rename requires a selection")
		return
	}
	source, err := renameTarget(selection, localDir, remoteDir)
	if err != nil {
		a.setStatus(err.Error())
		return
	}
	target, ok := a.promptRenameTarget(requestedSide, source)
	if !ok {
		a.appendLogLine("rename cancelled")
		return
	}
	if requestedSide == sideLocal {
		target = normalizeLocalTransferPath(target)
	}
	if target == source {
		a.setStatus("rename skipped: target is unchanged")
		return
	}
	if requestedSide == sideLocal {
		a.runLocalRename(source, target)
		return
	}
	a.runRemoteRename(source, target)
}

func (a *app) promptRenameTarget(selectedSide side, source string) (string, bool) {
	var dlg *walk.Dialog
	var targetEdit *walk.LineEdit
	var renameButton *walk.PushButton
	var cancelButton *walk.PushButton
	var target string
	scope := "local"
	if selectedSide == sideRemote {
		scope = "remote"
	}
	confirmRename := func() {
		target = targetEdit.Text()
		dlg.Close(renameConfirm)
	}

	err := (Dialog{
		AssignTo:      &dlg,
		Title:         "Move / rename",
		MinSize:       Size{Width: 640, Height: 180},
		Font:          appFont(),
		Layout:        VBox{Margins: Margins{Left: 10, Top: 10, Right: 10, Bottom: 10}, Spacing: 8},
		CancelButton:  &cancelButton,
		DefaultButton: &renameButton,
		Children: []Widget{
			Label{Text: "Edit the full " + scope + " path"},
			LineEdit{AssignTo: &targetEdit, OnKeyDown: func(key walk.Key) {
				if key == walk.KeyReturn {
					confirmRename()
				}
			}},
			Composite{Layout: HBox{MarginsZero: true, Spacing: 8}, Children: []Widget{
				HSpacer{},
				PushButton{AssignTo: &renameButton, Text: "MV", Font: buttonFont(), MinSize: Size{Width: 96, Height: buttonHeight}, OnClicked: confirmRename},
				PushButton{AssignTo: &cancelButton, Text: "Cancel", Font: buttonFont(), MinSize: Size{Width: 96, Height: buttonHeight}, OnClicked: func() {
					dlg.Close(walk.DlgCmdCancel)
				}},
			}},
		},
	}).Create(a.mw)
	if err != nil {
		a.setStatus("rename dialog failed: " + err.Error())
		return "", false
	}
	defer dlg.Dispose()
	if err := targetEdit.SetText(source); err != nil {
		a.setStatus("rename dialog failed: " + err.Error())
		return "", false
	}
	_ = targetEdit.SetFocus()
	if dlg.Run() != renameConfirm {
		return "", false
	}
	if strings.TrimSpace(target) == "" {
		a.setStatus("rename target is empty")
		return "", false
	}
	return target, true
}

func (a *app) runLocalRename(source, target string) {
	go func() {
		if !a.startOperationWithStatus("renaming local selection") {
			return
		}
		defer a.endOperation()
		a.appendLogLine("rename local: " + source + " -> " + target)
		if err := os.Rename(source, target); err != nil {
			a.setStatus("rename failed: " + err.Error())
			return
		}
		a.setStatus("rename complete")
		a.refreshLocal()
	}()
}

func (a *app) runRemoteRename(source, target string) {
	command, err := buildRemoteRenameCommand(source, target)
	if err != nil {
		a.setStatus(err.Error())
		return
	}
	args := buildChildArgs(a.rawArgs, "--no-reconnect", "--", command)
	go func() {
		if !a.startOperation() {
			return
		}
		defer a.endOperation()
		_, code, err := a.runChild(args, false)
		if err != nil {
			a.setStatus(fmt.Sprintf("rename failed (%d): %v", code, err))
			return
		}
		a.setStatus("rename complete")
		a.mu.Lock()
		currentRemote := a.remoteNav.Current
		a.mu.Unlock()
		_ = a.loadRemoteUnderOperation(currentRemote)
	}()
}

func transferPaths(sel selectionState, localDir, remoteDir string) ([]string, string, error) {
	names, err := sel.names()
	if err != nil {
		return nil, "", err
	}
	sources := make([]string, 0, len(names))
	switch sel.Side {
	case sideLocal:
		localDir = normalizeLocalTransferPath(localDir)
		for _, name := range names {
			sources = append(sources, normalizeLocalTransferPath(filepath.Join(localDir, name)))
		}
		return sources, remoteDir, nil
	case sideRemote:
		localDir = normalizeLocalTransferPath(localDir)
		for _, name := range names {
			sources = append(sources, remoteJoin(remoteDir, name))
		}
		return sources, localDir, nil
	default:
		return nil, "", fmt.Errorf("no selected transfer sources")
	}
}

func deleteTargets(sel selectionState, localDir, remoteDir string) ([]string, error) {
	if !sel.valid() {
		return nil, fmt.Errorf("no selected delete targets")
	}
	names, err := sel.names()
	if err != nil {
		return nil, err
	}
	targets := make([]string, 0, len(names))
	switch sel.Side {
	case sideLocal:
		localDir = normalizeLocalTransferPath(localDir)
		for _, name := range names {
			targets = append(targets, normalizeLocalTransferPath(filepath.Join(localDir, name)))
		}
	case sideRemote:
		if remoteDir == "" {
			return nil, fmt.Errorf("empty remote directory")
		}
		for _, name := range names {
			targets = append(targets, remoteJoin(remoteDir, name))
		}
	default:
		return nil, fmt.Errorf("no selected delete targets")
	}
	return targets, nil
}

func renameTarget(sel selectionState, localDir, remoteDir string) (string, error) {
	if !selectionSingle(sel) {
		return "", fmt.Errorf("rename requires exactly one selected item")
	}
	targets, err := deleteTargets(sel, localDir, remoteDir)
	if err != nil {
		return "", err
	}
	if len(targets) != 1 {
		return "", fmt.Errorf("rename requires exactly one selected item")
	}
	return targets[0], nil
}

func newLocalDirTarget(currentDir, name string) (string, error) {
	if currentDir == "" {
		return "", fmt.Errorf("empty local directory")
	}
	name, err := normalizeNewDirName(name)
	if err != nil {
		return "", err
	}
	currentDir = normalizeLocalTransferPath(currentDir)
	return normalizeLocalTransferPath(filepath.Join(currentDir, name)), nil
}

func newRemoteDirTarget(currentDir, name string) (string, error) {
	if currentDir == "" {
		return "", fmt.Errorf("empty remote directory")
	}
	name, err := normalizeNewDirName(name)
	if err != nil {
		return "", err
	}
	return remoteJoin(currentDir, name), nil
}

func (a *app) startOperation() bool {
	return a.startOperationWithStatus(promptNotice)
}

func (a *app) startOperationWithStatus(status string) bool {
	a.mu.Lock()
	if a.busy {
		a.mu.Unlock()
		return false
	}
	a.busy = true
	a.mu.Unlock()
	a.setStatus(status)
	a.setButtons()
	return true
}

func (a *app) endOperation() {
	a.mu.Lock()
	a.busy = false
	a.current = nil
	a.mu.Unlock()
	a.setButtons()
}

func (a *app) runChild(args []string, captureStdout bool) ([]byte, int, error) {
	a.appendMainLogLine("command: " + formatChildCommand(a.exe, args))
	child, stdout, stderr, err := startChild(a.exe, args)
	if err != nil {
		return nil, 1, err
	}
	a.mu.Lock()
	a.current = child
	a.mu.Unlock()
	a.appendMainLogLine("spawn: " + childDescription(args))

	var stdoutBuf bytes.Buffer
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if captureStdout {
			_, _ = io.Copy(&stdoutBuf, stdout)
			return
		}
		_, _ = io.Copy(io.MultiWriter(newTerminalSourceWriter(os.Stdout, "child stdout"), guiLogWriter{a: a}), stdout)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(io.MultiWriter(newTerminalSourceWriter(os.Stderr, "child stderr"), guiLogWriter{a: a}), stderr)
	}()

	err = child.wait()
	wg.Wait()
	code := 0
	if err != nil {
		code = 1
		if exitErr, ok := err.(*exec.ExitError); ok {
			code = exitErr.ExitCode()
		}
	}
	a.appendMainLogLine(fmt.Sprintf("exit code: %d", code))
	return stdoutBuf.Bytes(), code, err
}

func startChild(executable string, args []string) (*childProcess, io.ReadCloser, io.ReadCloser, error) {
	cmd := exec.Command(executable, args...)
	cmd.Stdin = os.Stdin
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, nil, nil, err
	}
	job, err := createKillOnCloseJob()
	if err != nil {
		return nil, nil, nil, err
	}
	if err := cmd.Start(); err != nil {
		_ = windows.CloseHandle(job)
		return nil, nil, nil, err
	}
	process, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid))
	if err != nil {
		_ = cmd.Process.Kill()
		_ = windows.CloseHandle(job)
		return nil, nil, nil, err
	}
	err = windows.AssignProcessToJobObject(job, process)
	_ = windows.CloseHandle(process)
	if err != nil {
		_ = cmd.Process.Kill()
		_ = windows.CloseHandle(job)
		return nil, nil, nil, err
	}
	return &childProcess{cmd: cmd, job: job}, stdout, stderr, nil
}

func createKillOnCloseJob() (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, err
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	_, err = windows.SetInformationJobObject(
		job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	)
	if err != nil {
		_ = windows.CloseHandle(job)
		return 0, err
	}
	return job, nil
}

func (a *app) killCurrent() {
	a.mu.Lock()
	child := a.current
	a.mu.Unlock()
	if child != nil {
		child.kill()
	}
}

func (a *app) setButtons() {
	a.mu.Lock()
	enabled := !a.busy && a.selection.valid() && a.remoteNav.Current != ""
	localNewDirEnabled := !a.busy && a.localNav.Current != ""
	remoteNewDirEnabled := !a.busy && a.remoteNav.Current != ""
	localDeleteEnabled := !a.busy && a.selection.valid() && a.selection.Side == sideLocal
	remoteDeleteEnabled := !a.busy && a.selection.valid() && a.selection.Side == sideRemote && a.remoteNav.Current != ""
	localRenameEnabled := localDeleteEnabled && selectionSingle(a.selection)
	remoteRenameEnabled := remoteDeleteEnabled && selectionSingle(a.selection)
	rsyncEnabled := a.rsyncAvailable
	selection := a.selection
	a.mu.Unlock()
	a.ui(func() {
		_ = a.scpButton.SetText(transferButtonText("scp", selection))
		_ = a.rsyncButton.SetText(transferButtonText("rsync", selection))
		a.scpButton.SetEnabled(enabled)
		a.rsyncButton.SetEnabled(enabled && rsyncEnabled)
		a.localNewDir.SetEnabled(localNewDirEnabled)
		a.remoteNewDir.SetEnabled(remoteNewDirEnabled)
		a.localRename.SetEnabled(localRenameEnabled)
		a.remoteRename.SetEnabled(remoteRenameEnabled)
		a.localDelete.SetEnabled(localDeleteEnabled)
		a.remoteDelete.SetEnabled(remoteDeleteEnabled)
	})
}

func selectionSingle(selection selectionState) bool {
	return selection.count() == 1
}

func transferButtonText(protocol string, selection selectionState) string {
	label := strings.ToUpper(protocol)
	if !selection.valid() {
		return label
	}
	switch selection.Side {
	case sideLocal:
		return label + " Upload ->"
	case sideRemote:
		return "<- " + label + " Download"
	default:
		return label
	}
}

func (a *app) setStatus(status string) {
	a.ui(func() { a.status.SetText(status) })
	a.appendLogLine(status)
}

func (a *app) appendLogLine(line string) {
	a.appendLogLineFrom("gui", line)
}

func (a *app) appendMainLogLine(line string) {
	a.appendLogLineFrom("main", line)
}

func (a *app) appendLogLineFrom(source, line string) {
	now := time.Now().Format("15:04:05")
	a.appendLogText(now + " " + line + "\r\n")
	writeTerminalLogLine(source, now, line)
}

func (a *app) appendLogText(text string) {
	if text == "" {
		return
	}
	a.ui(func() {
		a.log.AppendText(text)
		end := a.log.TextLength()
		a.log.SetTextSelection(end, end)
		a.log.ScrollToCaret()
	})
}

func (a *app) clearLog() {
	a.ui(func() {
		a.log.SetText("")
	})
}

func (a *app) ui(fn func()) {
	if a.mw != nil {
		a.mw.Synchronize(fn)
	}
}

type guiLogWriter struct {
	a *app
}

func (w guiLogWriter) Write(p []byte) (int, error) {
	text := strings.ReplaceAll(string(p), "\r\n", "\n")
	text = strings.ReplaceAll(text, "\n", "\r\n")
	w.a.appendLogText(text)
	return len(p), nil
}

type terminalSourceWriter struct {
	out         io.Writer
	source      string
	atLineStart bool
}

func newTerminalSourceWriter(out io.Writer, source string) *terminalSourceWriter {
	return &terminalSourceWriter{out: out, source: source, atLineStart: true}
}

func (w *terminalSourceWriter) Write(p []byte) (int, error) {
	terminalLogMu.Lock()
	defer terminalLogMu.Unlock()

	written := 0
	remaining := p
	for len(remaining) > 0 {
		if w.atLineStart {
			if _, err := fmt.Fprintf(w.out, "%s [%s] ", time.Now().Format("15:04:05"), w.source); err != nil {
				return written, err
			}
			w.atLineStart = false
		}
		next := bytes.IndexByte(remaining, '\n')
		if next < 0 {
			n, err := w.out.Write(remaining)
			written += n
			return written, err
		}
		n, err := w.out.Write(remaining[:next+1])
		written += n
		if err != nil {
			return written, err
		}
		w.atLineStart = true
		remaining = remaining[next+1:]
	}
	return len(p), nil
}

func writeTerminalLogLine(source, timestamp, line string) {
	terminalLogMu.Lock()
	defer terminalLogMu.Unlock()
	fmt.Fprintf(os.Stderr, "%s [%s] %s\n", timestamp, source, line)
}

func listLocal(dir string) ([]fileEntry, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	result := make([]fileEntry, 0, len(entries))
	for _, entry := range entries {
		full := filepath.Join(dir, entry.Name())
		info, err := os.Stat(full)
		if err != nil {
			info, err = entry.Info()
			if err != nil {
				continue
			}
		}
		isDir := info.IsDir()
		size := info.Size()
		mtime := info.ModTime().Unix()
		result = append(result, fileEntry{
			Name:    entry.Name(),
			IsDir:   isDir,
			Size:    size,
			MTime:   mtime,
			Display: formatEntryDisplay(entry.Name(), isDir, size, mtime, "", "", ""),
		})
	}
	sortEntries(result, sortByName)
	return result, nil
}

func sortEntries(entries []fileEntry, mode sortMode) {
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].IsDir != entries[j].IsDir {
			return entries[i].IsDir
		}
		switch mode {
		case sortByTime:
			if less, ok := sortValueDescUnknownLast(entries[i].MTime, entries[j].MTime); ok {
				return less
			}
		case sortBySize:
			if less, ok := sortValueDescUnknownLast(entries[i].Size, entries[j].Size); ok {
				return less
			}
		}
		return strings.ToLower(entries[i].Name) < strings.ToLower(entries[j].Name)
	})
}

func sortValueDescUnknownLast(left, right int64) (bool, bool) {
	leftUnknown := left < 0
	rightUnknown := right < 0
	if leftUnknown || rightUnknown {
		if leftUnknown != rightUnknown {
			return !leftUnknown, true
		}
		return false, false
	}
	if left != right {
		return left > right, true
	}
	return false, false
}

func sortModeLabels() []string {
	return []string{"Name", "Time", "Size"}
}

func sortModeFromIndex(index int) sortMode {
	switch index {
	case 1:
		return sortByTime
	case 2:
		return sortBySize
	default:
		return sortByName
	}
}

func validateLocalDir(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("not a directory")
	}
	return nil
}

func entryDisplays(entries []fileEntry) []string {
	if len(entries) == 0 {
		return []string{"(empty)"}
	}
	result := make([]string, 0, len(entries))
	for _, entry := range entries {
		result = append(result, entry.Display)
	}
	return result
}

func remoteJoin(dir, name string) string {
	if dir == "" || dir == "/" {
		return "/" + name
	}
	return path.Join(dir, name)
}

func remoteParent(dir string) string {
	if dir == "" || dir == "/" {
		return "/"
	}
	return path.Dir(dir)
}

func connectionSummary(opts *cli.Options) string {
	target := opts.Host
	if opts.User != "" {
		target = opts.User + "@" + target
	}
	if opts.Port > 0 {
		target = fmt.Sprintf("%s:%d", target, opts.Port)
	}
	parts := []string{target}
	if len(opts.ExtraHosts) > 0 {
		parts = append(parts, fmt.Sprintf("%d extra hop(s)", len(opts.ExtraHosts)))
	}
	if opts.SocksProxy != "" {
		parts = append(parts, "SOCKS "+opts.SocksProxy)
	}
	return strings.Join(parts, " via ")
}

func childDescription(args []string) string {
	for _, arg := range args {
		switch {
		case arg == "--gui-internal-home":
			return "remote HOME probe"
		case arg == "--gui-internal-list" || strings.HasPrefix(arg, "--gui-internal-list="):
			return "remote directory listing"
		case arg == "--scp-upload":
			return "SCP upload"
		case arg == "--scp-download":
			return "SCP download"
		case arg == "--rsync-upload":
			return "rsync upload"
		case arg == "--rsync-download":
			return "rsync download"
		case strings.Contains(arg, `rm -rf -- "$1"`):
			return "remote delete"
		case strings.Contains(arg, `mv -- "$1" "$2"`):
			return "remote rename"
		case strings.Contains(arg, `mkdir -- "$1"`) || strings.Contains(arg, "flyssh-mkdir"):
			return "remote mkdir"
		}
	}
	return "flyssh subprocess"
}
