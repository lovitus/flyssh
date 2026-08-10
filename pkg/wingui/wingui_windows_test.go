//go:build windows

package wingui

import (
	"bytes"
	"reflect"
	"strings"
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
	localSel.Dirs["folder"] = true
	got, err := deleteTargets(localSel, `D:work`, "/remote")
	if err != nil {
		t.Fatalf("deleteTargets local returned error: %v", err)
	}
	want := []string{`D:\work\a.txt`, `D:\work\folder`}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected local targets: got %#v want %#v", got, want)
	}

	remoteSel := newSelectionState()
	remoteSel.Side = sideRemote
	remoteSel.Files["b.txt"] = true
	remoteSel.Dirs["folder"] = true
	got, err = deleteTargets(remoteSel, `D:\work`, "/remote")
	if err != nil {
		t.Fatalf("deleteTargets remote returned error: %v", err)
	}
	want = []string{"/remote/b.txt", "/remote/folder"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected remote targets: got %#v want %#v", got, want)
	}
}

func TestValidateSelectedName(t *testing.T) {
	rejected := []string{"", "a/b", `a\b`, ".", "..", "~", "~/x", `~\x`, "C:", "C:foo", `C:\x`, "C:/x"}
	for _, name := range rejected {
		if err := validateSelectedName(name); err == nil {
			t.Fatalf("expected %q to be rejected", name)
		}
	}

	allowed := []string{"-foo", "±", "中文.txt", "backup~", "foo~bar"}
	for _, name := range allowed {
		if err := validateSelectedName(name); err != nil {
			t.Fatalf("expected %q to be allowed, got %v", name, err)
		}
	}
}

func TestNormalizeNewDirName(t *testing.T) {
	rejected := []string{"", "   ", ".", "..", "~", "~/x", `~\x`, "a/b", `a\b`, "C:", "C:foo", `C:\x`, "C:/x"}
	for _, name := range rejected {
		if got, err := normalizeNewDirName(name); err == nil {
			t.Fatalf("expected %q to be rejected, got %q", name, got)
		}
	}

	allowed := map[string]string{
		" new folder ": "new folder",
		"-foo":         "-foo",
		"中文":           "中文",
		"±":            "±",
		"backup~":      "backup~",
	}
	for in, want := range allowed {
		got, err := normalizeNewDirName(in)
		if err != nil {
			t.Fatalf("expected %q to be allowed, got %v", in, err)
		}
		if got != want {
			t.Fatalf("unexpected normalized name: got %q want %q", got, want)
		}
	}
}

func TestSelectionFromIndexesAllowsMixedSelection(t *testing.T) {
	entries := []fileEntry{
		{Name: "b.txt"},
		{Name: "folder", IsDir: true},
		{Name: "a.txt"},
		{Name: "nested", IsDir: true},
	}
	sel, normalized, err := selectionFromIndexes(sideLocal, []int{3, -1, 1, 0, 3}, entries)
	if err != nil {
		t.Fatalf("selectionFromIndexes returned error: %v", err)
	}
	if !reflect.DeepEqual(normalized, []int{3, 1, 0}) {
		t.Fatalf("unexpected normalized indexes: %#v", normalized)
	}
	if !sel.hasDir() {
		t.Fatal("mixed selection should report directories")
	}
	names, err := sel.names()
	if err != nil {
		t.Fatalf("selection names returned error: %v", err)
	}
	if want := []string{"b.txt", "folder", "nested"}; !reflect.DeepEqual(names, want) {
		t.Fatalf("unexpected selected names: got %#v want %#v", names, want)
	}
}

func TestSelectionFromIndexesRejectsInvalidNameAtomically(t *testing.T) {
	entries := []fileEntry{{Name: "ok.txt"}, {Name: "a/b"}}
	sel, normalized, err := selectionFromIndexes(sideRemote, []int{0, 1}, entries)
	if err == nil {
		t.Fatal("expected invalid selected name error")
	}
	if sel.valid() {
		t.Fatalf("invalid selection should be cleared: %#v", sel)
	}
	if len(normalized) != 0 {
		t.Fatalf("invalid selection should not keep partial indexes: %#v", normalized)
	}
}

func TestSelectionNamesRejectsInvalidNameFallback(t *testing.T) {
	sel := newSelectionState()
	sel.Side = sideLocal
	sel.Files["ok.txt"] = true
	sel.Dirs["a/b"] = true
	if _, err := sel.names(); err == nil {
		t.Fatal("expected invalid selected name error")
	}
}

func TestTransferPathsMixedSelection(t *testing.T) {
	localSel := newSelectionState()
	localSel.Side = sideLocal
	localSel.Files["a.txt"] = true
	localSel.Dirs["folder"] = true
	sources, target, err := transferPaths(localSel, `D:work`, "/remote")
	if err != nil {
		t.Fatalf("transferPaths local returned error: %v", err)
	}
	if want := []string{`D:\work\a.txt`, `D:\work\folder`}; !reflect.DeepEqual(sources, want) {
		t.Fatalf("unexpected local sources: got %#v want %#v", sources, want)
	}
	if target != "/remote" {
		t.Fatalf("unexpected local target: %q", target)
	}
	scpFlag, scpRaw, err := buildTransferArgs("scp", true, localSel.hasDir(), sources, target)
	if err != nil {
		t.Fatalf("buildTransferArgs scp returned error: %v", err)
	}
	if scpFlag != "--scp-upload" || !strings.Contains(scpRaw, "-r") {
		t.Fatalf("unexpected scp args: flag=%q raw=%q", scpFlag, scpRaw)
	}
	rsyncFlag, rsyncRaw, err := buildTransferArgs("rsync", true, localSel.hasDir(), sources, target)
	if err != nil {
		t.Fatalf("buildTransferArgs rsync returned error: %v", err)
	}
	if rsyncFlag != "--rsync-upload" || !strings.Contains(rsyncRaw, "-avh") {
		t.Fatalf("unexpected rsync args: flag=%q raw=%q", rsyncFlag, rsyncRaw)
	}

	remoteSel := newSelectionState()
	remoteSel.Side = sideRemote
	remoteSel.Files["a.txt"] = true
	remoteSel.Dirs["folder"] = true
	sources, target, err = transferPaths(remoteSel, `D:\work`, "/remote")
	if err != nil {
		t.Fatalf("transferPaths remote returned error: %v", err)
	}
	if want := []string{"/remote/a.txt", "/remote/folder"}; !reflect.DeepEqual(sources, want) {
		t.Fatalf("unexpected remote sources: got %#v want %#v", sources, want)
	}
	if target != `D:\work` {
		t.Fatalf("unexpected remote target: %q", target)
	}
}

func TestSelectedNameFallbackValidationInOperations(t *testing.T) {
	invalid := newSelectionState()
	invalid.Side = sideRemote
	invalid.Files["a/b"] = true
	if _, _, err := transferPaths(invalid, `D:\work`, "/remote"); err == nil {
		t.Fatal("expected transferPaths to reject invalid selected name")
	}
	if _, err := deleteTargets(invalid, `D:\work`, "/remote"); err == nil {
		t.Fatal("expected deleteTargets to reject invalid selected name")
	}
	if _, err := renameTarget(invalid, `D:\work`, "/remote"); err == nil {
		t.Fatal("expected renameTarget to reject invalid selected name")
	}
}

func TestNewDirTargets(t *testing.T) {
	local, err := newLocalDirTarget(`D:work`, "foo")
	if err != nil {
		t.Fatalf("newLocalDirTarget returned error: %v", err)
	}
	if want := `D:\work\foo`; local != want {
		t.Fatalf("unexpected local target: got %q want %q", local, want)
	}

	remote, err := newRemoteDirTarget("/remote", "foo")
	if err != nil {
		t.Fatalf("newRemoteDirTarget returned error: %v", err)
	}
	if want := "/remote/foo"; remote != want {
		t.Fatalf("unexpected remote target: got %q want %q", remote, want)
	}

	remote, err = newRemoteDirTarget("/", "foo")
	if err != nil {
		t.Fatalf("newRemoteDirTarget root returned error: %v", err)
	}
	if want := "/foo"; remote != want {
		t.Fatalf("unexpected root remote target: got %q want %q", remote, want)
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
	dir.Dirs["folder"] = true
	if !selectionSingle(dir) {
		t.Fatal("directory selection should be single")
	}
	mixed := newSelectionState()
	mixed.Side = sideLocal
	mixed.Files["a.txt"] = true
	mixed.Dirs["folder"] = true
	if selectionSingle(mixed) {
		t.Fatal("mixed selection should not be single")
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

func TestChildDescriptionDetectsRemoteMkdir(t *testing.T) {
	command, err := buildRemoteMkdirCommand("/tmp/a")
	if err != nil {
		t.Fatalf("buildRemoteMkdirCommand returned error: %v", err)
	}
	if got, want := childDescription([]string{"user@host", command}), "remote mkdir"; got != want {
		t.Fatalf("unexpected child description: got %q want %q", got, want)
	}
}

func TestChildDescriptionDetectsShellGateway(t *testing.T) {
	args := []string{"user@host", "--gui-internal-gateway", "flyssh:secret@127.0.0.1:0"}
	if got, want := childDescription(args), "local shell gateway"; got != want {
		t.Fatalf("unexpected child description: got %q want %q", got, want)
	}
}

func TestTerminalSourceWriterPrefixesLines(t *testing.T) {
	var buf bytes.Buffer
	w := newTerminalSourceWriter(&buf, "child stdout")
	if _, err := w.Write([]byte("first\nsecond")); err != nil {
		t.Fatalf("first write failed: %v", err)
	}
	if _, err := w.Write([]byte(" tail\n")); err != nil {
		t.Fatalf("second write failed: %v", err)
	}
	got := buf.String()
	if strings.Count(got, "[child stdout]") != 2 {
		t.Fatalf("unexpected prefixed output: %q", got)
	}
	if !strings.Contains(got, "[child stdout] first\n") || !strings.Contains(got, "[child stdout] second tail\n") {
		t.Fatalf("unexpected terminal output: %q", got)
	}
}

func entryNames(entries []fileEntry) []string {
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name)
	}
	return names
}
