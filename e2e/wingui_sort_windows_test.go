//go:build windows

package e2e_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// Exercise the independently packaged/released executable, using the same
// native Windows driver and real loopback SSH fixture as the hash tests.
func TestWindowsGUISorting(t *testing.T) {
	binary := os.Getenv("FLYSSH_GUI_BINARY")
	if binary == "" {
		t.Skip("set FLYSSH_GUI_BINARY to an extracted Windows release executable")
	}
	binary, err := filepath.Abs(binary)
	if err != nil {
		t.Fatal(err)
	}
	bash := filepath.Join(os.Getenv("ProgramFiles"), "Git", "bin", "bash.exe")
	if _, err := os.Stat(bash); err != nil {
		t.Fatal(err)
	}
	localDir, remoteDir, home := t.TempDir(), t.TempDir(), t.TempDir()
	names := []string{"a.txt", "B 'quote' 数据.bin", "c.txt"}
	sizes := []int{2, 1024 * 1024, 100}
	times := []int64{1700000300, 1700000100, 1700000200}
	for _, dir := range []string{localDir, remoteDir} {
		if err := os.Mkdir(filepath.Join(dir, "folder"), 0700); err != nil {
			t.Fatal(err)
		}
		for i, name := range names {
			file := filepath.Join(dir, name)
			if err := os.WriteFile(file, make([]byte, sizes[i]), 0600); err != nil {
				t.Fatal(err)
			}
			when := time.Unix(times[i], 0)
			if err := os.Chtimes(file, when, when); err != nil {
				t.Fatal(err)
			}
		}
	}
	addr := startHashSSHFixture(t, bash, remoteDir)
	var output hashLockedBuffer
	cmd := exec.Command(binary, "gui:fixture-password@"+addr, "--wingui", "--no-reconnect")
	cmd.Dir = localDir
	cmd.Env = hashTestEnv(os.Environ(), map[string]string{"HOME": home, "USERPROFILE": home})
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	u := newHashUIDriver(t, uint32(cmd.Process.Pid))
	var main uintptr
	t.Cleanup(func() {
		if dir := os.Getenv("FLYSSH_GUI_TEST_ARTIFACTS"); dir != "" {
			_ = os.MkdirAll(dir, 0755)
			_ = os.WriteFile(filepath.Join(dir, "sort-console.log"), []byte(output.String()), 0600)
		}
		// Always reap the process, even after a failed UI assertion.
		_ = cmd.Process.Kill()
		<-done
		if t.Failed() {
			t.Logf("executable output:\n%s", output.String())
		}
	})
	u.wait("main sorting window", func() bool { main = u.window("FlySSH Transfer"); return main != 0 })
	var lists, combos, directions, hashes, refresh []uintptr
	u.wait("sorting controls and listings ready", func() bool {
		lists = u.controls(main, "ListBox", "")
		combos = u.controls(main, "ComboBox", "")
		directions = u.controls(main, "Button", "Asc")
		hashes = u.controls(main, "Button", "Hash")
		refresh = u.controls(main, "Button", "Refresh")
		return len(lists) == 2 && len(combos) == 2 && len(directions) == 2 && len(hashes) == 2 && len(refresh) == 2 &&
			u.send(lists[0], 0x018B, 0, 0) == 4 && u.send(lists[1], 0x018B, 0, 0) == 4 && strings.Contains(output.String(), "ready")
	})
	for _, combo := range combos {
		if got := sortComboItems(u, combo); !reflect.DeepEqual(got, []string{"Name", "Size", "Date"}) {
			t.Fatalf("sort options: %v", got)
		}
	}

	for pane := range lists {
		t.Run([]string{"local", "remote"}[pane], func(t *testing.T) {
			parentTest := u.t
			u.t = t
			defer func() { u.t = parentTest }()
			// Real selections must follow names, not old numeric indexes.
			u.selectItems(lists[pane], names[0], names[2])
			u.wait("hash enabled for selected sort targets", func() bool { return u.enabled(hashes[pane]) })
			chooseSortKey(u, combos[pane], 1) // Change away from Name before testing its default.
			otherBefore := sortListNames(u, lists[1-pane])
			for _, key := range []struct {
				index            int
				label            string
				initial, reverse []string
				initialDirection string
			}{
				{0, "Name", []string{"folder/", names[0], names[1], names[2]}, []string{"folder/", names[2], names[1], names[0]}, "Asc"},
				{1, "Size", []string{"folder/", names[1], names[2], names[0]}, []string{"folder/", names[0], names[2], names[1]}, "Desc"},
				{2, "Date", []string{"folder/", names[0], names[2], names[1]}, []string{"folder/", names[1], names[2], names[0]}, "Desc"},
			} {
				chooseSortKey(u, combos[pane], key.index)
				u.wait(key.label+" default order", func() bool {
					return reflect.DeepEqual(sortListNames(u, lists[pane]), key.initial) && u.text(directions[pane]) == key.initialDirection
				})
				assertSortSelection(t, u, lists[pane], names[0], names[2])
				u.click(directions[pane])
				u.wait(key.label+" reversed order", func() bool {
					return reflect.DeepEqual(sortListNames(u, lists[pane]), key.reverse) && u.text(directions[pane]) != key.initialDirection
				})
				assertSortSelection(t, u, lists[pane], names[0], names[2])
				if !u.enabled(hashes[pane]) || u.enabled(hashes[1-pane]) {
					t.Fatal("sorting changed selection-dependent button state")
				}
				if got := sortListNames(u, lists[1-pane]); !reflect.DeepEqual(got, otherBefore) {
					t.Fatalf("sorting affected the other pane: %v", got)
				}
			}

			// Sorting the inactive pane must not clear the active selection.
			u.click(directions[1-pane])
			u.wait("inactive pane order changed", func() bool { return !reflect.DeepEqual(sortListNames(u, lists[1-pane]), otherBefore) })
			assertSortSelection(t, u, lists[pane], names[0], names[2])
			if !u.enabled(hashes[pane]) {
				t.Fatal("inactive sort cleared the active selection")
			}

			// Hash after a reorder, without selecting again: verify the selected
			// paths, not the files now occupying their original indexes.
			u.click(u.button(main, "Clear"))
			u.wait("sort log cleared", func() bool { return u.logText(main) == "" })
			u.click(hashes[pane])
			u.click(u.button(u.waitDialog(), "Calculate"))
			u.wait("hashing preserved selections", func() bool {
				return strings.Contains(u.logText(main), "hash complete: 2 file(s), sha256") && u.enabled(hashes[pane])
			})
			log := u.logText(main)
			for _, i := range []int{0, 2} {
				if !strings.Contains(log, hashFixtureDigest("sha256", make([]byte, sizes[i]))+"  ") {
					t.Fatalf("missing selected checksum after sorting: %s", log)
				}
			}
			if strings.Contains(log, hashFixtureDigest("sha256", make([]byte, sizes[1]))+"  ") {
				t.Fatal("hash used an obsolete selection index")
			}

			// Refresh must retain this pane's Date/ascending order. Adding an
			// actual file provides a completion signal rather than a sleep.
			dir := []string{localDir, remoteDir}[pane]
			added := filepath.Join(dir, "new.txt")
			if err := os.WriteFile(added, []byte("new"), 0600); err != nil {
				t.Fatal(err)
			}
			stamp := time.Unix(1700000400, 0)
			if err := os.Chtimes(added, stamp, stamp); err != nil {
				t.Fatal(err)
			}
			u.click(refresh[pane])
			want := []string{"folder/", names[1], names[2], names[0], "new.txt"}
			u.wait("refresh retains Date/ascending", func() bool { return reflect.DeepEqual(sortListNames(u, lists[pane]), want) })
			if u.text(directions[pane]) != "Asc" || u.send(combos[pane], 0x0147, 0, 0) != 2 {
				t.Fatal("refresh reset sort controls")
			}
			// Enter an empty child folder then go Up. Sorting survives navigation.
			u.selectItems(lists[pane], "folder/")
			u.send(lists[pane], 0x019E, 0, 0)    // LB_SETCARETINDEX for MultiSelection ListBox
			notifySortControl(u, lists[pane], 2) // LBN_DBLCLK -> OnItemActivated
			u.wait("empty child folder", func() bool { return reflect.DeepEqual(sortListNames(u, lists[pane]), []string{"(empty)"}) })
			u.click(u.controls(main, "Button", "Up")[pane])
			u.wait("navigation retains Date/ascending", func() bool { return reflect.DeepEqual(sortListNames(u, lists[pane]), want) })
			if pane == 1 {
				hashScreenshot(t, "name-size-date-sorting.png")
			}
		})
	}
	t.Log("Published/packaged executable: Name/Size/Date, both directions, numeric metadata, folders first, pane independence, selection/hash preservation, refresh and navigation passed")
}

func notifySortControl(u *hashUIDriver, hwnd uintptr, notification uintptr) {
	parent, _, _ := hashUser32.NewProc("GetParent").Call(hwnd)
	id, _, _ := hashUser32.NewProc("GetDlgCtrlID").Call(hwnd)
	u.send(parent, 0x0111, (id&0xffff)|(notification<<16), hwnd)
}

func chooseSortKey(u *hashUIDriver, combo uintptr, index int) {
	u.send(combo, 0x014E, uintptr(index), 0) // CB_SETCURSEL
	// CB_SETCURSEL does not emit CBN_SELCHANGE; simulate the user's event.
	notifySortControl(u, combo, 1)
}

func sortComboItems(u *hashUIDriver, combo uintptr) []string {
	var items []string
	for i, count := uintptr(0), u.send(combo, 0x0146, 0, 0); i < count; i++ {
		n := u.send(combo, 0x0149, i, 0)
		buf := make([]uint16, n+1)
		u.send(combo, 0x0148, i, uintptr(unsafe.Pointer(&buf[0])))
		items = append(items, syscall.UTF16ToString(buf))
	}
	return items
}

func sortListNames(u *hashUIDriver, list uintptr) []string {
	var names []string
	for i, count := uintptr(0), u.send(list, 0x018B, 0, 0); i < count; i++ {
		n := u.send(list, 0x018A, i, 0)
		buf := make([]uint16, n+1)
		u.send(list, 0x0189, i, uintptr(unsafe.Pointer(&buf[0])))
		name, _, _ := strings.Cut(syscall.UTF16ToString(buf), "  ")
		names = append(names, name)
	}
	return names
}

func assertSortSelection(t *testing.T, u *hashUIDriver, list uintptr, selected ...string) {
	t.Helper()
	want := make(map[string]bool)
	for _, name := range selected {
		want[name] = true
	}
	got := make(map[string]bool)
	for i, name := range sortListNames(u, list) {
		if u.send(list, 0x0187, uintptr(i), 0) == 1 {
			got[name] = true
		} // LB_GETSEL
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("selected %v, want %v", got, want)
	}
}
