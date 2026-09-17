//go:build windows

package e2e_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/crypto/ssh"
)

// This test drives a separately packaged executable, not the Go test process.
// The loopback SSH fixture executes the real remote commands with Git Bash.
// No personal accounts, credentials, files, or SSH servers are used.
func TestWindowsGUIHashes(t *testing.T) {
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
		t.Fatalf("Git Bash is required for the real SSH fixture: %v", err)
	}
	localDir, remoteDir, home := t.TempDir(), t.TempDir(), t.TempDir()
	files := map[string][]byte{
		"a.txt":             []byte("abc"),
		"b 'quoted' 数据.bin": []byte("binary\x00\xff\r\n"),
		"empty.txt":         {},
	}
	for _, dir := range []string{localDir, remoteDir} {
		if err := os.Mkdir(filepath.Join(dir, "folder"), 0700); err != nil {
			t.Fatal(err)
		}
		for name, data := range files {
			if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	addr := startHashSSHFixture(t, bash, remoteDir)
	var output hashLockedBuffer
	command := exec.Command(binary, "gui:fixture-password@"+addr, "--wingui", "--no-reconnect")
	command.Dir = localDir
	command.Env = hashTestEnv(os.Environ(), map[string]string{"HOME": home, "USERPROFILE": home})
	command.Stdout, command.Stderr = &output, &output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	ui := newHashUIDriver(t, uint32(command.Process.Pid))
	var main uintptr
	t.Cleanup(func() {
		if dir := os.Getenv("FLYSSH_GUI_TEST_ARTIFACTS"); dir != "" {
			_ = os.MkdirAll(dir, 0755)
			_ = os.WriteFile(filepath.Join(dir, "gui-console.log"), []byte(output.String()), 0600)
			if main != 0 {
				_ = os.WriteFile(filepath.Join(dir, "gui-log.txt"), []byte(ui.logText(main)), 0600)
			}
		}
		if main != 0 {
			ui.post(main, 0x0010, 0, 0) // WM_CLOSE
		}
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = command.Process.Kill()
			<-done
		}
		if t.Failed() {
			t.Logf("executable output:\n%s", output.String())
		}
	})
	ui.wait("main window", func() bool { main = ui.window("FlySSH Transfer"); return main != 0 })
	var lists, hashes []uintptr
	ui.wait("both file panes initialized", func() bool {
		lists = ui.controls(main, "ListBox", "")
		hashes = ui.controls(main, "Button", "Hash")
		return len(lists) == 2 && len(hashes) == 2 && ui.send(lists[0], 0x018B, 0, 0) == 4 && ui.send(lists[1], 0x018B, 0, 0) == 4
	})
	for i, hash := range hashes {
		if ui.enabled(hash) {
			t.Fatal("Hash must initially be disabled")
		}
		newDir, mv := ui.controls(main, "Button", "+Dir"), ui.controls(main, "Button", "MV")
		left, middle, right := ui.rect(newDir[i]), ui.rect(hash), ui.rect(mv[i])
		if left.right > middle.left || middle.right > right.left {
			t.Fatalf("pane %d: Hash is not between +Dir and MV", i)
		}
	}

	for pane := range lists {
		t.Run([]string{"local", "remote"}[pane], func(t *testing.T) {
			parentTest := ui.t
			ui.t = t
			defer func() { ui.t = parentTest }()
			ui.selectItems(lists[pane], "folder/")
			ui.wait("directory selection disabled", func() bool { return !ui.enabled(hashes[pane]) })
			ui.selectItems(lists[pane], "folder/", "a.txt")
			ui.wait("mixed selection disabled", func() bool { return !ui.enabled(hashes[pane]) })
			ui.selectItems(lists[pane], "a.txt")
			ui.wait("single file enabled", func() bool { return ui.enabled(hashes[pane]) && !ui.enabled(hashes[1-pane]) })
			ui.click(hashes[pane])
			dialog := ui.waitDialog()
			combos := ui.controls(dialog, "ComboBox", "")
			if len(combos) != 1 || ui.send(combos[0], 0x0147, 0, 0) != 3 {
				t.Fatal("hash chooser must default to SHA-256")
			}
			ui.click(ui.button(dialog, "Cancel"))
			ui.wait("cancel restores button", func() bool { return ui.window("Calculate file hashes") == 0 && ui.enabled(hashes[pane]) })

			methods := []string{"md5", "sha1", "sha224", "sha256", "sha384", "sha512"}
			for index, method := range methods {
				t.Run(method, func(t *testing.T) {
					parentTest := ui.t
					ui.t = t
					defer func() { ui.t = parentTest }()
					ui.selectItems(lists[pane], "a.txt", "b 'quoted' 数据.bin", "empty.txt")
					ui.wait("files selected", func() bool { return ui.enabled(hashes[pane]) })
					ui.click(ui.button(main, "Clear"))
					ui.wait("log cleared", func() bool { return ui.logText(main) == "" })
					ui.click(hashes[pane])
					dialog := ui.waitDialog()
					combo := ui.controls(dialog, "ComboBox", "")[0]
					ui.send(combo, 0x014E, uintptr(index), 0) // CB_SETCURSEL
					if pane == 1 && method == "sha256" {
						hashScreenshot(t, "hash-chooser.png")
					}
					ui.click(ui.button(dialog, "Calculate"))
					ui.wait("all hashes printed", func() bool {
						return strings.Contains(ui.logText(main), "hash complete: 3 file(s), "+method) && ui.enabled(hashes[pane])
					})
					log := ui.logText(main)
					for name, data := range files {
						want := hashFixtureDigest(method, data)
						found := false
						for _, line := range strings.Split(log, "\n") {
							if strings.Contains(line, want+"  ") && strings.HasSuffix(strings.TrimSuffix(line, "\r"), name) {
								found = true
							}
						}
						if !found {
							t.Fatalf("missing %s checksum for %q: %s\n%s", method, name, want, log)
						}
					}
					if pane == 1 && method == "sha512" {
						hashScreenshot(t, "remote-hash-results.png")
					}
				})
			}
		})
	}

	// A file disappears after listing: report its failure, but still hash the
	// remaining selected files. This exercises the actual SSH exit status too.
	if err := os.Remove(filepath.Join(remoteDir, "a.txt")); err != nil {
		t.Fatal(err)
	}
	ui.selectItems(lists[1], "a.txt", "empty.txt")
	ui.wait("remote selection enabled", func() bool { return ui.enabled(hashes[1]) })
	ui.click(ui.button(main, "Clear"))
	ui.wait("log cleared", func() bool { return ui.logText(main) == "" })
	ui.click(hashes[1])
	ui.click(ui.button(ui.waitDialog(), "Calculate"))
	ui.wait("per-file error and remaining result", func() bool {
		log := ui.logText(main)
		return strings.Contains(log, "hash complete with errors") && strings.Contains(log, hashFixtureDigest("sha256", nil)+"  ") && ui.enabled(hashes[1])
	})
	if !strings.Contains(ui.logText(main), "not a regular file:") {
		t.Fatal("missing-file diagnostic was not displayed")
	}
	t.Log("Packaged Windows executable: layout, selection, chooser/cancel, all six algorithms on both panes, SSH execution, and partial failures passed")
}

func startHashSSHFixture(t *testing.T, bash, directory string) string {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	config := &ssh.ServerConfig{PasswordCallback: func(c ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		if c.User() == "gui" && string(password) == "fixture-password" {
			return nil, nil
		}
		return nil, fmt.Errorf("invalid fixture credentials")
	}}
	config.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var mu sync.Mutex
	var connections []net.Conn
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range connections {
			_ = c.Close()
		}
	})
	gitRoot := filepath.Dir(filepath.Dir(bash))
	remoteHome := filepath.ToSlash(directory)
	if len(remoteHome) > 2 && remoteHome[1] == ':' {
		remoteHome = "/" + strings.ToLower(remoteHome[:1]) + remoteHome[2:]
	}
	env := hashTestEnv(os.Environ(), map[string]string{
		"HOME": remoteHome,
		"PATH": filepath.Join(gitRoot, "usr", "bin") + ";" + filepath.Dir(bash) + ";" + os.Getenv("PATH"),
	})
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			connections = append(connections, conn)
			mu.Unlock()
			go func() {
				defer conn.Close()
				server, channels, requests, err := ssh.NewServerConn(conn, config)
				if err != nil {
					return
				}
				defer server.Close()
				go ssh.DiscardRequests(requests)
				for incoming := range channels {
					if incoming.ChannelType() != "session" {
						_ = incoming.Reject(ssh.UnknownChannelType, "session only")
						continue
					}
					channel, reqs, err := incoming.Accept()
					if err != nil {
						continue
					}
					go func() {
						defer channel.Close()
						for req := range reqs {
							if req.Type != "exec" {
								_ = req.Reply(req.Type == "env", nil)
								continue
							}
							var payload struct{ Command string }
							if ssh.Unmarshal(req.Payload, &payload) != nil {
								_ = req.Reply(false, nil)
								return
							}
							_ = req.Reply(true, nil)
							runCtx, stop := context.WithTimeout(ctx, 30*time.Second)
							cmd := exec.CommandContext(runCtx, bash, "--noprofile", "--norc", "-c", payload.Command)
							cmd.Env, cmd.Dir = env, directory
							cmd.Stdout, cmd.Stderr = channel, channel.Stderr()
							err := cmd.Run()
							stop()
							status := uint32(0)
							if err != nil {
								status = 1
								if e, ok := err.(*exec.ExitError); ok {
									status = uint32(e.ExitCode())
								}
							}
							_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
							return
						}
					}()
				}
			}()
		}
	}()
	return listener.Addr().String()
}

func hashTestEnv(base []string, values map[string]string) []string {
	out := make([]string, 0, len(base)+len(values))
	for _, entry := range base {
		key, _, _ := strings.Cut(entry, "=")
		replaced := false
		for name := range values {
			if strings.EqualFold(key, name) {
				replaced = true
				break
			}
		}
		if !replaced {
			out = append(out, entry)
		}
	}
	for key, value := range values {
		out = append(out, key+"="+value)
	}
	return out
}

func hashFixtureDigest(method string, data []byte) string {
	switch method {
	case "md5":
		return fmt.Sprintf("%x", md5.Sum(data))
	case "sha1":
		return fmt.Sprintf("%x", sha1.Sum(data))
	case "sha224":
		return fmt.Sprintf("%x", sha256.Sum224(data))
	case "sha256":
		return fmt.Sprintf("%x", sha256.Sum256(data))
	case "sha384":
		return fmt.Sprintf("%x", sha512.Sum384(data))
	case "sha512":
		return fmt.Sprintf("%x", sha512.Sum512(data))
	default:
		panic("unknown fixture hash")
	}
}

type hashLockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *hashLockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}
func (b *hashLockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

var hashUser32 = syscall.NewLazyDLL("user32.dll")

type hashUIDriver struct {
	t                                   *testing.T
	pid                                 uint32
	windowCallback, controlCallback     uintptr
	wantedTitle, wantedClass, wantedText string
	foundWindow                         uintptr
	foundControls                       []uintptr
}

// Windows callback thunks cannot be freed. Allocate only two per test, rather
// than leaking a new callback on every polling iteration.
func newHashUIDriver(t *testing.T, pid uint32) *hashUIDriver {
	u := &hashUIDriver{t: t, pid: pid}
	u.windowCallback = syscall.NewCallback(func(hwnd, _ uintptr) uintptr {
		var windowPID uint32
		hashUser32.NewProc("GetWindowThreadProcessId").Call(hwnd, uintptr(unsafe.Pointer(&windowPID)))
		if windowPID == u.pid && u.text(hwnd) == u.wantedTitle {
			u.foundWindow = hwnd
			return 0
		}
		return 1
	})
	u.controlCallback = syscall.NewCallback(func(hwnd, _ uintptr) uintptr {
		if strings.EqualFold(u.class(hwnd), u.wantedClass) && (u.wantedText == "" || u.text(hwnd) == u.wantedText) {
			u.foundControls = append(u.foundControls, hwnd)
		}
		return 1
	})
	return u
}

type hashRect struct{ left, top, right, bottom int32 }

func (u *hashUIDriver) wait(description string, predicate func() bool) {
	u.t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if predicate() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	u.t.Fatalf("timed out waiting for %s", description)
}
func (u *hashUIDriver) send(hwnd, message, wparam, lparam uintptr) uintptr {
	u.t.Helper()
	var result uintptr
	ok, _, err := hashUser32.NewProc("SendMessageTimeoutW").Call(hwnd, message, wparam, lparam, 2, 2000, uintptr(unsafe.Pointer(&result)))
	if ok == 0 {
		u.t.Fatalf("UI message %#x to %#x failed: %v", message, hwnd, err)
	}
	return result
}
func (u *hashUIDriver) post(hwnd, message, wparam, lparam uintptr) {
	u.t.Helper()
	ok, _, err := hashUser32.NewProc("PostMessageW").Call(hwnd, message, wparam, lparam)
	if ok == 0 {
		u.t.Fatalf("post UI message: %v", err)
	}
}
func (u *hashUIDriver) text(hwnd uintptr) string {
	n := u.send(hwnd, 0x000E, 0, 0)
	buf := make([]uint16, n+1)
	u.send(hwnd, 0x000D, uintptr(len(buf)), uintptr(unsafe.Pointer(&buf[0])))
	return syscall.UTF16ToString(buf)
}
func (u *hashUIDriver) class(hwnd uintptr) string {
	buf := make([]uint16, 256)
	hashUser32.NewProc("GetClassNameW").Call(hwnd, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	return syscall.UTF16ToString(buf)
}
func (u *hashUIDriver) rect(hwnd uintptr) hashRect {
	var r hashRect
	hashUser32.NewProc("GetWindowRect").Call(hwnd, uintptr(unsafe.Pointer(&r)))
	return r
}
func (u *hashUIDriver) window(title string) uintptr {
	u.wantedTitle, u.foundWindow = title, 0
	hashUser32.NewProc("EnumWindows").Call(u.windowCallback, 0)
	return u.foundWindow
}
func (u *hashUIDriver) controls(parent uintptr, class, text string) []uintptr {
	u.wantedClass, u.wantedText = class, text
	u.foundControls = nil
	hashUser32.NewProc("EnumChildWindows").Call(parent, u.controlCallback, 0)
	found := u.foundControls
	sort.Slice(found, func(i, j int) bool { return u.rect(found[i]).left < u.rect(found[j]).left })
	return found
}
func (u *hashUIDriver) button(parent uintptr, text string) uintptr {
	u.t.Helper()
	buttons := u.controls(parent, "Button", text)
	if len(buttons) != 1 {
		u.t.Fatalf("expected one %q button, found %d", text, len(buttons))
	}
	return buttons[0]
}
func (u *hashUIDriver) click(hwnd uintptr) { u.post(hwnd, 0x00F5, 0, 0) }
func (u *hashUIDriver) enabled(hwnd uintptr) bool {
	r, _, _ := hashUser32.NewProc("IsWindowEnabled").Call(hwnd)
	return r != 0
}
func (u *hashUIDriver) waitDialog() uintptr {
	var dialog uintptr
	u.wait("hash algorithm chooser", func() bool { dialog = u.window("Calculate file hashes"); return dialog != 0 })
	return dialog
}
func (u *hashUIDriver) logText(main uintptr) string {
	for _, edit := range u.controls(main, "Edit", "") {
		style, _, _ := hashUser32.NewProc("GetWindowLongW").Call(edit, ^uintptr(15)) // GWL_STYLE
		if style&4 != 0 {                                                       // ES_MULTILINE
			return u.text(edit)
		}
	}
	return ""
}
func (u *hashUIDriver) selectItems(list uintptr, names ...string) {
	u.t.Helper()
	u.send(list, 0x0185, 0, ^uintptr(0)) // LB_SETSEL: clear all
	for _, name := range names {
		found := false
		count := u.send(list, 0x018B, 0, 0)
		for i := uintptr(0); i < count; i++ {
			n := u.send(list, 0x018A, i, 0)
			buf := make([]uint16, n+1)
			u.send(list, 0x0189, i, uintptr(unsafe.Pointer(&buf[0])))
			if strings.HasPrefix(syscall.UTF16ToString(buf), name+" ") {
				u.send(list, 0x0185, 1, i)
				found = true
				break
			}
		}
		if !found {
			u.t.Fatalf("file %q not found in list", name)
		}
	}
	parent, _, _ := hashUser32.NewProc("GetParent").Call(list)
	id, _, _ := hashUser32.NewProc("GetDlgCtrlID").Call(list)
	u.send(parent, 0x0111, (id&0xffff)|(1<<16), list) // WM_COMMAND, LBN_SELCHANGE
}

func hashScreenshot(t *testing.T, name string) {
	dir := os.Getenv("FLYSSH_GUI_TEST_ARTIFACTS")
	if dir == "" {
		return
	}
	_ = os.MkdirAll(dir, 0755)
	script := `Add-Type -AssemblyName System.Windows.Forms; Add-Type -AssemblyName System.Drawing; $r=[System.Windows.Forms.SystemInformation]::VirtualScreen; $b=New-Object System.Drawing.Bitmap($r.Width,$r.Height); $g=[System.Drawing.Graphics]::FromImage($b); try { $g.CopyFromScreen($r.Left,$r.Top,0,0,$b.Size); $b.Save($env:FLYSSH_SCREENSHOT) } finally { $g.Dispose(); $b.Dispose() }`
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.Env = hashTestEnv(os.Environ(), map[string]string{"FLYSSH_SCREENSHOT": filepath.Join(dir, name)})
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Logf("optional screenshot unavailable: %v: %s", err, output)
	}
}
