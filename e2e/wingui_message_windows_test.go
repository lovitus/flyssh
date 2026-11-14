//go:build windows

package e2e_test

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// A native output buffer must remain valid even when the Go wrapper grows its
// stack before entering SendMessageTimeoutW. Without the wrapper's uintptr
// escape annotation, Windows may write to the old (relocated) Go stack.
func TestWindowsGUIMessageBufferLifetime(t *testing.T) {
	for trial := 0; trial < 16; trial++ {
		done := make(chan string, 1)
		go func() {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			result := "native read did not complete"
			defer func() { done <- result }()
			class, _ := syscall.UTF16PtrFromString("STATIC")
			caption, _ := syscall.UTF16PtrFromString("Clear")
			hwnd, _, err := hashUser32.NewProc("CreateWindowExW").Call(
				0, uintptr(unsafe.Pointer(class)), uintptr(unsafe.Pointer(caption)),
				0, 0, 0, 10, 10, 0, 0, 0, 0)
			if hwnd == 0 {
				result = fmt.Sprintf("CreateWindowExW: %v", err)
				return
			}
			defer hashUser32.NewProc("DestroyWindow").Call(hwnd)
			u := &hashUIDriver{t: t, beforeSend: func() { growHashTestStack(32) }}
			var buffer [64]uint16
			u.send(hwnd, 0x000D, uintptr(len(buffer)), uintptr(unsafe.Pointer(&buffer[0])))
			result = syscall.UTF16ToString(buffer[:])
		}()
		select {
		case got := <-done:
			if got != "Clear" {
				t.Fatalf("native buffer mismatch after stack growth: got %q, want Clear (trial %d)", got, trial)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("native buffer test timed out")
		}
	}
}

// Force an actual native refresh between GETCOUNT and the first row read.
// The former helper converted LB_ERR from GETTEXTLEN to a zero-sized buffer
// and panicked. No timing or production executable is needed to reproduce it.
func TestWindowsGUIListSnapshotDuringRefresh(t *testing.T) {
	for _, replace := range []bool{false, true} {
		t.Run(fmt.Sprintf("replace=%v", replace), func(t *testing.T) {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			class, _ := syscall.UTF16PtrFromString("LISTBOX")
			hwnd, _, err := hashUser32.NewProc("CreateWindowExW").Call(0, uintptr(unsafe.Pointer(class)), 0, 0, 0, 0, 10, 10, 0, 0, 0, 0)
			if hwnd == 0 {
				t.Fatalf("CreateWindowExW: %v", err)
			}
			defer hashUser32.NewProc("DestroyWindow").Call(hwnd)
			u := &hashUIDriver{t: t}
			add := func(text string) {
				value, _ := syscall.UTF16PtrFromString(text)
				u.send(hwnd, 0x0180, 0, uintptr(unsafe.Pointer(value)))
			}
			add("a  metadata")
			calls := 0
			longName := strings.Repeat("long", 1024)
			u.beforeSend = func() {
				calls++
				if calls != 2 {
					return
				}
				u.beforeSend = nil
				u.send(hwnd, 0x0184, 0, 0) // LB_RESETCONTENT between count and row read.
				if replace {
					add(longName + "  metadata")
				}
			}
			got := sortListNames(u, hwnd)
			if replace {
				if !reflect.DeepEqual(got, []string{longName}) {
					t.Fatalf("replacement snapshot mismatch: %v", got)
				}
			} else {
				if got != nil {
					t.Fatalf("removed row must invalidate snapshot: %v", got)
				}
				add("(empty)")
				if got := sortListNames(u, hwnd); !reflect.DeepEqual(got, []string{"(empty)"}) {
					t.Fatalf("next stable snapshot: %v", got)
				}
			}
		})
	}
}

//go:noinline
func growHashTestStack(depth int) uint64 {
	var padding [4096]uint64
	padding[depth] = uint64(depth)
	var result uint64
	if depth > 0 {
		result = growHashTestStack(depth - 1)
	}
	runtime.KeepAlive(&padding)
	return result + padding[depth]
}
