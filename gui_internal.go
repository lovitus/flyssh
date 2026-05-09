package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/flyssh/flyssh/pkg/cli"
	"golang.org/x/crypto/ssh"
)

type guiRemoteEntry struct {
	Name  string `json:"name"`
	IsDir bool   `json:"is_dir"`
	Size  int64  `json:"size"`
	MTime int64  `json:"mtime"`
}

func runGUIInternalHome(opts *cli.Options) int {
	_, clients, finalClient, err := connectChain(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "flyssh: %v\n", err)
		return 255
	}
	defer closeClients(clients)

	out, err := runGUIInternalRemoteCommand(finalClient, `sh -c 'printf %s "$HOME"'`)
	if err != nil {
		return guiInternalExitCode("read remote HOME", err)
	}
	if _, err := os.Stdout.Write(out); err != nil {
		fmt.Fprintf(os.Stderr, "flyssh: write HOME output: %v\n", err)
		return 255
	}
	return 0
}

func runGUIInternalList(opts *cli.Options, dir string) int {
	_, clients, finalClient, err := connectChain(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "flyssh: %v\n", err)
		return 255
	}
	defer closeClients(clients)

	out, err := runGUIInternalRemoteCommand(finalClient, guiInternalListCommand(dir))
	if err != nil {
		return guiInternalExitCode("list remote directory", err)
	}
	entries, err := parseGUIRemoteList(out)
	if err != nil {
		fmt.Fprintf(os.Stderr, "flyssh: parse remote listing: %v\n", err)
		return 255
	}
	sortGUIRemoteEntries(entries)
	if err := json.NewEncoder(os.Stdout).Encode(entries); err != nil {
		fmt.Fprintf(os.Stderr, "flyssh: encode remote listing: %v\n", err)
		return 255
	}
	return 0
}

func runGUIInternalRemoteCommand(client *ssh.Client, cmd string) ([]byte, error) {
	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	defer session.Close()

	var stdout bytes.Buffer
	session.Stdin = os.Stdin
	session.Stdout = &stdout
	session.Stderr = os.Stderr
	err = session.Run(cmd)
	return stdout.Bytes(), err
}

func guiInternalExitCode(action string, err error) int {
	if exitErr, ok := err.(*ssh.ExitError); ok {
		return exitErr.ExitStatus()
	}
	fmt.Fprintf(os.Stderr, "flyssh: %s: %v\n", action, err)
	return 255
}

func guiInternalListCommand(dir string) string {
	script := `
dir=$1
cd "$dir" || exit 17
for f in .* *; do
  [ "$f" = "." ] && continue
  [ "$f" = ".." ] && continue
  [ -e "$f" ] || [ -L "$f" ] || continue
  if [ -d "$f" ]; then isdir=1; else isdir=0; fi
  if size=$(stat -c %s -- "$f" 2>/dev/null); then
    mtime=$(stat -c %Y -- "$f" 2>/dev/null || printf 0)
  elif size=$(stat -f %z "$f" 2>/dev/null); then
    mtime=$(stat -f %m "$f" 2>/dev/null || printf 0)
  else
    size=0
    mtime=0
  fi
  printf '%s\0%s\0%s\0%s\0' "$isdir" "$size" "$mtime" "$f"
done
`
	return "sh -c " + guiShellQuote(script) + " sh " + guiShellQuote(dir)
}

func parseGUIRemoteList(data []byte) ([]guiRemoteEntry, error) {
	if len(data) == 0 {
		// Keep nil here: the internal JSON output becomes "null", which the GUI
		// treats exactly like an empty list when unmarshalling into a slice.
		return nil, nil
	}
	parts := bytes.Split(data, []byte{0})
	if len(parts) > 0 && len(parts[len(parts)-1]) == 0 {
		parts = parts[:len(parts)-1]
	}
	if len(parts)%4 != 0 {
		return nil, fmt.Errorf("malformed remote listing: got %d fields", len(parts))
	}
	entries := make([]guiRemoteEntry, 0, len(parts)/4)
	for i := 0; i < len(parts); i += 4 {
		size, err := strconv.ParseInt(string(parts[i+1]), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("parse size for %q: %w", parts[i+3], err)
		}
		mtime, err := strconv.ParseInt(string(parts[i+2]), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("parse mtime for %q: %w", parts[i+3], err)
		}
		name := string(parts[i+3])
		if name == "" || name == "." || name == ".." {
			continue
		}
		entries = append(entries, guiRemoteEntry{
			Name:  name,
			IsDir: string(parts[i]) == "1",
			Size:  size,
			MTime: mtime,
		})
	}
	return entries, nil
}

func sortGUIRemoteEntries(entries []guiRemoteEntry) {
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].IsDir != entries[j].IsDir {
			return entries[i].IsDir
		}
		return strings.ToLower(entries[i].Name) < strings.ToLower(entries[j].Name)
	})
}

func guiShellQuote(s string) string {
	if s == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}
