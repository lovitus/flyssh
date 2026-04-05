package transfer

import (
	"testing"

	"github.com/flyssh/flyssh/pkg/cli"
)

func TestFromOptions_RsyncUploadParsesFlagsAndOperands(t *testing.T) {
	opts := &cli.Options{
		RsyncUpload: `-avzhP --dry-run --exclude '*.tmp' --filter "+ *.go" ./src/ /data/app/`,
	}

	spec, err := FromOptions(opts)
	if err != nil {
		t.Fatalf("FromOptions returned error: %v", err)
	}
	if spec.Mode != ModeRsync || spec.Direction != DirectionUpload {
		t.Fatalf("unexpected spec identity: %+v", spec)
	}
	if len(spec.Sources) != 1 || spec.Sources[0] != "./src/" {
		t.Fatalf("unexpected sources: %#v", spec.Sources)
	}
	if spec.Target != "/data/app/" {
		t.Fatalf("unexpected target: %q", spec.Target)
	}
	for _, want := range []string{"--exclude", "*.tmp", "--filter", "+ *.go", "--dry-run"} {
		if !contains(spec.Flags, want) {
			t.Fatalf("expected flag token %q in %#v", want, spec.Flags)
		}
	}
}

func TestFromOptions_RsyncRejectsTransportOverride(t *testing.T) {
	opts := &cli.Options{RsyncUpload: `-avz -e ssh ./src/ /dst/`}

	_, err := FromOptions(opts)
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != "rsync transfer arguments must not include -e or --rsh" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFromOptions_RsyncRejectsRemoteSpecs(t *testing.T) {
	tests := []string{
		`-avz ./src host:/dst`,
		`-avz ./src user@host:/dst`,
		`-avz ./src :/dst`,
	}

	for _, raw := range tests {
		t.Run(raw, func(t *testing.T) {
			_, err := FromOptions(&cli.Options{RsyncUpload: raw})
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestFromOptions_WindowsDrivePathsRemainLocal(t *testing.T) {
	spec, err := FromOptions(&cli.Options{ScpUpload: `C:\src D:\dst`})
	if err != nil {
		t.Fatalf("FromOptions returned error: %v", err)
	}
	if got, want := spec.Sources[0], `C:\src`; got != want {
		t.Fatalf("unexpected source: got %q want %q", got, want)
	}
	if got, want := spec.Target, `D:\dst`; got != want {
		t.Fatalf("unexpected target: got %q want %q", got, want)
	}
}

func TestFromOptions_LocalColonPathAfterSeparatorAllowed(t *testing.T) {
	spec, err := FromOptions(&cli.Options{ScpUpload: `./dir:name/file ./out`})
	if err != nil {
		t.Fatalf("FromOptions returned error: %v", err)
	}
	if got, want := spec.Sources[0], "./dir:name/file"; got != want {
		t.Fatalf("unexpected source: got %q want %q", got, want)
	}
}

func TestFromOptions_BareColonLocalNameRejected(t *testing.T) {
	_, err := FromOptions(&cli.Options{ScpUpload: `a:b ./out`})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestFromOptions_SCPMultiSourceAndDoubleDash(t *testing.T) {
	spec, err := FromOptions(&cli.Options{ScpUpload: `-rpv -- -leading file2 /remote/dir`})
	if err != nil {
		t.Fatalf("FromOptions returned error: %v", err)
	}
	if len(spec.Sources) != 2 {
		t.Fatalf("unexpected source count: %#v", spec.Sources)
	}
	if spec.Sources[0] != "-leading" || spec.Sources[1] != "file2" {
		t.Fatalf("unexpected sources: %#v", spec.Sources)
	}
	if spec.Target != "/remote/dir" {
		t.Fatalf("unexpected target: %q", spec.Target)
	}
}

func TestFromOptions_SCPRejectsUnsupportedOption(t *testing.T) {
	_, err := FromOptions(&cli.Options{ScpUpload: `-3 ./src ./dst`})
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != "unsupported scp option: -3" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFromOptions_TooFewOperands(t *testing.T) {
	_, err := FromOptions(&cli.Options{ScpUpload: `-r ./src`})
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != "transfer arguments must include at least one source and one destination" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func contains(tokens []string, want string) bool {
	for _, token := range tokens {
		if token == want {
			return true
		}
	}
	return false
}
