package transfer

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/flyssh/flyssh/pkg/cli"
)

type Mode string

const (
	ModeRsync Mode = "rsync"
	ModeSCP   Mode = "scp"
)

type Direction string

const (
	DirectionUpload   Direction = "upload"
	DirectionDownload Direction = "download"
)

type Spec struct {
	Mode      Mode
	Direction Direction
	Raw       string
	Flags     []string
	Sources   []string
	Target    string
}

func FromOptions(opts *cli.Options) (*Spec, error) {
	switch {
	case opts.RsyncUpload != "":
		return parseRsync(DirectionUpload, opts.RsyncUpload)
	case opts.RsyncDownload != "":
		return parseRsync(DirectionDownload, opts.RsyncDownload)
	case opts.ScpUpload != "":
		return parseSCP(DirectionUpload, opts.ScpUpload)
	case opts.ScpDownload != "":
		return parseSCP(DirectionDownload, opts.ScpDownload)
	default:
		return nil, nil
	}
}

func parseRsync(direction Direction, raw string) (*Spec, error) {
	tokens, err := shellSplit(raw)
	if err != nil {
		return nil, err
	}
	flags, operands, err := consumeRsyncTokens(tokens)
	if err != nil {
		return nil, err
	}
	if err := validateOperands(operands); err != nil {
		return nil, err
	}
	return &Spec{
		Mode:      ModeRsync,
		Direction: direction,
		Raw:       raw,
		Flags:     flags,
		Sources:   append([]string(nil), operands[:len(operands)-1]...),
		Target:    operands[len(operands)-1],
	}, nil
}

func parseSCP(direction Direction, raw string) (*Spec, error) {
	tokens, err := shellSplit(raw)
	if err != nil {
		return nil, err
	}
	flags, operands, err := consumeSCPTokens(tokens)
	if err != nil {
		return nil, err
	}
	if err := validateOperands(operands); err != nil {
		return nil, err
	}
	return &Spec{
		Mode:      ModeSCP,
		Direction: direction,
		Raw:       raw,
		Flags:     flags,
		Sources:   append([]string(nil), operands[:len(operands)-1]...),
		Target:    operands[len(operands)-1],
	}, nil
}

func validateOperands(operands []string) error {
	if len(operands) < 2 {
		return fmt.Errorf("transfer arguments must include at least one source and one destination")
	}
	for _, operand := range operands {
		if err := validateOperand(operand); err != nil {
			return err
		}
	}
	return nil
}

func validateOperand(operand string) error {
	if operand == "" {
		return fmt.Errorf("empty path operand is not allowed")
	}
	if strings.HasPrefix(operand, "scp://") || strings.HasPrefix(operand, "rsync://") {
		return fmt.Errorf("transfer arguments must not include remote URL operands like %q", operand)
	}
	if isRemoteLikeOperand(operand) {
		return fmt.Errorf("transfer arguments must not include remote host specs like %q", operand)
	}
	return nil
}

func isRemoteLikeOperand(operand string) bool {
	if operand == "" {
		return false
	}
	if operand[0] == ':' {
		return true
	}
	if looksLikeWindowsDrivePath(operand) {
		return false
	}
	for i := 0; i < len(operand); i++ {
		switch operand[i] {
		case '/', '\\':
			return false
		case ':':
			return true
		}
	}
	return false
}

func looksLikeWindowsDrivePath(s string) bool {
	return len(s) >= 3 && isAlpha(s[0]) && s[1] == ':' && (s[2] == '\\' || s[2] == '/')
}

func isAlpha(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func consumeSCPTokens(tokens []string) ([]string, []string, error) {
	var flags []string
	var operands []string
	afterDoubleDash := false
	for _, token := range tokens {
		if afterDoubleDash {
			operands = append(operands, token)
			continue
		}
		if token == "--" {
			afterDoubleDash = true
			continue
		}
		if strings.HasPrefix(token, "--") {
			return nil, nil, fmt.Errorf("unsupported scp option: %s", token)
		}
		if strings.HasPrefix(token, "-") && token != "-" {
			for _, ch := range token[1:] {
				switch ch {
				case 'r', 'R', 'p', 'q', 'v':
					// supported
				case '3':
					return nil, nil, fmt.Errorf("unsupported scp option: -3")
				default:
					return nil, nil, fmt.Errorf("unsupported scp option: -%c", ch)
				}
			}
			flags = append(flags, token)
			continue
		}
		operands = append(operands, token)
	}
	return flags, operands, nil
}

func consumeRsyncTokens(tokens []string) ([]string, []string, error) {
	var flags []string
	var operands []string
	afterDoubleDash := false

	for i := 0; i < len(tokens); i++ {
		token := tokens[i]
		if afterDoubleDash {
			operands = append(operands, token)
			continue
		}
		if token == "--" {
			afterDoubleDash = true
			continue
		}
		if token == "-e" || token == "--rsh" || token == "--rsh=" || strings.HasPrefix(token, "--rsh=") {
			return nil, nil, fmt.Errorf("rsync transfer arguments must not include -e or --rsh")
		}
		if strings.HasPrefix(token, "--") {
			name, value, hasValue := splitLongOption(token)
			spec, ok := rsyncLongOptions[name]
			if !ok {
				return nil, nil, fmt.Errorf("unsupported rsync option: --%s", name)
			}
			if spec.reject {
				return nil, nil, fmt.Errorf("unsupported rsync option: --%s", name)
			}
			if spec.takesValue {
				if !hasValue {
					i++
					if i >= len(tokens) {
						return nil, nil, fmt.Errorf("option --%s requires an argument", name)
					}
					value = tokens[i]
				}
				flags = append(flags, "--"+name, value)
				continue
			}
			if hasValue {
				return nil, nil, fmt.Errorf("option --%s does not take an argument", name)
			}
			flags = append(flags, token)
			continue
		}
		if strings.HasPrefix(token, "-") && token != "-" {
			consumed, nextIndex, err := consumeRsyncShortToken(tokens, i)
			if err != nil {
				return nil, nil, err
			}
			flags = append(flags, consumed...)
			i = nextIndex
			continue
		}
		operands = append(operands, token)
	}

	return flags, operands, nil
}

type optionSpec struct {
	takesValue bool
	reject     bool
}

func splitLongOption(token string) (name, value string, hasValue bool) {
	body := strings.TrimPrefix(token, "--")
	if idx := strings.IndexByte(body, '='); idx >= 0 {
		return body[:idx], body[idx+1:], true
	}
	return body, "", false
}

func consumeRsyncShortToken(tokens []string, index int) ([]string, int, error) {
	token := tokens[index]
	if token == "-" {
		return nil, index, nil
	}

	var flags []string
	body := token[1:]
	for pos := 0; pos < len(body); pos++ {
		ch := body[pos]
		spec, ok := rsyncShortOptions[ch]
		if !ok {
			return nil, index, fmt.Errorf("unsupported rsync option: -%c", ch)
		}
		if spec.reject {
			return nil, index, fmt.Errorf("unsupported rsync option: -%c", ch)
		}
		if spec.takesValue {
			flags = append(flags, "-"+string(ch))
			if pos+1 < len(body) {
				flags = append(flags, body[pos+1:])
				return flags, index, nil
			}
			index++
			if index >= len(tokens) {
				return nil, index, fmt.Errorf("option -%c requires an argument", ch)
			}
			flags = append(flags, tokens[index])
			return flags, index, nil
		}
		flags = append(flags, "-"+string(ch))
	}
	return flags, index, nil
}

func shellSplit(input string) ([]string, error) {
	var tokens []string
	var current strings.Builder
	var quote rune
	escaped := false
	var escapedRune rune

	flush := func() {
		if current.Len() > 0 {
			tokens = append(tokens, current.String())
			current.Reset()
		}
	}

	for _, r := range input {
		switch {
		case escaped:
			if quote == '"' || r == '\\' || r == '"' || unicode.IsSpace(r) {
				current.WriteRune(r)
			} else {
				current.WriteRune(escapedRune)
				current.WriteRune(r)
			}
			escaped = false
			escapedRune = 0
		case quote != 0:
			if r == quote {
				quote = 0
			} else if r == '\\' && quote == '"' {
				escaped = true
				escapedRune = r
			} else {
				current.WriteRune(r)
			}
		case unicode.IsSpace(r):
			flush()
		case r == '\\':
			escaped = true
			escapedRune = r
		case r == '\'' || r == '"':
			quote = r
		default:
			current.WriteRune(r)
		}
	}
	if escaped {
		current.WriteRune(escapedRune)
	}
	if quote != 0 {
		return nil, fmt.Errorf("unterminated quote in transfer arguments")
	}
	flush()
	return tokens, nil
}

var rsyncLongOptions = map[string]optionSpec{
	"8-bit-output":        {},
	"address":             {takesValue: true},
	"append":              {},
	"append-verify":       {},
	"archive":             {},
	"backup":              {},
	"backup-dir":          {takesValue: true},
	"blocking-io":         {},
	"bwlimit":             {takesValue: true},
	"cache":               {},
	"checksum":            {},
	"checksum-choice":     {takesValue: true},
	"chmod":               {takesValue: true},
	"chown":               {takesValue: true},
	"compare-dest":        {takesValue: true},
	"compress":            {},
	"compress-choice":     {takesValue: true},
	"compress-level":      {takesValue: true},
	"contimeout":          {takesValue: true},
	"copy-dest":           {takesValue: true},
	"copy-links":          {},
	"copy-unsafe-links":   {},
	"crtimes":             {},
	"debug":               {takesValue: true},
	"delay-updates":       {},
	"delete":              {},
	"delete-after":        {},
	"delete-before":       {},
	"delete-delay":        {},
	"delete-during":       {},
	"delete-excluded":     {},
	"devices":             {},
	"dirs":                {},
	"dry-run":             {},
	"exclude":             {takesValue: true},
	"exclude-from":        {takesValue: true},
	"existing":            {},
	"fake-super":          {},
	"filter":              {takesValue: true},
	"files-from":          {takesValue: true, reject: true},
	"force":               {},
	"from0":               {reject: true},
	"fuzzy":               {},
	"group":               {},
	"groupmap":            {takesValue: true},
	"hard-links":          {},
	"human-readable":      {},
	"iconv":               {takesValue: true},
	"ignore-errors":       {},
	"ignore-existing":     {},
	"ignore-missing-args": {},
	"ignore-non-existing": {},
	"ignore-times":        {},
	"include":             {takesValue: true},
	"include-from":        {takesValue: true},
	"info":                {takesValue: true},
	"inplace":             {},
	"itemize-changes":     {},
	"keep-dirlinks":       {},
	"link-dest":           {takesValue: true},
	"links":               {},
	"log-file":            {takesValue: true},
	"log-file-format":     {takesValue: true},
	"max-alloc":           {takesValue: true},
	"max-delete":          {takesValue: true},
	"max-size":            {takesValue: true},
	"min-size":            {takesValue: true},
	"mkpath":              {},
	"modify-window":       {takesValue: true},
	"msgs2stderr":         {},
	"no-compress":         {},
	"no-dirs":             {},
	"no-group":            {},
	"no-implied-dirs":     {},
	"no-links":            {},
	"no-motd":             {},
	"no-owner":            {},
	"no-perms":            {},
	"no-recursive":        {},
	"no-relative":         {},
	"numeric-ids":         {},
	"omit-dir-times":      {},
	"omit-link-times":     {},
	"one-file-system":     {},
	"only-write-batch":    {takesValue: true},
	"open-noatime":        {},
	"out-format":          {takesValue: true},
	"owner":               {},
	"partial":             {},
	"partial-dir":         {takesValue: true},
	"password-file":       {takesValue: true},
	"perms":               {},
	"port":                {takesValue: true},
	"preallocate":         {},
	"prune-empty-dirs":    {},
	"progress":            {},
	"protocol":            {takesValue: true},
	"protect-args":        {},
	"read-batch":          {takesValue: true},
	"recursive":           {},
	"relative":            {},
	"remove-source-files": {},
	"rsync-path":          {takesValue: true},
	"safe-links":          {},
	"size-only":           {},
	"skip-compress":       {takesValue: true},
	"sockopts":            {takesValue: true},
	"specials":            {},
	"stats":               {},
	"stderr":              {takesValue: true},
	"suffix":              {takesValue: true},
	"super":               {},
	"temp-dir":            {takesValue: true},
	"timeout":             {takesValue: true},
	"times":               {},
	"update":              {},
	"usermap":             {takesValue: true},
	"verbose":             {},
	"version":             {},
	"write-batch":         {takesValue: true},
	"xattrs":              {},
}

var rsyncShortOptions = map[byte]optionSpec{
	'0': {},
	'4': {},
	'6': {},
	'8': {},
	'a': {},
	'b': {},
	'B': {takesValue: true},
	'c': {},
	'd': {},
	'D': {},
	'e': {takesValue: true, reject: true},
	'E': {},
	'f': {takesValue: true},
	'g': {},
	'h': {},
	'H': {},
	'i': {},
	'I': {},
	'k': {},
	'l': {},
	'L': {},
	'm': {},
	'n': {},
	'o': {},
	'O': {},
	'p': {},
	'P': {},
	'q': {},
	'r': {},
	'R': {},
	's': {},
	'S': {},
	't': {},
	'T': {takesValue: true},
	'u': {},
	'v': {},
	'W': {},
	'x': {},
	'y': {},
	'z': {},
	'M': {takesValue: true},
}
