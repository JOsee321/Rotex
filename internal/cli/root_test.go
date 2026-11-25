package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestVersionCommand(t *testing.T) {
	var out bytes.Buffer
	cmd := NewRootCommand()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"version"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("version command failed: %v", err)
	}

	if !strings.Contains(out.String(), "rotex ") {
		t.Fatalf("unexpected version output: %q", out.String())
	}
}

func TestScanHelpCommand(t *testing.T) {
	var out bytes.Buffer
	cmd := NewRootCommand()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"scan", "--help"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("scan --help failed: %v", err)
	}

	output := out.String()
	for _, flag := range []string{"--org", "--repo", "--format", "--with-aws"} {
		if !strings.Contains(output, flag) {
			t.Fatalf("expected %s flag in scan help output, got:\n%s", flag, output)
		}
	}
}
