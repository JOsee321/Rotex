package security

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestSensitiveStringRedaction(t *testing.T) {
	const raw = "ghp_superSecretTokenValue12345"
	s := NewSensitiveString(raw)

	if s.Expose() != raw {
		t.Fatalf("expected Expose() to return raw value")
	}
	if s.IsEmpty() {
		t.Fatalf("expected non-empty SensitiveString")
	}

	checks := []string{
		fmt.Sprint(s),
		fmt.Sprintf("%s", s),
		fmt.Sprintf("%v", s),
		fmt.Sprintf("%+v", s),
		fmt.Sprintf("%#v", s),
	}
	for i, out := range checks {
		if strings.Contains(out, raw) {
			t.Fatalf("check %d leaked secret: %q", i, out)
		}
		if !strings.Contains(out, "[REDACTED]") {
			t.Fatalf("check %d missing [REDACTED]: %q", i, out)
		}
	}

	payload, err := json.Marshal(struct {
		Token SensitiveString `json:"token"`
	}{Token: s})
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	if strings.Contains(string(payload), raw) || string(payload) != `{"token":"[REDACTED]"}` {
		t.Fatalf("unexpected JSON output: %s", payload)
	}
}

func TestSensitiveBytesRedactionAndWipe(t *testing.T) {
	orig := []byte("secret-material-xyz")
	sb := NewSensitiveBytes(orig)
	// Mutating caller slice must not affect wrapped copy.
	orig[0] = 'X'

	if got := string(sb.Expose()); got != "secret-material-xyz" {
		t.Fatalf("unexpected Expose() value: %q", got)
	}

	if out := fmt.Sprintf("%v %#v", sb, sb); strings.Contains(out, "secret-material-xyz") {
		t.Fatalf("SensitiveBytes leaked secret: %q", out)
	}

	rawJSON, err := json.Marshal(sb)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	if string(rawJSON) != `"[REDACTED]"` {
		t.Fatalf("unexpected JSON output: %s", rawJSON)
	}

	backing := sb.Expose()
	sb.Wipe()
	for i, b := range backing {
		if b != 0 {
			t.Fatalf("byte %d not zeroed after Wipe: %d", i, b)
		}
	}
	if sb.Len() != 0 || sb.Expose() != nil {
		t.Fatalf("expected nil/zero length after Wipe")
	}
}

func TestSanitizeError(t *testing.T) {
	if SanitizeError(nil, "abc") != nil {
		t.Fatalf("expected nil error to stay nil")
	}

	const tok = "ghp_leak_987654321"
	err := errors.New("GET https://api.github.com failed with bearer " + tok)
	sanitized := SanitizeError(err, "", tok)
	if strings.Contains(sanitized.Error(), tok) {
		t.Fatalf("SanitizeError leaked token: %v", sanitized)
	}
	if !strings.Contains(sanitized.Error(), "[REDACTED]") {
		t.Fatalf("expected [REDACTED] in sanitized error: %v", sanitized)
	}
}
