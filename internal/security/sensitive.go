package security

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
)

const redactedPlaceholder = "[REDACTED]"

// SensitiveString wraps a secret string so it cannot be accidentally printed,
// formatted, or serialized to JSON/text logs.
type SensitiveString struct {
	val string
}

// NewSensitiveString constructs a SensitiveString from a raw secret value.
func NewSensitiveString(v string) SensitiveString {
	return SensitiveString{val: v}
}

// Expose returns the underlying raw value. Callers must never log or persist
// the returned string.
func (s SensitiveString) Expose() string {
	return s.val
}

// IsEmpty reports whether the wrapped value is empty.
func (s SensitiveString) IsEmpty() bool {
	return s.val == ""
}

// String implements fmt.Stringer and always returns a redacted placeholder.
func (s SensitiveString) String() string {
	return redactedPlaceholder
}

// GoString implements fmt.GoStringer and always returns a redacted placeholder.
func (s SensitiveString) GoString() string {
	return redactedPlaceholder
}

// MarshalText implements encoding.TextMarshaler with redaction.
func (s SensitiveString) MarshalText() ([]byte, error) {
	return []byte(redactedPlaceholder), nil
}

// MarshalJSON implements json.Marshaler with redaction.
func (s SensitiveString) MarshalJSON() ([]byte, error) {
	return json.Marshal(redactedPlaceholder)
}

// SensitiveBytes wraps raw secret bytes with redaction on formatting/serialization
// and explicit memory zeroing via Wipe.
type SensitiveBytes struct {
	val []byte
}

// NewSensitiveBytes copies src into a new SensitiveBytes container.
func NewSensitiveBytes(src []byte) *SensitiveBytes {
	if len(src) == 0 {
		return &SensitiveBytes{}
	}
	cp := make([]byte, len(src))
	copy(cp, src)
	return &SensitiveBytes{val: cp}
}

// Expose returns the underlying slice. Callers should call Wipe when done.
func (s *SensitiveBytes) Expose() []byte {
	if s == nil {
		return nil
	}
	return s.val
}

// Len returns the byte length of the wrapped secret.
func (s *SensitiveBytes) Len() int {
	if s == nil {
		return 0
	}
	return len(s.val)
}

// Wipe zeros the underlying byte slice in place and releases the reference.
func (s *SensitiveBytes) Wipe() {
	if s == nil {
		return
	}
	WipeBytes(s.val)
	s.val = nil
}

// String implements fmt.Stringer and always returns a redacted placeholder.
func (s SensitiveBytes) String() string {
	return redactedPlaceholder
}

// GoString implements fmt.GoStringer and always returns a redacted placeholder.
func (s SensitiveBytes) GoString() string {
	return redactedPlaceholder
}

// MarshalText implements encoding.TextMarshaler with redaction.
func (s SensitiveBytes) MarshalText() ([]byte, error) {
	return []byte(redactedPlaceholder), nil
}

// MarshalJSON implements json.Marshaler with redaction.
func (s SensitiveBytes) MarshalJSON() ([]byte, error) {
	return json.Marshal(redactedPlaceholder)
}

// WipeBytes overwrites every byte in b with zero.
func WipeBytes(b []byte) {
	clear(b)
}

// SanitizeString scrubs any occurrences of the provided secret strings from text,
// replacing longest secrets first to avoid leaving partial suffixes.
func SanitizeString(text string, secrets ...string) string {
	if text == "" || len(secrets) == 0 {
		return text
	}
	ordered := make([]string, 0, len(secrets))
	for _, s := range secrets {
		if s != "" {
			ordered = append(ordered, s)
		}
	}
	if len(ordered) == 0 {
		return text
	}
	slices.SortFunc(ordered, func(a, b string) int {
		return len(b) - len(a)
	})
	for _, secret := range ordered {
		if strings.Contains(text, secret) {
			text = strings.ReplaceAll(text, secret, redactedPlaceholder)
		}
	}
	return text
}

// SanitizeError scrubs any occurrences of the provided secret strings from err.
func SanitizeError(err error, secrets ...string) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	clean := SanitizeString(msg, secrets...)
	if clean == msg {
		return err
	}
	return errors.New(clean)
}
