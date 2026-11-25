package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/JOsee321/Rotex/internal/security"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

const publicKeySize = 32

// SealForGitHub encrypts secret using a base64-encoded GitHub Actions public key
// (libsodium anonymous sealed box) and returns the base64 ciphertext payload.
func SealForGitHub(publicKeyB64 string, secret *security.SensitiveBytes) (string, error) {
	if secret == nil || secret.Len() == 0 {
		return "", errors.New("secret value must not be empty")
	}

	rawKey, err := base64.StdEncoding.DecodeString(publicKeyB64)
	if err != nil {
		return "", fmt.Errorf("decode GitHub public key: %w", err)
	}
	defer security.WipeBytes(rawKey)
	if len(rawKey) != publicKeySize {
		return "", fmt.Errorf("invalid GitHub public key length: got %d, want %d", len(rawKey), publicKeySize)
	}

	var recipientPK [publicKeySize]byte
	copy(recipientPK[:], rawKey)
	defer security.WipeBytes(recipientPK[:])

	if err := validateX25519PublicKey(&recipientPK); err != nil {
		return "", err
	}

	sealed, err := box.SealAnonymous(nil, secret.Expose(), &recipientPK, rand.Reader)
	if err != nil {
		return "", fmt.Errorf("seal secret payload: %w", err)
	}
	defer security.WipeBytes(sealed)

	return base64.StdEncoding.EncodeToString(sealed), nil
}

// validateX25519PublicKey rejects all-zero and Curve25519 small-subgroup low-order keys
// that would cause box.SealAnonymous (via curve25519.ScalarMult) to derive a zero shared secret.
func validateX25519PublicKey(pk *[publicKeySize]byte) error {
	var allZero [publicKeySize]byte
	if *pk == allZero {
		return errors.New("invalid GitHub public key: all-zero Curve25519 key rejected")
	}
	var probeScalar [publicKeySize]byte
	probeScalar[0] = 9
	if _, err := curve25519.X25519(probeScalar[:], pk[:]); err != nil {
		return fmt.Errorf("invalid GitHub public key (weak Curve25519 point): %w", err)
	}
	return nil
}
