package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/JOsee321/Rotex/internal/security"
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
	if len(rawKey) != publicKeySize {
		return "", fmt.Errorf("invalid GitHub public key length: got %d, want %d", len(rawKey), publicKeySize)
	}

	var recipientPK [publicKeySize]byte
	copy(recipientPK[:], rawKey)
	defer security.WipeBytes(recipientPK[:])

	sealed, err := box.SealAnonymous(nil, secret.Expose(), &recipientPK, rand.Reader)
	if err != nil {
		return "", fmt.Errorf("seal secret payload: %w", err)
	}
	defer security.WipeBytes(sealed)

	return base64.StdEncoding.EncodeToString(sealed), nil
}
