package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/JOsee321/Rotex/internal/security"
	"golang.org/x/crypto/nacl/box"
)

func TestSealForGitHubRoundTrip(t *testing.T) {
	pubKey, privKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("box.GenerateKey failed: %v", err)
	}

	pubB64 := base64.StdEncoding.EncodeToString(pubKey[:])
	secret := security.NewSensitiveBytes([]byte("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"))
	defer secret.Wipe()

	encryptedB64, err := SealForGitHub(pubB64, secret)
	if err != nil {
		t.Fatalf("SealForGitHub failed: %v", err)
	}

	cipherBytes, err := base64.StdEncoding.DecodeString(encryptedB64)
	if err != nil {
		t.Fatalf("decode encrypted payload failed: %v", err)
	}

	opened, ok := box.OpenAnonymous(nil, cipherBytes, pubKey, privKey)
	if !ok {
		t.Fatalf("box.OpenAnonymous failed to decrypt sealed payload")
	}
	if string(opened) != "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" {
		t.Fatalf("decrypted plaintext mismatch: %q", string(opened))
	}
}

func TestSealForGitHubValidation(t *testing.T) {
	secret := security.NewSensitiveBytes([]byte("val"))
	defer secret.Wipe()

	if _, err := SealForGitHub("not-base64!!!", secret); err == nil {
		t.Fatalf("expected error on invalid base64 key")
	}
	shortKey := base64.StdEncoding.EncodeToString([]byte("short"))
	if _, err := SealForGitHub(shortKey, secret); err == nil {
		t.Fatalf("expected error on wrong public key size")
	}
	if _, err := SealForGitHub(shortKey, nil); err == nil {
		t.Fatalf("expected error on nil secret")
	}
}
