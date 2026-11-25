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

func TestSealForGitHubRejectsLowOrderPublicKeys(t *testing.T) {
	secret := security.NewSensitiveBytes([]byte("aws-secret-do-not-seal-with-weak-key"))
	defer secret.Wipe()

	lowOrderPoints := [][]byte{
		make([]byte, 32), // All-zero point (order 1)
		{1},              // Order 2 point (u = 1)
		{
			0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae,
			0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a,
			0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd,
			0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00,
		},
		{
			0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24,
			0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b,
			0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86,
			0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57,
		},
		{
			0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
		},
		{
			0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
		},
	}

	for i, pt := range lowOrderPoints {
		var key [32]byte
		copy(key[:], pt)
		b64 := base64.StdEncoding.EncodeToString(key[:])
		if _, err := SealForGitHub(b64, secret); err == nil {
			t.Fatalf("case %d: expected weak/low-order Curve25519 key to be rejected", i)
		}
	}
}
