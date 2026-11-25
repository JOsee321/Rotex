package github

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/JOsee321/Rotex/internal/model"
	"github.com/JOsee321/Rotex/internal/rotate"
	"github.com/JOsee321/Rotex/internal/security"
	"golang.org/x/crypto/nacl/box"
)

func TestSecretStoreUpdateSecretSealedBox(t *testing.T) {
	pubKey, privKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("box.GenerateKey failed: %v", err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(pubKey[:])

	var receivedKeyID string
	var receivedCipherB64 string

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/api/actions/secrets/public-key":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"key_id": "key-2026",
				"key":    pubB64,
			})
		case r.Method == http.MethodPut && r.URL.Path == "/repos/acme/api/actions/secrets/AWS_SECRET_ACCESS_KEY":
			var body struct {
				EncryptedValue string `json:"encrypted_value"`
				KeyID          string `json:"key_id"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			receivedKeyID = body.KeyID
			receivedCipherB64 = body.EncryptedValue
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})

	store := NewSecretStore(newMockRESTClient("pat-token", handler))
	scope := rotate.StoreScope{Scope: model.ScopeRepo, Repo: "acme/api"}

	if err := store.PreflightScope(context.Background(), scope); err != nil {
		t.Fatalf("PreflightScope failed: %v", err)
	}

	secret := security.NewSensitiveBytes([]byte("super-secret-aws-value"))
	defer secret.Wipe()

	if err := store.UpdateSecret(context.Background(), scope, "AWS_SECRET_ACCESS_KEY", secret); err != nil {
		t.Fatalf("UpdateSecret failed: %v", err)
	}
	if receivedKeyID != "key-2026" {
		t.Fatalf("unexpected key_id: %q", receivedKeyID)
	}

	cipherBytes, err := base64.StdEncoding.DecodeString(receivedCipherB64)
	if err != nil {
		t.Fatalf("decode encrypted_value failed: %v", err)
	}
	plain, ok := box.OpenAnonymous(nil, cipherBytes, pubKey, privKey)
	if !ok || string(plain) != "super-secret-aws-value" {
		t.Fatalf("failed to decrypt sealed secret: ok=%v, plain=%q", ok, string(plain))
	}
}
