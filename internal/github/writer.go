package github

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/JOsee321/Rotex/internal/crypto"
	"github.com/JOsee321/Rotex/internal/model"
	"github.com/JOsee321/Rotex/internal/rotate"
	"github.com/JOsee321/Rotex/internal/security"
)

// PublicKey represents a GitHub Actions libsodium public key used for client-side encryption.
type PublicKey struct {
	KeyID string `json:"key_id"`
	Key   string `json:"key"`
}

// SecretStore implements rotate.SecretStore on top of a GitHub RESTClient.
type SecretStore struct {
	client *RESTClient
}

// NewSecretStore wraps client as a write-capable GitHub Actions secret store.
func NewSecretStore(client *RESTClient) *SecretStore {
	return &SecretStore{client: client}
}

// Name returns the store identifier.
func (s *SecretStore) Name() string {
	return "github-actions"
}

// PreflightScope verifies that the target scope exists and its public key is readable.
func (s *SecretStore) PreflightScope(ctx context.Context, scope rotate.StoreScope) error {
	_, err := s.getPublicKey(ctx, scope)
	return err
}

// UpdateSecret encrypts value locally with the target scope's public key and writes it to GitHub.
func (s *SecretStore) UpdateSecret(ctx context.Context, scope rotate.StoreScope, name string, value *security.SensitiveBytes) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("secret name must not be empty")
	}
	if value == nil || value.Len() == 0 {
		return fmt.Errorf("secret value for %s must not be empty", name)
	}

	pk, err := s.getPublicKey(ctx, scope)
	if err != nil {
		return err
	}

	encryptedB64, err := crypto.SealForGitHub(pk.Key, value)
	if err != nil {
		return err
	}

	endpoint, err := secretPutEndpoint(scope, name)
	if err != nil {
		return err
	}

	payload := map[string]string{
		"encrypted_value": encryptedB64,
		"key_id":          pk.KeyID,
	}
	if scope.Scope == model.ScopeOrg {
		payload["visibility"] = "private"
	}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	if err := s.client.putJSON(ctx, endpoint, bodyBytes); err != nil {
		return security.SanitizeError(err, s.client.token.Expose(), string(value.Expose()))
	}
	return nil
}

func (s *SecretStore) getPublicKey(ctx context.Context, scope rotate.StoreScope) (PublicKey, error) {
	endpoint, err := publicKeyEndpoint(scope)
	if err != nil {
		return PublicKey{}, err
	}
	body, _, err := s.client.get(ctx, endpoint, "application/vnd.github+json")
	if err != nil {
		return PublicKey{}, err
	}
	var pk PublicKey
	if err := json.Unmarshal(body, &pk); err != nil {
		return PublicKey{}, fmt.Errorf("decode public key for %s: %w", scope.Label(), err)
	}
	if pk.KeyID == "" || pk.Key == "" {
		return PublicKey{}, fmt.Errorf("incomplete public key returned for %s", scope.Label())
	}
	return pk, nil
}

func publicKeyEndpoint(scope rotate.StoreScope) (string, error) {
	switch scope.Scope {
	case model.ScopeOrg:
		if strings.TrimSpace(scope.Org) == "" {
			return "", fmt.Errorf("org name is required for org scope")
		}
		return fmt.Sprintf("/orgs/%s/actions/secrets/public-key", url.PathEscape(scope.Org)), nil
	case model.ScopeEnvironment:
		owner, repo, ok := strings.Cut(scope.Repo, "/")
		if !ok || owner == "" || repo == "" || strings.TrimSpace(scope.Environment) == "" {
			return "", fmt.Errorf("invalid environment scope %q/%q", scope.Repo, scope.Environment)
		}
		return fmt.Sprintf("/repos/%s/%s/environments/%s/secrets/public-key",
			url.PathEscape(owner), url.PathEscape(repo), url.PathEscape(scope.Environment)), nil
	default:
		owner, repo, ok := strings.Cut(scope.Repo, "/")
		if !ok || owner == "" || repo == "" {
			return "", fmt.Errorf("invalid repository scope %q", scope.Repo)
		}
		return fmt.Sprintf("/repos/%s/%s/actions/secrets/public-key",
			url.PathEscape(owner), url.PathEscape(repo)), nil
	}
}

func secretPutEndpoint(scope rotate.StoreScope, secretName string) (string, error) {
	escapedName := url.PathEscape(secretName)
	switch scope.Scope {
	case model.ScopeOrg:
		return fmt.Sprintf("/orgs/%s/actions/secrets/%s", url.PathEscape(scope.Org), escapedName), nil
	case model.ScopeEnvironment:
		owner, repo, ok := strings.Cut(scope.Repo, "/")
		if !ok || owner == "" || repo == "" || strings.TrimSpace(scope.Environment) == "" {
			return "", fmt.Errorf("invalid environment scope %q/%q", scope.Repo, scope.Environment)
		}
		return fmt.Sprintf("/repos/%s/%s/environments/%s/secrets/%s",
			url.PathEscape(owner), url.PathEscape(repo), url.PathEscape(scope.Environment), escapedName), nil
	default:
		owner, repo, ok := strings.Cut(scope.Repo, "/")
		if !ok || owner == "" || repo == "" {
			return "", fmt.Errorf("invalid repository scope %q", scope.Repo)
		}
		return fmt.Sprintf("/repos/%s/%s/actions/secrets/%s",
			url.PathEscape(owner), url.PathEscape(repo), escapedName), nil
	}
}

func (c *RESTClient) putJSON(ctx context.Context, endpoint string, payload []byte) error {
	fullURL := c.baseURL + endpoint
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, fullURL, bytes.NewReader(payload))
	if err != nil {
		return security.SanitizeError(err, c.token.Expose())
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Api-Version", defaultAPIVersion)
	req.Header.Set("User-Agent", c.userAgent)
	if !c.token.IsEmpty() {
		req.Header.Set("Authorization", "Bearer "+c.token.Expose())
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return security.SanitizeError(err, c.token.Expose())
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return security.SanitizeError(err, c.token.Expose())
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return parseAPIError(resp, endpoint, body)
	}
	return nil
}
