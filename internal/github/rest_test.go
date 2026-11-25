package github

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JOsee321/Rotex/internal/model"
	"github.com/JOsee321/Rotex/internal/security"
)

type handlerRoundTripper struct {
	handler http.Handler
}

func (rt handlerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	rt.handler.ServeHTTP(rec, req)
	resp := rec.Result()
	resp.Request = req
	return resp, nil
}

func newMockRESTClient(token string, handler http.Handler) *RESTClient {
	return NewRESTClient(
		security.NewSensitiveString(token),
		WithBaseURL("https://mock.github.local"),
		WithHTTPClient(&http.Client{Transport: handlerRoundTripper{handler: handler}}),
	)
}

func TestRESTClientOrgReposPaginationAndETag(t *testing.T) {
	var hits atomic.Int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		hits.Add(1)

		switch {
		case r.URL.Path == "/orgs/acme/repos" && r.URL.Query().Get("page") == "":
			if r.Header.Get("If-None-Match") == `"etag-p1"` {
				w.Header().Set("Link", `<https://mock.github.local/orgs/acme/repos?page=2>; rel="next"`)
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", `"etag-p1"`)
			w.Header().Set("Link", `<https://mock.github.local/orgs/acme/repos?page=2>; rel="next"`)
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{
					"name":           "api",
					"full_name":      "acme/api",
					"default_branch": "main",
					"archived":       false,
					"owner":          map[string]any{"login": "acme"},
				},
			})
		case r.URL.Path == "/orgs/acme/repos" && r.URL.Query().Get("page") == "2":
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{
					"name":           "legacy",
					"full_name":      "acme/legacy",
					"default_branch": "master",
					"archived":       true,
					"owner":          map[string]any{"login": "acme"},
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})

	client := newMockRESTClient("test-token", handler)
	repos, err := client.ListOrgRepos(context.Background(), "acme")
	if err != nil {
		t.Fatalf("ListOrgRepos failed: %v", err)
	}
	if len(repos) != 2 {
		t.Fatalf("expected 2 repos across pagination, got %d", len(repos))
	}
	if repos[0].FullName != "acme/api" || !repos[1].Archived {
		t.Fatalf("unexpected repo metadata: %+v", repos)
	}

	// Second call should leverage ETag 304 on page 1.
	repos2, err := client.ListOrgRepos(context.Background(), "acme")
	if err != nil || len(repos2) != 2 {
		t.Fatalf("second ListOrgRepos failed: %v, len=%d", err, len(repos2))
	}
	if hits.Load() != 4 {
		t.Fatalf("expected 4 HTTP hits, got %d", hits.Load())
	}
}

func TestRESTClientSecretsEnvironmentsAndWorkflows(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/orgs/acme/actions/secrets":
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{"message": "Resource not accessible by integration"})
		case "/repos/acme/api/actions/secrets":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"secrets": []map[string]any{
					{"name": "AWS_ACCESS_KEY_ID", "updated_at": "2026-01-01T00:00:00Z"},
				},
			})
		case "/repos/acme/api/environments":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"environments": []map[string]any{{"name": "production"}},
			})
		case "/repos/acme/api/environments/production/secrets":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"secrets": []map[string]any{
					{"name": "PROD_DB_URL", "updated_at": "2026-10-01T00:00:00Z"},
				},
			})
		case "/repos/acme/api/contents/.github/workflows":
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"name": "ci.yml", "path": ".github/workflows/ci.yml", "type": "file"},
				{"name": "notes.md", "path": ".github/workflows/notes.md", "type": "file"},
			})
		case "/repos/acme/api/contents/.github/workflows/ci.yml":
			if r.Header.Get("Accept") == "application/vnd.github.raw+json" {
				_, _ = w.Write([]byte("on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n"))
				return
			}
			w.WriteHeader(http.StatusNotAcceptable)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})

	client := newMockRESTClient("secret-pat", handler)
	ctx := context.Background()

	_, err := client.ListOrgSecrets(ctx, "acme")
	if !IsPermissionDenied(err) {
		t.Fatalf("expected IsPermissionDenied for 403 org secrets, got %v", err)
	}
	if strings.Contains(err.Error(), "secret-pat") {
		t.Fatalf("error leaked bearer token: %v", err)
	}

	repoSecrets, err := client.ListRepoSecrets(ctx, "acme", "api")
	if err != nil || len(repoSecrets) != 1 || repoSecrets[0].Scope != model.ScopeRepo {
		t.Fatalf("unexpected repo secrets: %+v, err=%v", repoSecrets, err)
	}

	envs, err := client.ListEnvironments(ctx, "acme", "api")
	if err != nil || len(envs) != 1 || envs[0].Name != "production" {
		t.Fatalf("unexpected environments: %+v, err=%v", envs, err)
	}

	envSecrets, err := client.ListEnvironmentSecrets(ctx, "acme", "api", "production")
	if err != nil || len(envSecrets) != 1 || envSecrets[0].Environment != "production" {
		t.Fatalf("unexpected env secrets: %+v, err=%v", envSecrets, err)
	}

	files, err := client.ListWorkflowFiles(ctx, "acme", "api", "main")
	if err != nil || len(files) != 1 || files[0].Path != ".github/workflows/ci.yml" {
		t.Fatalf("unexpected workflow files: %+v, err=%v", files, err)
	}

	// Missing workflows directory should return empty slice without error.
	emptyFiles, err := client.ListWorkflowFiles(ctx, "acme", "noworkflows", "main")
	if err != nil || len(emptyFiles) != 0 {
		t.Fatalf("expected empty workflow files on 404, got %+v, err=%v", emptyFiles, err)
	}
}

func TestRESTClientLockfilesAndWorkflowRuns(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/acme/api/git/trees/main":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"tree": []map[string]any{
					{"path": "apps/web/package-lock.json", "type": "blob"},
					{"path": "README.md", "type": "blob"},
				},
			})
		case "/repos/acme/api/contents/apps/web/package-lock.json":
			_, _ = w.Write([]byte(`{"lockfileVersion":3,"packages":{"node_modules/evil":{"version":"1.0.0"}}}`))
		case "/repos/acme/api/actions/runs":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"workflow_runs": []map[string]any{
					{
						"id":         101,
						"path":       ".github/workflows/ci.yml",
						"name":       "CI",
						"event":      "push",
						"status":     "completed",
						"conclusion": "success",
						"created_at": "2026-11-25T10:00:00Z",
					},
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})

	client := newMockRESTClient("tok", handler)
	ctx := context.Background()

	lockfiles, err := client.ListRepoLockfiles(ctx, "acme", "api", "main")
	if err != nil || len(lockfiles) != 1 || lockfiles[0].Path != "apps/web/package-lock.json" {
		t.Fatalf("unexpected lockfiles: %+v, err=%v", lockfiles, err)
	}

	runs, err := client.ListWorkflowRuns(ctx, "acme", "api", mustTime(t, "2026-11-24T00:00:00Z"))
	if err != nil || len(runs) != 1 || runs[0].ID != 101 {
		t.Fatalf("unexpected runs: %+v, err=%v", runs, err)
	}
}

func TestRESTClientDistinguishes403RateLimitFromPermissionDenied(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/acme/rate-limited/actions/secrets":
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.Header().Set("X-RateLimit-Reset", "1795600000")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{"message": "API rate limit exceeded"})
		case "/repos/acme/forbidden/actions/secrets":
			w.Header().Set("X-RateLimit-Remaining", "50")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{"message": "Resource not accessible by integration"})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})

	client := newMockRESTClient("tok", handler)
	ctx := context.Background()

	_, rlErr := client.ListRepoSecrets(ctx, "acme", "rate-limited")
	if !IsRateLimited(rlErr) {
		t.Fatalf("expected IsRateLimited=true, got %v", rlErr)
	}
	if IsPermissionDenied(rlErr) {
		t.Fatalf("rate-limited 403 must NOT be treated as permission denied")
	}

	_, permErr := client.ListRepoSecrets(ctx, "acme", "forbidden")
	if !IsPermissionDenied(permErr) || IsRateLimited(permErr) {
		t.Fatalf("expected IsPermissionDenied=true and IsRateLimited=false, got %v", permErr)
	}
}

func mustTime(t *testing.T, raw string) time.Time {
	t.Helper()
	ts, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		t.Fatalf("time.Parse failed: %v", err)
	}
	return ts
}

func TestRESTClientRejectsCrossOriginPaginationLinkAndRedirects(t *testing.T) {
	const token = "ghp_super_secret_redirect_token"
	var attackerCalled atomic.Bool

	rt := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Host {
		case "attacker.example":
			attackerCalled.Store(true)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("[]"))
		case "api.example.com", "sub.api.example.com":
			if r.URL.Host == "sub.api.example.com" {
				attackerCalled.Store(true)
				w.WriteHeader(http.StatusOK)
				return
			}
			switch r.URL.Path {
			case "/orgs/evil-link/repos":
				w.Header().Set("Link", `<https://attacker.example/steal>; rel="next"`)
				_ = json.NewEncoder(w).Encode([]map[string]any{{"name": "a", "full_name": "evil-link/a"}})
			case "/orgs/loop/repos":
				w.Header().Set("Link", `<https://api.example.com/orgs/loop/repos?per_page=100&type=all>; rel="next"`)
				_ = json.NewEncoder(w).Encode([]map[string]any{})
			case "/repos/acme/redirect-sub":
				w.Header().Set("Location", "https://sub.api.example.com/steal")
				w.WriteHeader(http.StatusFound)
			case "/repos/acme/redirect-downgrade":
				w.Header().Set("Location", "http://api.example.com/downgraded")
				w.WriteHeader(http.StatusMovedPermanently)
			case "/repos/acme/echo-token":
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]string{"message": "bad token " + token})
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})

	client := NewRESTClient(
		security.NewSensitiveString(token),
		WithBaseURL("https://api.example.com"),
		WithHTTPClient(&http.Client{Transport: handlerRoundTripper{handler: rt}}),
	)
	ctx := context.Background()

	if _, err := client.ListOrgRepos(ctx, "evil-link"); err == nil {
		t.Fatalf("expected cross-origin Link rel=next to fail")
	}
	if attackerCalled.Load() {
		t.Fatalf("client sent request (and Authorization header) to cross-origin host!")
	}

	if _, err := client.ListOrgRepos(ctx, "loop"); err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("expected pagination cycle error, got %v", err)
	}

	if _, err := client.GetRepo(ctx, "acme", "redirect-sub"); err == nil {
		t.Fatalf("expected cross-origin subdomain redirect to be refused")
	}
	if attackerCalled.Load() {
		t.Fatalf("redirect reached subdomain host!")
	}

	if _, err := client.GetRepo(ctx, "acme", "redirect-downgrade"); err == nil {
		t.Fatalf("expected HTTPS->HTTP redirect downgrade to be refused")
	}

	_, err := client.GetRepo(ctx, "acme", "echo-token")
	if err == nil || !IsUnauthorized(err) {
		t.Fatalf("expected unauthorized APIError, got %v", err)
	}
	if strings.Contains(err.Error(), token) {
		t.Fatalf("APIError leaked token: %v", err)
	}
}

func TestRESTClientRejectsPathTraversalAndOversizedResponse(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/acme/api/git/trees/main":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"tree": []map[string]any{
					{"path": "../../../orgs/victim/actions/secrets/package-lock.json", "type": "blob"},
				},
			})
		case "/repos/acme/huge/actions/secrets":
			// Exceed 16 MiB response cap without allocating a huge slice in one shot.
			chunk := bytes.Repeat([]byte("A"), 1<<20)
			for range 17 {
				_, _ = w.Write(chunk)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})

	client := newMockRESTClient("tok", handler)
	ctx := context.Background()

	if _, err := client.GetRepo(ctx, "acme", ".."); err == nil {
		t.Fatalf("expected path traversal dot-segment repo to be rejected")
	}
	if _, err := client.ListEnvironmentSecrets(ctx, "acme", "api", "../other"); err == nil {
		t.Fatalf("expected path traversal env to be rejected")
	}
	if _, err := client.ListRepoLockfiles(ctx, "acme", "api", "main"); err == nil {
		t.Fatalf("expected traversal path in git tree to be rejected")
	}
	if _, err := client.ListRepoSecrets(ctx, "acme", "huge"); err == nil || !strings.Contains(err.Error(), "exceeded maximum") {
		t.Fatalf("expected oversized response error, got %v", err)
	}
}
