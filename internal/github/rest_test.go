package github

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

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
