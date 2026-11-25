package github

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/JOsee321/Rotex/internal/lockfile"
	"github.com/JOsee321/Rotex/internal/model"
	"github.com/JOsee321/Rotex/internal/security"
	"github.com/JOsee321/Rotex/internal/workflow"
)

const (
	defaultBaseURL    = "https://api.github.com"
	defaultAPIVersion = "2022-11-28"
	defaultUserAgent  = "rotex-cli"
)

var nextLinkRe = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

type cachedResponse struct {
	etag string
	body []byte
}

// RESTClient implements Client against the GitHub REST API with ETag caching.
type RESTClient struct {
	baseURL    string
	httpClient *http.Client
	token      security.SensitiveString
	userAgent  string

	mu    sync.RWMutex
	cache map[string]cachedResponse
}

// Option configures a RESTClient instance.
type Option func(*RESTClient)

// WithBaseURL overrides the GitHub REST API base URL (useful for testing or GHES).
func WithBaseURL(rawURL string) Option {
	return func(c *RESTClient) {
		if trimmed := strings.TrimRight(strings.TrimSpace(rawURL), "/"); trimmed != "" {
			c.baseURL = trimmed
		}
	}
}

// WithHTTPClient sets a custom http.Client on RESTClient.
func WithHTTPClient(client *http.Client) Option {
	return func(c *RESTClient) {
		if client != nil {
			c.httpClient = client
		}
	}
}

// WithUserAgent sets the User-Agent header sent on GitHub API requests.
func WithUserAgent(ua string) Option {
	return func(c *RESTClient) {
		if strings.TrimSpace(ua) != "" {
			c.userAgent = ua
		}
	}
}

// NewRESTClient constructs a read-only GitHub REST API client.
func NewRESTClient(token security.SensitiveString, opts ...Option) *RESTClient {
	c := &RESTClient{
		baseURL:    defaultBaseURL,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		token:      token,
		userAgent:  defaultUserAgent,
		cache:      make(map[string]cachedResponse),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(c)
		}
	}
	return c
}

type apiRepo struct {
	Name          string `json:"name"`
	FullName      string `json:"full_name"`
	DefaultBranch string `json:"default_branch"`
	Archived      bool   `json:"archived"`
	Private       bool   `json:"private"`
	Owner         struct {
		Login string `json:"login"`
	} `json:"owner"`
}

func (r apiRepo) toModel() Repository {
	owner := r.Owner.Login
	if owner == "" && strings.Contains(r.FullName, "/") {
		parts := strings.SplitN(r.FullName, "/", 2)
		owner = parts[0]
	}
	return Repository{
		Owner:         owner,
		Name:          r.Name,
		FullName:      r.FullName,
		DefaultBranch: r.DefaultBranch,
		Archived:      r.Archived,
		Private:       r.Private,
	}
}

type apiSecret struct {
	Name       string    `json:"name"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
	Visibility string    `json:"visibility"`
}

type apiSecretsResponse struct {
	Secrets []apiSecret `json:"secrets"`
}

type apiEnvironmentsResponse struct {
	Environments []struct {
		Name string `json:"name"`
	} `json:"environments"`
}

type apiContentItem struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	Type     string `json:"type"`
	Encoding string `json:"encoding"`
	Content  string `json:"content"`
}

// ListOrgRepos lists all repositories belonging to org across paginated responses.
func (c *RESTClient) ListOrgRepos(ctx context.Context, org string) ([]Repository, error) {
	endpoint := fmt.Sprintf("/orgs/%s/repos?per_page=100&type=all", url.PathEscape(org))
	var repos []Repository

	for endpoint != "" {
		body, next, err := c.get(ctx, endpoint, "application/vnd.github+json")
		if err != nil {
			return nil, err
		}
		var page []apiRepo
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("decode org repos: %w", err)
		}
		for _, item := range page {
			repos = append(repos, item.toModel())
		}
		endpoint = next
	}
	return repos, nil
}

// GetRepo fetches metadata for a single owner/name repository.
func (c *RESTClient) GetRepo(ctx context.Context, owner, name string) (Repository, error) {
	endpoint := fmt.Sprintf("/repos/%s/%s", url.PathEscape(owner), url.PathEscape(name))
	body, _, err := c.get(ctx, endpoint, "application/vnd.github+json")
	if err != nil {
		return Repository{}, err
	}
	var repo apiRepo
	if err := json.Unmarshal(body, &repo); err != nil {
		return Repository{}, fmt.Errorf("decode repo %s/%s: %w", owner, name, err)
	}
	return repo.toModel(), nil
}

// ListOrgSecrets lists organization-level Actions secret metadata.
func (c *RESTClient) ListOrgSecrets(ctx context.Context, org string) ([]model.SecretMetadata, error) {
	endpoint := fmt.Sprintf("/orgs/%s/actions/secrets?per_page=100", url.PathEscape(org))
	var out []model.SecretMetadata

	for endpoint != "" {
		body, next, err := c.get(ctx, endpoint, "application/vnd.github+json")
		if err != nil {
			return nil, err
		}
		var resp apiSecretsResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("decode org secrets: %w", err)
		}
		for _, s := range resp.Secrets {
			out = append(out, model.SecretMetadata{
				Name:       s.Name,
				Scope:      model.ScopeOrg,
				Owner:      org,
				Visibility: s.Visibility,
				CreatedAt:  s.CreatedAt,
				UpdatedAt:  s.UpdatedAt,
			})
		}
		endpoint = next
	}
	return out, nil
}

// ListRepoSecrets lists repository-level Actions secret metadata.
func (c *RESTClient) ListRepoSecrets(ctx context.Context, owner, repo string) ([]model.SecretMetadata, error) {
	endpoint := fmt.Sprintf("/repos/%s/%s/actions/secrets?per_page=100", url.PathEscape(owner), url.PathEscape(repo))
	var out []model.SecretMetadata

	for endpoint != "" {
		body, next, err := c.get(ctx, endpoint, "application/vnd.github+json")
		if err != nil {
			return nil, err
		}
		var resp apiSecretsResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("decode repo secrets: %w", err)
		}
		for _, s := range resp.Secrets {
			out = append(out, model.SecretMetadata{
				Name:      s.Name,
				Scope:     model.ScopeRepo,
				Owner:     owner,
				Repo:      owner + "/" + repo,
				CreatedAt: s.CreatedAt,
				UpdatedAt: s.UpdatedAt,
			})
		}
		endpoint = next
	}
	return out, nil
}

// ListEnvironments lists deployment environments configured on owner/repo.
func (c *RESTClient) ListEnvironments(ctx context.Context, owner, repo string) ([]Environment, error) {
	endpoint := fmt.Sprintf("/repos/%s/%s/environments?per_page=100", url.PathEscape(owner), url.PathEscape(repo))
	var out []Environment

	for endpoint != "" {
		body, next, err := c.get(ctx, endpoint, "application/vnd.github+json")
		if err != nil {
			return nil, err
		}
		var resp apiEnvironmentsResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("decode environments: %w", err)
		}
		for _, env := range resp.Environments {
			if env.Name != "" {
				out = append(out, Environment{Name: env.Name})
			}
		}
		endpoint = next
	}
	return out, nil
}

// ListEnvironmentSecrets lists Actions secret metadata scoped to a repository environment.
func (c *RESTClient) ListEnvironmentSecrets(ctx context.Context, owner, repo, env string) ([]model.SecretMetadata, error) {
	endpoint := fmt.Sprintf("/repos/%s/%s/environments/%s/secrets?per_page=100",
		url.PathEscape(owner), url.PathEscape(repo), url.PathEscape(env))
	var out []model.SecretMetadata

	for endpoint != "" {
		body, next, err := c.get(ctx, endpoint, "application/vnd.github+json")
		if err != nil {
			return nil, err
		}
		var resp apiSecretsResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("decode environment secrets: %w", err)
		}
		for _, s := range resp.Secrets {
			out = append(out, model.SecretMetadata{
				Name:        s.Name,
				Scope:       model.ScopeEnvironment,
				Owner:       owner,
				Repo:        owner + "/" + repo,
				Environment: env,
				CreatedAt:   s.CreatedAt,
				UpdatedAt:   s.UpdatedAt,
			})
		}
		endpoint = next
	}
	return out, nil
}

// ListWorkflowFiles fetches YAML workflow definitions under .github/workflows/ for owner/repo.
func (c *RESTClient) ListWorkflowFiles(ctx context.Context, owner, repo, ref string) ([]WorkflowFile, error) {
	endpoint := fmt.Sprintf("/repos/%s/%s/contents/.github/workflows", url.PathEscape(owner), url.PathEscape(repo))
	if strings.TrimSpace(ref) != "" {
		endpoint += "?ref=" + url.QueryEscape(ref)
	}

	body, _, err := c.get(ctx, endpoint, "application/vnd.github+json")
	if err != nil {
		if IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}

	var entries []apiContentItem
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("decode workflow directory listing: %w", err)
	}

	var files []WorkflowFile
	for _, entry := range entries {
		if entry.Type != "file" || !workflow.IsWorkflowFile(entry.Path) {
			continue
		}
		raw, err := c.fetchFileContent(ctx, owner, repo, entry.Path, ref)
		if err != nil {
			return nil, err
		}
		files = append(files, WorkflowFile{
			Path:    entry.Path,
			Content: raw,
		})
	}
	return files, nil
}

// ListRepoLockfiles discovers and fetches supported dependency lockfiles in owner/repo.
func (c *RESTClient) ListRepoLockfiles(ctx context.Context, owner, repo, ref string) ([]RepoFile, error) {
	if strings.TrimSpace(ref) == "" {
		ref = "HEAD"
	}
	treeEndpoint := fmt.Sprintf("/repos/%s/%s/git/trees/%s?recursive=1",
		url.PathEscape(owner), url.PathEscape(repo), url.PathEscape(ref))

	var lockPaths []string
	body, _, err := c.get(ctx, treeEndpoint, "application/vnd.github+json")
	if err == nil {
		var treeResp struct {
			Tree []struct {
				Path string `json:"path"`
				Type string `json:"type"`
			} `json:"tree"`
		}
		if json.Unmarshal(body, &treeResp) == nil {
			for _, entry := range treeResp.Tree {
				if entry.Type == "blob" && lockfile.IsLockfile(entry.Path) {
					lockPaths = append(lockPaths, entry.Path)
				}
			}
		}
	} else if !IsNotFound(err) && !IsPermissionDenied(err) {
		return nil, err
	} else {
		// Fallback to root directory listing when git tree is unavailable.
		rootEndpoint := fmt.Sprintf("/repos/%s/%s/contents", url.PathEscape(owner), url.PathEscape(repo))
		if ref != "HEAD" {
			rootEndpoint += "?ref=" + url.QueryEscape(ref)
		}
		rootBody, _, rootErr := c.get(ctx, rootEndpoint, "application/vnd.github+json")
		if rootErr != nil {
			if IsNotFound(rootErr) {
				return nil, nil
			}
			return nil, rootErr
		}
		var entries []apiContentItem
		if json.Unmarshal(rootBody, &entries) == nil {
			for _, entry := range entries {
				if entry.Type == "file" && lockfile.IsLockfile(entry.Path) {
					lockPaths = append(lockPaths, entry.Path)
				}
			}
		}
	}

	var files []RepoFile
	for _, p := range lockPaths {
		raw, fetchErr := c.fetchFileContent(ctx, owner, repo, p, ref)
		if fetchErr != nil {
			if IsNotFound(fetchErr) {
				continue
			}
			return nil, fetchErr
		}
		files = append(files, RepoFile{Path: p, Content: raw})
	}
	return files, nil
}

// ListWorkflowRuns lists workflow runs in owner/repo created at or after since.
func (c *RESTClient) ListWorkflowRuns(ctx context.Context, owner, repo string, since time.Time) ([]WorkflowRun, error) {
	endpoint := fmt.Sprintf("/repos/%s/%s/actions/runs?per_page=100", url.PathEscape(owner), url.PathEscape(repo))
	if !since.IsZero() {
		endpoint += "&created=" + url.QueryEscape(">="+since.UTC().Format(time.RFC3339))
	}

	var runs []WorkflowRun
	for endpoint != "" {
		body, next, err := c.get(ctx, endpoint, "application/vnd.github+json")
		if err != nil {
			if IsNotFound(err) {
				return nil, nil
			}
			return nil, err
		}
		var resp struct {
			WorkflowRuns []struct {
				ID         int64     `json:"id"`
				Path       string    `json:"path"`
				Name       string    `json:"name"`
				Event      string    `json:"event"`
				Status     string    `json:"status"`
				Conclusion string    `json:"conclusion"`
				CreatedAt  time.Time `json:"created_at"`
			} `json:"workflow_runs"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("decode workflow runs: %w", err)
		}
		for _, r := range resp.WorkflowRuns {
			if !since.IsZero() && r.CreatedAt.Before(since) {
				continue
			}
			runs = append(runs, WorkflowRun{
				ID:         r.ID,
				Path:       r.Path,
				Name:       r.Name,
				Event:      r.Event,
				Status:     r.Status,
				Conclusion: r.Conclusion,
				CreatedAt:  r.CreatedAt,
			})
		}
		endpoint = next
	}
	return runs, nil
}

func (c *RESTClient) fetchFileContent(ctx context.Context, owner, repo, filePath, ref string) ([]byte, error) {
	escapedPath := escapeRepoPath(filePath)
	endpoint := fmt.Sprintf("/repos/%s/%s/contents/%s", url.PathEscape(owner), url.PathEscape(repo), escapedPath)
	if strings.TrimSpace(ref) != "" {
		endpoint += "?ref=" + url.QueryEscape(ref)
	}

	body, _, err := c.get(ctx, endpoint, "application/vnd.github.raw+json")
	if err != nil {
		return nil, err
	}

	// Fallback: if a server returns JSON with base64 content instead of raw bytes.
	var item apiContentItem
	if json.Unmarshal(body, &item) == nil && item.Encoding == "base64" && item.Content != "" {
		decoded, decErr := base64.StdEncoding.DecodeString(strings.ReplaceAll(item.Content, "\n", ""))
		if decErr == nil {
			return decoded, nil
		}
	}
	return body, nil
}

func (c *RESTClient) get(ctx context.Context, endpointOrURL, accept string) ([]byte, string, error) {
	fullURL := endpointOrURL
	if !strings.HasPrefix(endpointOrURL, "http://") && !strings.HasPrefix(endpointOrURL, "https://") {
		fullURL = c.baseURL + endpointOrURL
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		return nil, "", security.SanitizeError(err, c.token.Expose())
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("X-GitHub-Api-Version", defaultAPIVersion)
	req.Header.Set("User-Agent", c.userAgent)
	if !c.token.IsEmpty() {
		req.Header.Set("Authorization", "Bearer "+c.token.Expose())
	}

	cacheKey := accept + "|" + fullURL
	c.mu.RLock()
	cached, hasCached := c.cache[cacheKey]
	c.mu.RUnlock()
	if hasCached && cached.etag != "" {
		req.Header.Set("If-None-Match", cached.etag)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, "", security.SanitizeError(err, c.token.Expose())
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", security.SanitizeError(err, c.token.Expose())
	}

	if resp.StatusCode == http.StatusNotModified && hasCached {
		return cached.body, parseNextLink(resp.Header.Get("Link")), nil
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, "", parseAPIError(resp, endpointOrURL, body)
	}

	if etag := resp.Header.Get("ETag"); etag != "" {
		c.mu.Lock()
		c.cache[cacheKey] = cachedResponse{etag: etag, body: body}
		c.mu.Unlock()
	}

	return body, parseNextLink(resp.Header.Get("Link")), nil
}

func parseAPIError(resp *http.Response, endpoint string, body []byte) error {
	var payload struct {
		Message string `json:"message"`
	}
	_ = json.Unmarshal(body, &payload)

	var resetAt time.Time
	if raw := resp.Header.Get("X-RateLimit-Reset"); raw != "" {
		if unixSec, err := strconv.ParseInt(raw, 10, 64); err == nil {
			resetAt = time.Unix(unixSec, 0).UTC()
		}
	}

	return &APIError{
		StatusCode:     resp.StatusCode,
		Message:        payload.Message,
		Endpoint:       endpoint,
		RateLimitReset: resetAt,
	}
}

func parseNextLink(header string) string {
	if header == "" {
		return ""
	}
	matches := nextLinkRe.FindStringSubmatch(header)
	if len(matches) < 2 {
		return ""
	}
	return matches[1]
}

func escapeRepoPath(p string) string {
	parts := strings.Split(strings.TrimLeft(p, "/"), "/")
	for i := range parts {
		parts[i] = url.PathEscape(parts[i])
	}
	return strings.Join(parts, "/")
}
