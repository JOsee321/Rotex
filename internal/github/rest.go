package github

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/JOsee321/Rotex/internal/lockfile"
	"github.com/JOsee321/Rotex/internal/model"
	"github.com/JOsee321/Rotex/internal/security"
	"github.com/JOsee321/Rotex/internal/workflow"
)

const (
	defaultBaseURL        = "https://api.github.com"
	defaultAPIVersion     = "2022-11-28"
	defaultUserAgent      = "rotex-cli"
	maxAPIResponseBytes   = 16 << 20 // 16 MiB
	maxWriteResponseBytes = 1 << 20  // 1 MiB
	maxCacheEntries       = 256
	maxCacheEntryBytes    = 1 << 20 // 1 MiB
	maxPaginationPages    = 500
	maxHTTPRedirects      = 10
)

var nextLinkRe = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

type cachedResponse struct {
	etag string
	body []byte
}

// RESTClient implements Client against the GitHub REST API with ETag caching.
type RESTClient struct {
	baseURL    string
	parsedBase *url.URL
	baseErr    error
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
			cloned := *client
			c.httpClient = &cloned
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
	c.parsedBase, c.baseErr = parseAndValidateBaseURL(c.baseURL)
	if c.parsedBase != nil {
		c.installRedirectGuard()
	}
	return c
}

func parseAndValidateBaseURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid GitHub API base URL: %w", err)
	}
	if (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, fmt.Errorf("invalid GitHub API base URL %q: scheme and host are required", raw)
	}
	if u.User != nil {
		return nil, errors.New("GitHub API base URL must not contain embedded credentials")
	}
	return u, nil
}

func (c *RESTClient) installRedirectGuard() {
	cloned := *c.httpClient
	userCheck := cloned.CheckRedirect
	base := c.parsedBase

	cloned.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxHTTPRedirects {
			req.Header.Del("Authorization")
			return fmt.Errorf("stopped after %d redirects", maxHTTPRedirects)
		}
		if len(via) > 0 && strings.EqualFold(via[0].URL.Scheme, "https") && !strings.EqualFold(req.URL.Scheme, "https") {
			req.Header.Del("Authorization")
			return errors.New("refusing insecure HTTP redirect downgrade from HTTPS")
		}
		if len(via) > 0 && via[0].Method == http.MethodPut {
			req.Header.Del("Authorization")
			return errors.New("refusing HTTP redirect on write request")
		}
		if !sameOrigin(req.URL, base) || req.URL.User != nil {
			req.Header.Del("Authorization")
			return fmt.Errorf("refusing cross-origin HTTP redirect to %s://%s", req.URL.Scheme, req.URL.Host)
		}
		if userCheck != nil {
			return userCheck(req, via)
		}
		return nil
	}
	c.httpClient = &cloned
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
	if err := validatePathSegment("org", org, false); err != nil {
		return nil, err
	}
	endpoint := fmt.Sprintf("/orgs/%s/repos?per_page=100&type=all", url.PathEscape(org))
	var repos []Repository

	err := c.getPaginated(ctx, endpoint, "application/vnd.github+json", func(body []byte) error {
		var page []apiRepo
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("decode org repos: %w", err)
		}
		for _, item := range page {
			repos = append(repos, item.toModel())
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return repos, nil
}

// GetRepo fetches metadata for a single owner/name repository.
func (c *RESTClient) GetRepo(ctx context.Context, owner, name string) (Repository, error) {
	if err := validatePathSegment("owner", owner, false); err != nil {
		return Repository{}, err
	}
	if err := validatePathSegment("repo", name, false); err != nil {
		return Repository{}, err
	}
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
	if err := validatePathSegment("org", org, false); err != nil {
		return nil, err
	}
	endpoint := fmt.Sprintf("/orgs/%s/actions/secrets?per_page=100", url.PathEscape(org))
	var out []model.SecretMetadata

	err := c.getPaginated(ctx, endpoint, "application/vnd.github+json", func(body []byte) error {
		var resp apiSecretsResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("decode org secrets: %w", err)
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
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ListRepoSecrets lists repository-level Actions secret metadata.
func (c *RESTClient) ListRepoSecrets(ctx context.Context, owner, repo string) ([]model.SecretMetadata, error) {
	if err := validatePathSegment("owner", owner, false); err != nil {
		return nil, err
	}
	if err := validatePathSegment("repo", repo, false); err != nil {
		return nil, err
	}
	endpoint := fmt.Sprintf("/repos/%s/%s/actions/secrets?per_page=100", url.PathEscape(owner), url.PathEscape(repo))
	var out []model.SecretMetadata

	err := c.getPaginated(ctx, endpoint, "application/vnd.github+json", func(body []byte) error {
		var resp apiSecretsResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("decode repo secrets: %w", err)
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
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ListEnvironments lists deployment environments configured on owner/repo.
func (c *RESTClient) ListEnvironments(ctx context.Context, owner, repo string) ([]Environment, error) {
	if err := validatePathSegment("owner", owner, false); err != nil {
		return nil, err
	}
	if err := validatePathSegment("repo", repo, false); err != nil {
		return nil, err
	}
	endpoint := fmt.Sprintf("/repos/%s/%s/environments?per_page=100", url.PathEscape(owner), url.PathEscape(repo))
	var out []Environment

	err := c.getPaginated(ctx, endpoint, "application/vnd.github+json", func(body []byte) error {
		var resp apiEnvironmentsResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("decode environments: %w", err)
		}
		for _, env := range resp.Environments {
			if env.Name != "" {
				out = append(out, Environment{Name: env.Name})
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ListEnvironmentSecrets lists Actions secret metadata scoped to a repository environment.
func (c *RESTClient) ListEnvironmentSecrets(ctx context.Context, owner, repo, env string) ([]model.SecretMetadata, error) {
	if err := validatePathSegment("owner", owner, false); err != nil {
		return nil, err
	}
	if err := validatePathSegment("repo", repo, false); err != nil {
		return nil, err
	}
	if err := validatePathSegment("environment", env, true); err != nil {
		return nil, err
	}
	endpoint := fmt.Sprintf("/repos/%s/%s/environments/%s/secrets?per_page=100",
		url.PathEscape(owner), url.PathEscape(repo), url.PathEscape(env))
	var out []model.SecretMetadata

	err := c.getPaginated(ctx, endpoint, "application/vnd.github+json", func(body []byte) error {
		var resp apiSecretsResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("decode environment secrets: %w", err)
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
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ListWorkflowFiles fetches YAML workflow definitions under .github/workflows/ for owner/repo.
func (c *RESTClient) ListWorkflowFiles(ctx context.Context, owner, repo, ref string) ([]WorkflowFile, error) {
	if err := validatePathSegment("owner", owner, false); err != nil {
		return nil, err
	}
	if err := validatePathSegment("repo", repo, false); err != nil {
		return nil, err
	}
	if err := validateRef(ref); err != nil {
		return nil, err
	}
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
	if err := validatePathSegment("owner", owner, false); err != nil {
		return nil, err
	}
	if err := validatePathSegment("repo", repo, false); err != nil {
		return nil, err
	}
	if strings.TrimSpace(ref) == "" {
		ref = "HEAD"
	} else if err := validateRef(ref); err != nil {
		return nil, err
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
	if err := validatePathSegment("owner", owner, false); err != nil {
		return nil, err
	}
	if err := validatePathSegment("repo", repo, false); err != nil {
		return nil, err
	}
	endpoint := fmt.Sprintf("/repos/%s/%s/actions/runs?per_page=100", url.PathEscape(owner), url.PathEscape(repo))
	if !since.IsZero() {
		endpoint += "&created=" + url.QueryEscape(">="+since.UTC().Format(time.RFC3339))
	}

	var runs []WorkflowRun
	err := c.getPaginated(ctx, endpoint, "application/vnd.github+json", func(body []byte) error {
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
			return fmt.Errorf("decode workflow runs: %w", err)
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
		return nil
	})
	if err != nil {
		if IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return runs, nil
}

func (c *RESTClient) fetchFileContent(ctx context.Context, owner, repo, filePath, ref string) ([]byte, error) {
	escapedPath, err := escapeRepoPath(filePath)
	if err != nil {
		return nil, err
	}
	if err := validateRef(ref); err != nil {
		return nil, err
	}
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

func (c *RESTClient) getPaginated(ctx context.Context, startEndpoint, accept string, handlePage func([]byte) error) error {
	endpoint := startEndpoint
	visited := make(map[string]struct{})
	for page := 0; endpoint != ""; page++ {
		if page >= maxPaginationPages {
			return fmt.Errorf("pagination exceeded maximum of %d pages", maxPaginationPages)
		}
		if _, seen := visited[endpoint]; seen {
			return fmt.Errorf("pagination cycle detected at %s", endpoint)
		}
		visited[endpoint] = struct{}{}

		body, next, err := c.get(ctx, endpoint, accept)
		if err != nil {
			return err
		}
		if err := handlePage(body); err != nil {
			return err
		}
		endpoint = next
	}
	return nil
}

func (c *RESTClient) get(ctx context.Context, endpointOrURL, accept string) ([]byte, string, error) {
	fullURL, err := c.resolveURL(endpointOrURL)
	if err != nil {
		return nil, "", security.SanitizeError(err, c.token.Expose())
	}

	cacheKey := accept + "|" + fullURL
	c.mu.RLock()
	cached, hasCached := c.cache[cacheKey]
	c.mu.RUnlock()

	headers := map[string]string{
		"Accept": accept,
	}
	if hasCached && cached.etag != "" {
		headers["If-None-Match"] = cached.etag
	}

	resp, body, err := c.doRequest(ctx, http.MethodGet, fullURL, endpointOrURL, headers, nil, maxAPIResponseBytes)
	if err != nil {
		return nil, "", err
	}

	next, linkErr := c.extractValidatedNextLink(resp.Header.Get("Link"))
	if linkErr != nil {
		return nil, "", linkErr
	}

	if resp.StatusCode == http.StatusNotModified && hasCached {
		return cached.body, next, nil
	}

	if etag := resp.Header.Get("ETag"); etag != "" && len(body) <= maxCacheEntryBytes {
		c.mu.Lock()
		if len(c.cache) >= maxCacheEntries {
			// Evict cache to keep memory strictly bounded on large org scans.
			clear(c.cache)
		}
		c.cache[cacheKey] = cachedResponse{etag: etag, body: body}
		c.mu.Unlock()
	}

	return body, next, nil
}

func (c *RESTClient) doRequest(
	ctx context.Context,
	method string,
	fullURL string,
	endpointLabel string,
	headers map[string]string,
	payload []byte,
	maxBytes int64,
	extraSecrets ...string,
) (*http.Response, []byte, error) {
	if c.baseErr != nil {
		return nil, nil, security.SanitizeError(c.baseErr, c.token.Expose())
	}

	var bodyReader io.Reader
	if payload != nil {
		bodyReader = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, fullURL, bodyReader)
	if err != nil {
		return nil, nil, security.SanitizeError(err, append(extraSecrets, c.token.Expose())...)
	}
	req.Header.Set("X-GitHub-Api-Version", defaultAPIVersion)
	req.Header.Set("User-Agent", c.userAgent)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if !c.token.IsEmpty() {
		req.Header.Set("Authorization", "Bearer "+c.token.Expose())
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, security.SanitizeError(err, append(extraSecrets, c.token.Expose())...)
	}
	defer resp.Body.Close()

	body, err := readLimitedBody(resp.Body, maxBytes)
	if err != nil {
		return nil, nil, security.SanitizeError(err, append(extraSecrets, c.token.Expose())...)
	}

	if resp.StatusCode == http.StatusNotModified && method == http.MethodGet {
		return resp, body, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, nil, parseAPIError(resp, endpointLabel, body, append(extraSecrets, c.token.Expose())...)
	}
	return resp, body, nil
}

func (c *RESTClient) resolveURL(endpointOrURL string) (string, error) {
	if c.baseErr != nil {
		return "", c.baseErr
	}
	if strings.HasPrefix(endpointOrURL, "http://") || strings.HasPrefix(endpointOrURL, "https://") {
		u, err := url.Parse(endpointOrURL)
		if err != nil {
			return "", fmt.Errorf("invalid GitHub URL: %w", err)
		}
		if !sameOrigin(u, c.parsedBase) || u.User != nil {
			return "", fmt.Errorf("refusing request to non-matching origin %s://%s", u.Scheme, u.Host)
		}
		if basePrefix := strings.TrimRight(c.parsedBase.Path, "/"); basePrefix != "" {
			if u.Path != basePrefix && !strings.HasPrefix(u.Path, basePrefix+"/") {
				return "", fmt.Errorf("refusing request outside API base path %q", basePrefix)
			}
		}
		return u.String(), nil
	}
	if !strings.HasPrefix(endpointOrURL, "/") {
		return "", fmt.Errorf("invalid relative API endpoint %q", endpointOrURL)
	}
	return c.baseURL + endpointOrURL, nil
}

func (c *RESTClient) extractValidatedNextLink(header string) (string, error) {
	next := parseNextLink(header)
	if next == "" {
		return "", nil
	}
	if strings.HasPrefix(next, "/") {
		resolved := c.parsedBase.ResolveReference(&url.URL{Path: ""})
		u, err := url.Parse(next)
		if err != nil {
			return "", fmt.Errorf("invalid pagination link: %w", err)
		}
		if strings.HasPrefix(next, "//") {
			return "", errors.New("refusing protocol-relative pagination link")
		}
		next = resolved.ResolveReference(u).String()
	}
	validated, err := c.resolveURL(next)
	if err != nil {
		return "", fmt.Errorf("invalid pagination next link: %w", err)
	}
	return validated, nil
}

func readLimitedBody(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("HTTP response exceeded maximum allowed size of %d bytes", limit)
	}
	return data, nil
}

func parseAPIError(resp *http.Response, endpoint string, body []byte, secrets ...string) error {
	var payload struct {
		Message string `json:"message"`
	}
	_ = json.Unmarshal(body, &payload)

	var remaining *int
	if rawRem := resp.Header.Get("X-RateLimit-Remaining"); rawRem != "" {
		if val, err := strconv.Atoi(rawRem); err == nil {
			remaining = &val
		}
	}

	var resetAt time.Time
	if raw := resp.Header.Get("X-RateLimit-Reset"); raw != "" {
		if unixSec, err := strconv.ParseInt(raw, 10, 64); err == nil {
			resetAt = time.Unix(unixSec, 0).UTC()
		}
	}

	return &APIError{
		StatusCode:         resp.StatusCode,
		Message:            security.SanitizeString(payload.Message, secrets...),
		Endpoint:           security.SanitizeString(endpoint, secrets...),
		RateLimitRemaining: remaining,
		RateLimitReset:     resetAt,
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

func sameOrigin(a, b *url.URL) bool {
	if a == nil || b == nil {
		return false
	}
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Host, b.Host)
}

func validatePathSegment(kind, val string, allowSpaces bool) error {
	if val == "" || strings.TrimSpace(val) == "" {
		return fmt.Errorf("%s must not be empty", kind)
	}
	if val != strings.TrimSpace(val) {
		return fmt.Errorf("invalid %s %q: leading or trailing whitespace is not allowed", kind, val)
	}
	if val == "." || val == ".." {
		return fmt.Errorf("invalid %s %q: dot path segments are not allowed", kind, val)
	}
	for _, r := range val {
		if r < 0x20 || r == 0x7f || r == '/' || r == '\\' || r == '?' || r == '#' || r == '%' {
			return fmt.Errorf("invalid %s %q: contains disallowed character", kind, val)
		}
		if !allowSpaces && unicode.IsSpace(r) {
			return fmt.Errorf("invalid %s %q: whitespace is not allowed", kind, val)
		}
	}
	return nil
}

func validateRef(ref string) error {
	if strings.TrimSpace(ref) == "" {
		return nil
	}
	if ref != strings.TrimSpace(ref) || ref == "." || ref == ".." || strings.Contains(ref, "..") {
		return fmt.Errorf("invalid git ref %q", ref)
	}
	for _, r := range ref {
		if r < 0x20 || r == 0x7f || r == '\\' || r == '?' || r == '#' || unicode.IsSpace(r) {
			return fmt.Errorf("invalid git ref %q", ref)
		}
	}
	return nil
}

func escapeRepoPath(p string) (string, error) {
	if p == "" || strings.HasPrefix(p, "/") || strings.HasPrefix(p, `\`) {
		return "", fmt.Errorf("invalid repository file path %q", p)
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f || r == '\\' || r == '?' || r == '#' {
			return "", fmt.Errorf("invalid repository file path %q", p)
		}
	}
	parts := strings.Split(p, "/")
	for i, seg := range parts {
		if seg == "" || seg == "." || seg == ".." {
			return "", fmt.Errorf("invalid repository file path %q: illegal segment %q", p, seg)
		}
		parts[i] = url.PathEscape(seg)
	}
	return strings.Join(parts, "/"), nil
}
