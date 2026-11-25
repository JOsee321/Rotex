package github

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/JOsee321/Rotex/internal/model"
)

// Repository represents read-only metadata for a GitHub repository.
type Repository struct {
	Owner         string
	Name          string
	FullName      string
	DefaultBranch string
	Archived      bool
	Private       bool
}

// Environment represents a GitHub Actions deployment environment.
type Environment struct {
	Name string
}

// WorkflowFile holds the path and raw YAML bytes of a GitHub Actions workflow.
type WorkflowFile struct {
	Path    string
	Content []byte
}

// RepoFile holds the repository-relative path and raw content of a file.
type RepoFile struct {
	Path    string
	Content []byte
}

// WorkflowRun represents read-only execution metadata for a GitHub Actions workflow run.
type WorkflowRun struct {
	ID         int64
	Path       string
	Name       string
	Event      string
	Status     string
	Conclusion string
	CreatedAt  time.Time
}

// Client defines read-only GitHub API operations required for Phase 1 scanning.
type Client interface {
	ListOrgRepos(ctx context.Context, org string) ([]Repository, error)
	GetRepo(ctx context.Context, owner, name string) (Repository, error)
	ListOrgSecrets(ctx context.Context, org string) ([]model.SecretMetadata, error)
	ListRepoSecrets(ctx context.Context, owner, repo string) ([]model.SecretMetadata, error)
	ListEnvironments(ctx context.Context, owner, repo string) ([]Environment, error)
	ListEnvironmentSecrets(ctx context.Context, owner, repo, env string) ([]model.SecretMetadata, error)
	ListWorkflowFiles(ctx context.Context, owner, repo, ref string) ([]WorkflowFile, error)
	ListRepoLockfiles(ctx context.Context, owner, repo, ref string) ([]RepoFile, error)
	ListWorkflowRuns(ctx context.Context, owner, repo string, since time.Time) ([]WorkflowRun, error)
}

// APIError captures an HTTP error response returned by the GitHub API.
type APIError struct {
	StatusCode         int
	Message            string
	Endpoint           string
	RateLimitRemaining *int
	RateLimitReset     time.Time
}

// IsRateLimited reports whether this APIError was caused by GitHub rate limiting.
func (e *APIError) IsRateLimited() bool {
	if e == nil {
		return false
	}
	if e.StatusCode == http.StatusTooManyRequests {
		return true
	}
	if e.StatusCode == http.StatusForbidden {
		if e.RateLimitRemaining != nil && *e.RateLimitRemaining == 0 {
			return true
		}
		lower := strings.ToLower(e.Message)
		return strings.Contains(lower, "rate limit") || strings.Contains(lower, "secondary rate")
	}
	return false
}

// Error implements the error interface without including sensitive credentials.
func (e *APIError) Error() string {
	base := fmt.Sprintf("github API %s returned HTTP %d", e.Endpoint, e.StatusCode)
	if e.Message != "" {
		base += ": " + e.Message
	}
	if e.IsRateLimited() && !e.RateLimitReset.IsZero() {
		base += fmt.Sprintf(" (rate limit resets at %s)", e.RateLimitReset.UTC().Format(time.RFC3339))
	}
	return base
}

// IsPermissionDenied reports whether err represents an HTTP 403 Forbidden error
// (excluding rate-limit responses).
func IsPermissionDenied(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusForbidden && !apiErr.IsRateLimited()
}

// IsRateLimited reports whether err represents a GitHub API rate-limit error.
func IsRateLimited(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.IsRateLimited()
}

// IsUnauthorized reports whether err represents an HTTP 401 Unauthorized error.
func IsUnauthorized(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusUnauthorized
}

// IsNotFound reports whether err represents an HTTP 404 Not Found error.
func IsNotFound(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound
}
