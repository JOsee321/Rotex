package github

import (
	"context"
	"errors"
	"fmt"
	"net/http"
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

// Client defines read-only GitHub API operations required for Phase 1 scanning.
type Client interface {
	ListOrgRepos(ctx context.Context, org string) ([]Repository, error)
	GetRepo(ctx context.Context, owner, name string) (Repository, error)
	ListOrgSecrets(ctx context.Context, org string) ([]model.SecretMetadata, error)
	ListRepoSecrets(ctx context.Context, owner, repo string) ([]model.SecretMetadata, error)
	ListEnvironments(ctx context.Context, owner, repo string) ([]Environment, error)
	ListEnvironmentSecrets(ctx context.Context, owner, repo, env string) ([]model.SecretMetadata, error)
	ListWorkflowFiles(ctx context.Context, owner, repo, ref string) ([]WorkflowFile, error)
}

// APIError captures an HTTP error response returned by the GitHub API.
type APIError struct {
	StatusCode     int
	Message        string
	Endpoint       string
	RateLimitReset time.Time
}

// Error implements the error interface without including sensitive credentials.
func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("github API %s returned HTTP %d: %s", e.Endpoint, e.StatusCode, e.Message)
	}
	return fmt.Sprintf("github API %s returned HTTP %d", e.Endpoint, e.StatusCode)
}

// IsPermissionDenied reports whether err represents an HTTP 403 Forbidden error.
func IsPermissionDenied(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusForbidden
}

// IsNotFound reports whether err represents an HTTP 404 Not Found error.
func IsNotFound(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound
}
