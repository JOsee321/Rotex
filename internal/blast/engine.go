package blast

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/JOsee321/Rotex/internal/aws"
	"github.com/JOsee321/Rotex/internal/github"
	"github.com/JOsee321/Rotex/internal/lockfile"
	"github.com/JOsee321/Rotex/internal/model"
	"github.com/JOsee321/Rotex/internal/scanner"
)

const (
	defaultSince       = 72 * time.Hour
	defaultConcurrency = 5
)

// Request specifies the target repositories, compromised packages, and incident window.
type Request struct {
	Target   model.ScanTarget
	Packages []lockfile.PackageSpec
	Since    time.Duration
}

// Option configures a blast Service.
type Option func(*Service)

// WithClock overrides the clock used for incident window calculations.
func WithClock(fn func() time.Time) Option {
	return func(s *Service) {
		if fn != nil {
			s.now = fn
		}
	}
}

// WithConcurrency sets the bounded worker pool size.
func WithConcurrency(n int) Option {
	return func(s *Service) {
		if n < 1 {
			n = 1
		}
		if n > 16 {
			n = 16
		}
		s.concurrency = n
	}
}

// WithAWSInspector enables AWS privilege metadata correlation during blast ranking.
func WithAWSInspector(insp aws.Inspector) Option {
	return func(s *Service) {
		s.aws = insp
	}
}

// WithAllowUnauthenticated enables read-only blast analysis without a GitHub token.
func WithAllowUnauthenticated(allow bool) Option {
	return func(s *Service) {
		s.allowUnauthenticated = allow
	}
}

// Service correlates dependency lockfiles, GitHub Actions run history, and secret exposures.
type Service struct {
	gh                   github.Client
	aws                  aws.Inspector
	now                  func() time.Time
	concurrency          int
	allowUnauthenticated bool
}

// NewService constructs a read-only blast radius Service.
func NewService(gh github.Client, opts ...Option) *Service {
	s := &Service{
		gh:          gh,
		now:         func() time.Time { return time.Now().UTC() },
		concurrency: defaultConcurrency,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}
	return s
}

type repoBlastData struct {
	repo     github.Repository
	matches  []model.CompromisedMatch
	runs     []github.WorkflowRun
	warnings []model.ScanWarning
	fatalErr error
}

// Analyze maps compromised packages to affected repos, recent workflow runs, and prioritized secret rotation queue.
func (s *Service) Analyze(ctx context.Context, req Request) (*model.BlastReport, error) {
	if s.gh == nil {
		return nil, errors.New("github client must not be nil")
	}
	if len(req.Packages) == 0 {
		return nil, errors.New("specify at least one package (--pkg or --advisory)")
	}
	since := req.Since
	if since <= 0 {
		since = defaultSince
	}

	now := s.now().UTC()
	repos, err := s.resolveRepos(ctx, req.Target)
	if err != nil {
		return nil, err
	}

	scannerOpts := []scanner.Option{
		scanner.WithClock(func() time.Time { return now }),
		scanner.WithConcurrency(s.concurrency),
		scanner.WithAllowUnauthenticated(s.allowUnauthenticated),
	}
	if s.aws != nil {
		scannerOpts = append(scannerOpts, scanner.WithAWSInspector(s.aws))
	}

	scanReport, err := scanner.NewService(s.gh, scannerOpts...).ScanRepos(ctx, req.Target, repos)
	if err != nil {
		return nil, err
	}

	var activeRepos []github.Repository
	for _, r := range repos {
		if r.Archived && !req.Target.IncludeArchived {
			continue
		}
		activeRepos = append(activeRepos, r)
	}

	repoResults, err := s.inspectReposBounded(ctx, activeRepos, req.Packages, now.Add(-since))
	if err != nil {
		return nil, err
	}

	report := &model.BlastReport{
		Target:      req.Target,
		GeneratedAt: now,
		SinceHours:  int(since / time.Hour),
		Packages:    formatSpecs(req.Packages),
		Warnings:    slices.Clone(scanReport.Warnings),
	}

	affectedRepoSet := make(map[string]struct{})
	runsByRepo := make(map[string][]github.WorkflowRun)

	for _, res := range repoResults {
		report.Warnings = append(report.Warnings, res.warnings...)
		if len(res.matches) == 0 {
			continue
		}
		affectedRepoSet[res.repo.FullName] = struct{}{}
		report.Matches = append(report.Matches, res.matches...)
		runsByRepo[res.repo.FullName] = res.runs
	}

	sort.Slice(report.Matches, func(i, j int) bool {
		if report.Matches[i].Repo != report.Matches[j].Repo {
			return report.Matches[i].Repo < report.Matches[j].Repo
		}
		if report.Matches[i].Package != report.Matches[j].Package {
			return report.Matches[i].Package < report.Matches[j].Package
		}
		return report.Matches[i].Lockfile < report.Matches[j].Lockfile
	})

	report.RotationQueue = buildRotationQueue(scanReport.Exposures, affectedRepoSet, runsByRepo)
	return report, nil
}

func (s *Service) resolveRepos(ctx context.Context, target model.ScanTarget) ([]github.Repository, error) {
	if target.Org != "" {
		return s.gh.ListOrgRepos(ctx, target.Org)
	}
	owner, name, _ := strings.Cut(target.Repo, "/")
	repo, err := s.gh.GetRepo(ctx, owner, name)
	if err != nil {
		return nil, err
	}
	return []github.Repository{repo}, nil
}

func (s *Service) inspectReposBounded(ctx context.Context, repos []github.Repository, specs []lockfile.PackageSpec, since time.Time) ([]repoBlastData, error) {
	results := make([]repoBlastData, len(repos))
	if len(repos) == 0 {
		return results, nil
	}

	workers := min(s.concurrency, len(repos))
	jobs := make(chan int)
	var wg sync.WaitGroup

	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				if ctx.Err() != nil {
					results[idx] = repoBlastData{repo: repos[idx], fatalErr: ctx.Err()}
					continue
				}
				results[idx] = s.inspectSingleRepo(ctx, repos[idx], specs, since)
			}
		}()
	}

dispatch:
	for i := range repos {
		select {
		case <-ctx.Done():
			break dispatch
		case jobs <- i:
		}
	}
	close(jobs)
	wg.Wait()

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for _, res := range results {
		if res.fatalErr != nil {
			return nil, res.fatalErr
		}
	}
	return results, nil
}

func (s *Service) inspectSingleRepo(ctx context.Context, repo github.Repository, specs []lockfile.PackageSpec, since time.Time) repoBlastData {
	res := repoBlastData{repo: repo}

	lockfiles, err := s.gh.ListRepoLockfiles(ctx, repo.Owner, repo.Name, repo.DefaultBranch)
	if err != nil {
		if s.isDegradable(err) {
			res.warnings = append(res.warnings, model.ScanWarning{
				Scope:   "lockfile",
				Target:  repo.FullName,
				Code:    "access_skipped",
				Message: fmt.Sprintf("unable to read lockfiles: %v", err),
			})
			return res
		}
		res.fatalErr = fmt.Errorf("list lockfiles for %s: %w", repo.FullName, err)
		return res
	}

	for _, lf := range lockfiles {
		deps, parseErr := lockfile.Parse(lf.Path, lf.Content)
		if parseErr != nil {
			res.warnings = append(res.warnings, model.ScanWarning{
				Scope:   "lockfile",
				Target:  repo.FullName + ":" + lf.Path,
				Code:    "parse_error",
				Message: parseErr.Error(),
			})
			continue
		}
		for _, hit := range lockfile.Match(deps, specs) {
			res.matches = append(res.matches, model.CompromisedMatch{
				Repo:      repo.FullName,
				Ecosystem: string(hit.Ecosystem),
				Package:   hit.Name,
				Version:   hit.Version,
				Lockfile:  hit.Lockfile,
			})
		}
	}

	if len(res.matches) == 0 {
		return res
	}

	runs, runsErr := s.gh.ListWorkflowRuns(ctx, repo.Owner, repo.Name, since)
	if runsErr != nil {
		if s.isDegradable(runsErr) {
			res.warnings = append(res.warnings, model.ScanWarning{
				Scope:   "workflow_runs",
				Target:  repo.FullName,
				Code:    "access_skipped",
				Message: fmt.Sprintf("unable to read workflow run history: %v", runsErr),
			})
			return res
		}
		res.fatalErr = fmt.Errorf("list workflow runs for %s: %w", repo.FullName, runsErr)
		return res
	}
	res.runs = runs
	return res
}

func buildRotationQueue(exposures []model.SecretExposure, affectedRepos map[string]struct{}, runsByRepo map[string][]github.WorkflowRun) []model.ExposedSecretPriority {
	var queue []model.ExposedSecretPriority

	for _, exp := range exposures {
		var hitRepos []string
		for _, r := range exp.Repos {
			if _, ok := affectedRepos[r]; ok {
				hitRepos = append(hitRepos, r)
			}
		}
		if len(hitRepos) == 0 {
			continue
		}
		sort.Strings(hitRepos)

		var recentWorkflows []string
		recentRuns := 0
		for _, repo := range hitRepos {
			refPaths := make(map[string]struct{})
			for _, ref := range exp.WorkflowRefs {
				if ref.Repo == repo {
					refPaths[ref.Path] = struct{}{}
				}
			}
			for _, run := range runsByRepo[repo] {
				if len(refPaths) == 0 {
					recentRuns++
					if run.Path != "" {
						recentWorkflows = appendUniqueStr(recentWorkflows, repo+":"+run.Path)
					}
					continue
				}
				if _, ok := refPaths[run.Path]; ok {
					recentRuns++
					recentWorkflows = appendUniqueStr(recentWorkflows, repo+":"+run.Path)
				}
			}
		}
		sort.Strings(recentWorkflows)

		score := len(hitRepos) * 25
		if recentRuns > 0 {
			score += 35 + min(recentRuns*5, 25)
		}
		if slices.Contains(exp.Scopes, model.ScopeOrg) {
			score += 20
		}
		for _, flag := range exp.RiskFlags {
			switch flag {
			case model.RiskAWSOverprivileged, model.RiskPullRequestTarget, model.RiskWorkflowRun, model.RiskSecretsInherit:
				score += 15
			case model.RiskUnpinnedAction, model.RiskStaleSecret, model.RiskAWSStaleKey:
				score += 10
			}
		}

		severity := scoreToSeverity(score, recentRuns > 0)
		reason := buildReason(len(hitRepos), recentRuns, exp.Scopes, exp.RiskFlags)

		queue = append(queue, model.ExposedSecretPriority{
			Severity:        severity,
			Score:           score,
			SecretName:      exp.SecretName,
			Scopes:          slices.Clone(exp.Scopes),
			AffectedRepos:   hitRepos,
			RecentRunCount:  recentRuns,
			RecentWorkflows: recentWorkflows,
			RiskFlags:       slices.Clone(exp.RiskFlags),
			Reason:          reason,
		})
	}

	sort.Slice(queue, func(i, j int) bool {
		if queue[i].Score != queue[j].Score {
			return queue[i].Score > queue[j].Score
		}
		if len(queue[i].AffectedRepos) != len(queue[j].AffectedRepos) {
			return len(queue[i].AffectedRepos) > len(queue[j].AffectedRepos)
		}
		return queue[i].SecretName < queue[j].SecretName
	})

	for i := range queue {
		queue[i].Priority = i + 1
	}
	return queue
}

func scoreToSeverity(score int, executedRecently bool) string {
	if score >= 85 || (executedRecently && score >= 65) {
		return "CRITICAL"
	}
	if score >= 50 {
		return "HIGH"
	}
	if score >= 25 {
		return "MEDIUM"
	}
	return "LOW"
}

func buildReason(repoCount, runCount int, scopes []model.SecretScope, flags []model.RiskFlag) string {
	var parts []string
	parts = append(parts, fmt.Sprintf("used in %d affected repo(s)", repoCount))
	if runCount > 0 {
		parts = append(parts, fmt.Sprintf("%d workflow run(s) during incident window", runCount))
	}
	if slices.Contains(scopes, model.ScopeOrg) {
		parts = append(parts, "org-scoped")
	}
	if slices.Contains(flags, model.RiskAWSOverprivileged) {
		parts = append(parts, "overprivileged AWS IAM")
	}
	return strings.Join(parts, "; ")
}

func formatSpecs(specs []lockfile.PackageSpec) []string {
	out := make([]string, 0, len(specs))
	for _, s := range specs {
		if s.Version != "" {
			out = append(out, s.Name+"@"+s.Version)
		} else {
			out = append(out, s.Name)
		}
	}
	return out
}

func (s *Service) isDegradable(err error) bool {
	if github.IsPermissionDenied(err) || github.IsNotFound(err) {
		return true
	}
	return s.allowUnauthenticated && github.IsUnauthorized(err)
}

func appendUniqueStr(dst []string, val string) []string {
	if val == "" || slices.Contains(dst, val) {
		return dst
	}
	return append(dst, val)
}
