package scanner

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/JOsee321/Rotex/internal/github"
	"github.com/JOsee321/Rotex/internal/model"
	"github.com/JOsee321/Rotex/internal/workflow"
)

const (
	defaultConcurrency = 5
	maxConcurrency     = 16
)

// Option configures a Service instance.
type Option func(*Service)

// WithClock overrides the time source used to compute secret ages.
func WithClock(fn func() time.Time) Option {
	return func(s *Service) {
		if fn != nil {
			s.now = fn
		}
	}
}

// WithConcurrency sets the maximum number of concurrent repository workers.
func WithConcurrency(n int) Option {
	return func(s *Service) {
		if n < 1 {
			n = 1
		}
		if n > maxConcurrency {
			n = maxConcurrency
		}
		s.concurrency = n
	}
}

// WithStaleDays sets the age threshold (in days) for flagging stale secrets.
func WithStaleDays(days int) Option {
	return func(s *Service) {
		if days > 0 {
			s.staleDays = days
		}
	}
}

// Service orchestrates read-only secret discovery and workflow exposure mapping.
type Service struct {
	gh          github.Client
	now         func() time.Time
	concurrency int
	staleDays   int
}

// NewService constructs a read-only scanner Service.
func NewService(gh github.Client, opts ...Option) *Service {
	s := &Service{
		gh:          gh,
		now:         func() time.Time { return time.Now().UTC() },
		concurrency: defaultConcurrency,
		staleDays:   model.StaleSecretAgeDays,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}
	return s
}

type repoScanResult struct {
	repo       github.Repository
	secrets    []model.SecretMetadata
	workflows  []*workflow.ParsedWorkflow
	warnings   []model.ScanWarning
	fatalError error
}

// Scan discovers secrets and workflow usages across the requested org or single repository.
func (s *Service) Scan(ctx context.Context, target model.ScanTarget) (*model.ScanReport, error) {
	if s.gh == nil {
		return nil, errors.New("github client must not be nil")
	}
	if err := validateTarget(target); err != nil {
		return nil, err
	}

	now := s.now().UTC()
	report := &model.ScanReport{
		Target:      target,
		GeneratedAt: now,
	}

	var activeRepos []github.Repository
	var orgSecrets []model.SecretMetadata

	if target.Org != "" {
		repos, err := s.gh.ListOrgRepos(ctx, target.Org)
		if err != nil {
			return nil, fmt.Errorf("list repositories for org %s: %w", target.Org, err)
		}
		for _, r := range repos {
			if r.Archived && !target.IncludeArchived {
				report.Summary.ReposSkipped++
				continue
			}
			activeRepos = append(activeRepos, r)
		}

		secrets, err := s.gh.ListOrgSecrets(ctx, target.Org)
		if err != nil {
			if isDegradableError(err) {
				report.Warnings = append(report.Warnings, model.ScanWarning{
					Scope:   string(model.ScopeOrg),
					Target:  target.Org,
					Code:    warningCode(err),
					Message: fmt.Sprintf("unable to read organization secrets: %v", err),
				})
			} else {
				return nil, fmt.Errorf("list org secrets for %s: %w", target.Org, err)
			}
		} else {
			orgSecrets = secrets
		}
	} else {
		owner, name, _ := strings.Cut(target.Repo, "/")
		repo, err := s.gh.GetRepo(ctx, owner, name)
		if err != nil {
			return nil, fmt.Errorf("get repository %s: %w", target.Repo, err)
		}
		if repo.Archived && !target.IncludeArchived {
			report.Summary.ReposSkipped++
			report.Warnings = append(report.Warnings, model.ScanWarning{
				Scope:   string(model.ScopeRepo),
				Target:  repo.FullName,
				Code:    "archived_skipped",
				Message: "archived repository skipped (pass --include-archived to scan)",
			})
		} else {
			activeRepos = append(activeRepos, repo)
		}
	}

	results, err := s.scanReposBounded(ctx, activeRepos)
	if err != nil {
		return nil, err
	}

	s.aggregate(report, orgSecrets, results, now)
	return report, nil
}

func (s *Service) scanReposBounded(ctx context.Context, repos []github.Repository) ([]repoScanResult, error) {
	results := make([]repoScanResult, len(repos))
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
					results[idx] = repoScanResult{repo: repos[idx], fatalError: ctx.Err()}
					continue
				}
				results[idx] = s.scanSingleRepo(ctx, repos[idx])
			}
		}()
	}

dispatchLoop:
	for i := range repos {
		select {
		case <-ctx.Done():
			break dispatchLoop
		case jobs <- i:
		}
	}
	close(jobs)
	wg.Wait()

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for _, res := range results {
		if res.fatalError != nil {
			return nil, res.fatalError
		}
	}
	return results, nil
}

func (s *Service) scanSingleRepo(ctx context.Context, repo github.Repository) repoScanResult {
	res := repoScanResult{repo: repo}

	repoSecrets, err := s.gh.ListRepoSecrets(ctx, repo.Owner, repo.Name)
	if err != nil {
		if isDegradableError(err) {
			res.warnings = append(res.warnings, model.ScanWarning{
				Scope:   string(model.ScopeRepo),
				Target:  repo.FullName,
				Code:    warningCode(err),
				Message: fmt.Sprintf("unable to read repository secrets: %v", err),
			})
		} else {
			res.fatalError = fmt.Errorf("list repo secrets for %s: %w", repo.FullName, err)
			return res
		}
	} else {
		res.secrets = append(res.secrets, repoSecrets...)
	}

	envs, err := s.gh.ListEnvironments(ctx, repo.Owner, repo.Name)
	if err != nil {
		if isDegradableError(err) {
			res.warnings = append(res.warnings, model.ScanWarning{
				Scope:   string(model.ScopeEnvironment),
				Target:  repo.FullName,
				Code:    warningCode(err),
				Message: fmt.Sprintf("unable to list environments: %v", err),
			})
		} else {
			res.fatalError = fmt.Errorf("list environments for %s: %w", repo.FullName, err)
			return res
		}
	} else {
		for _, env := range envs {
			if ctx.Err() != nil {
				res.fatalError = ctx.Err()
				return res
			}
			envSecrets, envErr := s.gh.ListEnvironmentSecrets(ctx, repo.Owner, repo.Name, env.Name)
			if envErr != nil {
				if isDegradableError(envErr) {
					res.warnings = append(res.warnings, model.ScanWarning{
						Scope:   string(model.ScopeEnvironment),
						Target:  repo.FullName + "/" + env.Name,
						Code:    warningCode(envErr),
						Message: fmt.Sprintf("unable to read environment secrets: %v", envErr),
					})
					continue
				}
				res.fatalError = fmt.Errorf("list environment secrets for %s/%s: %w", repo.FullName, env.Name, envErr)
				return res
			}
			res.secrets = append(res.secrets, envSecrets...)
		}
	}

	wfFiles, err := s.gh.ListWorkflowFiles(ctx, repo.Owner, repo.Name, repo.DefaultBranch)
	if err != nil {
		if isDegradableError(err) {
			res.warnings = append(res.warnings, model.ScanWarning{
				Scope:   "workflow",
				Target:  repo.FullName,
				Code:    warningCode(err),
				Message: fmt.Sprintf("unable to read workflow files: %v", err),
			})
		} else {
			res.fatalError = fmt.Errorf("list workflow files for %s: %w", repo.FullName, err)
			return res
		}
	} else {
		for _, wf := range wfFiles {
			parsed, parseErr := workflow.Parse(wf.Path, wf.Content)
			if parseErr != nil {
				res.warnings = append(res.warnings, model.ScanWarning{
					Scope:   "workflow",
					Target:  repo.FullName + ":" + wf.Path,
					Code:    "parse_error",
					Message: parseErr.Error(),
				})
				continue
			}
			res.workflows = append(res.workflows, parsed)
		}
	}

	return res
}

func (s *Service) aggregate(report *model.ScanReport, orgSecrets []model.SecretMetadata, results []repoScanResult, now time.Time) {
	exposures := make(map[string]*model.SecretExposure)
	getOrCreate := func(secretName string) *model.SecretExposure {
		upper := strings.ToUpper(secretName)
		if exp, ok := exposures[upper]; ok {
			return exp
		}
		exp := &model.SecretExposure{SecretName: upper}
		exposures[upper] = exp
		return exp
	}

	orgSecretNames := make([]string, 0, len(orgSecrets))
	for _, meta := range orgSecrets {
		meta.AgeDays = model.ComputeAgeDays(meta.UpdatedAt, now)
		exp := getOrCreate(meta.Name)
		addDefinition(exp, meta)
		orgSecretNames = appendUniqueString(orgSecretNames, strings.ToUpper(meta.Name))
	}

	report.Summary.ReposScanned = len(results)

	for _, res := range results {
		report.Warnings = append(report.Warnings, res.warnings...)
		report.Summary.WorkflowsParsed += len(res.workflows)

		repoDefinedSecrets := make([]string, 0, len(res.secrets))
		for _, meta := range res.secrets {
			meta.AgeDays = model.ComputeAgeDays(meta.UpdatedAt, now)
			exp := getOrCreate(meta.Name)
			addDefinition(exp, meta)
			repoDefinedSecrets = appendUniqueString(repoDefinedSecrets, strings.ToUpper(meta.Name))
		}

		for _, wf := range res.workflows {
			for _, ref := range wf.References {
				exp := getOrCreate(ref.SecretName)
				exp.Repos = appendUniqueString(exp.Repos, res.repo.FullName)
				exp.WorkflowRefs = append(exp.WorkflowRefs, model.WorkflowRef{
					Repo:         res.repo.FullName,
					Path:         wf.Path,
					WorkflowName: wf.Name,
					Triggers:     slices.Clone(wf.Triggers),
					JobID:        ref.JobID,
					StepName:     ref.StepName,
					Location:     ref.Location,
					RiskFlags:    slices.Clone(ref.RiskFlags),
					UnpinnedUses: slices.Clone(ref.UnpinnedUses),
				})
				for _, flag := range ref.RiskFlags {
					exp.RiskFlags = appendUniqueRiskFlag(exp.RiskFlags, flag)
				}
			}

			if len(wf.InheritJobs) > 0 {
				accessible := append(slices.Clone(repoDefinedSecrets), orgSecretNames...)
				for _, secretName := range accessible {
					exp := getOrCreate(secretName)
					exp.Repos = appendUniqueString(exp.Repos, res.repo.FullName)
					for _, job := range wf.InheritJobs {
						exp.WorkflowRefs = append(exp.WorkflowRefs, model.WorkflowRef{
							Repo:         res.repo.FullName,
							Path:         wf.Path,
							WorkflowName: wf.Name,
							Triggers:     slices.Clone(wf.Triggers),
							JobID:        job.JobID,
							Location:     "job.secrets: inherit",
							RiskFlags:    slices.Clone(job.RiskFlags),
							UnpinnedUses: slices.Clone(job.UnpinnedUses),
						})
						for _, flag := range job.RiskFlags {
							exp.RiskFlags = appendUniqueRiskFlag(exp.RiskFlags, flag)
						}
					}
				}
			}
		}
	}

	out := make([]model.SecretExposure, 0, len(exposures))
	for _, exp := range exposures {
		if len(exp.Definitions) > 0 && exp.MaxAgeDays >= s.staleDays {
			exp.RiskFlags = appendUniqueRiskFlag(exp.RiskFlags, model.RiskStaleSecret)
			report.Summary.StaleSecrets++
		}
		if len(exp.Definitions) > 0 && len(exp.WorkflowRefs) == 0 {
			exp.RiskFlags = appendUniqueRiskFlag(exp.RiskFlags, model.RiskUnreferencedSecret)
		}
		if len(exp.Definitions) == 0 && len(exp.WorkflowRefs) > 0 {
			exp.RiskFlags = appendUniqueRiskFlag(exp.RiskFlags, model.RiskUndefinedSecret)
		}

		sortExposureFields(exp)
		if len(exp.RiskFlags) > 0 {
			report.Summary.RiskyExposures++
		}
		out = append(out, *exp)
	}

	sort.Slice(out, func(i, j int) bool {
		if len(out[i].RiskFlags) != len(out[j].RiskFlags) {
			return len(out[i].RiskFlags) > len(out[j].RiskFlags)
		}
		if len(out[i].Repos) != len(out[j].Repos) {
			return len(out[i].Repos) > len(out[j].Repos)
		}
		if out[i].MaxAgeDays != out[j].MaxAgeDays {
			return out[i].MaxAgeDays > out[j].MaxAgeDays
		}
		return out[i].SecretName < out[j].SecretName
	})

	report.Exposures = out
	report.Summary.UniqueSecrets = len(out)
	report.Summary.WarningsCount = len(report.Warnings)
}

func addDefinition(exp *model.SecretExposure, meta model.SecretMetadata) {
	exp.Definitions = append(exp.Definitions, meta)
	if !slices.Contains(exp.Scopes, meta.Scope) {
		exp.Scopes = append(exp.Scopes, meta.Scope)
	}
	if meta.Repo != "" {
		exp.Repos = appendUniqueString(exp.Repos, meta.Repo)
	}
	if meta.Environment != "" {
		exp.Environments = appendUniqueString(exp.Environments, meta.Environment)
	}
	if meta.AgeDays > exp.MaxAgeDays {
		exp.MaxAgeDays = meta.AgeDays
	}
}

func sortExposureFields(exp *model.SecretExposure) {
	sort.Slice(exp.Scopes, func(i, j int) bool { return exp.Scopes[i] < exp.Scopes[j] })
	sort.Strings(exp.Repos)
	sort.Strings(exp.Environments)
	sort.Slice(exp.RiskFlags, func(i, j int) bool { return exp.RiskFlags[i] < exp.RiskFlags[j] })
	sort.Slice(exp.WorkflowRefs, func(i, j int) bool {
		if exp.WorkflowRefs[i].Repo != exp.WorkflowRefs[j].Repo {
			return exp.WorkflowRefs[i].Repo < exp.WorkflowRefs[j].Repo
		}
		if exp.WorkflowRefs[i].Path != exp.WorkflowRefs[j].Path {
			return exp.WorkflowRefs[i].Path < exp.WorkflowRefs[j].Path
		}
		if exp.WorkflowRefs[i].JobID != exp.WorkflowRefs[j].JobID {
			return exp.WorkflowRefs[i].JobID < exp.WorkflowRefs[j].JobID
		}
		return exp.WorkflowRefs[i].Location < exp.WorkflowRefs[j].Location
	})
}

func validateTarget(target model.ScanTarget) error {
	hasOrg := strings.TrimSpace(target.Org) != ""
	hasRepo := strings.TrimSpace(target.Repo) != ""
	if hasOrg == hasRepo {
		return errors.New("specify exactly one of --org or --repo")
	}
	if hasRepo {
		owner, name, ok := strings.Cut(target.Repo, "/")
		if !ok || strings.TrimSpace(owner) == "" || strings.TrimSpace(name) == "" || strings.Contains(name, "/") {
			return fmt.Errorf("invalid --repo %q: expected owner/name format", target.Repo)
		}
	}
	return nil
}

func isDegradableError(err error) bool {
	return github.IsPermissionDenied(err) || github.IsNotFound(err)
}

func warningCode(err error) string {
	var apiErr *github.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.StatusCode {
		case http.StatusForbidden:
			return "permission_denied"
		case http.StatusNotFound:
			return "not_found"
		}
	}
	return "warning"
}

func appendUniqueString(dst []string, val string) []string {
	if val == "" || slices.Contains(dst, val) {
		return dst
	}
	return append(dst, val)
}

func appendUniqueRiskFlag(dst []model.RiskFlag, flag model.RiskFlag) []model.RiskFlag {
	if slices.Contains(dst, flag) {
		return dst
	}
	return append(dst, flag)
}
