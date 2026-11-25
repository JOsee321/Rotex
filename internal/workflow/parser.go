package workflow

import (
	"bytes"
	"fmt"
	pathpkg "path"
	"regexp"
	"slices"
	"strings"

	"github.com/JOsee321/Rotex/internal/model"
	"gopkg.in/yaml.v3"
)

const (
	maxWorkflowBytes = 2 << 20 // 2 MiB
	maxYAMLWalkDepth = 128
	maxAliasHops     = 16
)

var (
	exprBlockRe    = regexp.MustCompile(`(?s)\$\{\{(.*?)\}\}`)
	secretRefRe    = regexp.MustCompile(`(?i)\bsecrets\.([A-Za-z_][A-Za-z0-9_]*)\b`)
	secretBrkRe    = regexp.MustCompile(`(?i)\bsecrets\[['"]([A-Za-z_][A-Za-z0-9_]*)['"]\]`)
	commitSHA1Re   = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)
	commitSHA2Re   = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
	dockerDigestRe = regexp.MustCompile(`@sha256:[0-9a-fA-F]{64}$`)
)

// SecretUsage represents one secret reference found inside a workflow file.
type SecretUsage struct {
	SecretName   string
	JobID        string
	StepName     string
	Location     string
	RiskFlags    []model.RiskFlag
	UnpinnedUses []string
}

// InheritJob represents a reusable workflow call job configured with `secrets: inherit`.
type InheritJob struct {
	JobID        string
	Uses         string
	RiskFlags    []model.RiskFlag
	UnpinnedUses []string
}

// ParsedWorkflow summarizes triggers, secret usages, and security risk flags for a workflow.
type ParsedWorkflow struct {
	Path              string
	Name              string
	Triggers          []string
	WorkflowRiskFlags []model.RiskFlag
	References        []SecretUsage
	InheritJobs       []InheritJob
}

// IsWorkflowFile reports whether path is a top-level YAML workflow under .github/workflows/.
func IsWorkflowFile(p string) bool {
	clean := pathpkg.Clean(strings.ReplaceAll(p, "\\", "/"))
	if pathpkg.Dir(clean) != ".github/workflows" {
		return false
	}
	ext := strings.ToLower(pathpkg.Ext(clean))
	return ext == ".yml" || ext == ".yaml"
}

// Parse extracts secret references, triggers, unpinned actions, and `secrets: inherit`
// usage from a GitHub Actions workflow YAML document.
func Parse(path string, content []byte) (*ParsedWorkflow, error) {
	result := &ParsedWorkflow{Path: path}
	if len(content) > maxWorkflowBytes {
		return nil, fmt.Errorf("parse workflow %s: workflow size %d bytes exceeds %d byte limit", path, len(content), maxWorkflowBytes)
	}
	if len(bytes.TrimSpace(content)) == 0 {
		return result, nil
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(content, &doc); err != nil {
		return nil, fmt.Errorf("parse workflow %s: %w", path, err)
	}
	if doc.Kind == 0 || len(doc.Content) == 0 {
		return result, nil
	}

	root := derefAlias(doc.Content[0])
	if root == nil || root.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("parse workflow %s: expected YAML mapping at root", path)
	}

	result.Name = mappingScalar(root, "name")
	result.Triggers = parseTriggers(mappingValue(root, "on"))
	result.WorkflowRiskFlags = triggerRiskFlags(result.Triggers)

	var workflowLevelRefs []SecretUsage
	if envNode := mappingValue(root, "env"); envNode != nil {
		for _, name := range extractSecretsFromNode(envNode) {
			workflowLevelRefs = append(workflowLevelRefs, SecretUsage{
				SecretName: name,
				Location:   "workflow.env",
			})
		}
	}

	var anyJobUnpinned []string
	var anyJobInherit bool

	if jobsNode := mappingValue(root, "jobs"); jobsNode != nil && jobsNode.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(jobsNode.Content); i += 2 {
			jobID := jobsNode.Content[i].Value
			jobNode := derefAlias(jobsNode.Content[i+1])
			if jobNode == nil || jobNode.Kind != yaml.MappingNode {
				continue
			}

			refs, inheritJob, jobUnpinned := parseJob(jobID, jobNode, result.WorkflowRiskFlags)
			result.References = append(result.References, refs...)
			if inheritJob != nil {
				anyJobInherit = true
				result.InheritJobs = append(result.InheritJobs, *inheritJob)
			}
			anyJobUnpinned = mergeUniqueStrings(anyJobUnpinned, jobUnpinned)
		}
	}

	for i := range workflowLevelRefs {
		flags := slices.Clone(result.WorkflowRiskFlags)
		if len(anyJobUnpinned) > 0 {
			flags = appendUniqueFlag(flags, model.RiskUnpinnedAction)
			workflowLevelRefs[i].UnpinnedUses = slices.Clone(anyJobUnpinned)
		}
		if anyJobInherit {
			flags = appendUniqueFlag(flags, model.RiskSecretsInherit)
		}
		workflowLevelRefs[i].RiskFlags = flags
	}
	result.References = append(workflowLevelRefs, result.References...)

	return result, nil
}

func parseJob(jobID string, jobNode *yaml.Node, workflowFlags []model.RiskFlag) ([]SecretUsage, *InheritJob, []string) {
	var jobRefs []SecretUsage
	var unpinnedUses []string
	var inherit bool

	jobUses := mappingScalar(jobNode, "uses")
	if isUnpinnedActionRef(jobUses) {
		unpinnedUses = append(unpinnedUses, jobUses)
	}

	jobLocations := []struct {
		key string
		loc string
	}{
		{"if", "job.if"},
		{"env", "job.env"},
		{"with", "job.with"},
		{"services", "job.services"},
		{"container", "job.container"},
		{"strategy", "job.strategy"},
	}
	for _, jl := range jobLocations {
		if node := mappingValue(jobNode, jl.key); node != nil {
			var names []string
			if jl.key == "if" {
				names = extractSecretsFromConditionNode(node)
			} else {
				names = extractSecretsFromNode(node)
			}
			for _, name := range names {
				jobRefs = append(jobRefs, SecretUsage{
					SecretName: name,
					JobID:      jobID,
					Location:   jl.loc,
				})
			}
		}
	}

	if secretsNode := mappingValue(jobNode, "secrets"); secretsNode != nil {
		if secretsNode.Kind == yaml.ScalarNode && strings.EqualFold(strings.TrimSpace(secretsNode.Value), "inherit") {
			inherit = true
		} else {
			for _, name := range extractSecretsFromNode(secretsNode) {
				jobRefs = append(jobRefs, SecretUsage{
					SecretName: name,
					JobID:      jobID,
					Location:   "job.secrets",
				})
			}
		}
	}

	if stepsNode := mappingValue(jobNode, "steps"); stepsNode != nil && stepsNode.Kind == yaml.SequenceNode {
		for idx, rawStepNode := range stepsNode.Content {
			stepNode := derefAlias(rawStepNode)
			if stepNode == nil || stepNode.Kind != yaml.MappingNode {
				continue
			}
			stepName := mappingScalar(stepNode, "name")
			if stepName == "" {
				stepName = fmt.Sprintf("step-%d", idx+1)
			}
			if stepUses := mappingScalar(stepNode, "uses"); isUnpinnedActionRef(stepUses) {
				unpinnedUses = mergeUniqueStrings(unpinnedUses, []string{stepUses})
			}

			stepLocations := []struct {
				key string
				loc string
			}{
				{"if", "step.if"},
				{"env", "step.env"},
				{"with", "step.with"},
				{"run", "step.run"},
			}
			for _, sl := range stepLocations {
				if node := mappingValue(stepNode, sl.key); node != nil {
					var names []string
					if sl.key == "if" {
						names = extractSecretsFromConditionNode(node)
					} else {
						names = extractSecretsFromNode(node)
					}
					for _, name := range names {
						jobRefs = append(jobRefs, SecretUsage{
							SecretName: name,
							JobID:      jobID,
							StepName:   stepName,
							Location:   sl.loc,
						})
					}
				}
			}
		}
	}

	jobFlags := slices.Clone(workflowFlags)
	if len(unpinnedUses) > 0 {
		jobFlags = appendUniqueFlag(jobFlags, model.RiskUnpinnedAction)
	}
	if inherit {
		jobFlags = appendUniqueFlag(jobFlags, model.RiskSecretsInherit)
	}

	for i := range jobRefs {
		jobRefs[i].RiskFlags = slices.Clone(jobFlags)
		if len(unpinnedUses) > 0 {
			jobRefs[i].UnpinnedUses = slices.Clone(unpinnedUses)
		}
	}

	var inheritJob *InheritJob
	if inherit {
		inheritJob = &InheritJob{
			JobID:        jobID,
			Uses:         jobUses,
			RiskFlags:    slices.Clone(jobFlags),
			UnpinnedUses: slices.Clone(unpinnedUses),
		}
	}

	return jobRefs, inheritJob, unpinnedUses
}

func parseTriggers(onNode *yaml.Node) []string {
	if onNode == nil {
		return nil
	}
	var triggers []string
	switch onNode.Kind {
	case yaml.ScalarNode:
		if v := strings.TrimSpace(onNode.Value); v != "" {
			triggers = append(triggers, v)
		}
	case yaml.SequenceNode:
		for _, item := range onNode.Content {
			if item.Kind == yaml.ScalarNode {
				if v := strings.TrimSpace(item.Value); v != "" {
					triggers = mergeUniqueStrings(triggers, []string{v})
				}
			}
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(onNode.Content); i += 2 {
			if k := strings.TrimSpace(onNode.Content[i].Value); k != "" {
				triggers = mergeUniqueStrings(triggers, []string{k})
			}
		}
	}
	return triggers
}

func triggerRiskFlags(triggers []string) []model.RiskFlag {
	var flags []model.RiskFlag
	for _, trig := range triggers {
		switch trig {
		case "pull_request_target":
			flags = appendUniqueFlag(flags, model.RiskPullRequestTarget)
		case "workflow_run":
			flags = appendUniqueFlag(flags, model.RiskWorkflowRun)
		}
	}
	return flags
}

// isUnpinnedActionRef reports whether a GitHub Actions `uses:` reference points
// to a mutable branch/tag instead of a full commit SHA.
func isUnpinnedActionRef(uses string) bool {
	uses = strings.TrimSpace(uses)
	if uses == "" || strings.HasPrefix(uses, "./") || strings.HasPrefix(uses, ".\\") {
		return false
	}
	if strings.HasPrefix(uses, "docker://") {
		return !dockerDigestRe.MatchString(uses)
	}
	at := strings.LastIndex(uses, "@")
	if at <= 0 || at == len(uses)-1 {
		return true
	}
	ref := uses[at+1:]
	return !commitSHA1Re.MatchString(ref) && !commitSHA2Re.MatchString(ref)
}

func extractSecretsFromNode(node *yaml.Node) []string {
	return walkSecrets(node, ExtractSecretNames)
}

func extractSecretsFromConditionNode(node *yaml.Node) []string {
	return walkSecrets(node, extractSecretNamesFromExpression)
}

func walkSecrets(node *yaml.Node, extractor func(string) []string) []string {
	if node == nil {
		return nil
	}
	var found []string
	visited := make(map[*yaml.Node]struct{})
	var walk func(n *yaml.Node, depth int)
	walk = func(n *yaml.Node, depth int) {
		if n == nil || depth > maxYAMLWalkDepth {
			return
		}
		if _, seen := visited[n]; seen {
			return
		}
		visited[n] = struct{}{}

		switch n.Kind {
		case yaml.ScalarNode:
			for _, name := range extractor(n.Value) {
				found = mergeUniqueStrings(found, []string{name})
			}
		case yaml.SequenceNode:
			for _, child := range n.Content {
				walk(child, depth+1)
			}
		case yaml.MappingNode:
			for i := 0; i+1 < len(n.Content); i += 2 {
				walk(n.Content[i+1], depth+1)
			}
		case yaml.AliasNode:
			if n.Alias != nil {
				walk(n.Alias, depth+1)
			}
		}
	}
	walk(node, 0)
	return found
}

// ExtractSecretNames returns normalized uppercase secret names referenced via
// `${{ secrets.NAME }}` or `${{ secrets['NAME'] }}` expressions in text, excluding GITHUB_TOKEN.
func ExtractSecretNames(text string) []string {
	var names []string
	blocks := exprBlockRe.FindAllStringSubmatch(text, -1)
	for _, block := range blocks {
		if len(block) < 2 {
			continue
		}
		names = mergeUniqueStrings(names, extractSecretNamesFromExpression(block[1]))
	}
	return names
}

// extractSecretNamesFromExpression matches secrets references directly inside an expression
// (used for `if:` conditions, which GitHub Actions evaluates even without `${{ ... }}`).
func extractSecretNamesFromExpression(expr string) []string {
	var names []string
	for _, re := range []*regexp.Regexp{secretRefRe, secretBrkRe} {
		for _, m := range re.FindAllStringSubmatch(expr, -1) {
			if len(m) < 2 {
				continue
			}
			upper := strings.ToUpper(m[1])
			// GITHUB_TOKEN is ephemeral and provisioned automatically per workflow run.
			if upper == "GITHUB_TOKEN" {
				continue
			}
			names = mergeUniqueStrings(names, []string{upper})
		}
	}
	return names
}

func derefAlias(n *yaml.Node) *yaml.Node {
	for hop := 0; n != nil && n.Kind == yaml.AliasNode && hop < maxAliasHops; hop++ {
		n = n.Alias
	}
	if n != nil && n.Kind == yaml.AliasNode {
		return nil
	}
	return n
}

func mappingValue(m *yaml.Node, key string) *yaml.Node {
	m = derefAlias(m)
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return derefAlias(m.Content[i+1])
		}
	}
	return nil
}

func mappingScalar(m *yaml.Node, key string) string {
	val := mappingValue(m, key)
	if val != nil && val.Kind == yaml.ScalarNode {
		return strings.TrimSpace(val.Value)
	}
	return ""
}

func appendUniqueFlag(flags []model.RiskFlag, flag model.RiskFlag) []model.RiskFlag {
	if slices.Contains(flags, flag) {
		return flags
	}
	return append(flags, flag)
}

func mergeUniqueStrings(dst, src []string) []string {
	for _, s := range src {
		if !slices.Contains(dst, s) {
			dst = append(dst, s)
		}
	}
	return dst
}
