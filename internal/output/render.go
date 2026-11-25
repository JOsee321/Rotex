package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/JOsee321/Rotex/internal/model"
)

// Format identifies a supported report output format.
type Format string

const (
	FormatTable    Format = "table"
	FormatJSON     Format = "json"
	FormatMarkdown Format = "markdown"
)

// Options controls report rendering.
type Options struct {
	Format  Format
	NoColor bool
}

// ParseFormat validates and normalizes a report output format string.
func ParseFormat(raw string) (Format, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", string(FormatTable):
		return FormatTable, nil
	case string(FormatJSON):
		return FormatJSON, nil
	case string(FormatMarkdown):
		return FormatMarkdown, nil
	default:
		return "", fmt.Errorf("unsupported output format %q (expected table, json, or markdown)", raw)
	}
}

// Render writes report to w in the requested format.
func Render(w io.Writer, report *model.ScanReport, opts Options) error {
	if report == nil {
		return fmt.Errorf("report must not be nil")
	}

	switch opts.Format {
	case "", FormatTable:
		return renderTable(w, report, opts.NoColor)
	case FormatJSON:
		return renderJSON(w, report)
	case FormatMarkdown:
		return renderMarkdown(w, report)
	default:
		return fmt.Errorf("unsupported output format %q", opts.Format)
	}
}

func renderJSON(w io.Writer, report *model.ScanReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

func renderTable(w io.Writer, report *model.ScanReport, noColor bool) error {
	targetLabel := formatTarget(report.Target)
	if _, err := fmt.Fprintf(w, "Rotex Exposure Scan (%s)\n", targetLabel); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "Repos scanned: %d | Skipped: %d | Workflows parsed: %d | Unique secrets: %d | Risky: %d | Warnings: %d\n\n",
		report.Summary.ReposScanned,
		report.Summary.ReposSkipped,
		report.Summary.WorkflowsParsed,
		report.Summary.UniqueSecrets,
		report.Summary.RiskyExposures,
		report.Summary.WarningsCount,
	); err != nil {
		return err
	}

	if len(report.Exposures) == 0 {
		if _, err := fmt.Fprintln(w, "No secrets or workflow secret references found."); err != nil {
			return err
		}
	} else {
		tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
		if _, err := fmt.Fprintln(tw, "SECRET NAME\tSCOPES\tREPOS\tWORKFLOWS\tAGE (DAYS)\tRISK FLAGS"); err != nil {
			return err
		}
		for _, exp := range report.Exposures {
			flags := formatRiskFlags(exp.RiskFlags)
			if !noColor && len(exp.RiskFlags) > 0 {
				flags = colorizeRisk(flags, exp.RiskFlags)
			}
			if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\t%s\n",
				exp.SecretName,
				formatScopes(exp.Scopes),
				formatRepos(exp.Repos),
				uniqueWorkflowCount(exp.WorkflowRefs),
				formatAge(exp),
				flags,
			); err != nil {
				return err
			}
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}

	if len(report.Warnings) > 0 {
		if _, err := fmt.Fprintln(w, "\nWarnings:"); err != nil {
			return err
		}
		for _, warn := range report.Warnings {
			if _, err := fmt.Fprintf(w, "- [%s] %s (%s): %s\n", warn.Code, warn.Target, warn.Scope, warn.Message); err != nil {
				return err
			}
		}
	}
	return nil
}

func renderMarkdown(w io.Writer, report *model.ScanReport) error {
	if _, err := fmt.Fprintf(w, "## Rotex Exposure Scan (`%s`)\n\n", formatTarget(report.Target)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "- **Repos scanned:** %d (skipped: %d)\n- **Workflows parsed:** %d\n- **Unique secrets:** %d (stale: %d, risky: %d)\n- **Warnings:** %d\n\n",
		report.Summary.ReposScanned,
		report.Summary.ReposSkipped,
		report.Summary.WorkflowsParsed,
		report.Summary.UniqueSecrets,
		report.Summary.StaleSecrets,
		report.Summary.RiskyExposures,
		report.Summary.WarningsCount,
	); err != nil {
		return err
	}

	if len(report.Exposures) == 0 {
		if _, err := fmt.Fprintln(w, "_No secrets or workflow secret references found._"); err != nil {
			return err
		}
	} else {
		if _, err := fmt.Fprintln(w, "| Secret | Scopes | Repos | Workflows | Max Age (Days) | Risk Flags |"); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(w, "| :--- | :--- | :--- | ---: | ---: | :--- |"); err != nil {
			return err
		}
		for _, exp := range report.Exposures {
			if _, err := fmt.Fprintf(w, "| `%s` | %s | %s | %d | %s | %s |\n",
				escapeMD(exp.SecretName),
				escapeMD(formatScopes(exp.Scopes)),
				escapeMD(formatRepos(exp.Repos)),
				uniqueWorkflowCount(exp.WorkflowRefs),
				formatAge(exp),
				escapeMD(formatRiskFlags(exp.RiskFlags)),
			); err != nil {
				return err
			}
		}
	}

	if len(report.Warnings) > 0 {
		if _, err := fmt.Fprintln(w, "\n### Warnings"); err != nil {
			return err
		}
		for _, warn := range report.Warnings {
			if _, err := fmt.Fprintf(w, "- `%s` (`%s` / `%s`): %s\n", warn.Code, warn.Scope, warn.Target, warn.Message); err != nil {
				return err
			}
		}
	}
	return nil
}

func formatTarget(t model.ScanTarget) string {
	if t.Org != "" {
		return "org:" + t.Org
	}
	return "repo:" + t.Repo
}

func formatScopes(scopes []model.SecretScope) string {
	if len(scopes) == 0 {
		return "-"
	}
	parts := make([]string, len(scopes))
	for i, s := range scopes {
		parts[i] = string(s)
	}
	return strings.Join(parts, ",")
}

func formatRepos(repos []string) string {
	if len(repos) == 0 {
		return "-"
	}
	if len(repos) <= 2 {
		return strings.Join(repos, ", ")
	}
	return fmt.Sprintf("%s, %s (+%d)", repos[0], repos[1], len(repos)-2)
}

func uniqueWorkflowCount(refs []model.WorkflowRef) int {
	if len(refs) == 0 {
		return 0
	}
	seen := make(map[string]struct{}, len(refs))
	for _, r := range refs {
		seen[r.Repo+":"+r.Path] = struct{}{}
	}
	return len(seen)
}

func formatAge(exp model.SecretExposure) string {
	if len(exp.Definitions) == 0 {
		return "-"
	}
	return strconv.Itoa(exp.MaxAgeDays)
}

func formatRiskFlags(flags []model.RiskFlag) string {
	if len(flags) == 0 {
		return "none"
	}
	parts := make([]string, len(flags))
	for i, f := range flags {
		parts[i] = string(f)
	}
	return strings.Join(parts, ",")
}

func colorizeRisk(text string, flags []model.RiskFlag) string {
	for _, f := range flags {
		if f == model.RiskPullRequestTarget || f == model.RiskWorkflowRun || f == model.RiskSecretsInherit {
			return "\033[31m" + text + "\033[0m"
		}
	}
	return "\033[33m" + text + "\033[0m"
}

func escapeMD(s string) string {
	return strings.ReplaceAll(s, "|", `\|`)
}
