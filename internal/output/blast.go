package output

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/JOsee321/Rotex/internal/model"
)

// RenderBlast writes an incident BlastReport to w in the requested format.
func RenderBlast(w io.Writer, report *model.BlastReport, opts Options) error {
	if report == nil {
		return fmt.Errorf("blast report must not be nil")
	}

	switch opts.Format {
	case "", FormatTable:
		return renderBlastTable(w, report, opts.NoColor)
	case FormatJSON:
		return renderJSON(w, report)
	case FormatMarkdown:
		return renderBlastMarkdown(w, report)
	default:
		return fmt.Errorf("unsupported output format %q", opts.Format)
	}
}

func renderBlastTable(w io.Writer, report *model.BlastReport, noColor bool) error {
	if _, err := fmt.Fprintf(w, "Rotex Incident Blast Radius (%s)\n", formatTarget(report.Target)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "Packages: %s | Window: %dh | Affected Lockfiles: %d | Secrets to Rotate: %d\n\n",
		strings.Join(report.Packages, ", "),
		report.SinceHours,
		len(report.Matches),
		len(report.RotationQueue),
	); err != nil {
		return err
	}

	if len(report.Matches) > 0 {
		if _, err := fmt.Fprintln(w, "Affected Dependencies:"); err != nil {
			return err
		}
		tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
		if _, err := fmt.Fprintln(tw, "REPO\tECOSYSTEM\tPACKAGE\tVERSION\tLOCKFILE"); err != nil {
			return err
		}
		for _, m := range report.Matches {
			if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
				sanitizeText(m.Repo), sanitizeText(m.Ecosystem), sanitizeText(m.Package), sanitizeText(m.Version), sanitizeText(m.Lockfile)); err != nil {
				return err
			}
		}
		if err := tw.Flush(); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(w); err != nil {
			return err
		}
	}

	if len(report.RotationQueue) == 0 {
		if _, err := fmt.Fprintln(w, "No exposed secrets matched the affected repositories."); err != nil {
			return err
		}
	} else {
		if _, err := fmt.Fprintln(w, "Prioritized Rotation Queue:"); err != nil {
			return err
		}
		tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
		if _, err := fmt.Fprintln(tw, "PRIORITY\tSEVERITY\tSECRET NAME\tAFFECTED REPOS\tRECENT RUNS\tREASON"); err != nil {
			return err
		}
		for _, item := range report.RotationQueue {
			sev := item.Severity
			if !noColor {
				sev = colorizeSeverity(sev)
			}
			if _, err := fmt.Fprintf(tw, "#%d\t%s\t%s\t%s\t%d\t%s\n",
				item.Priority,
				sev,
				sanitizeText(item.SecretName),
				sanitizeText(formatRepos(item.AffectedRepos)),
				item.RecentRunCount,
				sanitizeText(item.Reason),
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
			if _, err := fmt.Fprintf(w, "- [%s] %s (%s): %s\n",
				sanitizeText(warn.Code), sanitizeText(warn.Target), sanitizeText(warn.Scope), sanitizeText(warn.Message)); err != nil {
				return err
			}
		}
	}
	return nil
}

func renderBlastMarkdown(w io.Writer, report *model.BlastReport) error {
	if _, err := fmt.Fprintf(w, "## Rotex Incident Blast Radius (`%s`)\n\n", formatTarget(report.Target)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "- **Target packages:** `%s`\n- **Incident window:** %dh\n- **Affected lockfiles:** %d\n- **Secrets to rotate:** %d\n\n",
		escapeMD(strings.Join(report.Packages, ", ")),
		report.SinceHours,
		len(report.Matches),
		len(report.RotationQueue),
	); err != nil {
		return err
	}

	if len(report.RotationQueue) == 0 {
		_, err := fmt.Fprintln(w, "_No exposed secrets matched the affected repositories._")
		return err
	}

	if _, err := fmt.Fprintln(w, "| Priority | Severity | Secret | Affected Repos | Recent Runs | Reason |"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "| ---: | :--- | :--- | :--- | ---: | :--- |"); err != nil {
		return err
	}
	for _, item := range report.RotationQueue {
		if _, err := fmt.Fprintf(w, "| #%d | **%s** | `%s` | %s | %d | %s |\n",
			item.Priority,
			item.Severity,
			escapeMD(item.SecretName),
			escapeMD(formatRepos(item.AffectedRepos)),
			item.RecentRunCount,
			escapeMD(item.Reason),
		); err != nil {
			return err
		}
	}
	return nil
}

func colorizeSeverity(sev string) string {
	switch sev {
	case "CRITICAL":
		return "\033[31m" + sev + "\033[0m"
	case "HIGH":
		return "\033[33m" + sev + "\033[0m"
	default:
		return sev
	}
}
