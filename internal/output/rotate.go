package output

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/JOsee321/Rotex/internal/rotate"
)

// RenderRotationPlan formats a dry-run ExecutionPlan in table, json, or markdown format.
func RenderRotationPlan(w io.Writer, plan *rotate.ExecutionPlan, opts Options) error {
	if plan == nil {
		return fmt.Errorf("execution plan must not be nil")
	}
	switch opts.Format {
	case "", FormatTable:
		return renderPlanTable(w, plan)
	case FormatJSON:
		return renderJSON(w, plan)
	case FormatMarkdown:
		return renderPlanMarkdown(w, plan)
	default:
		return fmt.Errorf("unsupported output format %q", opts.Format)
	}
}

// RenderRunState formats a rotation RunState in table, json, or markdown format.
func RenderRunState(w io.Writer, state *rotate.RunState, opts Options) error {
	if state == nil {
		return fmt.Errorf("run state must not be nil")
	}
	switch opts.Format {
	case "", FormatTable:
		return renderStateTable(w, state)
	case FormatJSON:
		return renderJSON(w, state)
	case FormatMarkdown:
		return renderStateMarkdown(w, state)
	default:
		return fmt.Errorf("unsupported output format %q", opts.Format)
	}
}

func renderPlanTable(w io.Writer, plan *rotate.ExecutionPlan) error {
	oldKey := plan.Target.OldKeyID
	if oldKey == "" {
		oldKey = "(none)"
	}
	if _, err := fmt.Fprintf(w, "Rotex Rotation Plan [DRY-RUN] (%s)\n", plan.Provider); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "IAM User: %s | Existing Keys: %d/2 | Old Key: %s | Secrets: %s | Immediate Delete: %t\n\n",
		plan.Target.IAMUser,
		plan.Preflight.ExistingKeyCount,
		oldKey,
		strings.Join(plan.SecretNames, ", "),
		plan.ImmediateDelete,
	); err != nil {
		return err
	}

	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "STEP\tTARGET\tACTION"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(tw, "1. PREFLIGHT\t%s\tVerify AWS 2-key quota and GitHub public keys\n", plan.Target.IAMUser); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(tw, "2. MINT\t%s\tCreate dual AWS IAM access key in memory\n", plan.Target.IAMUser); err != nil {
		return err
	}
	for _, sc := range plan.StoreTargets {
		if _, err := fmt.Fprintf(tw, "3. INJECT\t%s\tEncrypt with SealedBox and update %s\n", sc.Label(), strings.Join(plan.SecretNames, ", ")); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(tw, "4. VERIFY\t%s\tVerify new key via sts:GetCallerIdentity\n", plan.Target.IAMUser); err != nil {
		return err
	}
	action := "Deactivate old key (24h grace window)"
	if plan.ImmediateDelete {
		action = "Deactivate and permanently delete old key"
	}
	if _, err := fmt.Fprintf(tw, "5. FINALIZE\t%s\t%s\n", oldKey, action); err != nil {
		return err
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	for _, warn := range plan.Warnings {
		if _, err := fmt.Fprintf(w, "\nWarning: %s\n", warn); err != nil {
			return err
		}
	}
	return nil
}

func renderPlanMarkdown(w io.Writer, plan *rotate.ExecutionPlan) error {
	if _, err := fmt.Fprintf(w, "## Rotex Rotation Plan (Dry-Run)\n\n- **Provider:** `%s`\n- **IAM User:** `%s`\n- **Old Key ID:** `%s`\n- **Secrets:** `%s`\n\n",
		plan.Provider, plan.Target.IAMUser, plan.Target.OldKeyID, strings.Join(plan.SecretNames, ", ")); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "| Scope | Target |"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "| :--- | :--- |"); err != nil {
		return err
	}
	for _, sc := range plan.StoreTargets {
		if _, err := fmt.Fprintf(w, "| `%s` | `%s` |\n", sc.Scope, sc.Label()); err != nil {
			return err
		}
	}
	return nil
}

func renderStateTable(w io.Writer, state *rotate.RunState) error {
	if _, err := fmt.Fprintf(w, "Rotex Rotation Run (%s)\n", state.RunID); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "Stage: %s | IAM User: %s | Old Key: %s | New Key: %s | Old Deactivated: %t | Old Deleted: %t | New Deleted: %t\n\n",
		state.Stage, state.Target.IAMUser, state.OldKeyID, state.NewKeyID, state.OldDeactivated, state.OldDeleted, state.NewDeleted,
	); err != nil {
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "SCOPE\tTARGET\tSTATUS\tERROR"); err != nil {
		return err
	}
	for _, t := range state.Targets {
		errMsg := t.Error
		if errMsg == "" {
			errMsg = "-"
		}
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", t.Target.Scope, t.Target.Label(), t.Status, errMsg); err != nil {
			return err
		}
	}
	return tw.Flush()
}

func renderStateMarkdown(w io.Writer, state *rotate.RunState) error {
	if _, err := fmt.Fprintf(w, "## Rotex Rotation Run `%s`\n\n- **Stage:** `%s`\n- **IAM User:** `%s`\n- **Old Key:** `%s`\n- **New Key:** `%s`\n\n",
		state.RunID, state.Stage, state.Target.IAMUser, state.OldKeyID, state.NewKeyID); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "| Scope | Target | Status |"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "| :--- | :--- | :--- |"); err != nil {
		return err
	}
	for _, t := range state.Targets {
		if _, err := fmt.Fprintf(w, "| `%s` | `%s` | `%s` |\n", t.Target.Scope, t.Target.Label(), t.Status); err != nil {
			return err
		}
	}
	return nil
}
