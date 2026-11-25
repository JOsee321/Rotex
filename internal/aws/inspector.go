package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/smithy-go"
)

const (
	defaultStaleKeyDays  = 90
	defaultZombieKeyDays = 30
	maxCloudTrailPages   = 5
)

// IAMReadClient captures the read-only IAM operations required for security auditing.
type IAMReadClient interface {
	ListUsers(ctx context.Context, params *iam.ListUsersInput, optFns ...func(*iam.Options)) (*iam.ListUsersOutput, error)
	ListAccessKeys(ctx context.Context, params *iam.ListAccessKeysInput, optFns ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error)
	GetAccessKeyLastUsed(ctx context.Context, params *iam.GetAccessKeyLastUsedInput, optFns ...func(*iam.Options)) (*iam.GetAccessKeyLastUsedOutput, error)
	ListAttachedUserPolicies(ctx context.Context, params *iam.ListAttachedUserPoliciesInput, optFns ...func(*iam.Options)) (*iam.ListAttachedUserPoliciesOutput, error)
	ListUserPolicies(ctx context.Context, params *iam.ListUserPoliciesInput, optFns ...func(*iam.Options)) (*iam.ListUserPoliciesOutput, error)
	GetUserPolicy(ctx context.Context, params *iam.GetUserPolicyInput, optFns ...func(*iam.Options)) (*iam.GetUserPolicyOutput, error)
}

// CloudTrailReadClient captures read-only CloudTrail event lookup operations.
type CloudTrailReadClient interface {
	LookupEvents(ctx context.Context, params *cloudtrail.LookupEventsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error)
}

// Inspector performs read-only AWS IAM and CloudTrail auditing.
type Inspector interface {
	Inspect(ctx context.Context, lookback time.Duration) (*AuditReport, error)
}

// AccessKeyAudit holds read-only hygiene, privilege, and usage findings for one IAM access key.
type AccessKeyAudit struct {
	UserName               string
	AccessKeyID            string
	Status                 string
	CreatedAt              time.Time
	AgeDays                int
	LastUsedAt             *time.Time
	LastUsedService        string
	Stale                  bool
	Zombie                 bool
	Overprivileged         bool
	OverprivilegedPolicies []string
	GitHubRunnerSeen       bool
	ExternalUsageSeen      bool
	ExternalSources        []string
}

// AuditReport aggregates AWS IAM access key audits and any non-fatal permission warnings.
type AuditReport struct {
	Keys     []AccessKeyAudit
	Warnings []string
}

// InspectorOption configures an SDKInspector.
type InspectorOption func(*SDKInspector)

// WithClock overrides the clock used by SDKInspector.
func WithClock(fn func() time.Time) InspectorOption {
	return func(s *SDKInspector) {
		if fn != nil {
			s.now = fn
		}
	}
}

// SDKInspector implements Inspector using AWS IAM and CloudTrail clients.
type SDKInspector struct {
	iam        IAMReadClient
	cloudtrail CloudTrailReadClient
	now        func() time.Time
}

// NewSDKInspector constructs an Inspector backed by explicit IAM and CloudTrail clients.
func NewSDKInspector(iamClient IAMReadClient, ctClient CloudTrailReadClient, opts ...InspectorOption) *SDKInspector {
	s := &SDKInspector{
		iam:        iamClient,
		cloudtrail: ctClient,
		now:        func() time.Time { return time.Now().UTC() },
	}
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}
	return s
}

// NewDefaultInspector loads standard AWS SDK credentials (~/.aws/credentials or env vars)
// and returns a read-only SDKInspector.
func NewDefaultInspector(ctx context.Context, optFns ...func(*config.LoadOptions) error) (*SDKInspector, error) {
	cfg, err := config.LoadDefaultConfig(ctx, optFns...)
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}
	return NewSDKInspector(iam.NewFromConfig(cfg), cloudtrail.NewFromConfig(cfg)), nil
}

// Inspect audits all IAM user access keys and correlates recent CloudTrail activity.
func (s *SDKInspector) Inspect(ctx context.Context, lookback time.Duration) (*AuditReport, error) {
	if s.iam == nil {
		return nil, errors.New("AWS IAM client must not be nil")
	}
	if lookback <= 0 {
		lookback = 7 * 24 * time.Hour
	}

	now := s.now().UTC()
	report := &AuditReport{}

	users, err := s.listAllUsers(ctx)
	if err != nil {
		return nil, err
	}

	keyIndex := make(map[string]int)

	for _, user := range users {
		userName := awssdk.ToString(user.UserName)
		if userName == "" {
			continue
		}

		overprivPolicies, policyWarns, err := s.inspectUserPrivileges(ctx, userName)
		if err != nil {
			return nil, err
		}
		report.Warnings = append(report.Warnings, policyWarns...)

		keys, keyWarns, err := s.listUserKeys(ctx, userName)
		if err != nil {
			return nil, err
		}
		report.Warnings = append(report.Warnings, keyWarns...)

		for _, k := range keys {
			keyID := awssdk.ToString(k.AccessKeyId)
			createdAt := awssdk.ToTime(k.CreateDate).UTC()
			status := string(k.Status)
			ageDays := daysBetween(createdAt, now)

			audit := AccessKeyAudit{
				UserName:               userName,
				AccessKeyID:            keyID,
				Status:                 status,
				CreatedAt:              createdAt,
				AgeDays:                ageDays,
				Overprivileged:         len(overprivPolicies) > 0,
				OverprivilegedPolicies: slices.Clone(overprivPolicies),
			}

			lastUsedOut, lastErr := s.iam.GetAccessKeyLastUsed(ctx, &iam.GetAccessKeyLastUsedInput{
				AccessKeyId: k.AccessKeyId,
			})
			if lastErr != nil {
				if IsAccessDenied(lastErr) {
					report.Warnings = append(report.Warnings,
						fmt.Sprintf("AWS iam:GetAccessKeyLastUsed denied for key %s (%s)", keyID, userName))
				} else {
					return nil, fmt.Errorf("get access key last used for %s: %w", keyID, lastErr)
				}
			} else if lastUsedOut != nil && lastUsedOut.AccessKeyLastUsed != nil {
				if lastUsedOut.AccessKeyLastUsed.LastUsedDate != nil {
					t := lastUsedOut.AccessKeyLastUsed.LastUsedDate.UTC()
					audit.LastUsedAt = &t
				}
				audit.LastUsedService = awssdk.ToString(lastUsedOut.AccessKeyLastUsed.ServiceName)
			}

			if status == string(iamtypes.StatusTypeActive) {
				if ageDays > defaultStaleKeyDays {
					audit.Stale = true
				}
				if audit.LastUsedAt != nil {
					if daysBetween(*audit.LastUsedAt, now) > defaultZombieKeyDays {
						audit.Zombie = true
					}
				} else if ageDays > defaultZombieKeyDays {
					audit.Zombie = true
				}
			}

			keyIndex[keyID] = len(report.Keys)
			report.Keys = append(report.Keys, audit)
		}
	}

	if s.cloudtrail != nil && len(report.Keys) > 0 {
		s.correlateCloudTrail(ctx, report, keyIndex, now, lookback)
	}

	return report, nil
}

func (s *SDKInspector) listAllUsers(ctx context.Context) ([]iamtypes.User, error) {
	var users []iamtypes.User
	var marker *string
	for {
		out, err := s.iam.ListUsers(ctx, &iam.ListUsersInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("list IAM users: %w", err)
		}
		users = append(users, out.Users...)
		if !out.IsTruncated || out.Marker == nil {
			break
		}
		marker = out.Marker
	}
	return users, nil
}

func (s *SDKInspector) listUserKeys(ctx context.Context, userName string) ([]iamtypes.AccessKeyMetadata, []string, error) {
	var keys []iamtypes.AccessKeyMetadata
	var marker *string
	for {
		out, err := s.iam.ListAccessKeys(ctx, &iam.ListAccessKeysInput{
			UserName: awssdk.String(userName),
			Marker:   marker,
		})
		if err != nil {
			if IsAccessDenied(err) {
				return nil, []string{fmt.Sprintf("AWS iam:ListAccessKeys denied for user %s", userName)}, nil
			}
			return nil, nil, fmt.Errorf("list access keys for %s: %w", userName, err)
		}
		keys = append(keys, out.AccessKeyMetadata...)
		if !out.IsTruncated || out.Marker == nil {
			break
		}
		marker = out.Marker
	}
	return keys, nil, nil
}

func (s *SDKInspector) inspectUserPrivileges(ctx context.Context, userName string) ([]string, []string, error) {
	var flagged []string
	var warnings []string

	var attachedMarker *string
	for {
		attached, err := s.iam.ListAttachedUserPolicies(ctx, &iam.ListAttachedUserPoliciesInput{
			UserName: awssdk.String(userName),
			Marker:   attachedMarker,
		})
		if err != nil {
			if IsAccessDenied(err) {
				warnings = append(warnings, fmt.Sprintf("AWS iam:ListAttachedUserPolicies denied for user %s", userName))
				break
			}
			return nil, nil, fmt.Errorf("list attached policies for %s: %w", userName, err)
		}
		for _, p := range attached.AttachedPolicies {
			name := awssdk.ToString(p.PolicyName)
			arn := awssdk.ToString(p.PolicyArn)
			if isHighRiskManagedPolicy(name, arn) {
				flagged = appendUnique(flagged, name)
			}
		}
		if !attached.IsTruncated || attached.Marker == nil {
			break
		}
		attachedMarker = attached.Marker
	}

	var inlineNames []string
	var inlineMarker *string
	for {
		inlineOut, err := s.iam.ListUserPolicies(ctx, &iam.ListUserPoliciesInput{
			UserName: awssdk.String(userName),
			Marker:   inlineMarker,
		})
		if err != nil {
			if IsAccessDenied(err) {
				warnings = append(warnings, fmt.Sprintf("AWS iam:ListUserPolicies denied for user %s", userName))
				return flagged, warnings, nil
			}
			return nil, nil, fmt.Errorf("list inline policies for %s: %w", userName, err)
		}
		inlineNames = append(inlineNames, inlineOut.PolicyNames...)
		if !inlineOut.IsTruncated || inlineOut.Marker == nil {
			break
		}
		inlineMarker = inlineOut.Marker
	}

	for _, policyName := range inlineNames {
		docOut, docErr := s.iam.GetUserPolicy(ctx, &iam.GetUserPolicyInput{
			UserName:   awssdk.String(userName),
			PolicyName: awssdk.String(policyName),
		})
		if docErr != nil {
			if IsAccessDenied(docErr) {
				warnings = append(warnings, fmt.Sprintf("AWS iam:GetUserPolicy denied for %s/%s", userName, policyName))
				continue
			}
			return nil, nil, fmt.Errorf("get inline policy %s for %s: %w", policyName, userName, docErr)
		}
		if isWildcardInlinePolicy(awssdk.ToString(docOut.PolicyDocument)) {
			flagged = appendUnique(flagged, "inline:"+policyName)
		}
	}

	return flagged, warnings, nil
}

func (s *SDKInspector) correlateCloudTrail(ctx context.Context, report *AuditReport, keyIndex map[string]int, now time.Time, lookback time.Duration) {
	startTime := now.Add(-lookback)
	var nextToken *string

	for page := 0; page < maxCloudTrailPages; page++ {
		out, err := s.cloudtrail.LookupEvents(ctx, &cloudtrail.LookupEventsInput{
			StartTime: awssdk.Time(startTime),
			EndTime:   awssdk.Time(now),
			NextToken: nextToken,
		})
		if err != nil {
			if IsAccessDenied(err) {
				report.Warnings = append(report.Warnings, "AWS cloudtrail:LookupEvents denied; runner correlation skipped")
			} else {
				report.Warnings = append(report.Warnings, fmt.Sprintf("AWS cloudtrail:LookupEvents failed: %v", err))
			}
			return
		}

		for _, ev := range out.Events {
			raw := awssdk.ToString(ev.CloudTrailEvent)
			if raw == "" {
				continue
			}
			var parsed struct {
				UserAgent       string `json:"userAgent"`
				SourceIPAddress string `json:"sourceIPAddress"`
				UserIdentity    struct {
					AccessKeyID string `json:"accessKeyId"`
				} `json:"userIdentity"`
			}
			if json.Unmarshal([]byte(raw), &parsed) != nil {
				continue
			}
			idx, ok := keyIndex[parsed.UserIdentity.AccessKeyID]
			if !ok {
				continue
			}
			if isGitHubActionsUserAgent(parsed.UserAgent) {
				report.Keys[idx].GitHubRunnerSeen = true
			} else if isExternalInvocation(parsed.UserAgent, parsed.SourceIPAddress) {
				report.Keys[idx].ExternalUsageSeen = true
				src := formatExternalSource(parsed.UserAgent, parsed.SourceIPAddress)
				report.Keys[idx].ExternalSources = appendUnique(report.Keys[idx].ExternalSources, src)
			}
		}

		if out.NextToken == nil || *out.NextToken == "" {
			return
		}
		nextToken = out.NextToken
	}
}

func isHighRiskManagedPolicy(name, arn string) bool {
	lowerName := strings.ToLower(name)
	lowerARN := strings.ToLower(arn)
	switch lowerName {
	case "administratoraccess", "iamfullaccess", "poweruseraccess":
		return true
	}
	return strings.HasSuffix(lowerARN, "/administratoraccess") || strings.HasSuffix(lowerARN, "/iamfullaccess")
}

func isWildcardInlinePolicy(encodedDoc string) bool {
	if encodedDoc == "" {
		return false
	}
	decoded, err := url.QueryUnescape(encodedDoc)
	if err != nil {
		decoded = encodedDoc
	}

	var doc struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if json.Unmarshal([]byte(decoded), &doc) != nil || len(doc.Statement) == 0 {
		return false
	}

	var statements []struct {
		Effect   string          `json:"Effect"`
		Action   json.RawMessage `json:"Action"`
		Resource json.RawMessage `json:"Resource"`
	}
	if doc.Statement[0] == '[' {
		if json.Unmarshal(doc.Statement, &statements) != nil {
			return false
		}
	} else {
		var single struct {
			Effect   string          `json:"Effect"`
			Action   json.RawMessage `json:"Action"`
			Resource json.RawMessage `json:"Resource"`
		}
		if json.Unmarshal(doc.Statement, &single) != nil {
			return false
		}
		statements = append(statements, single)
	}

	for _, st := range statements {
		if !strings.EqualFold(st.Effect, "Allow") {
			continue
		}
		actions := parseStringOrSlice(st.Action)
		resources := parseStringOrSlice(st.Resource)
		hasWildcardAction := slices.Contains(actions, "*") || slices.Contains(actions, "*:*")
		hasWildcardResource := slices.Contains(resources, "*")
		if hasWildcardAction && hasWildcardResource {
			return true
		}
	}
	return false
}

func parseStringOrSlice(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var single string
	if json.Unmarshal(raw, &single) == nil {
		return []string{single}
	}
	var list []string
	if json.Unmarshal(raw, &list) == nil {
		return list
	}
	return nil
}

func isGitHubActionsUserAgent(ua string) bool {
	lower := strings.ToLower(ua)
	return strings.Contains(lower, "github") || strings.Contains(lower, "actions")
}

func isExternalInvocation(ua, ip string) bool {
	if strings.HasSuffix(strings.ToLower(ip), ".amazonaws.com") {
		return false
	}
	return strings.TrimSpace(ua) != "" || strings.TrimSpace(ip) != ""
}

func formatExternalSource(ua, ip string) string {
	ua = strings.TrimSpace(ua)
	ip = strings.TrimSpace(ip)
	if ua != "" && ip != "" {
		return ua + "@" + ip
	}
	if ua != "" {
		return ua
	}
	return ip
}

// IsAccessDenied reports whether err is an AWS authorization/permission failure.
func IsAccessDenied(err error) bool {
	if err == nil {
		return false
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		code := apiErr.ErrorCode()
		if code == "AccessDenied" || code == "AccessDeniedException" || code == "UnauthorizedOperation" {
			return true
		}
	}
	var respErr *awshttp.ResponseError
	if errors.As(err, &respErr) && respErr.HTTPStatusCode() == http.StatusForbidden {
		return true
	}
	return false
}

func daysBetween(past, now time.Time) int {
	if past.IsZero() || now.Before(past) {
		return 0
	}
	return int(now.Sub(past) / (24 * time.Hour))
}

func appendUnique(dst []string, val string) []string {
	if val == "" || slices.Contains(dst, val) {
		return dst
	}
	return append(dst, val)
}
