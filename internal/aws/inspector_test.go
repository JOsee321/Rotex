package aws

import (
	"context"
	"net/url"
	"slices"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/smithy-go"
)

type mockIAMClient struct {
	users            []iamtypes.User
	keys             map[string][]iamtypes.AccessKeyMetadata
	lastUsed         map[string]*iam.GetAccessKeyLastUsedOutput
	attachedPolicies map[string][]iamtypes.AttachedPolicy
	inlinePolicyList map[string][]string
	inlinePolicies   map[string]string
}

func (m *mockIAMClient) ListUsers(_ context.Context, _ *iam.ListUsersInput, _ ...func(*iam.Options)) (*iam.ListUsersOutput, error) {
	return &iam.ListUsersOutput{Users: m.users}, nil
}

func (m *mockIAMClient) ListAccessKeys(_ context.Context, in *iam.ListAccessKeysInput, _ ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error) {
	return &iam.ListAccessKeysOutput{AccessKeyMetadata: m.keys[awssdk.ToString(in.UserName)]}, nil
}

func (m *mockIAMClient) GetAccessKeyLastUsed(_ context.Context, in *iam.GetAccessKeyLastUsedInput, _ ...func(*iam.Options)) (*iam.GetAccessKeyLastUsedOutput, error) {
	if out, ok := m.lastUsed[awssdk.ToString(in.AccessKeyId)]; ok {
		return out, nil
	}
	return &iam.GetAccessKeyLastUsedOutput{}, nil
}

func (m *mockIAMClient) ListAttachedUserPolicies(_ context.Context, in *iam.ListAttachedUserPoliciesInput, _ ...func(*iam.Options)) (*iam.ListAttachedUserPoliciesOutput, error) {
	return &iam.ListAttachedUserPoliciesOutput{AttachedPolicies: m.attachedPolicies[awssdk.ToString(in.UserName)]}, nil
}

func (m *mockIAMClient) ListUserPolicies(_ context.Context, in *iam.ListUserPoliciesInput, _ ...func(*iam.Options)) (*iam.ListUserPoliciesOutput, error) {
	return &iam.ListUserPoliciesOutput{PolicyNames: m.inlinePolicyList[awssdk.ToString(in.UserName)]}, nil
}

func (m *mockIAMClient) GetUserPolicy(_ context.Context, in *iam.GetUserPolicyInput, _ ...func(*iam.Options)) (*iam.GetUserPolicyOutput, error) {
	key := awssdk.ToString(in.UserName) + "/" + awssdk.ToString(in.PolicyName)
	return &iam.GetUserPolicyOutput{
		UserName:       in.UserName,
		PolicyName:     in.PolicyName,
		PolicyDocument: awssdk.String(m.inlinePolicies[key]),
	}, nil
}

type mockCloudTrailClient struct {
	events []cttypes.Event
	err    error
}

func (m *mockCloudTrailClient) LookupEvents(_ context.Context, _ *cloudtrail.LookupEventsInput, _ ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &cloudtrail.LookupEventsOutput{Events: m.events}, nil
}

func TestSDKInspectorAuditAndCorrelation(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	lastUsedRecent := now.Add(-2 * 24 * time.Hour)
	lastUsedOld := now.Add(-45 * 24 * time.Hour)

	inlineDoc := url.QueryEscape(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`)

	iamMock := &mockIAMClient{
		users: []iamtypes.User{
			{UserName: awssdk.String("ci-deployer")},
			{UserName: awssdk.String("legacy-bot")},
		},
		keys: map[string][]iamtypes.AccessKeyMetadata{
			"ci-deployer": {
				{
					UserName:    awssdk.String("ci-deployer"),
					AccessKeyId: awssdk.String("AKIA_CI_ACTIVE"),
					Status:      iamtypes.StatusTypeActive,
					CreateDate:  awssdk.Time(now.Add(-110 * 24 * time.Hour)),
				},
			},
			"legacy-bot": {
				{
					UserName:    awssdk.String("legacy-bot"),
					AccessKeyId: awssdk.String("AKIA_ZOMBIE"),
					Status:      iamtypes.StatusTypeActive,
					CreateDate:  awssdk.Time(now.Add(-60 * 24 * time.Hour)),
				},
			},
		},
		lastUsed: map[string]*iam.GetAccessKeyLastUsedOutput{
			"AKIA_CI_ACTIVE": {
				AccessKeyLastUsed: &iamtypes.AccessKeyLastUsed{
					LastUsedDate: awssdk.Time(lastUsedRecent),
					ServiceName:  awssdk.String("s3"),
				},
			},
			"AKIA_ZOMBIE": {
				AccessKeyLastUsed: &iamtypes.AccessKeyLastUsed{
					LastUsedDate: awssdk.Time(lastUsedOld),
					ServiceName:  awssdk.String("ec2"),
				},
			},
		},
		attachedPolicies: map[string][]iamtypes.AttachedPolicy{
			"ci-deployer": {
				{
					PolicyName: awssdk.String("AdministratorAccess"),
					PolicyArn:  awssdk.String("arn:aws:iam::aws:policy/AdministratorAccess"),
				},
			},
		},
		inlinePolicyList: map[string][]string{
			"legacy-bot": {"wildcard-inline"},
		},
		inlinePolicies: map[string]string{
			"legacy-bot/wildcard-inline": inlineDoc,
		},
	}

	ctMock := &mockCloudTrailClient{
		events: []cttypes.Event{
			{
				CloudTrailEvent: awssdk.String(`{"userAgent":"github-actions/runner","sourceIPAddress":"140.82.112.1","userIdentity":{"accessKeyId":"AKIA_CI_ACTIVE"}}`),
			},
			{
				CloudTrailEvent: awssdk.String(`{"userAgent":"aws-cli/2.15.0","sourceIPAddress":"203.0.113.42","userIdentity":{"accessKeyId":"AKIA_CI_ACTIVE"}}`),
			},
		},
	}

	inspector := NewSDKInspector(iamMock, ctMock, WithClock(func() time.Time { return now }))
	report, err := inspector.Inspect(context.Background(), 7*24*time.Hour)
	if err != nil {
		t.Fatalf("Inspect failed: %v", err)
	}
	if len(report.Keys) != 2 {
		t.Fatalf("expected 2 audited keys, got %d", len(report.Keys))
	}

	ciKey := report.Keys[0]
	if !ciKey.Stale || ciKey.Zombie || !ciKey.Overprivileged {
		t.Fatalf("unexpected ciKey flags: %+v", ciKey)
	}
	if !ciKey.GitHubRunnerSeen || !ciKey.ExternalUsageSeen {
		t.Fatalf("expected both GitHubRunnerSeen and ExternalUsageSeen: %+v", ciKey)
	}
	if !slices.Contains(ciKey.ExternalSources, "aws-cli/2.15.0@203.0.113.42") {
		t.Fatalf("unexpected external sources: %v", ciKey.ExternalSources)
	}

	zombieKey := report.Keys[1]
	if zombieKey.Stale || !zombieKey.Zombie || !zombieKey.Overprivileged {
		t.Fatalf("unexpected zombieKey flags: %+v", zombieKey)
	}
	if !slices.Contains(zombieKey.OverprivilegedPolicies, "inline:wildcard-inline") {
		t.Fatalf("expected inline wildcard policy flag, got %v", zombieKey.OverprivilegedPolicies)
	}
}

func TestSDKInspectorGracefulCloudTrailAccessDenied(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	iamMock := &mockIAMClient{
		users: []iamtypes.User{{UserName: awssdk.String("ci-user")}},
		keys: map[string][]iamtypes.AccessKeyMetadata{
			"ci-user": {{
				UserName:    awssdk.String("ci-user"),
				AccessKeyId: awssdk.String("AKIA123"),
				Status:      iamtypes.StatusTypeActive,
				CreateDate:  awssdk.Time(now.Add(-10 * 24 * time.Hour)),
			}},
		},
	}
	ctMock := &mockCloudTrailClient{
		err: &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "not authorized"},
	}

	inspector := NewSDKInspector(iamMock, ctMock, WithClock(func() time.Time { return now }))
	report, err := inspector.Inspect(context.Background(), 24*time.Hour)
	if err != nil {
		t.Fatalf("expected graceful degradation, got error: %v", err)
	}
	if len(report.Warnings) != 1 {
		t.Fatalf("expected 1 CloudTrail permission warning, got %v", report.Warnings)
	}
}
