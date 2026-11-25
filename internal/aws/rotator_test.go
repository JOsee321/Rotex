package aws

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/JOsee321/Rotex/internal/rotate"
	"github.com/JOsee321/Rotex/internal/security"
)

type mockIAMWriteClient struct {
	keys        []iamtypes.AccessKeyMetadata
	mintedID    string
	mintedSec   string
	updatedTo   iamtypes.StatusType
	deletedKeys []string
}

func (m *mockIAMWriteClient) ListAccessKeys(_ context.Context, _ *iam.ListAccessKeysInput, _ ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error) {
	return &iam.ListAccessKeysOutput{AccessKeyMetadata: m.keys}, nil
}

func (m *mockIAMWriteClient) CreateAccessKey(_ context.Context, in *iam.CreateAccessKeyInput, _ ...func(*iam.Options)) (*iam.CreateAccessKeyOutput, error) {
	return &iam.CreateAccessKeyOutput{
		AccessKey: &iamtypes.AccessKey{
			UserName:        in.UserName,
			AccessKeyId:     awssdk.String(m.mintedID),
			SecretAccessKey: awssdk.String(m.mintedSec),
			Status:          iamtypes.StatusTypeActive,
		},
	}, nil
}

func (m *mockIAMWriteClient) UpdateAccessKey(_ context.Context, in *iam.UpdateAccessKeyInput, _ ...func(*iam.Options)) (*iam.UpdateAccessKeyOutput, error) {
	m.updatedTo = in.Status
	return &iam.UpdateAccessKeyOutput{}, nil
}

func (m *mockIAMWriteClient) DeleteAccessKey(_ context.Context, in *iam.DeleteAccessKeyInput, _ ...func(*iam.Options)) (*iam.DeleteAccessKeyOutput, error) {
	m.deletedKeys = append(m.deletedKeys, awssdk.ToString(in.AccessKeyId))
	return &iam.DeleteAccessKeyOutput{}, nil
}

type flakySTSVerifier struct {
	failuresBeforePass int32
	calls              atomic.Int32
}

func (f *flakySTSVerifier) VerifyCredentials(_ context.Context, _ string, _ *security.SensitiveBytes) error {
	n := f.calls.Add(1)
	if n <= f.failuresBeforePass {
		return errors.New("InvalidClientTokenId (eventual consistency)")
	}
	return nil
}

func TestSDKRotatorTwoKeyLimitGuard(t *testing.T) {
	iamMock := &mockIAMWriteClient{
		keys: []iamtypes.AccessKeyMetadata{
			{AccessKeyId: awssdk.String("AKIA_OLD_1"), Status: iamtypes.StatusTypeActive},
			{AccessKeyId: awssdk.String("AKIA_OLD_2"), Status: iamtypes.StatusTypeInactive},
		},
	}
	rotator := NewSDKRotator(iamMock)

	_, err := rotator.PreflightCheck(context.Background(), rotate.KeyTarget{IAMUser: "ci-deployer"})
	if err == nil || !strings.Contains(err.Error(), "2/2") {
		t.Fatalf("expected 2-key quota error, got: %v", err)
	}
}

func TestSDKRotatorMintVerifyBackoffAndLifecycle(t *testing.T) {
	iamMock := &mockIAMWriteClient{
		keys: []iamtypes.AccessKeyMetadata{
			{AccessKeyId: awssdk.String("AKIA_OLD"), Status: iamtypes.StatusTypeActive},
		},
		mintedID:  "AKIA_NEW",
		mintedSec: "superSecretAccessKeyValue12345",
	}
	stsMock := &flakySTSVerifier{failuresBeforePass: 2}
	rotator := NewSDKRotator(iamMock, WithSTSVerifier(stsMock), WithVerifyBackoff(500*time.Millisecond, 5*time.Millisecond))

	target := rotate.KeyTarget{IAMUser: "ci-deployer"}
	info, err := rotator.PreflightCheck(context.Background(), target)
	if err != nil || info.ResolvedOldKeyID != "AKIA_OLD" {
		t.Fatalf("unexpected preflight info: %+v, err=%v", info, err)
	}

	mat, err := rotator.MintKey(context.Background(), target)
	if err != nil {
		t.Fatalf("MintKey failed: %v", err)
	}
	defer mat.Wipe()

	if mat.KeyID != "AKIA_NEW" {
		t.Fatalf("unexpected minted key ID: %q", mat.KeyID)
	}

	if err := rotator.VerifyKey(context.Background(), mat); err != nil {
		t.Fatalf("VerifyKey should succeed after eventual consistency retry, got: %v", err)
	}
	if stsMock.calls.Load() != 3 {
		t.Fatalf("expected 3 STS attempts, got %d", stsMock.calls.Load())
	}

	if err := rotator.DeactivateKey(context.Background(), target, "AKIA_OLD"); err != nil || iamMock.updatedTo != iamtypes.StatusTypeInactive {
		t.Fatalf("DeactivateKey failed: %v", err)
	}
	if err := rotator.ReactivateKey(context.Background(), target, "AKIA_OLD"); err != nil || iamMock.updatedTo != iamtypes.StatusTypeActive {
		t.Fatalf("ReactivateKey failed: %v", err)
	}
	if err := rotator.DeleteKey(context.Background(), target, "AKIA_OLD"); err != nil || len(iamMock.deletedKeys) != 1 {
		t.Fatalf("DeleteKey failed: %v", err)
	}
}
