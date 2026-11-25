package aws

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/JOsee321/Rotex/internal/rotate"
	"github.com/JOsee321/Rotex/internal/security"
	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

const (
	maxIAMKeysPerUser     = 2
	maxIAMKeyPages        = 20
	defaultVerifyTimeout  = 30 * time.Second
	defaultInitialBackoff = 1 * time.Second
)

// IAMWriteClient captures IAM read/write operations needed for key rotation.
type IAMWriteClient interface {
	ListAccessKeys(ctx context.Context, params *iam.ListAccessKeysInput, optFns ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error)
	CreateAccessKey(ctx context.Context, params *iam.CreateAccessKeyInput, optFns ...func(*iam.Options)) (*iam.CreateAccessKeyOutput, error)
	UpdateAccessKey(ctx context.Context, params *iam.UpdateAccessKeyInput, optFns ...func(*iam.Options)) (*iam.UpdateAccessKeyOutput, error)
	DeleteAccessKey(ctx context.Context, params *iam.DeleteAccessKeyInput, optFns ...func(*iam.Options)) (*iam.DeleteAccessKeyOutput, error)
}

// STSVerifier validates newly minted AWS credentials via sts:GetCallerIdentity.
type STSVerifier interface {
	VerifyCredentials(ctx context.Context, keyID string, secret *security.SensitiveBytes) error
}

type sdkSTSVerifier struct {
	region   string
	endpoint string
}

func (v sdkSTSVerifier) VerifyCredentials(ctx context.Context, keyID string, secret *security.SensitiveBytes) error {
	if secret == nil || secret.Len() == 0 {
		return errors.New("secret access key must not be empty")
	}
	region := v.region
	if region == "" {
		region = "us-east-1"
	}

	opts := []func(*config.LoadOptions) error{
		config.WithRegion(region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(keyID, string(secret.Expose()), "")),
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return fmt.Errorf("build STS verification config: %w", err)
	}
	client := sts.NewFromConfig(cfg, func(o *sts.Options) {
		if v.endpoint != "" {
			o.BaseEndpoint = awssdk.String(v.endpoint)
		}
	})
	if _, err := client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}); err != nil {
		return security.SanitizeError(err, string(secret.Expose()))
	}
	return nil
}

// RotatorOption configures an SDKRotator.
type RotatorOption func(*SDKRotator)

// WithVerifyBackoff configures retry timeout and initial backoff for STS verification.
func WithVerifyBackoff(timeout, initial time.Duration) RotatorOption {
	return func(r *SDKRotator) {
		if timeout > 0 {
			r.verifyTimeout = timeout
		}
		if initial > 0 {
			r.initialBackoff = initial
		}
	}
}

// WithSTSVerifier overrides the STS credential verification implementation (useful in tests).
func WithSTSVerifier(v STSVerifier) RotatorOption {
	return func(r *SDKRotator) {
		if v != nil {
			r.sts = v
		}
	}
}

// SDKRotator implements rotate.CredentialProvider for AWS IAM User access keys.
type SDKRotator struct {
	iam            IAMWriteClient
	sts            STSVerifier
	verifyTimeout  time.Duration
	initialBackoff time.Duration
}

// NewSDKRotator constructs an AWS IAM CredentialProvider.
func NewSDKRotator(iamClient IAMWriteClient, opts ...RotatorOption) *SDKRotator {
	r := &SDKRotator{
		iam:            iamClient,
		sts:            sdkSTSVerifier{},
		verifyTimeout:  defaultVerifyTimeout,
		initialBackoff: defaultInitialBackoff,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(r)
		}
	}
	return r
}

// NewDefaultRotator loads AWS SDK configuration from the local environment/profile.
func NewDefaultRotator(ctx context.Context, iamEndpoint, stsEndpoint string, optFns ...func(*config.LoadOptions) error) (*SDKRotator, error) {
	cfg, err := config.LoadDefaultConfig(ctx, optFns...)
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}
	iamClient := iam.NewFromConfig(cfg, func(o *iam.Options) {
		if iamEndpoint != "" {
			o.BaseEndpoint = awssdk.String(iamEndpoint)
		}
	})
	return NewSDKRotator(iamClient, WithSTSVerifier(sdkSTSVerifier{
		region:   cfg.Region,
		endpoint: stsEndpoint,
	})), nil
}

// Name returns the provider identifier.
func (r *SDKRotator) Name() string {
	return "aws-iam"
}

// PreflightCheck enforces AWS IAM's 2-key-per-user quota and resolves the target key ID.
func (r *SDKRotator) PreflightCheck(ctx context.Context, target rotate.KeyTarget) (*rotate.PreflightInfo, error) {
	if strings.TrimSpace(target.IAMUser) == "" {
		return nil, errors.New("IAM user name is required")
	}

	var keys []iamtypes.AccessKeyMetadata
	var marker *string
	for page := 0; page < maxIAMKeyPages; page++ {
		out, err := r.iam.ListAccessKeys(ctx, &iam.ListAccessKeysInput{
			UserName: awssdk.String(target.IAMUser),
			Marker:   marker,
		})
		if err != nil {
			return nil, fmt.Errorf("list access keys for IAM user %s: %w", target.IAMUser, err)
		}
		keys = append(keys, out.AccessKeyMetadata...)
		if !out.IsTruncated || out.Marker == nil {
			break
		}
		marker = out.Marker
	}

	existingIDs := make([]string, 0, len(keys))
	for _, k := range keys {
		existingIDs = append(existingIDs, fmt.Sprintf("%s (%s)", awssdk.ToString(k.AccessKeyId), k.Status))
	}

	if len(keys) >= maxIAMKeysPerUser {
		return nil, fmt.Errorf(
			"IAM user %q already has %d/%d access keys (%s); delete an unused key before rotating",
			target.IAMUser, len(keys), maxIAMKeysPerUser, strings.Join(existingIDs, ", "),
		)
	}

	resolvedOld := strings.TrimSpace(target.OldKeyID)
	if resolvedOld == "" {
		if len(keys) == 1 {
			resolvedOld = awssdk.ToString(keys[0].AccessKeyId)
		}
	} else {
		found := false
		for _, k := range keys {
			if awssdk.ToString(k.AccessKeyId) == resolvedOld {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("old key %q not found on IAM user %q", resolvedOld, target.IAMUser)
		}
	}

	return &rotate.PreflightInfo{
		ResolvedOldKeyID: resolvedOld,
		ExistingKeyCount: len(keys),
		ExistingKeyIDs:   existingIDs,
	}, nil
}

// MintKey creates a new AWS IAM access key while leaving any existing key active.
func (r *SDKRotator) MintKey(ctx context.Context, target rotate.KeyTarget) (*rotate.SecretMaterial, error) {
	out, err := r.iam.CreateAccessKey(ctx, &iam.CreateAccessKeyInput{
		UserName: awssdk.String(target.IAMUser),
	})
	if err != nil {
		return nil, fmt.Errorf("create access key for IAM user %s: %w", target.IAMUser, err)
	}
	if out.AccessKey == nil {
		return nil, errors.New("AWS CreateAccessKey returned nil key payload")
	}

	keyID := awssdk.ToString(out.AccessKey.AccessKeyId)
	secretVal := awssdk.ToString(out.AccessKey.SecretAccessKey)
	if keyID == "" || secretVal == "" {
		return nil, errors.New("AWS CreateAccessKey returned incomplete credentials")
	}

	secretBytes := []byte(secretVal)
	defer security.WipeBytes(secretBytes)

	return &rotate.SecretMaterial{
		KeyID: keyID,
		Values: map[string]*security.SensitiveBytes{
			"AWS_ACCESS_KEY_ID":     security.NewSensitiveBytes([]byte(keyID)),
			"AWS_SECRET_ACCESS_KEY": security.NewSensitiveBytes(secretBytes),
		},
	}, nil
}

// VerifyKey validates the newly minted credentials via STS with exponential backoff.
func (r *SDKRotator) VerifyKey(ctx context.Context, mat *rotate.SecretMaterial) error {
	if mat == nil {
		return errors.New("secret material must not be nil")
	}
	secret := mat.Values["AWS_SECRET_ACCESS_KEY"]
	if secret == nil || secret.Len() == 0 {
		return errors.New("missing AWS_SECRET_ACCESS_KEY in secret material")
	}

	timeout := r.verifyTimeout
	if timeout <= 0 {
		timeout = defaultVerifyTimeout
	}
	backoff := r.initialBackoff
	if backoff <= 0 {
		backoff = defaultInitialBackoff
	}

	deadline := time.Now().Add(timeout)
	var lastErr error

	for {
		if err := r.sts.VerifyCredentials(ctx, mat.KeyID, secret); err == nil {
			return nil
		} else {
			lastErr = err
		}

		remaining := time.Until(deadline)
		if remaining <= 0 || ctx.Err() != nil {
			break
		}

		sleep := min(backoff, remaining)
		timer := time.NewTimer(sleep)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
		if backoff > remaining/2 {
			backoff = remaining
		} else {
			backoff *= 2
		}
	}

	return fmt.Errorf("verify minted AWS key %s via STS failed: %w", mat.KeyID, lastErr)
}

// DeactivateKey sets keyID status to Inactive without deleting it.
func (r *SDKRotator) DeactivateKey(ctx context.Context, target rotate.KeyTarget, keyID string) error {
	if strings.TrimSpace(target.IAMUser) == "" || strings.TrimSpace(keyID) == "" {
		return errors.New("IAM user and access key ID are required to deactivate key")
	}
	_, err := r.iam.UpdateAccessKey(ctx, &iam.UpdateAccessKeyInput{
		UserName:    awssdk.String(target.IAMUser),
		AccessKeyId: awssdk.String(keyID),
		Status:      iamtypes.StatusTypeInactive,
	})
	if err != nil {
		return fmt.Errorf("deactivate key %s on %s: %w", keyID, target.IAMUser, err)
	}
	return nil
}

// ReactivateKey restores an Inactive access key back to Active status.
func (r *SDKRotator) ReactivateKey(ctx context.Context, target rotate.KeyTarget, keyID string) error {
	if strings.TrimSpace(target.IAMUser) == "" || strings.TrimSpace(keyID) == "" {
		return errors.New("IAM user and access key ID are required to reactivate key")
	}
	_, err := r.iam.UpdateAccessKey(ctx, &iam.UpdateAccessKeyInput{
		UserName:    awssdk.String(target.IAMUser),
		AccessKeyId: awssdk.String(keyID),
		Status:      iamtypes.StatusTypeActive,
	})
	if err != nil {
		return fmt.Errorf("reactivate key %s on %s: %w", keyID, target.IAMUser, err)
	}
	return nil
}

// DeleteKey permanently deletes an IAM access key.
func (r *SDKRotator) DeleteKey(ctx context.Context, target rotate.KeyTarget, keyID string) error {
	if strings.TrimSpace(target.IAMUser) == "" || strings.TrimSpace(keyID) == "" {
		return errors.New("IAM user and access key ID are required to delete key")
	}
	_, err := r.iam.DeleteAccessKey(ctx, &iam.DeleteAccessKeyInput{
		UserName:    awssdk.String(target.IAMUser),
		AccessKeyId: awssdk.String(keyID),
	})
	if err != nil {
		return fmt.Errorf("delete key %s on %s: %w", keyID, target.IAMUser, err)
	}
	return nil
}
