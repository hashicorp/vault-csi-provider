// Copyright IBM Corp. 2019, 2026
// SPDX-License-Identifier: BUSL-1.1

package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/hashicorp/go-hclog"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/hashicorp/vault-csi-provider/internal/config"
)

const (
	// awsRoleARNAnnotation is the IAM roles for service accounts (IRSA)
	// annotation that associates a Kubernetes service account with an IAM role.
	awsRoleARNAnnotation = "eks.amazonaws.com/role-arn"

	defaultAWSRegion    = "us-east-1"
	defaultAWSMountPath = "aws"

	iamServerIDHeader     = "X-Vault-AWS-IAM-Server-ID"
	getCallerIdentityBody = "Action=GetCallerIdentity&Version=2011-06-15"
	roleSessionNamePrefix = "vault-csi-provider"
)

// stsClient is the subset of the STS API used by AWSIAMAuth.
type stsClient interface {
	AssumeRoleWithWebIdentity(ctx context.Context, params *sts.AssumeRoleWithWebIdentityInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error)
}

// AWSIAMAuth implements Vault's AWS auth method using the "iam" login type.
// It authenticates as the IAM role associated with the requesting pod's
// service account via IAM roles for service accounts (IRSA):
//  1. Look up the IAM role ARN from the service account's annotation.
//  2. Exchange a service account token for temporary AWS credentials with
//     sts:AssumeRoleWithWebIdentity.
//  3. Sign an sts:GetCallerIdentity request with those credentials and send it
//     to Vault, which forwards it to AWS to verify the caller's identity.
type AWSIAMAuth struct {
	logger    hclog.Logger
	k8sClient kubernetes.Interface
	params    config.Parameters

	// Overridable for tests.
	newSTSClient func(region, endpoint string) stsClient
	now          func() time.Time
}

func NewAWSIAMAuth(logger hclog.Logger, k8sClient kubernetes.Interface, params config.Parameters) *AWSIAMAuth {
	return &AWSIAMAuth{
		logger:    logger,
		k8sClient: k8sClient,
		params:    params,
		newSTSClient: func(region, endpoint string) stsClient {
			return newAnonymousSTSClient(region, endpoint)
		},
		now: time.Now,
	}
}

// newAnonymousSTSClient returns an STS client with no credentials configured.
// AssumeRoleWithWebIdentity is an unsigned API call, so none are needed. The
// client is built directly from sts.Options rather than the SDK's default
// config loader, so it never reads the provider's environment variables,
// shared config files, web identity token, or EC2 instance metadata. This
// ensures the provider's or node's own AWS identity is never used. If endpoint
// is set, it overrides the SDK's default STS endpoint for the region.
func newAnonymousSTSClient(region, endpoint string) *sts.Client {
	options := sts.Options{
		Region: region,
		AppID:  "vault-csi-provider",
	}
	if endpoint != "" {
		options.BaseEndpoint = aws.String(endpoint)
	}
	return sts.New(options)
}

// AuthRequest returns the request path and body required to authenticate
// using the configured auth role in Vault. If no appropriate service account
// token is provided in the CSI mount request, it will create a new one.
func (a *AWSIAMAuth) AuthRequest(ctx context.Context) (path string, body map[string]string, err error) {
	podInfo := a.params.PodInfo

	sa, err := a.k8sClient.CoreV1().ServiceAccounts(podInfo.Namespace).Get(ctx, podInfo.ServiceAccountName, metav1.GetOptions{})
	if err != nil {
		return "", nil, fmt.Errorf("failed to get service account %s/%s: %w", podInfo.Namespace, podInfo.ServiceAccountName, err)
	}
	roleARN := sa.Annotations[awsRoleARNAnnotation]
	if roleARN == "" {
		return "", nil, fmt.Errorf("service account %s/%s must have the %q annotation to use the %q auth type",
			podInfo.Namespace, podInfo.ServiceAccountName, awsRoleARNAnnotation, config.AuthTypeAWS)
	}

	token := podInfo.ServiceAccountToken
	if token == "" {
		a.logger.Debug("no suitable token found in mount request, using self-generated service account JWT")
		audience := a.params.Audience
		if audience == "" {
			audience = config.DefaultAWSAudience
		}
		token, err = createServiceAccountToken(ctx, a.logger, a.k8sClient, podInfo, audience)
		if err != nil {
			return "", nil, err
		}
	} else {
		a.logger.Debug("using token from mount request for AWS web identity")
	}

	region := a.params.VaultAuthAWS.Region
	if region == "" {
		region = defaultAWSRegion
	}

	sessionName := roleSessionNamePrefix
	if podInfo.UID != "" {
		sessionName = fmt.Sprintf("%s-%s", roleSessionNamePrefix, podInfo.UID)
	}

	stsEndpoint := a.params.VaultAuthAWS.STSEndpoint

	a.logger.Debug("assuming IAM role with web identity", "roleARN", roleARN, "region", region, "stsEndpoint", stsEndpoint)
	resp, err := a.newSTSClient(region, stsEndpoint).AssumeRoleWithWebIdentity(ctx, &sts.AssumeRoleWithWebIdentityInput{
		RoleArn:          aws.String(roleARN),
		RoleSessionName:  aws.String(sessionName),
		WebIdentityToken: aws.String(token),
	})
	if err != nil {
		return "", nil, fmt.Errorf("failed to assume IAM role %q with web identity: %w", roleARN, err)
	}
	if resp == nil || resp.Credentials == nil {
		return "", nil, fmt.Errorf("no credentials returned when assuming IAM role %q", roleARN)
	}

	creds := aws.Credentials{
		AccessKeyID:     aws.ToString(resp.Credentials.AccessKeyId),
		SecretAccessKey: aws.ToString(resp.Credentials.SecretAccessKey),
		SessionToken:    aws.ToString(resp.Credentials.SessionToken),
	}
	body, err = generateIAMLoginData(ctx, creds, region, stsEndpoint, a.params.VaultAuthAWS.IAMServerIDHeaderValue, a.now())
	if err != nil {
		return "", nil, fmt.Errorf("failed to generate AWS IAM login data: %w", err)
	}
	// Config validation requires a Vault role. If it is ever empty, leave the
	// role key out rather than sending "", so Vault applies its documented
	// default of using the IAM principal's friendly name.
	if a.params.VaultRoleName != "" {
		body["role"] = a.params.VaultRoleName
	}

	mountPath := a.params.VaultAuthMountPath
	if mountPath == "" {
		mountPath = defaultAWSMountPath
	}

	return fmt.Sprintf("/v1/auth/%s/login", mountPath), body, nil
}

// generateIAMLoginData signs an sts:GetCallerIdentity request and encodes it
// in the format expected by Vault's AWS auth "iam" login endpoint. The request
// is always signed for region.
//
// If stsEndpoint is set, the request targets that endpoint, and Vault's
// sts_endpoint and sts_region must be configured to match. Otherwise, for
// us-east-1, the request targets the global STS endpoint, which is what the
// Vault AWS auth method expects by default. For other regions, it targets the
// regional STS endpoint, and Vault's sts_endpoint and sts_region must be
// configured to match.
func generateIAMLoginData(ctx context.Context, creds aws.Credentials, region, stsEndpoint, iamServerIDHeaderValue string, signingTime time.Time) (map[string]string, error) {
	var stsURL url.URL
	if stsEndpoint != "" {
		u, err := url.Parse(stsEndpoint)
		if err != nil {
			return nil, fmt.Errorf("failed to parse STS endpoint %q: %w", stsEndpoint, err)
		}
		stsURL = *u
	} else {
		endpoint, err := sts.NewDefaultEndpointResolverV2().ResolveEndpoint(ctx, sts.EndpointParameters{
			Region:            aws.String(region),
			UseGlobalEndpoint: aws.Bool(region == defaultAWSRegion),
		})
		if err != nil {
			return nil, fmt.Errorf("failed to resolve STS endpoint for region %q: %w", region, err)
		}
		stsURL = endpoint.URI
	}
	if stsURL.Path == "" {
		stsURL.Path = "/"
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, stsURL.String(), strings.NewReader(getCallerIdentityBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	if iamServerIDHeaderValue != "" {
		// Must be set before signing so that it's included in the signature.
		req.Header.Set(iamServerIDHeader, iamServerIDHeaderValue)
	}

	payloadHash := sha256.Sum256([]byte(getCallerIdentityBody))
	if err := v4.NewSigner().SignHTTP(ctx, creds, req, hex.EncodeToString(payloadHash[:]), "sts", region, signingTime); err != nil {
		return nil, fmt.Errorf("failed to sign request: %w", err)
	}

	headersJSON, err := json.Marshal(req.Header)
	if err != nil {
		return nil, err
	}

	return map[string]string{
		"iam_http_request_method": req.Method,
		"iam_request_url":         base64.StdEncoding.EncodeToString([]byte(req.URL.String())),
		"iam_request_headers":     base64.StdEncoding.EncodeToString(headersJSON),
		"iam_request_body":        base64.StdEncoding.EncodeToString([]byte(getCallerIdentityBody)),
	}, nil
}
