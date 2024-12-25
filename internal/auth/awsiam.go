package auth

import (
	"context"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/defaults"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/service/sts/stsiface"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-secure-stdlib/awsutil"
	"github.com/hashicorp/vault-csi-provider/internal/config"
	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	k8scorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"os"
	"regexp"
)

type AWSIAMAuth struct {
	logger           hclog.Logger
	k8sClient        kubernetes.Interface
	params           config.Parameters
	defaultMountPath string
	stsClient        stsiface.STSAPI
}

const (
	roleARNAnnotation    = "eks.amazonaws.com/role-arn"
	audienceAnnotation   = "eks.amazonaws.com/audience"
	defaultTokenAudience = "sts.amazonaws.com"
	defaultAWSRegion     = "us-east-1"
	STSEndpointEnv       = "AWS_STS_ENDPOINT"
	defaultAWSMountPath  = "aws"
)

func setupConfig(params config.Parameters, credentials *credentials.Credentials) *aws.Config {
	// Get an initial session to use for STS calls.
	regionAWS := defaultAWSRegion
	if params.VaultAuth.AWSIAMAuth.Region != "" {
		regionAWS = params.VaultAuth.AWSIAMAuth.Region
	}
	handlers := defaults.Handlers()
	handlers.Build.PushBack(request.WithAppendUserAgent("vault-csi-provider"))
	awsConfig := aws.NewConfig().WithEndpointResolver(ResolveEndpoint())
	if regionAWS != "" {
		awsConfig.WithRegion(regionAWS)
	}

	if credentials != nil {
		awsConfig.WithCredentials(credentials)
	}
	return awsConfig
}

func NewAWSIAMAuth(logger hclog.Logger, k8sClient kubernetes.Interface, params config.Parameters, defaultMountPath string) (*AWSIAMAuth, error) {
	// Get an initial session to use for STS calls.
	awsConfig := setupConfig(params, nil)
	sess, err := session.NewSession(awsConfig)
	if err != nil {
		return nil, err
	}

	return &AWSIAMAuth{
		logger:           logger,
		k8sClient:        k8sClient,
		params:           params,
		defaultMountPath: defaultMountPath,
		stsClient:        sts.New(sess),
	}, nil
}

func ResolveEndpointWithServiceMap(customEndpoints map[string]string) endpoints.ResolverFunc {
	defaultResolver := endpoints.DefaultResolver()
	return func(service, region string, opts ...func(*endpoints.Options)) (endpoints.ResolvedEndpoint, error) {
		if ep, ok := customEndpoints[service]; ok {
			return endpoints.ResolvedEndpoint{
				URL: ep,
			}, nil
		}
		return defaultResolver.EndpointFor(service, region, opts...)
	}
}

// ResolveEndpoint returns a ResolverFunc with
// customizable endpoints.
func ResolveEndpoint() endpoints.ResolverFunc {
	customEndpoints := make(map[string]string)
	if v := os.Getenv(STSEndpointEnv); v != "" {
		customEndpoints["sts"] = v
	}
	return ResolveEndpointWithServiceMap(customEndpoints)
}

var regexReqIDs = []*regexp.Regexp{
	regexp.MustCompile(`request id: (\S+)`),
	regexp.MustCompile(` Credential=.+`),
}

func SanitizeErr(err error) error {
	msg := err.Error()
	for _, regex := range regexReqIDs {
		msg = string(regex.ReplaceAll([]byte(msg), nil))
	}
	return errors.New(msg)
}

type authTokenFetcher struct {
	Namespace string
	// Audience is the token aud claim
	// which is verified by the aws oidc provider
	// see: https://github.com/external-secrets/external-secrets/issues/1251#issuecomment-1161745849
	Audiences      []string
	ServiceAccount string
	k8sClient      k8scorev1.CoreV1Interface
}

// FetchToken satisfies the stscreds.TokenFetcher interface
// it is used to generate service account tokens which are consumed by the aws sdk.
func (p authTokenFetcher) FetchToken(ctx credentials.Context) ([]byte, error) {
	tokRsp, err := p.k8sClient.ServiceAccounts(p.Namespace).CreateToken(ctx, p.ServiceAccount, &authv1.TokenRequest{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: p.Namespace,
			Name:      p.ServiceAccount,
		},
		Spec: authv1.TokenRequestSpec{
			Audiences: p.Audiences,
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("error creating service account token: %w", err)
	}
	return []byte(tokRsp.Status.Token), nil
}

func getTokenFetcher(ctx context.Context, k *AWSIAMAuth) (string, *authTokenFetcher, error) {
	sa, err := k.k8sClient.CoreV1().ServiceAccounts(k.params.PodInfo.Namespace).Get(ctx, k.params.PodInfo.ServiceAccountName, metav1.GetOptions{})
	if err != nil {
		return "", nil, err
	}
	// the service account is expected to have a well-known annotation
	// this is used as input to assumeRoleWithWebIdentity
	roleArn := sa.Annotations[roleARNAnnotation]
	if roleArn == "" {
		return "", nil, fmt.Errorf("an IAM role must be associated with service account %s (namespace: %s)", k.params.PodInfo.ServiceAccountName, k.params.PodInfo.Namespace)
	}

	tokenAud := sa.Annotations[audienceAnnotation]
	if tokenAud == "" {
		tokenAud = defaultTokenAudience
	}

	audiences := []string{tokenAud}

	return roleArn, &authTokenFetcher{
		Namespace:      k.params.PodInfo.Namespace,
		Audiences:      audiences,
		ServiceAccount: k.params.PodInfo.ServiceAccountName,
		k8sClient:      k.k8sClient.CoreV1(),
	}, nil
}

func (k *AWSIAMAuth) AuthRequest(ctx context.Context) (path string, body map[string]any, additionalHeaders map[string]string, err error) {

	roleArn, tokenFetcher, err := getTokenFetcher(ctx, k)
	if err != nil {
		return "", nil, nil, err
	}

	webIdentityProvider := stscreds.NewWebIdentityRoleProviderWithOptions(
		k.stsClient, roleArn, "vault-csi-provider", tokenFetcher)

	awsConfig := setupConfig(k.params, credentials.NewCredentials(webIdentityProvider))

	sess, err := session.NewSession(awsConfig)
	if err != nil {
		return "", nil, nil, SanitizeErr(err)
	}

	awsCredentials, err := sess.Config.Credentials.Get()
	if err != nil {
		return "", nil, nil, SanitizeErr(err)
	}

	credentialsConfig := awsutil.CredentialsConfig{
		AccessKey:    awsCredentials.AccessKeyID,
		SecretKey:    awsCredentials.SecretAccessKey,
		SessionToken: awsCredentials.SessionToken,
		Logger:       k.logger,
	}

	credChainCredentials, err := credentialsConfig.GenerateCredentialChain()
	if err != nil {
		return "", nil, nil, err
	}
	if credChainCredentials == nil {
		return "", nil, nil, fmt.Errorf("could not compile valid credential providers from config")
	}

	_, err = credChainCredentials.Get()
	if err != nil {
		return "", nil, nil, fmt.Errorf("failed to retrieve credentials from credential chain: %w", err)
	}

	data, err := awsutil.GenerateLoginData(credChainCredentials, k.params.VaultAuth.AWSIAMAuth.XVaultAWSIAMServerID, *sess.Config.Region, k.logger)
	if err != nil {
		return "", nil, nil, fmt.Errorf("unable to generate login data for AWS auth endpoint: %w", err)
	}
	mountPath := k.params.VaultAuth.MouthPath
	if mountPath == "" {
		mountPath = defaultAWSMountPath
	}

	// Add role if we have one. If not, Vault will infer the role name based
	// on the IAM friendly name (iam auth type) or EC2 instance's
	// AMI ID (ec2 auth type).
	if k.params.VaultAuth.AWSIAMAuth.AWSIAMRole != "" {
		data["role"] = k.params.VaultAuth.AWSIAMAuth.AWSIAMRole
	}

	h := make(map[string]string)
	if k.params.VaultAuth.AWSIAMAuth.XVaultAWSIAMServerID != "" {
		h = map[string]string{
			"iam_server_id_header_value": k.params.VaultAuth.AWSIAMAuth.XVaultAWSIAMServerID}
	}
	return fmt.Sprintf("/v1/auth/%s/login", mountPath), data, h, nil
}
