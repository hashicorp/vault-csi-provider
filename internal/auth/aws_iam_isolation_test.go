// Copyright IBM Corp. 2019, 2026
// SPDX-License-Identifier: BUSL-1.1

package auth

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/require"
	authenticationv1 "k8s.io/api/authentication/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/hashicorp/vault-csi-provider/internal/config"
)

const (
	providerEnvAccessKeyID    = "AKIAPROVIDERENV"
	providerFileAccessKeyID   = "AKIAPROVIDERFILE"
	providerIRSARoleARN       = "arn:aws:iam::123456789012:role/provider-irsa-role"
	providerWebIdentityToken  = "provider-web-identity-token"
	appRoleAccessKeyID        = "AKIAAPPROLE"
	appRoleSessionToken       = "app-role-session-token"
	appServiceAccountJWTToken = "self-generated-token"
)

type recordedSTSRequest struct {
	action           string
	roleARN          string
	roleSessionName  string
	webIdentityToken string
	authorization    string
	securityToken    string
}

// providerCredentialSources makes every credential source the AWS SDK's
// default chain would consult available to the test process, as if the
// provider pod or node had its own AWS identity. It returns a counter of
// requests made to the instance metadata and container credential endpoints.
func providerCredentialSources(t *testing.T) *atomic.Int32 {
	t.Helper()

	var credentialEndpointHits atomic.Int32
	credentialEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		credentialEndpointHits.Add(1)
		http.Error(w, "provider/node credential endpoint must not be called", http.StatusTeapot)
	}))
	t.Cleanup(credentialEndpoint.Close)

	dir := t.TempDir()
	sharedCredentials := filepath.Join(dir, "credentials")
	require.NoError(t, os.WriteFile(sharedCredentials, []byte(fmt.Sprintf(
		"[default]\naws_access_key_id = %s\naws_secret_access_key = provider-file-secret\n", providerFileAccessKeyID)), 0o600))
	tokenFile := filepath.Join(dir, "token")
	require.NoError(t, os.WriteFile(tokenFile, []byte(providerWebIdentityToken), 0o600))

	// Static environment credentials.
	t.Setenv("AWS_ACCESS_KEY_ID", providerEnvAccessKeyID)
	t.Setenv("AWS_SECRET_ACCESS_KEY", "provider-env-secret")
	t.Setenv("AWS_SESSION_TOKEN", "provider-env-session-token")
	// Shared credentials and config files.
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", sharedCredentials)
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(dir, "config"))
	t.Setenv("AWS_PROFILE", "default")
	// The provider pod's own IRSA web identity.
	t.Setenv("AWS_ROLE_ARN", providerIRSARoleARN)
	t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", tokenFile)
	// Container credentials (ECS and EKS Pod Identity).
	t.Setenv("AWS_CONTAINER_CREDENTIALS_FULL_URI", credentialEndpoint.URL+"/v1/credentials")
	// EC2 instance metadata (the node's instance role).
	t.Setenv("AWS_EC2_METADATA_SERVICE_ENDPOINT", credentialEndpoint.URL)
	t.Setenv("AWS_EC2_METADATA_DISABLED", "false")

	return &credentialEndpointHits
}

// TestAWSIAMAuth_NeverUsesProviderOrNodeCredentials is a regression test for
// the requirement that the provider authenticates only as the IAM role of
// the requesting pod's service account. It runs the STS client factory that
// NewAWSIAMAuth installs, unchanged except for redirecting the endpoint to a
// fake STS server, with every provider/node credential source available.
// The AWS SDK always sends AssumeRoleWithWebIdentity unsigned, so this test
// cannot detect credentials configured on the STS client itself;
// TestNewAWSIAMAuth_STSClientHasNoCredentials covers that. This test checks
// that:
//   - those sources are never consulted,
//   - AssumeRoleWithWebIdentity is sent unsigned, for the application's role
//     and service account token,
//   - the Vault login data is signed only with the application role's
//     temporary credentials, and
//   - if assuming the application's role fails, an error is returned with no
//     fallback to any other identity, and
//   - if STS rejects a token supplied in the mount request, the mount fails
//     with that error instead of requesting a replacement token.
func TestAWSIAMAuth_NeverUsesProviderOrNodeCredentials(t *testing.T) {
	const suppliedToken = "token-from-mount-request"
	for name, tc := range map[string]struct {
		// suppliedToken is the token the CSI driver passed in the mount
		// request. If empty, the provider creates its own.
		suppliedToken string
		// stsErrorCode, if set, makes STS reject AssumeRoleWithWebIdentity.
		stsErrorCode string
		// stsNoCredentials makes STS return a successful response without
		// credentials.
		stsNoCredentials bool
		// stsEndpointFromConfig sets auth.aws.stsEndpoint to the fake STS
		// server and runs the production STS client factory without any
		// test override. Otherwise, the test redirects the production
		// factory's clients to the fake STS server.
		stsEndpointFromConfig bool
	}{
		"self-generated token, role assumed":          {},
		"supplied token, role assumed":                {suppliedToken: suppliedToken},
		"self-generated token, role assumption fails": {stsErrorCode: "AccessDenied"},
		"supplied token rejected as invalid":          {suppliedToken: suppliedToken, stsErrorCode: "InvalidIdentityToken"},
		"supplied token rejected as expired":          {suppliedToken: suppliedToken, stsErrorCode: "ExpiredTokenException"},
		"supplied token, role assumption fails":       {suppliedToken: suppliedToken, stsErrorCode: "AccessDenied"},
		"STS response without credentials":            {stsNoCredentials: true},
		"STS endpoint from config, role assumed":      {stsEndpointFromConfig: true},
		"STS endpoint from config, supplied token rejected": {
			suppliedToken:         suppliedToken,
			stsErrorCode:          "InvalidIdentityToken",
			stsEndpointFromConfig: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			credentialEndpointHits := providerCredentialSources(t)

			var mu sync.Mutex
			var stsRequests []recordedSTSRequest
			stsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := r.ParseForm(); err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				mu.Lock()
				stsRequests = append(stsRequests, recordedSTSRequest{
					action:           r.PostForm.Get("Action"),
					roleARN:          r.PostForm.Get("RoleArn"),
					roleSessionName:  r.PostForm.Get("RoleSessionName"),
					webIdentityToken: r.PostForm.Get("WebIdentityToken"),
					authorization:    r.Header.Get("Authorization"),
					securityToken:    r.Header.Get("X-Amz-Security-Token"),
				})
				mu.Unlock()

				w.Header().Set("Content-Type", "text/xml")
				if tc.stsErrorCode != "" {
					w.WriteHeader(http.StatusBadRequest)
					_, _ = fmt.Fprintf(w, `<ErrorResponse><Error><Type>Sender</Type><Code>%s</Code><Message>rejected by test</Message></Error><RequestId>test</RequestId></ErrorResponse>`, tc.stsErrorCode)
					return
				}
				if tc.stsNoCredentials {
					_, _ = fmt.Fprint(w, `<AssumeRoleWithWebIdentityResponse><AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>`)
					return
				}
				_, _ = fmt.Fprintf(w, `<AssumeRoleWithWebIdentityResponse><AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>%s</AccessKeyId><SecretAccessKey>app-role-secret</SecretAccessKey><SessionToken>%s</SessionToken><Expiration>2030-01-01T00:00:00Z</Expiration></Credentials></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>`,
					appRoleAccessKeyID, appRoleSessionToken)
			}))
			t.Cleanup(stsServer.Close)

			podInfo := testPodInfo()
			podInfo.ServiceAccountToken = tc.suppliedToken
			params := config.Parameters{
				VaultRoleName: "vault-role",
				VaultAuthType: config.AuthTypeAWS,
				PodInfo:       podInfo,
			}
			if tc.stsEndpointFromConfig {
				// Config validation requires https for stsEndpoint. This test
				// sets the parameters directly and uses a plain http test
				// server, because the production STS client does not trust a
				// test TLS certificate.
				params.VaultAuthAWS.Region = "us-west-2"
				params.VaultAuthAWS.STSEndpoint = stsServer.URL
			}
			var tokenRequests []*authenticationv1.TokenRequest
			a := newTestAWSIAMAuth(t, params, nil, &tokenRequests, testServiceAccount(map[string]string{awsRoleARNAnnotation: testRoleARN}))
			if !tc.stsEndpointFromConfig {
				a.newSTSClient = redirectSTSClient(t, a.newSTSClient, stsServer.URL)
			}

			path, body, err := a.AuthRequest(context.Background())

			// Exactly one STS call: AssumeRoleWithWebIdentity for the
			// application's role and token, sent unsigned.
			mu.Lock()
			defer mu.Unlock()
			require.Len(t, stsRequests, 1, "expected exactly one STS request and no fallback requests")
			req := stsRequests[0]
			require.Equal(t, "AssumeRoleWithWebIdentity", req.action)
			require.Equal(t, testRoleARN, req.roleARN)
			expectedToken := appServiceAccountJWTToken
			if tc.suppliedToken != "" {
				expectedToken = tc.suppliedToken
			}
			require.Equal(t, expectedToken, req.webIdentityToken)
			require.Equal(t, "vault-csi-provider-"+testPodUID, req.roleSessionName)
			require.Empty(t, req.authorization, "AssumeRoleWithWebIdentity must not be signed with any credentials")
			require.Empty(t, req.securityToken, "AssumeRoleWithWebIdentity must not carry a session token")

			// A token is only created when none was supplied, and never as a
			// replacement after STS rejects a supplied one.
			if tc.suppliedToken != "" {
				require.Empty(t, tokenRequests, "must not request a replacement service account token")
			} else {
				require.Len(t, tokenRequests, 1)
			}

			// The provider's/node's credential endpoints were never consulted.
			require.Zero(t, credentialEndpointHits.Load(), "instance metadata or container credentials endpoint was called")

			if tc.stsErrorCode != "" {
				require.ErrorContains(t, err, `failed to assume IAM role "`+testRoleARN+`" with web identity`)
				require.ErrorContains(t, err, tc.stsErrorCode)
				require.Empty(t, path)
				require.Nil(t, body)
				return
			}
			if tc.stsNoCredentials {
				require.ErrorContains(t, err, `no credentials returned when assuming IAM role "`+testRoleARN+`"`)
				require.Empty(t, path)
				require.Nil(t, body)
				return
			}

			// The Vault login request is signed only with the application
			// role's temporary credentials.
			require.NoError(t, err)
			require.Equal(t, "/v1/auth/aws/login", path)
			data := decodeLoginData(t, body)
			authz := data.headers.Get("Authorization")
			require.Contains(t, authz, "Credential="+appRoleAccessKeyID+"/")
			require.Equal(t, appRoleSessionToken, data.headers.Get("X-Amz-Security-Token"))
			decoded := fmt.Sprint(data.headers) + data.url + data.body
			for _, providerValue := range []string{providerEnvAccessKeyID, providerFileAccessKeyID, "provider-env-session-token", providerWebIdentityToken} {
				require.NotContains(t, decoded, providerValue, "login request contains provider credential")
			}
			if tc.stsEndpointFromConfig {
				// The signed login request targets the configured STS endpoint.
				require.Equal(t, stsServer.URL+"/", data.url)
			}
		})
	}
}

// redirectSTSClient wraps the production STS client factory so that the
// clients it builds send requests to endpoint. Every other client option,
// including credentials, comes from the production factory unchanged.
func redirectSTSClient(t *testing.T, productionFactory func(region, endpoint string) stsClient, endpoint string) func(region, endpoint string) stsClient {
	t.Helper()
	return func(region, configuredEndpoint string) stsClient {
		client, ok := productionFactory(region, configuredEndpoint).(*sts.Client)
		require.True(t, ok, "the production STS client factory must return an *sts.Client")
		return sts.New(client.Options(), func(o *sts.Options) {
			o.BaseEndpoint = aws.String(endpoint)
		})
	}
}

// TestNewAWSIAMAuth_STSClientHasNoCredentials checks that the STS client
// factory installed by NewAWSIAMAuth builds a client without a credentials
// provider, with every provider/node credential source available. This guards
// against a future change to the factory, such as loading the SDK's default
// config, which would give the client the provider's or node's credentials.
func TestNewAWSIAMAuth_STSClientHasNoCredentials(t *testing.T) {
	providerCredentialSources(t)
	a := NewAWSIAMAuth(hclog.NewNullLogger(), fake.NewClientset(), config.Parameters{})

	for name, tc := range map[string]struct {
		endpoint             string
		expectedBaseEndpoint *string
	}{
		"default endpoint": {},
		"custom endpoint": {
			endpoint:             "https://sts-fips.us-west-2.amazonaws.com",
			expectedBaseEndpoint: aws.String("https://sts-fips.us-west-2.amazonaws.com"),
		},
	} {
		t.Run(name, func(t *testing.T) {
			client, ok := a.newSTSClient("us-west-2", tc.endpoint).(*sts.Client)
			require.True(t, ok, "the production STS client factory must return an *sts.Client")
			options := client.Options()
			require.Nil(t, options.Credentials, "the STS client must not have a credentials provider")
			require.Equal(t, "us-west-2", options.Region)
			require.Equal(t, tc.expectedBaseEndpoint, options.BaseEndpoint)
		})
	}
}
