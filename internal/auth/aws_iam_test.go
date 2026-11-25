// Copyright IBM Corp. 2019, 2026
// SPDX-License-Identifier: BUSL-1.1

package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/require"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/hashicorp/vault-csi-provider/internal/config"
)

const (
	testRoleARN = "arn:aws:iam::123456789012:role/my-irsa-role"
	testPodUID  = "9aeb260f-d64a-426c-9872-95b6bab37e00"
)

var testSigningTime = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

type fakeSTS struct {
	region   string
	endpoint string
	input    *sts.AssumeRoleWithWebIdentityInput
	err      error
	// output, if set, is returned instead of the default successful response.
	output *sts.AssumeRoleWithWebIdentityOutput
	// nilOutput makes the call return a nil response without an error.
	nilOutput bool
}

func (f *fakeSTS) AssumeRoleWithWebIdentity(_ context.Context, input *sts.AssumeRoleWithWebIdentityInput, _ ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error) {
	f.input = input
	if f.err != nil {
		return nil, f.err
	}
	if f.nilOutput {
		return nil, nil
	}
	if f.output != nil {
		return f.output, nil
	}
	return &sts.AssumeRoleWithWebIdentityOutput{
		Credentials: &ststypes.Credentials{
			AccessKeyId:     aws.String("AKIAEXAMPLE"),
			SecretAccessKey: aws.String("secret"),
			SessionToken:    aws.String("session-token"),
		},
	}, nil
}

func testPodInfo() config.PodInfo {
	return config.PodInfo{
		Name:               "my-pod",
		UID:                testPodUID,
		Namespace:          "my-ns",
		ServiceAccountName: "my-sa",
	}
}

func testServiceAccount(annotations map[string]string) *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "my-sa",
			Namespace:   "my-ns",
			Annotations: annotations,
		},
	}
}

// newTestAWSIAMAuth returns an AWSIAMAuth with a fake Kubernetes client.
// Created service account token requests are appended to tokenRequests. If
// fakeSTSClient is non-nil, it replaces the STS client; otherwise the
// production STS client factory from NewAWSIAMAuth is kept.
func newTestAWSIAMAuth(t *testing.T, params config.Parameters, fakeSTSClient *fakeSTS, tokenRequests *[]*authenticationv1.TokenRequest, objects ...runtime.Object) *AWSIAMAuth {
	t.Helper()
	k8sClient := fake.NewClientset(objects...)
	k8sClient.PrependReactor("create", "serviceaccounts", func(action k8stesting.Action) (bool, runtime.Object, error) {
		if action.GetSubresource() != "token" {
			return false, nil, nil
		}
		tr := action.(k8stesting.CreateAction).GetObject().(*authenticationv1.TokenRequest)
		*tokenRequests = append(*tokenRequests, tr)
		return true, &authenticationv1.TokenRequest{
			Status: authenticationv1.TokenRequestStatus{Token: "self-generated-token"},
		}, nil
	})

	a := NewAWSIAMAuth(hclog.NewNullLogger(), k8sClient, params)
	if fakeSTSClient != nil {
		a.newSTSClient = func(region, endpoint string) stsClient {
			fakeSTSClient.region = region
			fakeSTSClient.endpoint = endpoint
			return fakeSTSClient
		}
	}
	a.now = func() time.Time { return testSigningTime }
	return a
}

type decodedLoginData struct {
	method  string
	url     string
	body    string
	headers http.Header
}

func decodeLoginData(t *testing.T, body map[string]string) decodedLoginData {
	t.Helper()
	decode := func(key string) string {
		t.Helper()
		b, err := base64.StdEncoding.DecodeString(body[key])
		require.NoError(t, err, key)
		return string(b)
	}
	var headers http.Header
	require.NoError(t, json.Unmarshal([]byte(decode("iam_request_headers")), &headers))
	return decodedLoginData{
		method:  body["iam_http_request_method"],
		url:     decode("iam_request_url"),
		body:    decode("iam_request_body"),
		headers: headers,
	}
}

func TestAWSIAMAuth_AuthRequest(t *testing.T) {
	for name, tc := range map[string]struct {
		params                config.Parameters
		expectedPath          string
		expectedRegion        string
		expectedSTSEndpoint   string
		expectedURL           string
		expectedToken         string
		expectedTokenAudience string
		expectedServerID      string
	}{
		"defaults with self-generated token": {
			params: config.Parameters{
				VaultRoleName: "vault-role",
				VaultAuthType: config.AuthTypeAWS,
				PodInfo:       testPodInfo(),
			},
			expectedPath:          "/v1/auth/aws/login",
			expectedRegion:        "us-east-1",
			expectedURL:           "https://sts.amazonaws.com/",
			expectedToken:         "self-generated-token",
			expectedTokenAudience: "sts.amazonaws.com",
		},
		"custom audience for self-generated token": {
			params: config.Parameters{
				VaultRoleName: "vault-role",
				VaultAuthType: config.AuthTypeAWS,
				Audience:      "custom-audience",
				PodInfo:       testPodInfo(),
			},
			expectedPath:          "/v1/auth/aws/login",
			expectedRegion:        "us-east-1",
			expectedURL:           "https://sts.amazonaws.com/",
			expectedToken:         "self-generated-token",
			expectedTokenAudience: "custom-audience",
		},
		"all settings with token from mount request": {
			params: config.Parameters{
				VaultRoleName:      "vault-role",
				VaultAuthType:      config.AuthTypeAWS,
				VaultAuthMountPath: "my-aws",
				VaultAuthAWS: config.AWSAuth{
					Region:                 "us-west-2",
					IAMServerIDHeaderValue: "vault.example.com",
				},
				PodInfo: func() config.PodInfo {
					p := testPodInfo()
					p.ServiceAccountToken = "mount-request-token"
					return p
				}(),
			},
			expectedPath:     "/v1/auth/my-aws/login",
			expectedRegion:   "us-west-2",
			expectedURL:      "https://sts.us-west-2.amazonaws.com/",
			expectedToken:    "mount-request-token",
			expectedServerID: "vault.example.com",
		},
		"custom STS endpoint with the default region": {
			params: config.Parameters{
				VaultRoleName: "vault-role",
				VaultAuthType: config.AuthTypeAWS,
				VaultAuthAWS: config.AWSAuth{
					STSEndpoint: "https://sts-fips.us-east-1.amazonaws.com",
				},
				PodInfo: testPodInfo(),
			},
			expectedPath:          "/v1/auth/aws/login",
			expectedRegion:        "us-east-1",
			expectedSTSEndpoint:   "https://sts-fips.us-east-1.amazonaws.com",
			expectedURL:           "https://sts-fips.us-east-1.amazonaws.com/",
			expectedToken:         "self-generated-token",
			expectedTokenAudience: "sts.amazonaws.com",
		},
		"custom STS endpoint with a region": {
			params: config.Parameters{
				VaultRoleName: "vault-role",
				VaultAuthType: config.AuthTypeAWS,
				VaultAuthAWS: config.AWSAuth{
					Region:                 "eu-west-1",
					STSEndpoint:            "https://vpce-0123456789abcdef0-abcdefgh.sts.eu-west-1.vpce.amazonaws.com/",
					IAMServerIDHeaderValue: "vault.example.com",
				},
				PodInfo: testPodInfo(),
			},
			expectedPath:          "/v1/auth/aws/login",
			expectedRegion:        "eu-west-1",
			expectedSTSEndpoint:   "https://vpce-0123456789abcdef0-abcdefgh.sts.eu-west-1.vpce.amazonaws.com/",
			expectedURL:           "https://vpce-0123456789abcdef0-abcdefgh.sts.eu-west-1.vpce.amazonaws.com/",
			expectedToken:         "self-generated-token",
			expectedTokenAudience: "sts.amazonaws.com",
			expectedServerID:      "vault.example.com",
		},
	} {
		t.Run(name, func(t *testing.T) {
			fakeSTSClient := &fakeSTS{}
			var tokenRequests []*authenticationv1.TokenRequest
			a := newTestAWSIAMAuth(t, tc.params, fakeSTSClient, &tokenRequests,
				testServiceAccount(map[string]string{awsRoleARNAnnotation: testRoleARN}))

			path, body, err := a.AuthRequest(context.Background())
			require.NoError(t, err)
			require.Equal(t, tc.expectedPath, path)

			// Service account token.
			if tc.expectedTokenAudience == "" {
				require.Empty(t, tokenRequests)
			} else {
				require.Len(t, tokenRequests, 1)
				require.Equal(t, []string{tc.expectedTokenAudience}, tokenRequests[0].Spec.Audiences)
				require.Equal(t, &authenticationv1.BoundObjectReference{
					Kind:       "Pod",
					APIVersion: "v1",
					Name:       "my-pod",
					UID:        testPodUID,
				}, tokenRequests[0].Spec.BoundObjectRef)
			}

			// STS AssumeRoleWithWebIdentity.
			require.Equal(t, tc.expectedRegion, fakeSTSClient.region)
			require.Equal(t, tc.expectedSTSEndpoint, fakeSTSClient.endpoint)
			require.Equal(t, testRoleARN, aws.ToString(fakeSTSClient.input.RoleArn))
			require.Equal(t, tc.expectedToken, aws.ToString(fakeSTSClient.input.WebIdentityToken))
			require.Equal(t, "vault-csi-provider-"+testPodUID, aws.ToString(fakeSTSClient.input.RoleSessionName))

			// Vault login body.
			require.Len(t, body, 5)
			require.Equal(t, "vault-role", body["role"])
			data := decodeLoginData(t, body)
			require.Equal(t, http.MethodPost, data.method)
			require.Equal(t, tc.expectedURL, data.url)
			require.Equal(t, "Action=GetCallerIdentity&Version=2011-06-15", data.body)
			require.Equal(t, "session-token", data.headers.Get("X-Amz-Security-Token"))
			require.Equal(t, "20260102T030405Z", data.headers.Get("X-Amz-Date"))
			authz := data.headers.Get("Authorization")
			require.Contains(t, authz, "Credential=AKIAEXAMPLE/20260102/"+tc.expectedRegion+"/sts/aws4_request")
			if tc.expectedServerID == "" {
				require.Empty(t, data.headers.Values(iamServerIDHeader))
				require.NotContains(t, authz, "x-vault-aws-iam-server-id")
			} else {
				require.Equal(t, tc.expectedServerID, data.headers.Get(iamServerIDHeader))
				require.Contains(t, authz, "x-vault-aws-iam-server-id")
			}
		})
	}
}

// TestAWSIAMAuth_AuthRequest_EmptyRoleOmitted checks that an empty Vault role
// is left out of the login body instead of being sent as "".
func TestAWSIAMAuth_AuthRequest_EmptyRoleOmitted(t *testing.T) {
	var tokenRequests []*authenticationv1.TokenRequest
	a := newTestAWSIAMAuth(t, config.Parameters{
		VaultAuthType: config.AuthTypeAWS,
		PodInfo:       testPodInfo(),
	}, &fakeSTS{}, &tokenRequests, testServiceAccount(map[string]string{awsRoleARNAnnotation: testRoleARN}))

	_, body, err := a.AuthRequest(context.Background())
	require.NoError(t, err)
	require.NotContains(t, body, "role")
	require.Len(t, body, 4)
}

func TestAWSIAMAuth_AuthRequest_Errors(t *testing.T) {
	params := config.Parameters{
		VaultRoleName: "vault-role",
		VaultAuthType: config.AuthTypeAWS,
		PodInfo:       testPodInfo(),
	}
	for name, tc := range map[string]struct {
		objects     []runtime.Object
		fakeSTS     *fakeSTS
		expectedErr string
	}{
		"service account not found": {
			fakeSTS:     &fakeSTS{},
			expectedErr: "failed to get service account my-ns/my-sa",
		},
		"service account without role annotation": {
			objects:     []runtime.Object{testServiceAccount(nil)},
			fakeSTS:     &fakeSTS{},
			expectedErr: `service account my-ns/my-sa must have the "eks.amazonaws.com/role-arn" annotation`,
		},
		"assume role fails": {
			objects:     []runtime.Object{testServiceAccount(map[string]string{awsRoleARNAnnotation: testRoleARN})},
			fakeSTS:     &fakeSTS{err: errors.New("access denied")},
			expectedErr: `failed to assume IAM role "` + testRoleARN + `" with web identity: access denied`,
		},
		"assume role returns no response": {
			objects:     []runtime.Object{testServiceAccount(map[string]string{awsRoleARNAnnotation: testRoleARN})},
			fakeSTS:     &fakeSTS{nilOutput: true},
			expectedErr: `no credentials returned when assuming IAM role "` + testRoleARN + `"`,
		},
		"assume role returns no credentials": {
			objects:     []runtime.Object{testServiceAccount(map[string]string{awsRoleARNAnnotation: testRoleARN})},
			fakeSTS:     &fakeSTS{output: &sts.AssumeRoleWithWebIdentityOutput{}},
			expectedErr: `no credentials returned when assuming IAM role "` + testRoleARN + `"`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			var tokenRequests []*authenticationv1.TokenRequest
			a := newTestAWSIAMAuth(t, params, tc.fakeSTS, &tokenRequests, tc.objects...)
			path, body, err := a.AuthRequest(context.Background())
			require.ErrorContains(t, err, tc.expectedErr)
			require.Empty(t, path)
			require.Nil(t, body)
		})
	}
}

// TestGenerateIAMLoginData_VaultRoundTrip checks that the login data survives
// the Vault server's handling and still verifies at STS:
//  1. The HTTP request is rebuilt exactly as Vault does before forwarding it
//     to STS (vaultBuildHTTPRequest below is a copy of Vault's
//     buildHttpRequest), using the STS endpoint Vault would be configured
//     with for that region.
//  2. Vault forwards to fmt.Sprintf("%s/%s", endpoint, RequestURI), so our
//     signed path "/" arrives at STS as "//". STS verifies SigV4 signatures
//     against the normalized path (redundant empty segments removed), which
//     is why every Vault AWS IAM client works. The test applies the same
//     normalization and checks the signature STS computes matches ours.
func TestGenerateIAMLoginData_VaultRoundTrip(t *testing.T) {
	creds := aws.Credentials{AccessKeyID: "AKIAEXAMPLE", SecretAccessKey: "secret", SessionToken: "session-token"}
	for name, tc := range map[string]struct {
		region string
		// stsEndpoint is the provider's auth.aws.stsEndpoint setting.
		stsEndpoint string
		// vaultSTSEndpoint is the endpoint Vault forwards the request to:
		// Vault's default, or the sts_endpoint configured on
		// auth/aws/config/client to match the region and endpoint.
		vaultSTSEndpoint string
	}{
		"us-east-1, Vault default endpoint":                  {region: "us-east-1", vaultSTSEndpoint: "https://sts.amazonaws.com"},
		"eu-west-1, configured endpoint":                     {region: "eu-west-1", vaultSTSEndpoint: "https://sts.eu-west-1.amazonaws.com"},
		"eu-west-1, configured endpoint with trailing slash": {region: "eu-west-1", vaultSTSEndpoint: "https://sts.eu-west-1.amazonaws.com/"},
		"us-gov-west-1, configured endpoint":                 {region: "us-gov-west-1", vaultSTSEndpoint: "https://sts.us-gov-west-1.amazonaws.com"},
		"cn-north-1, configured endpoint":                    {region: "cn-north-1", vaultSTSEndpoint: "https://sts.cn-north-1.amazonaws.com.cn"},
		"us-east-1, custom FIPS endpoint": {
			region:           "us-east-1",
			stsEndpoint:      "https://sts-fips.us-east-1.amazonaws.com",
			vaultSTSEndpoint: "https://sts-fips.us-east-1.amazonaws.com",
		},
		"eu-west-1, custom VPC endpoint with trailing slash": {
			region:           "eu-west-1",
			stsEndpoint:      "https://vpce-0123456789abcdef0-abcdefgh.sts.eu-west-1.vpce.amazonaws.com/",
			vaultSTSEndpoint: "https://vpce-0123456789abcdef0-abcdefgh.sts.eu-west-1.vpce.amazonaws.com",
		},
	} {
		t.Run(name, func(t *testing.T) {
			body, err := generateIAMLoginData(context.Background(), creds, tc.region, tc.stsEndpoint, "vault.example.com", testSigningTime)
			require.NoError(t, err)
			data := decodeLoginData(t, body)

			parsedURL, err := url.Parse(data.url)
			require.NoError(t, err)
			require.Equal(t, "/", parsedURL.Path)
			// Vault's sts_endpoint must point at the host the request was signed for.
			require.Equal(t, "https://"+parsedURL.Host, strings.TrimSuffix(tc.vaultSTSEndpoint, "/"))

			// 1. Rebuild the request exactly as Vault does.
			forwarded := vaultBuildHTTPRequest(data.method, tc.vaultSTSEndpoint, parsedURL, data.body, data.headers)
			require.NotNil(t, forwarded)
			require.Equal(t, parsedURL.Host, forwarded.Host, "Vault must send the signed Host")
			require.True(t, strings.HasPrefix(forwarded.URL.Path, "//"), "Vault forwards %q, not the signed path %q", forwarded.URL.Path, parsedURL.Path)
			require.Equal(t, data.headers, forwarded.Header, "Vault must forward the signed headers unchanged")
			forwardedBody, err := io.ReadAll(forwarded.Body)
			require.NoError(t, err)
			require.Equal(t, data.body, string(forwardedBody))

			// 2. Verify the signature as STS does: against the normalized path,
			// using the headers exactly as forwarded (including X-Amz-Date).
			normalizedPath := normalizeSigV4Path(forwarded.URL.Path)
			require.Equal(t, parsedURL.Path, normalizedPath)
			signedAt, err := time.Parse("20060102T150405Z", forwarded.Header.Get("X-Amz-Date"))
			require.NoError(t, err)

			verify := forwarded.Clone(context.Background())
			verify.URL.Path = normalizedPath
			verify.URL.RawPath = ""
			verify.Header.Del("Authorization")
			verify.Body = io.NopCloser(strings.NewReader(string(forwardedBody)))
			payloadHash := sha256.Sum256(forwardedBody)
			require.NoError(t, v4.NewSigner().SignHTTP(context.Background(), creds, verify, hex.EncodeToString(payloadHash[:]), "sts", tc.region, signedAt))

			// Re-signing must reproduce every forwarded header, so nothing that
			// STS checks was changed after signing, and the signatures match.
			require.Equal(t, forwarded.Header, verify.Header)
			sent := data.headers.Get("Authorization")
			require.Contains(t, sent, "x-vault-aws-iam-server-id", "the server ID header must be signed")
		})
	}
}

// vaultBuildHTTPRequest is a copy of buildHttpRequest from Vault's
// builtin/credential/aws/path_login.go, which rebuilds the client's signed
// GetCallerIdentity request before Vault forwards it to STS.
func vaultBuildHTTPRequest(method, endpoint string, parsedUrl *url.URL, body string, headers http.Header) *http.Request {
	targetUrl := fmt.Sprintf("%s/%s", endpoint, parsedUrl.RequestURI())
	request, err := http.NewRequest(method, targetUrl, strings.NewReader(body))
	if err != nil {
		return nil
	}
	request.Host = parsedUrl.Host
	for k, vals := range headers {
		for _, val := range vals {
			request.Header.Add(k, val)
		}
	}
	return request
}

// normalizeSigV4Path normalizes a URI path the way AWS SigV4 does for
// services other than S3: redundant ("//") and relative ("." and "..") path
// segments are removed, and a trailing slash is kept.
func normalizeSigV4Path(p string) string {
	var segments []string
	for _, s := range strings.Split(p, "/") {
		switch s {
		case "", ".":
		case "..":
			if len(segments) > 0 {
				segments = segments[:len(segments)-1]
			}
		default:
			segments = append(segments, s)
		}
	}
	normalized := "/" + strings.Join(segments, "/")
	if strings.HasSuffix(p, "/") && normalized != "/" {
		normalized += "/"
	}
	return normalized
}

func TestNormalizeSigV4Path(t *testing.T) {
	for in, expected := range map[string]string{
		"/":         "/",
		"//":        "/",
		"///":       "/",
		"//a//b/":   "/a/b/",
		"/a/./b":    "/a/b",
		"/a/b/../c": "/a/c",
	} {
		require.Equal(t, expected, normalizeSigV4Path(in), in)
	}
}

func TestNewAuthMethod(t *testing.T) {
	k8sClient := fake.NewClientset()
	for authType, expected := range map[string]Method{
		"":                        &KubernetesJWTAuth{},
		config.AuthTypeKubernetes: &KubernetesJWTAuth{},
		config.AuthTypeAWS:        &AWSIAMAuth{},
	} {
		method, err := NewAuthMethod(hclog.NewNullLogger(), k8sClient, config.Parameters{VaultAuthType: authType}, "kubernetes")
		require.NoError(t, err, authType)
		require.IsType(t, expected, method, authType)
	}

	_, err := NewAuthMethod(hclog.NewNullLogger(), k8sClient, config.Parameters{VaultAuthType: "gcp"}, "kubernetes")
	require.ErrorContains(t, err, `unsupported auth type "gcp"`)
}
