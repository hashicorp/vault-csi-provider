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
	region string
	input  *sts.AssumeRoleWithWebIdentityInput
	err    error
}

func (f *fakeSTS) AssumeRoleWithWebIdentity(_ context.Context, input *sts.AssumeRoleWithWebIdentityInput, _ ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error) {
	f.input = input
	if f.err != nil {
		return nil, f.err
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

// newTestAWSIAMAuth returns an AWSIAMAuth with fake Kubernetes and STS
// clients. Created service account token requests are appended to
// tokenRequests.
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
	a.newSTSClient = func(region string) stsClient {
		fakeSTSClient.region = region
		return fakeSTSClient
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

func TestAWSIAMAuth_AuthRequest_Errors(t *testing.T) {
	params := config.Parameters{
		VaultRoleName: "vault-role",
		VaultAuthType: config.AuthTypeAWS,
		PodInfo:       testPodInfo(),
	}
	for name, tc := range map[string]struct {
		objects     []runtime.Object
		stsErr      error
		expectedErr string
	}{
		"service account not found": {
			expectedErr: "failed to get service account my-ns/my-sa",
		},
		"service account without role annotation": {
			objects:     []runtime.Object{testServiceAccount(nil)},
			expectedErr: `service account my-ns/my-sa must have the "eks.amazonaws.com/role-arn" annotation`,
		},
		"assume role fails": {
			objects:     []runtime.Object{testServiceAccount(map[string]string{awsRoleARNAnnotation: testRoleARN})},
			stsErr:      errors.New("access denied"),
			expectedErr: `failed to assume IAM role "` + testRoleARN + `" with web identity: access denied`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			var tokenRequests []*authenticationv1.TokenRequest
			a := newTestAWSIAMAuth(t, params, &fakeSTS{err: tc.stsErr}, &tokenRequests, tc.objects...)
			_, _, err := a.AuthRequest(context.Background())
			require.ErrorContains(t, err, tc.expectedErr)
		})
	}
}

// TestGenerateIAMLoginData_VaultRoundTrip rebuilds the HTTP request from the
// login data the same way the Vault server does before forwarding it to STS,
// and checks that re-signing it produces the same signature. This ensures
// the encoded URL, headers and body are exactly what was signed.
func TestGenerateIAMLoginData_VaultRoundTrip(t *testing.T) {
	creds := aws.Credentials{AccessKeyID: "AKIAEXAMPLE", SecretAccessKey: "secret", SessionToken: "session-token"}
	for _, region := range []string{"us-east-1", "eu-west-1", "us-gov-west-1", "cn-north-1"} {
		t.Run(region, func(t *testing.T) {
			body, err := generateIAMLoginData(context.Background(), creds, region, "vault.example.com", testSigningTime)
			require.NoError(t, err)
			data := decodeLoginData(t, body)

			parsedURL, err := url.Parse(data.url)
			require.NoError(t, err)
			require.True(t, strings.HasPrefix(parsedURL.Host, "sts."), parsedURL.Host)

			// Mirrors buildHttpRequest in Vault's builtin/credential/aws/path_login.go.
			rebuilt, err := http.NewRequest(data.method, "https://"+parsedURL.Host+parsedURL.RequestURI(), strings.NewReader(data.body))
			require.NoError(t, err)
			rebuilt.Host = parsedURL.Host
			for k, vals := range data.headers {
				if k == "Authorization" {
					continue
				}
				for _, v := range vals {
					rebuilt.Header.Add(k, v)
				}
			}

			b, err := io.ReadAll(rebuilt.Body)
			require.NoError(t, err)
			payloadHash := sha256.Sum256(b)
			require.NoError(t, v4.NewSigner().SignHTTP(context.Background(), creds, rebuilt, hex.EncodeToString(payloadHash[:]), "sts", region, testSigningTime))
			require.Equal(t, data.headers.Get("Authorization"), rebuilt.Header.Get("Authorization"))
		})
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
