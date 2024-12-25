package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/service/sts/stsiface"
	"github.com/golang-jwt/jwt/v4"
	"github.com/hashicorp/go-hclog"
	authv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"errors"
	"fmt"
	"k8s.io/client-go/kubernetes"
	"testing"

	"github.com/hashicorp/vault-csi-provider/internal/config"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// Mock STS Client
type mockSTSClient struct {
	stsiface.STSAPI
}

func (m *mockSTSClient) AssumeRoleWithWebIdentity(input *sts.AssumeRoleWithWebIdentityInput) (*sts.AssumeRoleWithWebIdentityOutput, error) {
	if aws.StringValue(input.RoleArn) == "" {
		return nil, errors.New("role ARN is empty")
	}
	if aws.StringValue(input.WebIdentityToken) == "" {
		return nil, errors.New("web identity token is empty")
	}

	return &sts.AssumeRoleWithWebIdentityOutput{
		Credentials: &sts.Credentials{
			AccessKeyId:     aws.String("mockAccessKey"),
			SecretAccessKey: aws.String("mockSecretKey"),
			SessionToken:    aws.String("mockSessionToken"),
			Expiration:      aws.Time(time.Now().Add(1 * time.Hour)),
		},
	}, nil
}

func (m *mockSTSClient) AssumeRoleWithWebIdentityRequest(input *sts.AssumeRoleWithWebIdentityInput) (*request.Request, *sts.AssumeRoleWithWebIdentityOutput) {
	_ = input
	req := &request.Request{
		HTTPRequest: &http.Request{
			Method: "POST",
			URL:    &url.URL{Scheme: "https", Host: "sts.amazonaws.com", Path: "/"},
			Header: make(http.Header),
		},
		Operation: &request.Operation{
			Name:       "AssumeRoleWithWebIdentity",
			HTTPMethod: "POST",
			HTTPPath:   "/",
		},
		Data: &sts.AssumeRoleWithWebIdentityOutput{
			Credentials: &sts.Credentials{
				AccessKeyId:     aws.String("mockAccessKey"),
				SecretAccessKey: aws.String("mockSecretKey"),
				SessionToken:    aws.String("mockSessionToken"),
				Expiration:      aws.Time(time.Now().Add(1 * time.Hour)),
			},
		},
	}
	return req, req.Data.(*sts.AssumeRoleWithWebIdentityOutput)
}

// GenerateDummyPrivateKey generates a dummy RSA private key for testing.
func GenerateDummyPrivateKey() (string, error) {
	// Generate a new RSA private key.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", fmt.Errorf("failed to generate private key: %w", err)
	}

	// Encode the private key into PEM format.
	privKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	return string(privKeyPEM), nil
}

const (
	dummyIssuer = "https://oidc.eks.us-east-1.amazonaws.com/id/ABCDEFG7383928EEC764D2049AE19A7F5"
	// Mock service account
	serviceAccountName = "test-service-account"
	namespace          = "test-namespace"
	roleArn            = "arn:aws:iam::123456789012:role/test-role"
	tokenAudience      = "sts.amazonaws.com"
)

// GenerateValidToken generates a Kubernetes-like ServiceAccount token.
func GenerateMockValidToken(privateKey []byte, audiences []string, expiration time.Duration) (string, error) {
	key, err := jwt.ParseRSAPrivateKeyFromPEM(privateKey)
	if err != nil {
		return "", fmt.Errorf("unable to parse private key: %w", err)
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"iss": dummyIssuer,
		"sub": "system:serviceaccount:" + namespace + ":" + serviceAccountName,
		"aud": audiences,
		"exp": now.Add(expiration).Unix(),
		"iat": now.Unix(),
		"nbf": now.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signedToken, err := token.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("unable to sign token: %w", err)
	}

	return signedToken, nil
}

func MockNewIAMAuth(logger hclog.Logger, k8sClient kubernetes.Interface, params config.Parameters, defaultMountPath string) (*AWSIAMAuth, error) {
	return &AWSIAMAuth{
		logger:           logger,
		k8sClient:        k8sClient,
		params:           params,
		defaultMountPath: defaultMountPath,
		stsClient:        &mockSTSClient{},
	}, nil

}

func SetupFakeClientWithTokenReactor() *fake.Clientset {
	fakeClient := fake.NewClientset()

	// Add reactor for ServiceAccount token creation
	fakeClient.PrependReactor("create", "serviceaccounts/token", func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
		createAction, ok := action.(k8stesting.CreateAction)
		if !ok {
			return false, nil, fmt.Errorf("invalid action type")
		}

		tokenRequest, ok := createAction.GetObject().(*authv1.TokenRequest)
		if !ok {
			return false, nil, fmt.Errorf("unexpected object type: %T", createAction.GetObject())
		}

		if !strings.Contains(strings.Join(tokenRequest.Spec.Audiences, ","), "sts.amazonaws.com") {
			return true, nil, fmt.Errorf("invalid audience")
		}

		privateKey, err := GenerateDummyPrivateKey()
		if err != nil {
			fmt.Printf("Error generating private key: %v\n", err)
		}

		token, err := GenerateMockValidToken([]byte(privateKey), tokenRequest.Spec.Audiences, 1*time.Hour)
		if err != nil {
			return true, nil, fmt.Errorf("failed to generate token: %w", err)
		}

		// Mock TokenResponse
		expiration := metav1.NewTime(time.Now().Add(1 * time.Hour))
		tokenResponse := &authv1.TokenRequest{
			Status: authv1.TokenRequestStatus{
				Token:               token,
				ExpirationTimestamp: expiration,
			},
		}

		return true, tokenResponse, nil
	})

	return fakeClient
}

func TestAuthRequest(t *testing.T) {
	// Mock Kubernetes client
	k8sClient := SetupFakeClientWithTokenReactor()

	// Create a mock service account with annotations
	mockSA := &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ServiceAccount",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      serviceAccountName,
			Namespace: namespace,
			Annotations: map[string]string{
				roleARNAnnotation:  roleArn,
				audienceAnnotation: tokenAudience,
			},
		},
	}

	ctx := context.TODO()

	_, err := k8sClient.CoreV1().ServiceAccounts(namespace).Create(ctx, mockSA, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("failed to create mock service account: %v", err)
	}

	// Create a logger
	logger := hclog.New(&hclog.LoggerOptions{
		Name:  "test-logger",
		Level: hclog.Debug,
	})

	// Mock parameters
	params := config.Parameters{
		PodInfo: config.PodInfo{
			Namespace:          namespace,
			ServiceAccountName: serviceAccountName,
		},
		VaultAuth: config.Auth{
			MouthPath: "awstest",
			AWSIAMAuth: config.AWSIAMAuth{
				Region:               "us-east-1",
				AWSIAMRole:           "test-role",
				XVaultAWSIAMServerID: "test-server-id",
			},
		},
	}

	// Initialize Mock AWSIAMAuth
	// Initialize AWSIAMAuth
	auth, err := MockNewIAMAuth(logger, k8sClient, params, "aws")
	if err != nil {
		t.Fatalf("failed to create AWSIAMAuth: %v", err)
	}

	// Call AuthRequest
	path, body, headers, err := auth.AuthRequest(context.TODO())
	if err != nil {
		t.Fatalf("AuthRequest failed: %v", err)
	}

	// Validate outputs
	expectedPath := "/v1/auth/awstest/login"
	if path != expectedPath {
		t.Errorf("expected path %s, got %s", expectedPath, path)
	}

	if body["role"] != "test-role" {
		t.Errorf("expected role %s, got %s", "test-role", body["role"])
	}

	if len(headers) == 0 {
		t.Errorf("expected headers, got none")
	}

	if len(headers) > 0 && headers["iam_server_id_header_value"] != "test-server-id" {
		t.Errorf("unexpected IAM server ID header value: %s", headers["iam_server_id_header_value"])
	}
}

func TestAuthRequestMissingAnnotations(t *testing.T) {
	// Mock Kubernetes client
	k8sClient := fake.NewClientset()

	// Create a service account without annotations
	serviceAccountName := "test-service-account"
	namespace := "test-namespace"

	mockSA := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      serviceAccountName,
			Namespace: namespace,
		},
	}
	_, err := k8sClient.CoreV1().ServiceAccounts(namespace).Create(context.TODO(), mockSA, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("failed to create mock service account: %v", err)
	}

	// Create a logger
	logger := hclog.New(&hclog.LoggerOptions{
		Name:  "test-logger",
		Level: hclog.Debug,
	})

	// Mock parameters
	params := config.Parameters{
		PodInfo: config.PodInfo{
			Namespace:          namespace,
			ServiceAccountName: serviceAccountName,
		},
		VaultAuth: config.Auth{
			AWSIAMAuth: config.AWSIAMAuth{
				Region: "us-east-1",
			},
		},
	}

	// Initialize AWSIAMAuth
	auth, err := NewAWSIAMAuth(logger, k8sClient, params, "aws")
	if err != nil {
		t.Fatalf("failed to create AWSIAMAuth: %v", err)
	}

	// Call AuthRequest and expect an error
	_, _, _, err = auth.AuthRequest(context.TODO())
	if err == nil {
		t.Fatalf("expected error, got none")
	}

	expectedError := fmt.Sprintf("an IAM role must be associated with service account %s (namespace: %s)", serviceAccountName, namespace)
	if err.Error() != expectedError {
		t.Errorf("expected error %s, got %s", expectedError, err.Error())
	}
}
