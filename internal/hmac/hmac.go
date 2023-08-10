// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package hmac

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	hmacKeyName   = "key"
	hmacKeyLength = 32
)

var errDeleteSecret = errors.New("delete the kubernetes secret to trigger an automatic regeneration")

func NewHMACGenerator(client kubernetes.Interface, secretSpec *corev1.Secret) *HMACGenerator {
	return &HMACGenerator{
		client:     client,
		secretSpec: secretSpec,
	}
}

type HMACGenerator struct {
	client     kubernetes.Interface
	secretSpec *corev1.Secret
}

// GetOrCreateHMACKey will try to read an HMAC key from a Kubernetes secret and
// race with other pods to create it if not found. The HMAC key is persisted to
// a Kubernetes secret to ensure all pods are deterministically producing the
// same version hashes when given the same inputs.
func (g *HMACGenerator) GetOrCreateHMACKey(ctx context.Context) ([]byte, error) {
	// Fast path - most of the time the secret will already be created.
	secret, err := g.client.CoreV1().Secrets(g.secretSpec.Namespace).Get(ctx, g.secretSpec.Name, metav1.GetOptions{})
	if err == nil {
		return hmacKeyFromSecret(secret)
	}
	if !apierrors.IsNotFound(err) {
		return nil, err
	}

	// Secret not found. We'll join the race to create it.
	hmacKeyCandidate := make([]byte, hmacKeyLength)
	_, err = rand.Read(hmacKeyCandidate)
	if err != nil {
		return nil, err
	}

	// Make a copy of the secretSpec to avoid a data race.
	secretSpec := *g.secretSpec
	secretSpec.Data = map[string][]byte{
		hmacKeyName: hmacKeyCandidate,
	}

	var persistedHMACSecret *corev1.Secret

	// Try to create first
	persistedHMACSecret, err = g.client.CoreV1().Secrets(secretSpec.Namespace).Create(ctx, &secretSpec, metav1.CreateOptions{})
	switch {
	case err == nil:
		// We created the secret, nothing to handle.
	case apierrors.IsAlreadyExists(err):
		// We lost the race to create the secret. Read the existing secret instead.
		persistedHMACSecret, err = g.client.CoreV1().Secrets(secretSpec.Namespace).Get(ctx, secretSpec.Name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
	default:
		// Unexpected error case.
		return nil, err
	}

	return hmacKeyFromSecret(persistedHMACSecret)
}

func hmacKeyFromSecret(secret *corev1.Secret) ([]byte, error) {
	hmacKey, ok := secret.Data[hmacKeyName]
	if !ok {
		return nil, fmt.Errorf("expected secret %q to have a key %q; %w", secret.Name, hmacKeyName, errDeleteSecret)
	}

	if len(hmacKey) == 0 {
		return nil, fmt.Errorf("expected secret %q to have a non-zero HMAC key; %w", secret.Name, errDeleteSecret)
	}

	return hmacKey, nil
}
