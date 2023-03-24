package config

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/hashicorp/go-hclog"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"
)

func ParseHMACSecretConfig(logger hclog.Logger, secretName, namespaceFile, labelsFile, annotationsFile string) (*corev1.Secret, error) {
	namespace, err := os.ReadFile(namespaceFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read namespace from file: %s", err)
	}

	labels, err := parseMetadata(labelsFile)
	if err != nil {
		if os.IsNotExist(err) {
			logger.Warn("No labels metadata file found", "path", labelsFile)
		} else {
			return nil, fmt.Errorf("failed to read labels to use for HMAC key secret: %s", err)
		}
	}
	annotations, err := parseMetadata(annotationsFile)
	if err != nil {
		if os.IsNotExist(err) {
			logger.Warn("No annotations metadata file found", "path", annotationsFile)
		} else {
			return nil, fmt.Errorf("failed to read annotations to use for HMAC key secret: %s", err)
		}
	}

	hmacSecretSpec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        secretName,
			Namespace:   string(namespace),
			Labels:      labels,
			Annotations: annotations,
		},
		Immutable: pointer.Bool(true),
	}

	return hmacSecretSpec, nil
}

func parseMetadata(file string) (map[string]string, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	result := map[string]string{}
	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("expected key=\"value\" format, but got: %s", line)
		}
		// The way these map values get written by Kubernetes ultimately boils
		// down to strconv.AppendQuote on this line:
		// https://github.com/kubernetes/kubernetes/blob/d2be69ac11346d2a0fab8c3c168c4255db99c56f/pkg/fieldpath/fieldpath.go#L48
		// So we use strconv.Unquote to recover the original value.
		value, err := strconv.Unquote(parts[1])
		if err != nil {
			return nil, fmt.Errorf("error unquoting value %s from line %s: %w", parts[1], line, err)
		}
		result[parts[0]] = value
	}

	return result, nil
}
