// Copyright IBM Corp. 2019, 2026
// SPDX-License-Identifier: BUSL-1.1

package clientcache

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/require"

	vaultclient "github.com/hashicorp/vault-csi-provider/internal/client"
	"github.com/hashicorp/vault-csi-provider/internal/config"
)

// Parameters fields that are deliberately excluded from the cache key.
var cacheKeyExcludedFields = map[string]bool{
	"Secrets":                     true,
	"PodInfo.ServiceAccountToken": true,
}

// TestCacheKey_AllParameterFieldsAffectKey guards against new fields being
// added to config.Parameters (e.g. future auth settings) without being part
// of the client cache key. Every field must change the key unless it is
// deliberately listed in cacheKeyExcludedFields. Otherwise, mounts with
// different settings could reuse a cached Vault client and its token.
func TestCacheKey_AllParameterFieldsAffectKey(t *testing.T) {
	baseKey, err := makeCacheKey(config.Parameters{})
	require.NoError(t, err)

	fields := leafFields(t, reflect.TypeOf(config.Parameters{}), "", nil)
	require.NotEmpty(t, fields)
	for _, field := range fields {
		t.Run(field.path, func(t *testing.T) {
			var params config.Parameters
			setNonZero(t, reflect.ValueOf(&params).Elem().FieldByIndex(field.index))
			key, err := makeCacheKey(params)
			require.NoError(t, err)
			if cacheKeyExcludedFields[field.path] {
				require.Equal(t, baseKey, key, "%s is excluded from the cache key and must not change it", field.path)
			} else {
				require.NotEqual(t, baseKey, key, "%s must be part of the client cache key", field.path)
			}
		})
	}
}

// TestCacheKey_AuthSettingsIsolateClients checks that mounts which differ in
// any auth-related setting get separate Vault clients (and so separate Vault
// tokens), while changes to the service account token or the requested
// secrets reuse the same client.
func TestCacheKey_AuthSettingsIsolateClients(t *testing.T) {
	base := config.Parameters{
		VaultAddress:       "http://vault:8200",
		VaultRoleName:      "app-role",
		VaultAuthMountPath: "aws",
		VaultAuthType:      config.AuthTypeAWS,
		VaultAuthAWS: config.AWSAuth{
			Region:                 "us-west-2",
			IAMServerIDHeaderValue: "vault.example.com",
		},
		PodInfo: config.PodInfo{
			Name:                "app",
			UID:                 "pod-uid",
			Namespace:           "app-ns",
			ServiceAccountName:  "app-sa",
			ServiceAccountToken: "token-1",
		},
		Audience: "sts.amazonaws.com",
	}

	for name, tc := range map[string]struct {
		mutate      func(p *config.Parameters)
		reuseClient bool
	}{
		"different auth type":            {mutate: func(p *config.Parameters) { p.VaultAuthType = config.AuthTypeKubernetes }},
		"different Vault role":           {mutate: func(p *config.Parameters) { p.VaultRoleName = "other-role" }},
		"different mount path":           {mutate: func(p *config.Parameters) { p.VaultAuthMountPath = "aws-custom" }},
		"different AWS region":           {mutate: func(p *config.Parameters) { p.VaultAuthAWS.Region = "eu-west-1" }},
		"different IAM server ID header": {mutate: func(p *config.Parameters) { p.VaultAuthAWS.IAMServerIDHeaderValue = "other.example.com" }},
		"different STS endpoint":         {mutate: func(p *config.Parameters) { p.VaultAuthAWS.STSEndpoint = "https://sts-fips.us-west-2.amazonaws.com" }},
		"no IAM server ID header":        {mutate: func(p *config.Parameters) { p.VaultAuthAWS.IAMServerIDHeaderValue = "" }},
		"different token audience":       {mutate: func(p *config.Parameters) { p.Audience = "custom" }},
		"different Vault namespace":      {mutate: func(p *config.Parameters) { p.VaultNamespace = "team-a" }},
		"different Vault address":        {mutate: func(p *config.Parameters) { p.VaultAddress = "http://other-vault:8200" }},
		"different service account":      {mutate: func(p *config.Parameters) { p.PodInfo.ServiceAccountName = "other-sa" }},
		"different pod":                  {mutate: func(p *config.Parameters) { p.PodInfo.UID = "other-pod-uid" }},
		"new service account token only": {mutate: func(p *config.Parameters) { p.PodInfo.ServiceAccountToken = "token-2" }, reuseClient: true},
		"different secrets only":         {mutate: func(p *config.Parameters) { p.Secrets = []config.Secret{{ObjectName: "x"}} }, reuseClient: true},
	} {
		t.Run(name, func(t *testing.T) {
			cache, err := NewClientCache(hclog.NewNullLogger(), 10)
			require.NoError(t, err)

			c1, err := cache.GetOrCreateClient(base, config.FlagsConfig{})
			require.NoError(t, err)
			other := base
			tc.mutate(&other)
			c2, err := cache.GetOrCreateClient(other, config.FlagsConfig{})
			require.NoError(t, err)

			if tc.reuseClient {
				require.Same(t, c1, c2)
				require.Equal(t, 1, cache.cache.Len())
			} else {
				require.NotSame(t, c1, c2)
				require.Equal(t, 2, cache.cache.Len())
			}
		})
	}
}

// TestCacheKey_SecretProviderClassAuthIsolation runs SecretProviderClass
// parameters through config.Parse, as a real mount request does, and checks
// which pairs of SecretProviderClasses for the same pod share a cached Vault
// client. The cache key is built from the resolved parameters, so
// SecretProviderClasses that resolve to the same auth configuration may
// share a client, and anything else must not.
func TestCacheKey_SecretProviderClassAuthIsolation(t *testing.T) {
	podParams := map[string]string{
		"vaultAddress":                           "http://vault:8200",
		"objects":                                "- objectName: foo\n  secretPath: secret/data/foo\n  secretKey: foo",
		"csi.storage.k8s.io/pod.name":            "app",
		"csi.storage.k8s.io/pod.uid":             "pod-uid",
		"csi.storage.k8s.io/pod.namespace":       "app-ns",
		"csi.storage.k8s.io/serviceAccount.name": "app-sa",
	}
	spc := func(extra map[string]string) map[string]string {
		params := map[string]string{}
		for k, v := range podParams {
			params[k] = v
		}
		for k, v := range extra {
			params[k] = v
		}
		return params
	}

	for name, tc := range map[string]struct {
		a, b        map[string]string
		reuseClient bool
	}{
		"kubernetes vs aws auth, same role": {
			a: spc(map[string]string{"roleName": "app-role"}),
			b: spc(map[string]string{"roleName": "app-role", "auth": "type: aws"}),
		},
		"aws with auth.role override vs roleName": {
			a: spc(map[string]string{"roleName": "k8s-role", "auth": "type: aws\nrole: aws-role"}),
			b: spc(map[string]string{"roleName": "k8s-role", "auth": "type: aws"}),
		},
		"aws, different mount paths": {
			a: spc(map[string]string{"roleName": "app-role", "auth": "type: aws"}),
			b: spc(map[string]string{"roleName": "app-role", "auth": "type: aws\nmountPath: aws-custom"}),
		},
		"aws, different regions": {
			a: spc(map[string]string{"roleName": "app-role", "auth": "type: aws"}),
			b: spc(map[string]string{"roleName": "app-role", "auth": "type: aws\naws:\n  region: us-west-2"}),
		},
		"aws, with and without IAM server ID header": {
			a: spc(map[string]string{"roleName": "app-role", "auth": "type: aws"}),
			b: spc(map[string]string{"roleName": "app-role", "auth": "type: aws\naws:\n  iamServerIDHeaderValue: vault.example.com"}),
		},
		"aws, with and without STS endpoint": {
			a: spc(map[string]string{"roleName": "app-role", "auth": "type: aws"}),
			b: spc(map[string]string{"roleName": "app-role", "auth": "type: aws\naws:\n  region: us-east-1\n  stsEndpoint: https://sts-fips.us-east-1.amazonaws.com"}),
		},
		"kubernetes, different mount paths": {
			a: spc(map[string]string{"roleName": "app-role", "vaultKubernetesMountPath": "kubernetes"}),
			b: spc(map[string]string{"roleName": "app-role", "vaultAuthMountPath": "jwt"}),
		},
		"equivalent: roleName vs auth.role with the same value": {
			a:           spc(map[string]string{"roleName": "app-role", "auth": "type: aws"}),
			b:           spc(map[string]string{"auth": "type: aws\nrole: app-role"}),
			reuseClient: true,
		},
		"equivalent: legacy vaultAuthMountPath vs auth.mountPath": {
			a:           spc(map[string]string{"roleName": "app-role", "vaultAuthMountPath": "jwt"}),
			b:           spc(map[string]string{"roleName": "app-role", "auth": "mountPath: jwt"}),
			reuseClient: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			cache, err := NewClientCache(hclog.NewNullLogger(), 10)
			require.NoError(t, err)
			c1 := clientForSPC(t, cache, tc.a)
			c2 := clientForSPC(t, cache, tc.b)
			if tc.reuseClient {
				require.Same(t, c1, c2)
			} else {
				require.NotSame(t, c1, c2)
			}
		})
	}
}

func clientForSPC(t *testing.T, cache *ClientCache, spcParams map[string]string) *vaultclient.Client {
	t.Helper()
	paramsJSON, err := json.Marshal(spcParams)
	require.NoError(t, err)
	cfg, err := config.Parse(string(paramsJSON), "/target", "420")
	require.NoError(t, err)
	client, err := cache.GetOrCreateClient(cfg.Parameters, config.FlagsConfig{})
	require.NoError(t, err)
	return client
}

type leafField struct {
	path  string
	index []int
}

// leafFields returns the paths and indexes of all exported leaf fields of a
// struct type, recursing into nested structs.
func leafFields(t *testing.T, typ reflect.Type, prefix string, index []int) []leafField {
	t.Helper()
	var fields []leafField
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if !f.IsExported() {
			continue
		}
		path := strings.TrimPrefix(prefix+"."+f.Name, ".")
		idx := append(append([]int{}, index...), i)
		if f.Type.Kind() == reflect.Struct {
			fields = append(fields, leafFields(t, f.Type, path, idx)...)
			continue
		}
		fields = append(fields, leafField{path: path, index: idx})
	}
	return fields
}

func setNonZero(t *testing.T, v reflect.Value) {
	t.Helper()
	switch v.Kind() {
	case reflect.String:
		v.SetString("x")
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(1)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(1)
	case reflect.Slice:
		v.Set(reflect.MakeSlice(v.Type(), 1, 1))
	case reflect.Map:
		v.Set(reflect.MakeMap(v.Type()))
		v.SetMapIndex(reflect.New(v.Type().Key()).Elem(), reflect.New(v.Type().Elem()).Elem())
	default:
		t.Fatalf("unsupported field kind %s: extend setNonZero", v.Kind())
	}
}
