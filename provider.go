package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/net/context"
	yaml "gopkg.in/yaml.v2"

	"github.com/pkg/errors"
	"golang.org/x/net/http2"

	log "github.com/sirupsen/logrus"
	pb "sigs.k8s.io/secrets-store-csi-driver/provider/v1alpha1"
)

const (
	// VaultObjectTypeSecret secret vault object type for HashiCorp vault
	defaultVaultAddress                 string = "https://127.0.0.1:8200"
	defaultKubernetesServiceAccountPath string = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	defaultVaultKubernetesMountPath     string = "kubernetes"
)

var (
	_ pb.CSIDriverProviderServer = &ProviderServer{}
)

// Provider implements the secrets-store-csi-driver provider interface
// and communicates with the Vault API.
type Provider struct {
	VaultAddress                 string
	VaultCAPem                   string
	VaultCACert                  string
	VaultCAPath                  string
	VaultRole                    string
	VaultSkipVerify              bool
	VaultServerName              string
	VaultK8SMountPath            string
	KubernetesServiceAccountPath string
}

// ProviderServer implements the secrets-store-csi-driver provider gRPC service interface.
type ProviderServer struct {
}

func (p *ProviderServer) Version(context.Context, *pb.VersionRequest) (*pb.VersionResponse, error) {
	log.Info("Processing version method call")
	return &pb.VersionResponse{
		Version:        "v1alpha1",
		RuntimeName:    "secrets-store-csi-driver-provider-vault",
		RuntimeVersion: BuildVersion,
	}, nil
}

func (p *ProviderServer) Mount(ctx context.Context, req *pb.MountRequest) (*pb.MountResponse, error) {
	log.Infof("Processing mount method call: %+v", req)
	if len(req.Attributes) == 0 {
		return nil, errors.New("missing attributes field")
	}
	if len(req.Secrets) == 0 {
		return nil, errors.New("missing secrets field")
	}
	if len(req.TargetPath) == 0 {
		return nil, errors.New("missing target path field")
	}
	if len(req.Permission) == 0 {
		return nil, errors.New("missing permission field")
	}

	versions, err := HandleRequest(ctx, req.Attributes, req.Secrets, req.Permission, req.TargetPath)
	var ov []*pb.ObjectVersion
	for k, v := range versions {
		ov = append(ov, &pb.ObjectVersion{Id: k, Version: fmt.Sprintf("%d", v)})
	}
	log.Debugf("Finished mount request with err %s", err)
	return &pb.MountResponse{ObjectVersion: ov}, err
}

// KeyValueObject is the object stored in Vault's Key-Value store.
type KeyValueObject struct {
	// the path of the Key-Value Vault objects
	ObjectPath string `json:"objectPath" yaml:"objectPath"`
	// the name of the Key-Value Vault objects
	ObjectName string `json:"objectName" yaml:"objectName"`
	// the version of the Key-Value Vault objects
	ObjectVersion string `json:"objectVersion" yaml:"objectVersion"`
}

func (o KeyValueObject) ID() string {
	return fmt.Sprintf("%s:%s:%s", o.ObjectPath, o.ObjectName, o.ObjectVersion)
}

type StringArray struct {
	Array []string `json:"array" yaml:"array"`
}

type Mount struct {
	Type    string            `json:"type"`
	Options map[string]string `json:"options"`
}

// NewProvider creates a new provider HashiCorp Vault.
func NewProvider() (*Provider, error) {
	log.Debugf("NewVaultProvider")
	var p Provider
	return &p, nil
}

func readJWTToken(path string) (string, error) {
	log.Debugf("vault: reading jwt token.....")

	data, err := ioutil.ReadFile(path)
	if err != nil {
		return "", errors.Wrap(err, "failed to read jwt token")
	}

	return string(bytes.TrimSpace(data)), nil
}

func (p *Provider) getMountInfo(mountName, token string) (string, string, error) {
	log.Debugf("vault: checking mount info for %q", mountName)

	client, err := p.createHTTPClient()
	if err != nil {
		return "", "", err
	}

	addr := p.VaultAddress + "/v1/sys/mounts"
	req, err := http.NewRequest(http.MethodGet, addr, nil)
	if err != nil {
		return "", "", errors.Wrapf(err, "couldn't generate request")
	}
	// Set vault token.
	req.Header.Set("X-Vault-Token", token)
	req.Header.Set("X-Vault-Request", "true")
	resp, err := client.Do(req)
	if err != nil {
		return "", "", errors.Wrapf(err, "couldn't get sys mounts")
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		var b bytes.Buffer
		_, err := io.Copy(&b, resp.Body)
		if err != nil {
			return "", "", fmt.Errorf("failed to copy reponse body to byte buffer")
		}
		return "", "", fmt.Errorf("failed to get successful response: %#v, %s",
			resp, b.String())
	}

	var mount struct {
		Data map[string]Mount `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&mount); err != nil {
		return "", "", err
	}

	return mount.Data[mountName+"/"].Type, mount.Data[mountName+"/"].Options["version"], nil
}

func generateSecretEndpoint(vaultAddress string, secretMountType string, secretMountVersion string, secretPrefix string, secretSuffix string, secretVersion string) (string, error) {
	addr := ""
	errMessage := fmt.Errorf("Only mount types KV/1 and KV/2 are supported")
	switch secretMountType {
	case "kv":
		switch secretMountVersion {
		case "1":
			addr = vaultAddress + "/v1/" + secretPrefix + "/" + secretSuffix
		case "2":
			addr = vaultAddress + "/v1/" + secretPrefix + "/data/" + secretSuffix + "?version=" + secretVersion
		default:
			return "", errMessage
		}
	default:
		return "", errMessage
	}
	return addr, nil
}

func (p *Provider) createHTTPClient() (*http.Client, error) {
	rootCAs, err := p.getRootCAsPools()
	if err != nil {
		return nil, err
	}

	tlsClientConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    rootCAs,
	}

	if p.VaultSkipVerify {
		tlsClientConfig.InsecureSkipVerify = true
	}

	if p.VaultServerName != "" {
		tlsClientConfig.ServerName = p.VaultServerName
	}

	transport := &http.Transport{
		TLSClientConfig: tlsClientConfig,
	}

	if err := http2.ConfigureTransport(transport); err != nil {
		return nil, errors.New("failed to configure http2")
	}

	return &http.Client{
		Transport: transport,
	}, nil
}

func (p *Provider) login(jwt string, roleName string) (string, error) {
	log.Debugf("vault: performing vault login.....")

	client, err := p.createHTTPClient()
	if err != nil {
		return "", err
	}

	addr := p.VaultAddress + "/v1/auth/" + p.VaultK8SMountPath + "/login"
	body := fmt.Sprintf(`{"role": "%s", "jwt": "%s"}`, roleName, jwt)

	log.Debugf("vault: vault address: %s\n", addr)

	req, err := http.NewRequest(http.MethodPost, addr, strings.NewReader(body))
	if err != nil {
		return "", errors.Wrapf(err, "couldn't generate request")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", errors.Wrapf(err, "couldn't login")
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		var b bytes.Buffer
		_, err := io.Copy(&b, resp.Body)
		if err != nil {
			return "", fmt.Errorf("failed to copy reponse body to byte buffer")
		}
		return "", fmt.Errorf("failed to get successful response: %#v, %s",
			resp, b.String())
	}

	var s struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
		return "", errors.Wrapf(err, "failed to read body")
	}

	return s.Auth.ClientToken, nil
}

func (p *Provider) getSecret(token string, secretPath string, secretName string, secretVersion string) (string, int, error) {
	log.Debugf("vault: getting secrets from vault.....")

	client, err := p.createHTTPClient()
	if err != nil {
		return "", 0, err
	}

	if secretVersion == "" {
		secretVersion = "0"
	}

	s := regexp.MustCompile("/+").Split(secretPath, 3)
	if len(s) < 3 {
		return "", 0, fmt.Errorf("unable to parse secret path %q", secretPath)
	}
	secretPrefix := s[1]
	secretSuffix := s[2]

	secretMountType, secretMountVersion, err := p.getMountInfo(secretPrefix, token)
	if err != nil {
		return "", 0, err
	}

	addr, err := generateSecretEndpoint(p.VaultAddress, secretMountType, secretMountVersion, secretPrefix, secretSuffix, secretVersion)
	if err != nil {
		return "", 0, err
	}

	log.Debugf("vault: Requesting valid secret mounted at %q", addr)

	req, err := http.NewRequest(http.MethodGet, addr, nil)
	// Set vault token.
	req.Header.Set("X-Vault-Token", token)
	if err != nil {
		return "", 0, errors.Wrapf(err, "couldn't generate request")
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", 0, errors.Wrapf(err, "couldn't get secret")
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		var b bytes.Buffer
		_, err := io.Copy(&b, resp.Body)
		if err != nil {
			return "", 0, fmt.Errorf("failed to copy reponse body to byte buffer")
		}
		return "", 0, fmt.Errorf("failed to get successful response: %#v, %s",
			resp, b.String())
	}

	switch secretMountType {
	case "kv":
		switch secretMountVersion {
		case "1":
			var d struct {
				Data map[string]string `json:"data"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
				return "", 0, errors.Wrapf(err, "failed to read body")
			}
			return d.Data[secretName], 0, nil

		case "2":
			var d struct {
				Data struct {
					Data map[string]string `json:"data"`
					Metadata struct {
						Version int `json:version`
					} `json:metadata`
				} `json:"data"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
				return "", 0, errors.Wrapf(err, "failed to read body")
			}
			return d.Data.Data[secretName], d.Data.Metadata.Version, nil
		}
	}

	return "", 0, fmt.Errorf("failed to get secret value")
}

func (p *Provider) getRootCAsPools() (*x509.CertPool, error) {
	switch {
	case p.VaultCAPem != "":
		certPool := x509.NewCertPool()
		if err := loadCert(certPool, []byte(p.VaultCAPem)); err != nil {
			return nil, err
		}
		return certPool, nil
	case p.VaultCAPath != "":
		certPool := x509.NewCertPool()
		if err := loadCertFolder(certPool, p.VaultCAPath); err != nil {
			return nil, err
		}
		return certPool, nil
	case p.VaultCACert != "":
		certPool := x509.NewCertPool()
		if err := loadCertFile(certPool, p.VaultCACert); err != nil {
			return nil, err
		}
		return certPool, nil
	default:
		certPool, err := x509.SystemCertPool()
		if err != nil {
			return nil, errors.Wrapf(err, "couldn't load system certs")
		}
		return certPool, err
	}
}

// loadCert loads a single pem-encoded certificate into the given pool.
func loadCert(pool *x509.CertPool, pem []byte) error {
	if ok := pool.AppendCertsFromPEM(pem); !ok {
		return fmt.Errorf("failed to parse PEM")
	}
	return nil
}

// loadCertFile loads the certificate at the given path into the given pool.
func loadCertFile(pool *x509.CertPool, p string) error {
	pem, err := ioutil.ReadFile(p)
	if err != nil {
		return errors.Wrapf(err, "couldn't read CA file from disk")
	}

	if err := loadCert(pool, pem); err != nil {
		return errors.Wrapf(err, "couldn't load CA at %s", p)
	}

	return nil
}

// loadCertFolder iterates exactly one level below the given directory path and
// loads all certificates in that path. It does not recurse
func loadCertFolder(pool *x509.CertPool, p string) error {
	if err := filepath.Walk(p, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		return loadCertFile(pool, path)
	}); err != nil {
		return errors.Wrapf(err, "failed to load CAs at %s", p)
	}
	return nil
}

// MountSecretsStoreObjectContent mounts content of the vault object to target path
func (p *Provider) MountSecretsStoreObjectContent(ctx context.Context, attrib map[string]string, secrets map[string]string, targetPath string, permission os.FileMode) (map[string]int, error) {
	roleName := attrib["roleName"]
	if roleName == "" {
		return nil, errors.Errorf("missing vault role name. please specify 'roleName' in pv definition.")
	}
	p.VaultRole = roleName

	log.Debugf("vault: roleName %s", p.VaultRole)

	p.VaultAddress = attrib["vaultAddress"]
	if p.VaultAddress == "" {
		p.VaultAddress = defaultVaultAddress
	}
	log.Debugf("vault: vault address %s", p.VaultAddress)

	// One of the following variables should be set when vaultSkipTLSVerify is false.
	// Otherwise, system certificates are used to make requests to vault.
	p.VaultCAPem = attrib["vaultCAPem"]
	p.VaultCACert = attrib["vaultCACertPath"]
	p.VaultCAPath = attrib["vaultCADirectory"]
	// Vault tls server name.
	p.VaultServerName = attrib["vaultTLSServerName"]

	if s := attrib["vaultSkipTLSVerify"]; s != "" {
		b, err := strconv.ParseBool(s)
		if err != nil {
			return nil, err
		}
		p.VaultSkipVerify = b
	}

	p.VaultK8SMountPath = attrib["vaultKubernetesMountPath"]
	if p.VaultK8SMountPath == "" {
		p.VaultK8SMountPath = defaultVaultKubernetesMountPath
	}

	p.KubernetesServiceAccountPath = attrib["vaultKubernetesServiceAccountPath"]
	if p.KubernetesServiceAccountPath == "" {
		p.KubernetesServiceAccountPath = defaultKubernetesServiceAccountPath
	}

	var keyValueObjects []KeyValueObject
	objectsStrings := attrib["objects"]
	fmt.Printf("objectsStrings: [%s]\n", objectsStrings)

	var objects StringArray
	err := yaml.Unmarshal([]byte(objectsStrings), &objects)
	if err != nil {
		fmt.Printf("unmarshall failed for objects")
		return nil, err
	}
	fmt.Printf("objects: [%v]", objects.Array)
	for _, object := range objects.Array {
		fmt.Printf("unmarshal object: [%s]\n", object)
		var keyValueObject KeyValueObject
		err = yaml.Unmarshal([]byte(object), &keyValueObject)
		if err != nil {
			fmt.Printf("unmarshall failed for keyValueObjects at index")
			return nil, err
		}

		keyValueObjects = append(keyValueObjects, keyValueObject)
	}

	versions := make(map[string]int)
	for _, keyValueObject := range keyValueObjects {
		content, version, err := p.GetKeyValueObjectContent(ctx, keyValueObject.ObjectPath, keyValueObject.ObjectName, keyValueObject.ObjectVersion)
		if err != nil {
			return nil, err
		}
		versions[keyValueObject.ID()] = version
		objectContent := []byte(content)
		path := keyValueObject.ObjectName
		if err := validateFilePath(path); err != nil {
			return nil, err
		}
		if filepath.Base(path) != path {
			err = os.MkdirAll(filepath.Join(targetPath, filepath.Dir(path)), 0755)
			if err != nil {
				return nil, err
			}
		}
		if err := ioutil.WriteFile(filepath.Join(targetPath, path), objectContent, permission); err != nil {
			return nil, errors.Wrapf(err, "secrets-store csi driver failed to write %s at %s", path, targetPath)
		}
		log.Infof("secrets-store csi driver wrote %s at %s", path, targetPath)
	}

	return versions, nil
}

func validateFilePath(path string) error {
	segments := strings.Split(strings.ReplaceAll(path, `\`, "/"), "/")
	for _, segment := range segments {
		if segment == ".." {
			return fmt.Errorf("ObjectName %q invalid, must not contain any .. segments", path)
		}
	}

	return nil
}

// GetKeyValueObjectContent get content and version of the vault object
func (p *Provider) GetKeyValueObjectContent(ctx context.Context, objectPath string, objectName string, objectVersion string) (content string, version int, err error) {
	// Read the jwt token from disk
	jwt, err := readJWTToken(p.KubernetesServiceAccountPath)
	if err != nil {
		return "", 0, err
	}

	// Authenticate to vault using the jwt token
	token, err := p.login(jwt, p.VaultRole)
	if err != nil {
		return "", 0, err
	}

	// Get Secret
	value, version, err := p.getSecret(token, objectPath, objectName, objectVersion)
	if err != nil {
		return "", 0, err
	}

	return value, version, nil
}
