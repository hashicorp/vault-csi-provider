## Unreleased

CHANGES:

* Build with Go v1.23.6
* Test with K8s 1.28-1.32
* Updated Docker base image from alpine 3.20.2 -> 3.21.0
* Updated dependencies:
  * github.com/hashicorp/vault/api v1.14.0 -> v1.16.0
  * golang.org/x/crypto v0.26.0 => v0.32.0
  * golang.org/x/net v0.28.0 => v0.34.0
  * golang.org/x/sys v0.24.0 => v0.29.0
  * golang.org/x/term v0.23.0 => v0.28.0
  * golang.org/x/text v0.17.0 => v0.21.0
  * google.golang.org/grpc v1.65.0 -> v1.70.0
  * k8s.io/api v0.30.3 -> v0.32.2
  * k8s.io/apimachinery v0.30.3 -> v0.32.2
  * k8s.io/client-go v0.30.3 -> v0.32.2
  * k8s.io/utils v0.0.0-20230726121419-3b25d923346b -> v0.0.0-20241104100929-3ea5e8cea738
  * sigs.k8s.io/secrets-store-csi-driver v1.4.4 -> v1.4.8

## 1.5.0 (August 8th, 2024)

FEATURES:

* Add ability to tune log levels with `-log-level` flag. [[GH-295](https://github.com/hashicorp/vault-csi-provider/pull/295)]

CHANGES:

* Build with Go v1.22.6
* Updated Docker base image from alpine 3.20.1 -> 3.20.2
* Updated dependencies:
  * k8s.io/api v0.30.2 -> v0.30.3
  * k8s.io/apimachinery v0.30.2 -> v0.30.3
  * k8s.io/client-go v0.30.2 -> v0.30.3
  * golang.org/x/crypto v0.24.0 -> v0.26.0
  * golang.org/x/net v0.26.0 -> v0.28.0
  * golang.org/x/sys v0.21.0 -> v0.23.0 
  * golang.org/x/term v0.21.0 -> v0.23.0 
  * golang.org/x/text v0.16.0 -> v0.17.0

## 1.4.3 (July 3rd, 2024)

CHANGES:

* Build with Go v1.22.5
* Test with K8s 1.26-1.30
* Test with Vault 1.15-1.17
* Updated Docker base image from alpine 3.19.1 -> 3.20.1
* Updated dependencies:
  * github.com/hashicorp/go-hclog v1.6.2 -> v1.6.3
  * github.com/hashicorp/vault/api v1.12.2 -> v1.14.0
  * golang.org/x/crypto v0.21.0 -> v0.24.0
  * golang.org/x/net v0.22.0 -> v0.26.0
  * golang.org/x/sys v0.18.0 -> v0.21.0
  * golang.org/x/term v0.18.0 -> v0.21.0
  * golang.org/x/text v0.14.0 -> v0.16.0
  * google.golang.org/grpc v1.62.1 -> v1.65.0
  * k8s.io/api v0.29.3 -> v0.30.2
  * k8s.io/apimachinery v0.29.3 -> v0.30.2
  * k8s.io/client-go v0.29.3 -> v0.30.2
  * sigs.k8s.io/secrets-store-csi-driver v1.4.2 -> v1.4.4

## 1.4.2 (March 27th, 2024)

CHANGES:

* Build with Go v1.22.1
* Test with K8s 1.25-1.29
* Test with Vault 1.13-1.15
* Updated Docker base image from alpine 3.18.4 -> 3.19.1
* Updated dependencies:
  * github.com/go-jose/go-jose/v3 v3.0.1 -> 3.0.3
  * github.com/hashicorp/go-hclog v1.5.0 -> v1.6.2
  * github.com/hashicorp/golang-lru/v2 v2.0.2 -> v2.0.7
  * github.com/hashicorp/vault/api v1.9.0 -> v1.12.2
  * github.com/stretchr/testify v1.8.2 -> v1.9.0
  * golang.org/x/crypto v0.14.0 -> v0.21.0
  * golang.org/x/net v0.17.0 -> v0.22.0
  * golang.org/x/sys v0.13.0 -> v0.18.0
  * golang.org/x/term v0.13.0 -> v0.18.0
  * google.golang.org/grpc v1.56.3 -> v1.62.1
  * google.golang.org/protobuf v1.30.0 -> v1.33.0
  * k8s.io/api v0.26.3 -> v0.29.3
  * k8s.io/apimachinery v0.26.3 -> v0.29.3
  * k8s.io/client-go v0.26.3 -> v0.29.3
  * k8s.io/utils v0.0.0-20230313181309-38a27ef9d749 -> v0.0.0-20230726121419-3b25d923346b
  * sigs.k8s.io/secrets-store-csi-driver v1.3.3 -> v1.4.2

## 1.4.1 (October 26th, 2023)

CHANGES:

* Build with Go v1.21.3
* Test with K8s 1.24-1.28
* Updated Docker base image from alpine 3.17.3 -> 3.18.4
* Updated dependencies:
  * golang.org/x/crypto v0.6.0 -> v0.14.0
  * golang.org/x/net v0.8.0 -> v0.17.0
  * golang.org/x/sys v0.6.0 -> v0.13.0
  * golang.org/x/term v0.6.0 -> v0.13.0
  * golang.org/x/text v0.8.0 -> v0.13.0
  * google.golang.org/grpc v1.54.0 -> v1.56.3
  * sigs.k8s.io/secrets-store-csi-driver v1.3.2 -> v1.3.3

## 1.4.0 (April 28th, 2023)

CHANGES:

* SecretProviderClass objects now also accept `spec.parameters.vaultAuthMountPath` as an alternative to `spec.parameters.vaultKubernetesMountPath`. [[GH-210](https://github.com/hashicorp/vault-csi-provider/pull/210)]

FEATURES:

* The Provider will cache a Vault token per requesting pod in memory and re-use it until it expires. [[GH-202](https://github.com/hashicorp/vault-csi-provider/pull/202)]
* JWT auth is supported by setting role name and auth mount path in the same way as for Kubernetes auth. [[GH-210](https://github.com/hashicorp/vault-csi-provider/pull/210)]

## 1.3.0 (April 5th, 2023)

CHANGES:

* Vault CSI Provider will use service account tokens passed from the Secrets Store CSI Driver instead of generating one if an appropriate token is provided. [[GH-163](https://github.com/hashicorp/vault-csi-provider/pull/163)]
  * The Secrets Store CSI driver needs to be configured to generate tokens with the correct audience for this feature. Vault CSI Provider
    will look for a token with the audience specified in the SecretProviderClass, or otherwise "vault". To configure the driver to generate
    a token with the correct audience, use the
    [`tokenRequests`](https://github.com/kubernetes-sigs/secrets-store-csi-driver/tree/main/charts/secrets-store-csi-driver#configuration)
    option from the _driver_ helm chart via the flag `--set tokenRequests[0].audience="vault"`. See
    [CSI TokenRequests documentation](https://kubernetes-csi.github.io/docs/token-requests.html) for further details.
* Vault CSI Provider now creates a Kubernetes secret with an HMAC key to produce consistent hashes for secret versions. [[GH-198](https://github.com/hashicorp/vault-csi-provider/pull/198)]
  * Requires RBAC permissions to create secrets, and read the same specific secret back. Versions are not generated otherwise and a warning
    is logged on each mount that fails to generate a version.
  * Supports creating the secret with custom name via `-hmac-secret-name`
* Updated Docker base image from alpine 3.16.3 -> 3.17.3
* Build with Go v1.20.3
* Updated dependencies:
  * github.com/hashicorp/go-hclog v1.3.1 -> v1.5.0
  * github.com/hashicorp/vault/api v1.8.2 -> v1.9.0
  * github.com/stretchr/testify v1.8.1 -> v1.8.2
  * google.golang.org/grpc v1.50.1 -> v1.54.0
  * k8s.io/api v0.25.4 -> v0.26.3
  * k8s.io/apimachinery v0.25.4 -> v0.26.3
  * k8s.io/client-go v0.25.4 -> v0.26.3
  * k8s.io/utils v0.0.0-20220728103510-ee6ede2d64ed -> v0.0.0-20230313181309-38a27ef9d749
  * sigs.k8s.io/secrets-store-csi-driver v1.2.4 -> v1.3.2
* Tests are now run against Kubernetes versions: 1.22.17, 1.23.17, 1.24.12, 1.25.8, 1.26.3

IMPROVEMENTS:

* Support utf-8 (default), hex, and base64 encoded secrets [[GH-194](https://github.com/hashicorp/vault-csi-provider/pull/194)]

## 1.2.1 (November 21st, 2022)

CHANGES:

* Updated dependencies:
  * github.com/hashicorp/go-hclog v1.0.0 -> v1.3.1
  * github.com/hashicorp/vault/api v1.2.0 -> v1.8.2
  * github.com/stretchr/testify v1.7.2 -> v1.8.1
  * google.golang.org/grpc v1.41.0 -> v1.50.1
  * k8s.io/api v0.22.2 -> v0.25.4
  * k8s.io/apimachinery v0.22.2 -> v0.25.4
  * k8s.io/client-go v0.22.2 -> v0.25.4
  * sigs.k8s.io/secrets-store-csi-driver v1.0.0 -> v1.2.4
  * golang.org/x/net v0.0.0-20220722155237-a158d28d115b -> v0.0.0-20221012135044-0b7e1fb9d458
  * golang.org/x/sys v0.0.0-20220722155257-8c9f86f7a55f -> v0.0.0-20220728004956-3c1f35247d10
  * golang.org/x/text v0.3.7 -> v0.3.8
* Updated Docker base image from alpine 3.15.0 -> 3.16.3

## 1.2.0 (August 8th, 2022)

CHANGES:

* Duplicate object names now trigger an error instead of silently overwriting files. [[GH-148](https://github.com/hashicorp/vault-csi-provider/pull/148)]

BUGS:

* `VAULT_ADDR` environment variable can now be used to set the Vault address. [[GH-160](https://github.com/hashicorp/vault-csi-provider/pull/160)]
* Secret mounting correctly fails now if the secret path exists but the requested secret key does not. [[GH-166](https://github.com/hashicorp/vault-csi-provider/issues/166)]

IMPROVEMENTS:

* Secret versions are now reported as a hash of their input and contents instead of hardcoded to 0. [[GH-148](https://github.com/hashicorp/vault-csi-provider/pull/148)]
* Bump github.com/stretchr/testify from v1.7.0 to v1.7.2. [[GH-161](https://github.com/hashicorp/vault-csi-provider/pull/161)]
* Bump gopkg.in/yaml.v3 from v3.0.0-20210107192922-496545a6307b to v3.0.1. [[GH-161](https://github.com/hashicorp/vault-csi-provider/pull/161)]

## 1.1.0 (April 26th, 2022)

IMPROVEMENTS:

* New flags to configure default Vault namespace and TLS details. [[GH-138](https://github.com/hashicorp/vault-csi-provider/pull/138)]
  * `-vault-namespace`
  * `-vault-tls-ca-cert`
  * `-vault-tls-ca-directory`
  * `-vault-tls-server-name`
  * `-vault-tls-client-cert`
  * `-vault-tls-client-key`
  * `-vault-tls-skip-verify`
* Add an optional SecretProviderClass parameter `audience` to customize the `aud` claim in the JWT [[GH-144](https://github.com/hashicorp/vault-csi-provider/pull/144)]
* New SecretProviderClass field `filePermission` can be used per-secret to set the file permissions it is written with. [[GH-139](https://github.com/hashicorp/vault-csi-provider/pull/139)]

## 1.0.0 (January 25th, 2022)

CHANGES:

* `-write-secrets` flag removed. All secrets are now written to the filesystem by the CSI secrets store driver. [[GH-133](https://github.com/hashicorp/vault-csi-provider/pull/133)]
  * **NOTE:** CSI secrets store driver v0.0.21+ is required.
* `-health_addr` flag removed, use `-health-addr` instead. [[GH-133](https://github.com/hashicorp/vault-csi-provider/pull/133)]
* Warning logs are no longer printed when deprecated SecretProviderClass fields `kubernetesServiceAccountPath` and `vaultCAPem` are used. [[GH-134](https://github.com/hashicorp/vault-csi-provider/pull/134)]

## 0.4.0 (January 12th, 2022)

CHANGES:

* `-write-secrets` flag now defaults to `false`, delegating file writes to the driver. [[GH-127](https://github.com/hashicorp/vault-csi-provider/pull/127)]
  * **Note:** `-write-secrets` is deprecated and will be removed in the next major version.

FEATURES:

* Support extracting JSON values using `secretKey` in the SecretProviderClass [[GH-126](https://github.com/hashicorp/vault-csi-provider/pull/126)]

## 0.3.0 (June 7th, 2021)

FEATURES:

* Support for changing the default Vault address and Kubernetes mount path via CLI flag to the vault-csi-provider binary [[GH-96](https://github.com/hashicorp/vault-csi-provider/pull/96)]
* Support for sending secret contents to driver for writing via `-write-secrets=false` [[GH-89](https://github.com/hashicorp/vault-csi-provider/pull/89)]
  * **Note:** `-write-secrets=false` will become the default from v0.4.0 and require secrets-store-csi-driver v0.0.21+

CHANGES:

* `-health_addr` flag is marked deprecated and replaced by `-health-addr`. Slated for removal in v0.5.0 [[GH-100](https://github.com/hashicorp/vault-csi-provider/pull/100)]

BUGS:

* Added missing error handling when transforming SecretProviderClass config to a Vault request [[GH-97](https://github.com/hashicorp/vault-csi-provider/pull/97)]

## 0.2.0 (April 14th, 2021)

FEATURES:

* Support for Vault namespaces, via `vaultNamespace` option in SecretProviderClass parameters [[GH-84](https://github.com/hashicorp/vault-csi-provider/pull/84)]

## 0.1.0 (March 24th, 2021)

CHANGES:

* All secret engines are now supported [[GH-63](https://github.com/hashicorp/vault-csi-provider/pull/63)]
  * **This makes several breaking changes to the configuration of the SecretProviderClass' `objects` entry**
  * There is no top-level `array` entry under `objects`
  * `objectVersion` is now ignored
  * `objectPath` is renamed to `secretPath`
  * `secretKey`, `secretArgs` and `method` are newly available options
  * `objectName` no longer determines which key is read from the secret's data
  * If `secretKey` is set, that is the key from the secret's data that will be written
  * If `secretKey` is not set, the whole JSON response from Vault will be written
  * `vaultSkipTLSVerify` is no longer required to be set to `"true"` if the `vaultAddress` scheme is not `https`
* The provider will now authenticate to Vault as the requesting pod's service account [[GH-64](https://github.com/hashicorp/vault-csi-provider/pull/64)]
  * **This is likely a breaking change for existing deployments being upgraded**
  * vault-csi-provider service account now requires cluster-wide permission to create service account tokens
  * auth/kubernetes mounts in Vault will now need to bind ACL policies to the requesting pods'
    service accounts instead of the provider's service account.
  * `spec.parameters.kubernetesServiceAccountPath` is now ignored and will log a warning if set
* The provider now supports mTLS [[GH-65](https://github.com/hashicorp/vault-csi-provider/pull/65)]
  * `spec.parameters.vaultCAPem` is now ignored and will log a warning if set. **This is a breaking change**
  * `spec.parameters.vaultTLSClientCertPath` and `spec.parameters.vaultTLSClientKeyPath` are newly available options

IMPROVEMENTS

* The provider now uses the `hashicorp/vault/api` package to communicate with Vault [[GH-61](https://github.com/hashicorp/vault-csi-provider/pull/61)]
* `-version` flag will now print the version of Go used to build the provider [[GH-62](https://github.com/hashicorp/vault-csi-provider/pull/62)]
* CircleCI linting, tests and integration tests added [[GH-60](https://github.com/hashicorp/vault-csi-provider/pull/60)]

## 0.0.7 (January 20th, 2021)

CHANGES:

* Switch provider to gRPC. [[GH-54](https://github.com/hashicorp/vault-csi-provider/pull/54)]
  * Note this requires at least v0.0.14 of the driver, and the driver should have 'vault' included in `--grpcSupportedProviders`.
