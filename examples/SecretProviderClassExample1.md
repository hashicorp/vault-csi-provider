Below is an example for a SecretProviderClass for Vault with Kubernetes auth method.

```yaml
apiVersion: v1
items:
- apiVersion: secrets-store.csi.x-k8s.io/v1
  kind: SecretProviderClass
  metadata:
    name: vault-foo
    namespace: default
  spec:
    parameters:
      auth: |- # This block is optional. If this block is not specified, the default auth method is kubernetes
        type: kubernetes # Auth method type
        mouthPath: kubernetes # Mount path for Kubernetes auth method. Defaults to kubernetes if not specified.
      objects: |
        - secretPath: "secret/web-app"
          objectName: "creds"
          secretKey: "api-token"
      roleName: secret-store-csi-test # Vault Role Name
      vaultAddress: https://vault.address:8200
    provider: vault
  resourceVersion: ""

```