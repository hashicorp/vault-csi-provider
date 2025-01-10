Below is an example for a SecretProviderClass for Vault with AWS IAM auth method.

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
        type: aws # Auth method type
        mouthPath: aws # Mount path for AWS auth method. Defaults to aws if not specified.
        aws:
          region: us-east-1 # AWS Region
          awsIAMRole: secrets-store-inline-irsa-role # AWS IAM Role
          xVaultAWSIAMServerID: vault.example.com # Vault AWS IAM Server ID. More info: https://www.vaultproject.io/docs/auth/aws#server-id
      objects: |
        - secretPath: "secret/web-app"
          objectName: "creds"
          secretKey: "api-token"
      roleName: secret-store-csi-test # Vault Role Name
      vaultAddress: https://vault.address:8200
    provider: vault
  resourceVersion: ""

```