## Unreleased

## 0.0.7 (January 20th, 2021)

CHANGES:

* Switch provider to gRPC. [[GH-54](https://github.com/hashicorp/secrets-store-csi-driver-provider-vault/pull/54)]
  * Note this requires at least v0.0.14 of the driver, and the driver should have 'vault' included in `--grpcSupportedProviders`.
