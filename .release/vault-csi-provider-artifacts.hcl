# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

schema = 1
artifacts {
  zip = [
    "vault-csi-provider_${version}_linux_386.zip",
    "vault-csi-provider_${version}_linux_amd64.zip",
    "vault-csi-provider_${version}_linux_arm.zip",
    "vault-csi-provider_${version}_linux_arm64.zip",
  ]
  container = [
    "vault-csi-provider_default_linux_386_${version}_${commit_sha}.docker.tar",
    "vault-csi-provider_default_linux_amd64_${version}_${commit_sha}.docker.tar",
    "vault-csi-provider_default_linux_arm64_${version}_${commit_sha}.docker.tar",
    "vault-csi-provider_default_linux_s390x_${version}_${commit_sha}.docker.tar",
    "vault-csi-provider_default_linux_arm_${version}_${commit_sha}.docker.tar",
    "vault-csi-provider_release-ubi_linux_amd64_${version}_${commit_sha}.docker.tar",
    "vault-csi-provider_release-ubi_linux_arm64_${version}_${commit_sha}.docker.tar",
    "vault-csi-provider_release-ubi_linux_s390x_${version}_${commit_sha}.docker.tar",
    "vault-csi-provider_release-ubi_linux_amd64_${version}_${commit_sha}.docker.redhat.tar",
    "vault-csi-provider_release-ubi_linux_arm64_${version}_${commit_sha}.docker.redhat.tar",
    "vault-csi-provider_release-ubi_linux_s390x${version}_${commit_sha}.docker.redhat.tar",
  ]
}
