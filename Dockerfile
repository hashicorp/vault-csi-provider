# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

# This Dockerfile contains multiple targets.
# Use 'docker build --target=<name> .' to build one.

ARG GO_VERSION=latest

# devbuild compiles the binary
# -----------------------------------
FROM docker.mirror.hashicorp.services/golang:${GO_VERSION} AS devbuild
ENV CGO_ENABLED=0
# Leave the GOPATH
WORKDIR /build
COPY . ./
RUN go build -o vault-csi-provider

# dev runs the binary from devbuild
# -----------------------------------
FROM docker.mirror.hashicorp.services/alpine:3.22.2 AS dev
COPY --from=devbuild /build/vault-csi-provider /bin/
ENTRYPOINT [ "/bin/vault-csi-provider" ]

# Default release image.
# -----------------------------------
FROM docker.mirror.hashicorp.services/alpine:3.22.2 AS default

ARG PRODUCT_VERSION
ARG PRODUCT_REVISION
ARG PRODUCT_NAME=vault-csi-provider
ARG TARGETOS
ARG TARGETARCH

LABEL name="Vault Secrets Store CSI Provider" \
      maintainer="Vault Team <vault@hashicorp.com>" \
      vendor="HashiCorp" \
      version=$PRODUCT_VERSION \
      release=$PRODUCT_VERSION \
      revision=$PRODUCT_REVISION \
      org.opencontainers.image.licenses="BUSL-1.1" \
      summary="HashiCorp Vault Provider for Secrets Store CSI Driver for Kubernetes" \
      description="Provides a CSI provider for Kubernetes to interact with HashiCorp Vault."

RUN set -eux && \
    apk update && \
    apk upgrade --no-cache libcrypto3

# Copy license to conform to HC IPS-002
COPY LICENSE /usr/share/doc/$PRODUCT_NAME/LICENSE.txt

COPY dist/$TARGETOS/$TARGETARCH/vault-csi-provider /bin/
ENTRYPOINT [ "/bin/vault-csi-provider" ]

# ubi build image
# -----------------------------------
FROM registry.access.redhat.com/ubi10/ubi-minimal:10.1-1764604111 AS build-ubi
RUN microdnf --refresh --assumeyes upgrade ca-certificates

# ubi release image
# -----------------------------------
FROM registry.access.redhat.com/ubi10/ubi-micro:10.1-1763138307 AS release-ubi

ENV BIN_NAME=vault-csi-provider
ARG PRODUCT_VERSION
ARG PRODUCT_REVISION
ARG PRODUCT_NAME=$BIN_NAME
# TARGETARCH and TARGETOS are set automatically when --platform is provided.
ARG TARGETOS TARGETARCH

LABEL name="Vault Secrets Store CSI Provider" \
      maintainer="Vault Team <vault@hashicorp.com>" \
      vendor="HashiCorp" \
      version=$PRODUCT_VERSION \
      release=$PRODUCT_VERSION \
      revision=$PRODUCT_REVISION \
      org.opencontainers.image.licenses="BUSL-1.1" \
      summary="HashiCorp Vault Provider for Secrets Store CSI Driver for Kubernetes" \
      description="A Secrets Store CSI provider for Kubernetes to interact with HashiCorp Vault."

WORKDIR /

COPY dist/$TARGETOS/$TARGETARCH/$BIN_NAME /$BIN_NAME

# Copy license and EULA for Red Hat certification.
COPY LICENSE /licenses/copyright.txt
COPY .release/EULA_Red_Hat_Universal_Base_Image_English_20190422.pdf /licenses/EULA_Red_Hat_Universal_Base_Image_English_20190422.pdf
# Copy license to conform to HC IPS-002
COPY LICENSE /usr/share/doc/$PRODUCT_NAME/LICENSE.txt

COPY --from=build-ubi /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem /etc/pki/ca-trust/extracted/pem/

USER 65532:65532

ENTRYPOINT ["/vault-csi-provider"]

# ===================================
#
#   Set default target to 'dev'.
#
# ===================================
FROM dev
