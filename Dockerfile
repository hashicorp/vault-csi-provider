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
FROM docker.mirror.hashicorp.services/alpine:3.20.2 AS dev
COPY --from=devbuild /build/vault-csi-provider /bin/
ENTRYPOINT [ "/bin/vault-csi-provider" ]

# Default release image.
# -----------------------------------
FROM docker.mirror.hashicorp.services/alpine:3.20.2 AS default

ARG PRODUCT_VERSION
ARG PRODUCT_REVISION
ARG PRODUCT_NAME=vault-csi-provider
ARG TARGETOS TARGETARCH

LABEL version=$PRODUCT_VERSION
LABEL revision=$PRODUCT_REVISION

RUN set -eux && \
    apk update && \
    apk upgrade --no-cache libcrypto3

COPY dist/$TARGETOS/$TARGETARCH/vault-csi-provider /bin/
ENTRYPOINT [ "/bin/vault-csi-provider" ]

# ===================================
#
#   Set default target to 'dev'.
#
# ===================================
FROM dev
