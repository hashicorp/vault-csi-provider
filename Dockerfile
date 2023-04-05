# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

# This Dockerfile contains multiple targets.
# Use 'docker build --target=<name> .' to build one.

ARG ALPINE_VERSION=3.17.3
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
FROM docker.mirror.hashicorp.services/alpine:${ALPINE_VERSION} AS dev
COPY --from=devbuild /build/vault-csi-provider /bin/
ENTRYPOINT [ "/bin/vault-csi-provider" ]

# Default release image.
# -----------------------------------
FROM docker.mirror.hashicorp.services/alpine:${ALPINE_VERSION} AS default

ARG PRODUCT_VERSION
ARG PRODUCT_REVISION
ARG PRODUCT_NAME=vault-csi-provider
ARG TARGETOS TARGETARCH

LABEL version=$PRODUCT_VERSION
LABEL revision=$PRODUCT_REVISION

COPY dist/$TARGETOS/$TARGETARCH/vault-csi-provider /bin/
ENTRYPOINT [ "/bin/vault-csi-provider" ]

# ===================================
# 
#   Set default target to 'dev'.
#
# ===================================
FROM dev
