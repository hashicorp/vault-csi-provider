# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

# Default release image.
# -----------------------------------
FROM docker.mirror.hashicorp.services/alpine:3.18.4 AS default

ARG PRODUCT_VERSION
ARG PRODUCT_REVISION
ARG PRODUCT_NAME=vault-csi-provider
ARG TARGETOS TARGETARCH

LABEL version=$PRODUCT_VERSION
LABEL revision=$PRODUCT_REVISION

COPY dist/$TARGETOS/$TARGETARCH/vault-csi-provider /bin/
ENTRYPOINT [ "/bin/vault-csi-provider" ]
