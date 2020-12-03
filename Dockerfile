FROM alpine:3.10

ARG VERSION
ARG ARCH="amd64"
ARG OS="linux"

WORKDIR /bin

RUN apk add --no-cache bash

COPY ./_output/secrets-store-csi-driver-provider-vault_${OS}_${ARCH}_${VERSION} /bin/secrets-store-csi-driver-provider-vault
RUN chmod a+x /bin/secrets-store-csi-driver-provider-vault

ENTRYPOINT ["/bin/secrets-store-csi-driver-provider-vault"]

