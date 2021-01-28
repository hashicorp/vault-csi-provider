FROM hashicorp.jfrog.io/docker/alpine:3.10

ARG VERSION
ARG ARCH="amd64"
ARG OS="linux"

COPY ./_output/secrets-store-csi-driver-provider-vault_${OS}_${ARCH}_${VERSION} /bin/secrets-store-csi-driver-provider-vault

ENTRYPOINT ["/bin/secrets-store-csi-driver-provider-vault"]
