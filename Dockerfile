FROM docker.mirror.hashicorp.services/alpine:3.13

ARG VERSION
ARG ARCH="amd64"
ARG OS="linux"

COPY ./_output/vault-csi-provider_${OS}_${ARCH}_${VERSION} /bin/vault-csi-provider

ENTRYPOINT ["/bin/vault-csi-provider"]
