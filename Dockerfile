FROM alpine:3.10

WORKDIR /bin

RUN apk add --no-cache bash
ADD ./secrets-store-csi-driver-provider-vault /bin/secrets-store-csi-driver-provider-vault
RUN chmod a+x /bin/secrets-store-csi-driver-provider-vault
ADD ./install.sh /bin/install_vault_provider.sh

ENTRYPOINT ["/bin/install_vault_provider.sh"]