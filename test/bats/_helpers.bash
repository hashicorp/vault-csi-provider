# Copyright IBM Corp. 2019, 2026
# SPDX-License-Identifier: BUSL-1.1

wait_for_success() {
    echo $1
    for i in {0..60}; do
        if eval "$1"; then
            return
        fi
        sleep 1
    done
    # Fail the test.
    [ 1 -eq 2 ]
}

setup_postgres() {
    # Setup postgres, pulling the image first to help avoid CI timeouts.
    if [ -z "${OPENSHIFT}" ]; then
        POSTGRES_IMAGE="$(awk '/image:/{print $NF}' $CONFIGS/postgres.yaml)"
        docker pull "${POSTGRES_IMAGE}"
        # With Docker's containerd image store (default since Docker 29),
        # `kind load docker-image` exports every platform in the image index and
        # fails on those never downloaded, so load only the pulled platform.
        # Docker older than 28 lacks `docker save --platform`, but is not
        # affected, so it keeps the original command.
        POSTGRES_ARCHIVE="$(mktemp)"
        if docker save --platform "$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "${POSTGRES_IMAGE}")" \
                --output "${POSTGRES_ARCHIVE}" "${POSTGRES_IMAGE}"; then
            kind load image-archive "${POSTGRES_ARCHIVE}"
        else
            kind load docker-image "${POSTGRES_IMAGE}"
        fi
        rm -f "${POSTGRES_ARCHIVE}"
    fi
    POSTGRES_PASSWORD=$(openssl rand -base64 30)
    kubectl --namespace=test create secret generic postgres-root \
        --from-literal=POSTGRES_USER="root" \
        --from-literal=POSTGRES_PASSWORD="${POSTGRES_PASSWORD}"
    kubectl --namespace=test apply -f $CONFIGS/postgres.yaml
    kubectl wait --namespace=test --for=condition=Ready --timeout=10m pod -l app=postgres

    # Configure vault to manage postgres
    kubectl --namespace=csi exec vault-0 -- vault secrets enable database
    kubectl --namespace=csi exec vault-0 -- vault write database/config/postgres \
        plugin_name="postgresql-database-plugin" \
        allowed_roles="*" \
        connection_url="postgres://{{username}}:{{password}}@postgres.test.svc.cluster.local:5432/db?sslmode=disable" \
        username="root" \
        password="${POSTGRES_PASSWORD}" \
        verify_connection=false
    cat $CONFIGS/postgres-creation-statements.sql | kubectl --namespace=csi exec -i vault-0 -- vault write database/roles/test-role \
        db_name="postgres" \
        default_ttl="1h" max_ttl="24h" \
        creation_statements=-
}
