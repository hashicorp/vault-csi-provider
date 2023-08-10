# Copyright (c) HashiCorp, Inc.
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
    POSTGRES_IMAGE="$(awk '/image:/{print $NF}' $CONFIGS/postgres.yaml)"
    docker pull "${POSTGRES_IMAGE}"
    kind load docker-image "${POSTGRES_IMAGE}"
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
