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
        # Docker 29 uses the containerd image store by default. In that case,
        # `kind load docker-image` exports every platform in the image index and
        # fails on platforms that were not downloaded, so load only the pulled one.
        if ! DOCKER_VERSION="$(docker version --format '{{.Server.Version}}')"; then
            echo "Unable to determine Docker server version" >&2
            return 1
        fi
        DOCKER_MAJOR_VERSION="${DOCKER_VERSION%%.*}"
        case "${DOCKER_MAJOR_VERSION}" in
            ''|*[!0-9]*)
                echo "Invalid Docker server version: ${DOCKER_VERSION}" >&2
                return 1
                ;;
        esac
        if [ "${DOCKER_MAJOR_VERSION}" -ge 29 ]; then
            POSTGRES_ARCHIVE="$(mktemp)"
            docker save --platform "$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "${POSTGRES_IMAGE}")" \
                --output "${POSTGRES_ARCHIVE}" "${POSTGRES_IMAGE}"
            kind load image-archive "${POSTGRES_ARCHIVE}"
            rm -f "${POSTGRES_ARCHIVE}"
        else
            kind load docker-image "${POSTGRES_IMAGE}"
        fi
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
