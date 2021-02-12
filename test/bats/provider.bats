#!/usr/bin/env bats

load _helpers

export SETUP_TEARDOWN_OUTFILE=/dev/stdout
SUPPRESS_SETUP_TEARDOWN_LOGS=true       # Comment this line out to show setup/teardown logs for failed tests.
if [[ -n $SUPPRESS_SETUP_TEARDOWN_LOGS ]]; then
    export SETUP_TEARDOWN_OUTFILE=/dev/null
fi

#SKIP_TEARDOWN=true
CONFIGS=test/bats/configs

setup(){
    { # Braces used to redirect all setup logs.
    # 1. Configure Vault.
    # 1. a) Vault policies
    cat $CONFIGS/vault-policy-db.hcl | kubectl --namespace=csi exec -i vault-0 -- vault policy write db-policy -
    cat $CONFIGS/vault-policy-kv.hcl | kubectl --namespace=csi exec -i vault-0 -- vault policy write kv-policy -
    cat $CONFIGS/vault-policy-pki.hcl | kubectl --namespace=csi exec -i vault-0 -- vault policy write pki-policy -

    # 1. b) Setup kubernetes auth engine.
    kubectl --namespace=csi exec vault-0 -- vault auth enable kubernetes
    # `issuer` argument corresponds to value of --service-account-issuer for kube-apiserver,
    # and for this test assumes the default value that kind sets.
    kubectl --namespace=csi exec vault-0 -- sh -c 'vault write auth/kubernetes/config \
        token_reviewer_jwt="$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
        kubernetes_host="https://$KUBERNETES_PORT_443_TCP_ADDR:443" \
        kubernetes_ca_cert=@/var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
        issuer="https://kubernetes.default.svc.cluster.local"'
    kubectl --namespace=csi exec vault-0 -- vault write auth/kubernetes/role/db-role \
        bound_service_account_names=nginx-db \
        bound_service_account_namespaces=test \
        policies=db-policy \
        ttl=20m
    kubectl --namespace=csi exec vault-0 -- vault write auth/kubernetes/role/kv-role \
        bound_service_account_names=nginx-kv \
        bound_service_account_namespaces=test \
        policies=kv-policy \
        ttl=20m
    kubectl --namespace=csi exec vault-0 -- vault write auth/kubernetes/role/pki-role \
        bound_service_account_names=nginx-pki \
        bound_service_account_namespaces=test \
        policies=pki-policy \
        ttl=20m
    kubectl --namespace=csi exec vault-0 -- vault write auth/kubernetes/role/all-role \
        bound_service_account_names=nginx-all \
        bound_service_account_namespaces=test \
        policies=db-policy,kv-policy,pki-policy \
        ttl=20m

    # 1. c) Setup pki secrets engine.
    kubectl --namespace=csi exec vault-0 -- vault secrets enable pki
    kubectl --namespace=csi exec vault-0 -- vault write -field=certificate pki/root/generate/internal \
        common_name="example.com"
    kubectl --namespace=csi exec vault-0 -- vault write pki/config/urls \
        issuing_certificates="http://127.0.0.1:8200/v1/pki/ca"
    kubectl --namespace=csi exec vault-0 -- vault write pki/roles/example-dot-com \
        allowed_domains="example.com" \
        allow_subdomains=true

    # 1. d) Create kv secrets in Vault.
    kubectl --namespace=csi exec vault-0 -- vault kv put secret/foo1 bar1=hello1
    kubectl --namespace=csi exec vault-0 -- vault kv put secret/foo2 bar2=hello2
    kubectl --namespace=csi exec vault-0 -- vault kv put secret/foo-sync1 bar1=hello-sync1
    kubectl --namespace=csi exec vault-0 -- vault kv put secret/foo-sync2 bar2=hello-sync2

    # 2. Create shared k8s resources.
    kubectl create namespace test
    kubectl --namespace=test apply -f $CONFIGS/vault-all-secretproviderclass.yaml
    kubectl --namespace=test apply -f $CONFIGS/vault-dynamic-creds-secretproviderclass.yaml
    kubectl --namespace=test apply -f $CONFIGS/vault-foo-secretproviderclass.yaml
    kubectl --namespace=test apply -f $CONFIGS/vault-foo-sync-secretproviderclass.yaml
    kubectl --namespace=test apply -f $CONFIGS/vault-foo-sync-multiple-secretproviderclass.yaml
    kubectl --namespace=test apply -f $CONFIGS/vault-pki-secretproviderclass.yaml
    } > $SETUP_TEARDOWN_OUTFILE
}

teardown(){
    if [[ -n $SKIP_TEARDOWN ]]; then
        echo "Skipping teardown"
        return
    fi

    { # Braces used to redirect all teardown logs.
    # Teardown Vault configuration.
    kubectl --namespace=csi exec vault-0 -- vault auth disable kubernetes
    kubectl --namespace=csi exec vault-0 -- vault secrets disable pki
    kubectl --namespace=csi exec vault-0 -- vault secrets disable database
    kubectl --namespace=csi exec vault-0 -- vault policy delete example-policy
    kubectl --namespace=csi exec vault-0 -- vault kv delete secret/foo1
    kubectl --namespace=csi exec vault-0 -- vault kv delete secret/foo2
    kubectl --namespace=csi exec vault-0 -- vault kv delete secret/foo-sync1
    kubectl --namespace=csi exec vault-0 -- vault kv delete secret/foo-sync2

    # Teardown shared k8s resources.
    kubectl delete --ignore-not-found namespace test
    kubectl delete --ignore-not-found namespace negative-test-ns
    } > $SETUP_TEARDOWN_OUTFILE
}

@test "1 Inline secrets-store-csi volume" {
    kubectl --namespace=test apply -f $CONFIGS/nginx-inline-volume.yaml
    kubectl --namespace=test wait --for=condition=Ready --timeout=60s pod/nginx-inline

    result=$(kubectl --namespace=test exec nginx-inline -- cat /mnt/secrets-store/secret-1)
    [[ "$result" == "hello1" ]]

    result=$(kubectl --namespace=test exec nginx-inline -- cat /mnt/secrets-store/secret-2)
    [[ "$result" == "hello2" ]]
}

@test "2 Sync with kubernetes secrets" {
    # Deploy some pods that should cause k8s secrets to be created.
    kubectl --namespace=test apply -f $CONFIGS/nginx-env-var.yaml
    kubectl --namespace=test wait --for=condition=Ready --timeout=60s pod -l app=nginx

    POD=$(kubectl --namespace=test get pod -l app=nginx -o jsonpath="{.items[0].metadata.name}")
    result=$(kubectl --namespace=test exec $POD -- cat /mnt/secrets-store/secret-1)
    [[ "$result" == "hello-sync1" ]]

    result=$(kubectl --namespace=test exec $POD -- cat /mnt/secrets-store/secret-2)
    [[ "$result" == "hello-sync2" ]]

    run kubectl get secret --namespace=test foosecret
    [ "$status" -eq 0 ]

    result=$(kubectl --namespace=test get secret foosecret -o jsonpath="{.data.pwd}" | base64 -d)
    [[ "$result" == "hello-sync1" ]]

    result=$(kubectl --namespace=test exec $POD -- printenv | grep SECRET_USERNAME | awk -F"=" '{ print $2 }' | tr -d '\r\n')
    [[ "$result" == "hello-sync2" ]]

    result=$(kubectl --namespace=test get secret foosecret -o jsonpath="{.metadata.labels.environment}")
    [[ "${result//$'\r'}" == "test" ]]

    result=$(kubectl --namespace=test get secret foosecret -o jsonpath="{.metadata.labels.secrets-store\.csi\.k8s\.io/managed}")
    [[ "${result//$'\r'}" == "true" ]]

    # There isn't really an event we can wait for to ensure this has happened.
    for i in {0..60}; do
        result="$(kubectl --namespace=test get secret foosecret -o json | jq '.metadata.ownerReferences | length')"
        if [[ "$result" -eq 2 ]]; then
            break
        fi
        sleep 1
    done
    [[ "$result" -eq 2 ]]

    # Wait for secret deletion in a background process.
    kubectl --namespace=test wait --for=delete --timeout=60s secret foosecret &
    WAIT_PID=$!

    # Trigger deletion implicitly by deleting only owners.
    kubectl --namespace=test delete -f $CONFIGS/nginx-env-var.yaml
    echo "Waiting for foosecret to get deleted"
    wait $WAIT_PID

    # Ensure it actually got deleted.
    run kubectl --namespace=test get secret foosecret
    [ "$status" -eq 1 ]
}

@test "3 SecretProviderClass in different namespace not usable" {
    kubectl create namespace negative-test-ns
    kubectl --namespace=negative-test-ns apply -f $CONFIGS/nginx-inline-volume.yaml
    kubectl --namespace=negative-test-ns wait --for=condition=PodScheduled --timeout=60s pod nginx-inline

    wait_for_success "kubectl --namespace=negative-test-ns describe pod nginx-inline | grep 'FailedMount.*failed to get secretproviderclass negative-test-ns/vault-foo.*not found'"
}

@test "4 Pod with multiple SecretProviderClasses" {
    POD=nginx-multiple-volumes
    kubectl --namespace=test apply -f $CONFIGS/nginx-multiple-volumes.yaml
    kubectl --namespace=test wait --for=condition=Ready --timeout=60s pod $POD

    result=$(kubectl --namespace=test exec $POD -- cat /mnt/secrets-store-1/secret-1)
    [[ "$result" == "hello-sync1" ]]
    result=$(kubectl --namespace=test exec $POD -- cat /mnt/secrets-store-2/secret-2)
    [[ "$result" == "hello-sync2" ]]

    result=$(kubectl --namespace=test get secret foosecret-1 -o jsonpath="{.data.username}" | base64 -d)
    [[ "$result" == "hello-sync1" ]]
    result=$(kubectl --namespace=test get secret foosecret-2 -o jsonpath="{.data.pwd}" | base64 -d)
    [[ "$result" == "hello-sync2" ]]

    result=$(kubectl --namespace=test exec $POD -- printenv | grep SECRET_1_USERNAME | awk -F"=" '{ print $2 }' | tr -d '\r\n')
    [[ "$result" == "hello-sync1" ]]
    result=$(kubectl --namespace=test exec $POD -- printenv | grep SECRET_2_PWD | awk -F"=" '{ print $2 }' | tr -d '\r\n')
    [[ "$result" == "hello-sync2" ]]
}

@test "5 SecretProviderClass with query parameters and PUT method" {
    kubectl --namespace=test apply -f $CONFIGS/nginx-pki.yaml
    kubectl --namespace=test wait --for=condition=Ready --timeout=60s pod nginx-pki

    result=$(kubectl --namespace=test exec nginx-pki -- cat /mnt/secrets-store/certs)
    [[ "$result" != "" ]]

    # Ensure we have some valid x509 certificates.
    echo "$result" | jq -r '.data.certificate' | openssl x509 -noout
    echo "$result" | jq -r '.data.issuing_ca' | openssl x509 -noout
    echo "$result" | jq -r '.data.certificate' | openssl x509 -noout -text | grep "test.example.com"
}

@test "6 Dynamic secrets engine, endpoint is called only once per SecretProviderClass" {
    setup_postgres

    # Now deploy a pod that will generate some dynamic credentials.
    kubectl --namespace=test apply -f $CONFIGS/nginx-dynamic-creds.yaml
    kubectl --namespace=test wait --for=condition=Ready --timeout=60s pod nginx-dynamic-creds

    # Read the creds out of the pod and verify they work for a query.
    DYNAMIC_USERNAME=$(kubectl --namespace=test exec nginx-dynamic-creds -- cat /mnt/secrets-store/dbUsername)
    DYNAMIC_PASSWORD=$(kubectl --namespace=test exec nginx-dynamic-creds -- cat /mnt/secrets-store/dbPassword)
    result=$(kubectl --namespace=test exec postgres -- psql postgres://${DYNAMIC_USERNAME}:${DYNAMIC_PASSWORD}@127.0.0.1:5432/db --command="SELECT usename FROM pg_catalog.pg_user" --csv | sed -n '3 p')

    [[ "$result" != "" ]]
    [[ "$result" == "${DYNAMIC_USERNAME}" ]]
}

@test "7 SecretProviderClass with multiple secret types" {
    setup_postgres

    kubectl --namespace=test apply -f $CONFIGS/nginx-all.yaml
    kubectl --namespace=test wait --for=condition=Ready --timeout=60s pod nginx-all

    # Verify dynamic database creds.
    DYNAMIC_USERNAME=$(kubectl --namespace=test exec nginx-all -- cat /mnt/secrets-store/dbUsername)
    DYNAMIC_PASSWORD=$(kubectl --namespace=test exec nginx-all -- cat /mnt/secrets-store/dbPassword)
    result=$(kubectl --namespace=test exec postgres -- psql postgres://${DYNAMIC_USERNAME}:${DYNAMIC_PASSWORD}@127.0.0.1:5432/db --command="SELECT usename FROM pg_catalog.pg_user" --csv | sed -n '3 p')

    [[ "$result" != "" ]]
    [[ "$result" == "${DYNAMIC_USERNAME}" ]]

    # Verify kv secret.
    result=$(kubectl --namespace=test exec nginx-all -- cat /mnt/secrets-store/secret-1)
    [[ "$result" == "hello1" ]]

    # Verify certificates.
    result=$(kubectl --namespace=test exec nginx-all -- cat /mnt/secrets-store/certs)
    [[ "$result" != "" ]]

    echo "$result" | jq -r '.data.certificate' | openssl x509 -noout
    echo "$result" | jq -r '.data.issuing_ca' | openssl x509 -noout
    echo "$result" | jq -r '.data.certificate' | openssl x509 -noout -text | grep "test.example.com"
}
