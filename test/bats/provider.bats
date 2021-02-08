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
    # Configure Vault.
    # Setup kubernetes auth engine.
    kubectl --namespace=csi exec vault-0 -- vault auth enable kubernetes
    kubectl --namespace=csi exec vault-0 -- sh -c 'vault write auth/kubernetes/config \
        token_reviewer_jwt="$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
        kubernetes_host="https://$KUBERNETES_PORT_443_TCP_ADDR:443" \
        kubernetes_ca_cert=@/var/run/secrets/kubernetes.io/serviceaccount/ca.crt'
    cat $CONFIGS/vault-policy.hcl | kubectl --namespace=csi exec -i vault-0 -- vault policy write example-policy -
    kubectl --namespace=csi exec vault-0 -- vault write auth/kubernetes/role/example-role \
        bound_service_account_names=secrets-store-csi-driver-provider-vault \
        bound_service_account_namespaces=csi \
        policies=default,example-policy \
        ttl=20m

    # Setup pki secrets engine.
    kubectl --namespace=csi exec vault-0 -- vault secrets enable pki
    kubectl --namespace=csi exec vault-0 -- vault write -field=certificate pki/root/generate/internal \
        common_name="example.com"
    kubectl --namespace=csi exec vault-0 -- vault write pki/config/urls \
        issuing_certificates="http://127.0.0.1:8200/v1/pki/ca"
    kubectl --namespace=csi exec vault-0 -- vault write pki/roles/example-dot-com \
        allowed_domains="example.com" \
        allow_subdomains=true

    # Create kv secrets in Vault.
    kubectl --namespace=csi exec vault-0 -- vault kv put secret/foo1 bar1=hello1
    kubectl --namespace=csi exec vault-0 -- vault kv put secret/foo2 bar2=hello2
    kubectl --namespace=csi exec vault-0 -- vault kv put secret/foo-sync1 bar1=hello-sync1
    kubectl --namespace=csi exec vault-0 -- vault kv put secret/foo-sync2 bar2=hello-sync2

    # Create shared k8s resources.
    kubectl create namespace test
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
    kubectl --namespace=negative-test-ns apply -f $CONFIGS/nginx-env-var.yaml
    kubectl --namespace=negative-test-ns wait --for=condition=PodScheduled --timeout=60s pod -l app=nginx
    POD=$(kubectl get pod -l app=nginx -n negative-test-ns -o jsonpath="{.items[0].metadata.name}")

    wait_for_success "kubectl describe pod $POD -n negative-test-ns | grep 'FailedMount.*failed to get secretproviderclass negative-test-ns/vault-foo-sync.*not found'"
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
    kubectl --namespace=test wait --for=condition=Ready --timeout=60s pod/nginx-pki

    result=$(kubectl --namespace=test exec nginx-pki -- cat /mnt/secrets-store/certs)
    [[ "$result" != "" ]]
    # Ensure we have some valid x509 certificates.
    echo "$result" | jq -r '.data.certificate' | openssl x509 -noout
    echo "$result" | jq -r '.data.issuing_ca' | openssl x509 -noout
}
