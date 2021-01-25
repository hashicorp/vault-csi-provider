#!/usr/bin/env bats

CONFIGS=test/bats/configs

setup(){
    # Configure Vault.
    VAULT_POD=$(kubectl --namespace=csi get pod -l app=vault -o jsonpath="{.items[0].metadata.name}")
    kubectl --namespace=csi exec $VAULT_POD -- vault auth enable kubernetes
    CLUSTER_NAME="$(kubectl config view --raw \
    -o go-template="{{ range .contexts }}{{ if eq .name \"$(kubectl --namespace=csi config current-context)\" }}{{ index .context \"cluster\" }}{{ end }}{{ end }}")"

    SECRET_NAME="$(kubectl --namespace=csi get serviceaccount vault-auth \
        -o go-template='{{ (index .secrets 0).name }}')"

    export TR_ACCOUNT_TOKEN="$(kubectl --namespace=csi get secret ${SECRET_NAME} \
        -o go-template='{{ .data.token }}' | base64 --decode)"

    export K8S_HOST="https://$(kubectl get svc kubernetes -o go-template="{{ .spec.clusterIP }}")"

    export K8S_CACERT="$(kubectl config view --raw \
        -o go-template="{{ range .clusters }}{{ if eq .name \"${CLUSTER_NAME}\" }}{{ index .cluster \"certificate-authority-data\" }}{{ end }}{{ end }}" | base64 --decode)"

    kubectl --namespace=csi exec $VAULT_POD -- vault write auth/kubernetes/config \
        kubernetes_host="${K8S_HOST}" \
        kubernetes_ca_cert="${K8S_CACERT}" \
        token_reviewer_jwt="${TR_ACCOUNT_TOKEN}"

    kubectl --namespace=csi exec -ti $VAULT_POD -- vault policy write example-readonly -<<EOF
path "sys/mounts" {
  capabilities = ["read"]
}

path "secret/data/foo" {
  capabilities = ["read", "list"]
}

path "secret/data/foo1" {
  capabilities = ["read", "list"]
}

path "secret/*" {
  capabilities = ["read", "list"]
}

path "sys/renew/*" {
  capabilities = ["update"]
}
EOF

    kubectl --namespace=csi exec $VAULT_POD -- vault write auth/kubernetes/role/example-role \
        bound_service_account_names=secrets-store-csi-driver-provider-vault \
        bound_service_account_namespaces=csi \
        policies=default,example-readonly \
        ttl=20m

    kubectl --namespace=csi exec $VAULT_POD -- vault kv put secret/foo bar=hello > /dev/null
    kubectl --namespace=csi exec $VAULT_POD -- vault kv put secret/foo1 bar1=hello1 > /dev/null

    # Final setup pieces.
    kubectl create namespace test > /dev/null
    kubectl --namespace=test apply -f $CONFIGS/*-secretproviderclass.yaml
    kubectl --namespace=csi wait --for condition=established --timeout=60s crd/secretproviderclasses.secrets-store.csi.x-k8s.io > /dev/null
}

teardown(){
    # Teardown Vault configuration.
    kubectl --namespace=csi exec $VAULT_POD -- vault auth disable kubernetes
    kubectl --namespace=csi exec -ti $VAULT_POD -- vault policy delete example-readonly
    kubectl --namespace=csi exec $VAULT_POD -- vault kv delete secret/foo
    kubectl --namespace=csi exec $VAULT_POD -- vault kv delete secret/foo1

    # Teardown k8s resources.
    kubectl delete namespace test
}

@test "Inline secrets-store-csi volume" {
    kubectl --namespace=test apply -f $CONFIGS/nginx-inline-volume.yaml
    kubectl --namespace=test wait --for=condition=Ready --timeout=60s pod/nginx-secrets-store-inline

    result=$(kubectl --namespace=test exec nginx-secrets-store-inline -- cat /mnt/secrets-store/bar)
    [[ "$result" == "hello" ]]

    result=$(kubectl --namespace=test exec nginx-secrets-store-inline -- cat /mnt/secrets-store/bar1)
    [[ "$result" == "hello1" ]]
}

# @test "Sync with K8s secrets - create deployment" {
#   export VAULT_SERVICE_IP=$(kubectl --namespace=test get service vault -o jsonpath='{.spec.clusterIP}')

#   envsubst < $BATS_TESTS_DIR/vault_synck8s_v1alpha1_secretproviderclass.yaml | kubectl --namespace=test apply -f -

#   cmd="kubectl --namespace=test wait --for condition=established --timeout=60s crd/secretproviderclasses.secrets-store.csi.x-k8s.io"
#   wait_for_process $WAIT_TIME $SLEEP_TIME "$cmd"

#   cmd="kubectl --namespace=test get secretproviderclasses.secrets-store.csi.x-k8s.io/vault-foo-sync -o yaml | grep vault"
#   wait_for_process $WAIT_TIME $SLEEP_TIME "$cmd"

#   run kubectl --namespace=test apply -f $BATS_TESTS_DIR/nginx-deployment-synck8s.yaml
#   assert_success

#   run kubectl --namespace=test apply -f $BATS_TESTS_DIR/nginx-deployment-two-synck8s.yaml
#   assert_success

#   cmd="kubectl --namespace=test wait --for=condition=Ready --timeout=60s pod -l app=nginx"
#   wait_for_process $WAIT_TIME $SLEEP_TIME "$cmd"
# }

# @test "Sync with K8s secrets - read secret from pod, read K8s secret, read env var, check secret ownerReferences with multiple owners" {
#   POD=$(kubectl --namespace=test get pod -l app=nginx -o jsonpath="{.items[0].metadata.name}")
#   result=$(kubectl --namespace=test exec $POD -- cat /mnt/secrets-store/bar)
#   [[ "$result" == "hello" ]]

#   result=$(kubectl --namespace=test exec $POD -- cat /mnt/secrets-store/bar1)
#   [[ "$result" == "hello1" ]]

#   result=$(kubectl --namespace=test get secret foosecret -o jsonpath="{.data.pwd}" | base64 -d)
#   [[ "$result" == "hello" ]]

#   result=$(kubectl --namespace=test exec $POD -- printenv | grep SECRET_USERNAME | awk -F"=" '{ print $2 }' | tr -d '\r\n')
#   [[ "$result" == "hello1" ]]

#   result=$(kubectl --namespace=test get secret foosecret -o jsonpath="{.metadata.labels.environment}")
#   [[ "${result//$'\r'}" == "${LABEL_VALUE}" ]]

#   result=$(kubectl --namespace=test get secret foosecret -o jsonpath="{.metadata.labels.secrets-store\.csi\.k8s\.io/managed}")
#   [[ "${result//$'\r'}" == "true" ]]

#   run wait_for_process $WAIT_TIME $SLEEP_TIME "compare_owner_count foosecret default 4"
#   assert_success
# }

# @test "Sync with K8s secrets - delete deployment, check secret is deleted" {
#   run kubectl --namespace=test delete -f $BATS_TESTS_DIR/nginx-deployment-synck8s.yaml
#   assert_success
  
#   run wait_for_process $WAIT_TIME $SLEEP_TIME "compare_owner_count foosecret default 2"
#   assert_success

#   run kubectl --namespace=test delete -f $BATS_TESTS_DIR/nginx-deployment-two-synck8s.yaml
#   assert_success

#   run wait_for_process $WAIT_TIME $SLEEP_TIME "check_secret_deleted foosecret default"
#   assert_success

#   run kubectl --namespace=test delete -f $BATS_TESTS_DIR/vault_synck8s_v1alpha1_secretproviderclass.yaml
#   assert_success
# }

# @test "Test Namespaced scope SecretProviderClass - create deployment" {
#   export VAULT_SERVICE_IP=$(kubectl --namespace=test get service vault -o jsonpath='{.spec.clusterIP}')

#   run kubectl --namespace=test create ns test-ns
#   assert_success

#   envsubst < $BATS_TESTS_DIR/vault_v1alpha1_secretproviderclass_ns.yaml | kubectl --namespace=test apply -f -

#   cmd="kubectl --namespace=test wait --for condition=established --timeout=60s crd/secretproviderclasses.secrets-store.csi.x-k8s.io"
#   wait_for_process $WAIT_TIME $SLEEP_TIME "$cmd"

#   cmd="kubectl --namespace=test get secretproviderclasses.secrets-store.csi.x-k8s.io/vault-foo-sync -o yaml | grep vault"
#   wait_for_process $WAIT_TIME $SLEEP_TIME "$cmd"

#   cmd="kubectl --namespace=test get secretproviderclasses.secrets-store.csi.x-k8s.io/vault-foo-sync -n test-ns -o yaml | grep vault"
#   wait_for_process $WAIT_TIME $SLEEP_TIME "$cmd"

#   envsubst < $BATS_TESTS_DIR/nginx-deployment-synck8s.yaml | kubectl --namespace=test apply -n test-ns -f -

#   cmd="kubectl --namespace=test wait --for=condition=Ready --timeout=60s pod -l app=nginx -n test-ns"
#   wait_for_process $WAIT_TIME $SLEEP_TIME "$cmd"
# }

# @test "Test Namespaced scope SecretProviderClass - Sync with K8s secrets - read secret from pod, read K8s secret, read env var, check secret ownerReferences" {
#   POD=$(kubectl --namespace=test get pod -l app=nginx -n test-ns -o jsonpath="{.items[0].metadata.name}")
#   result=$(kubectl --namespace=test exec -n test-ns $POD -- cat /mnt/secrets-store/bar)
#   [[ "$result" == "hello" ]]

#   result=$(kubectl --namespace=test exec -n test-ns $POD -- cat /mnt/secrets-store/bar1)
#   [[ "$result" == "hello1" ]]

#   result=$(kubectl --namespace=test get secret foosecret -n test-ns -o jsonpath="{.data.pwd}" | base64 -d)
#   [[ "$result" == "hello" ]]

#   result=$(kubectl --namespace=test exec -n test-ns $POD -- printenv | grep SECRET_USERNAME | awk -F"=" '{ print $2 }' | tr -d '\r\n')
#   [[ "$result" == "hello1" ]]

#   run wait_for_process $WAIT_TIME $SLEEP_TIME "compare_owner_count foosecret test-ns 2"
#   assert_success
# }

# @test "Test Namespaced scope SecretProviderClass - Sync with K8s secrets - delete deployment, check secret deleted" {
#   run kubectl --namespace=test delete -f $BATS_TESTS_DIR/nginx-deployment-synck8s.yaml -n test-ns
#   assert_success

#   run wait_for_process $WAIT_TIME $SLEEP_TIME "check_secret_deleted foosecret test-ns"
#   assert_success
# }

# @test "Test Namespaced scope SecretProviderClass - Should fail when no secret provider class in same namespace" {
#   export VAULT_SERVICE_IP=$(kubectl --namespace=test get service vault -o jsonpath='{.spec.clusterIP}')

#   run kubectl --namespace=test create ns negative-test-ns
#   assert_success

#   envsubst < $BATS_TESTS_DIR/nginx-deployment-synck8s.yaml | kubectl --namespace=test apply -n negative-test-ns -f -
#   sleep 5

#   POD=$(kubectl --namespace=test get pod -l app=nginx -n negative-test-ns -o jsonpath="{.items[0].metadata.name}")
#   cmd="kubectl --namespace=test describe pod $POD -n negative-test-ns | grep 'FailedMount.*failed to get secretproviderclass negative-test-ns/vault-foo-sync.*not found'"
#   wait_for_process $WAIT_TIME $SLEEP_TIME "$cmd"

#   run kubectl --namespace=test delete -f $BATS_TESTS_DIR/nginx-deployment-synck8s.yaml -n negative-test-ns
#   assert_success

#   run kubectl --namespace=test delete ns negative-test-ns
#   assert_success
# }

# @test "deploy multiple vault secretproviderclass crd" {
#   export VAULT_SERVICE_IP=$(kubectl --namespace=test get service vault -o jsonpath='{.spec.clusterIP}')

#   envsubst < $BATS_TESTS_DIR/vault_v1alpha1_multiple_secretproviderclass.yaml | kubectl --namespace=test apply -f -

#   cmd="kubectl --namespace=test wait --for condition=established --timeout=60s crd/secretproviderclasses.secrets-store.csi.x-k8s.io"
#   wait_for_process $WAIT_TIME $SLEEP_TIME "$cmd"

#   cmd="kubectl --namespace=test get secretproviderclasses.secrets-store.csi.x-k8s.io/vault-foo-sync-0 -o yaml | grep vault-foo-sync-0"
#   wait_for_process $WAIT_TIME $SLEEP_TIME "$cmd"

#   cmd="kubectl --namespace=test get secretproviderclasses.secrets-store.csi.x-k8s.io/vault-foo-sync-1 -o yaml | grep vault-foo-sync-1"
#   wait_for_process $WAIT_TIME $SLEEP_TIME "$cmd"
# }

# @test "deploy pod with multiple secret provider class" {
#   envsubst < $BATS_TESTS_DIR/nginx-pod-vault-inline-volume-multiple-spc.yaml | kubectl --namespace=test apply -f -
  
#   cmd="kubectl --namespace=test wait --for=condition=Ready --timeout=60s pod/nginx-secrets-store-inline-multiple-crd"
#   wait_for_process $WAIT_TIME $SLEEP_TIME "$cmd"

#   run kubectl --namespace=test get pod/nginx-secrets-store-inline-multiple-crd
#   assert_success
# }

# @test "CSI inline volume test with multiple secret provider class" {
#   result=$(kubectl --namespace=test exec nginx-secrets-store-inline-multiple-crd -- cat /mnt/secrets-store-0/bar)
#   [[ "$result" == "hello" ]]

#   result=$(kubectl --namespace=test exec nginx-secrets-store-inline-multiple-crd -- cat /mnt/secrets-store-0/bar1)
#   [[ "$result" == "hello1" ]]

#   result=$(kubectl --namespace=test get secret foosecret-0 -o jsonpath="{.data.pwd}" | base64 -d)
#   [[ "$result" == "hello" ]]

#   result=$(kubectl --namespace=test exec nginx-secrets-store-inline-multiple-crd -- printenv | grep SECRET_USERNAME_0 | awk -F"=" '{ print $2 }' | tr -d '\r\n')
#   [[ "$result" == "hello1" ]]

#   run wait_for_process $WAIT_TIME $SLEEP_TIME "compare_owner_count foosecret-0 default 1"
#   assert_success

#   result=$(kubectl --namespace=test exec nginx-secrets-store-inline-multiple-crd -- cat /mnt/secrets-store-1/bar)
#   [[ "$result" == "hello" ]]

#   result=$(kubectl --namespace=test exec nginx-secrets-store-inline-multiple-crd -- cat /mnt/secrets-store-1/bar1)
#   [[ "$result" == "hello1" ]]

#   result=$(kubectl --namespace=test get secret foosecret-1 -o jsonpath="{.data.pwd}" | base64 -d)
#   [[ "$result" == "hello" ]]

#   result=$(kubectl --namespace=test exec nginx-secrets-store-inline-multiple-crd -- printenv | grep SECRET_USERNAME_1 | awk -F"=" '{ print $2 }' | tr -d '\r\n')
#   [[ "$result" == "hello1" ]]

#   run wait_for_process $WAIT_TIME $SLEEP_TIME "compare_owner_count foosecret-1 default 1"
#   assert_success
# }
