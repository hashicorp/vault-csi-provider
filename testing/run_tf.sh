cleanup() {
  kill -9 $(pgrep kubectl)
}
trap cleanup EXIT

CLUSTER_FQN="https://$(minikube ip)"

# created for us by the helm chart
SECRET_NAME="$(kubectl get serviceaccount vault \
	-o go-template='{{ (index .secrets 0).name }}')"

TR_ACCOUNT_TOKEN="$(kubectl get secret ${SECRET_NAME} \
	-o go-template='{{ .data.token }}' | base64 --decode)"

K8S_CACERT="$(kubectl config view --raw --minify --flatten -o jsonpath='{.clusters[].cluster.certificate-authority-data}' | base64 -d)"

K8S_HOST="$(kubectl config view --raw \
    -o go-template="{{ range .clusters }}{{ if eq .name \"${CLUSTER_FQN}\" }}{{ index .cluster \"server\" }}{{ end }}{{ end }}")"

export TF_VAR_k8s_host="${CLUSTER_FQN}"
export TF_VAR_k8s_cert="${K8S_CACERT}"
export TF_VAR_k8s_jwt="${TR_ACCOUNT_TOKEN}"
export VAULT_ADDR='http://localhost:8200'

# port forward vault to the local machine to get around not having a ingress on the service
# kubectl port-forward vault-0 8200:8200 > /dev/null &
# vault operator init -n 1 -t 1
# vault operator unseal
# vault login

terraform init || true
terraform "$@"
