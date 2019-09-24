variable "k8s_host" {}
variable "k8s_cert" {}
variable "k8s_jwt" {}

variable "bound_sa_name" {
  default = "vault"
}

variable "bound_sa_namespace" {
  default = "default"
}

### Configure Kubernetes ###
resource "kubernetes_cluster_role_binding" "role-tokenreview-binding" {
  metadata {
    name = "role-tokenreveiw-binding"
  }

  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = "system:auth-delegator"
  }

  subject {
    kind      = "ServiceAccount"
    name      = "${var.bound_sa_name}"
    namespace = "${var.bound_sa_namespace}"
  }
}

### Configure Vault ###

esource "vault_auth_backend" "kubernetes" {
  type = "kubernetes"
}

resource "vault_kubernetes_auth_backend_config" "kubernetes" {
  backend            = "${vault_auth_backend.kubernetes.path}"
  kubernetes_host    = "${var.k8s_host}:8443"
  kubernetes_ca_cert = "${var.k8s_cert}"
  token_reviewer_jwt = "${var.k8s_jwt}"
}

resource "vault_kubernetes_auth_backend_role" "example" {
  backend                          = "${vault_auth_backend.kubernetes.path}"
  role_name                        = "exampleapp"
  bound_service_account_names      = ["${var.bound_sa_name}"]
  bound_service_account_namespaces = ["${var.bound_sa_namespace}"]
  token_ttl                        = 3600
  token_policies                   = ["default", "exampleapp"]
}

resource "vault_policy" "exampleapp" {
  name = "exampleapp"

  policy = <<EOT
path "secret/data/exampleapp/*" {
  capabilities =  ["create", "read", "update", "delete", "list"]
}
EOT
}
