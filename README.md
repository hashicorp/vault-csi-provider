# HashiCorp Vault Provider for Secret Store CSI Driver

HashiCorp [Vault](https://vaultproject.io) provider for Secret Store CSI driver
enables you retrieve Vault secrets and mount them as volumes through the Secret
Store CSI driver interface.

**This is an experimental project. This project isn't production ready.**

## Attribution

This project is forked from and initially developed by our awesome partners at
Microsoft (https://github.com/deislabs/secrets-store-csi-driver). Thank you to
[Rita](https://github.com/deislabs/secrets-store-csi-driver/commits?author=ritazh)
and
[Mishra](https://github.com/deislabs/secrets-store-csi-driver/commits?author=anubhavmishra)
for pushing this great project forward.

## Demo

![Secret Store CSI Driver Vault Provider Demo](./images/secret-store-csi-driver-vault-provider-demo.gif "Secret Store CSI Driver Vault Provider Demo")

The [Mount Vault Secrets through Container Storage Interface (CSI)
Volume](https://learn.hashicorp.com/vault/getting-started-k8s/secret-store-driver)
learn guide demonstrates its function in Minikube.

## Prerequisites

* [kubectl](https://kubernetes.io/docs/tasks/tools/install-kubectl/)
  installed
* [helm](https://github.com/helm/helm#install) installed
* Kubernetes cluster running (Version **v1.15.x+**)

## Usage

With the prerequisites met it is time to:

- install the Vault Helm chart
- create a secret in Vault
- configure the Vault Kubernetes authenication method
- install the Secrets Store CSI Driver Helm chart
- install the Vault Provider for Secret Store CSI Driver
- Create a SecretProviderClass resource
- create a pod that mounts the secret volume

### Install the Vault Helm chart

Vault manages the secrets that are written to these mountable volumes. To
provide these secrets a single Vault server is required. For this demonstration
Vault can be run in development mode to automatically handle initialization,
unsealing, and setup of a KV secrets engine.

Install the Vault Helm chart version 0.4.0 with pods prefixed with the name
vault. This will create a Kubernetes pod running Vault in ["dev"
mode](https://www.vaultproject.io/docs/concepts/dev-server.html).

```shell
$ helm install vault \
    --set "server.dev.enabled=true" \
    --set "injector.enabled=false" \
    https://github.com/hashicorp/vault-helm/archive/v0.4.0.tar.gz

NAME: vault
##...
```

The Vault server runs in development mode on a single pod
`server.dev.enabled=true`. By default the Helm chart starts a Vault-Agent
injector pod but that is disabled `injector.enabled=false`.

### Create a secret in Vault

The volume mounted to the pod in the README expects a secret stored at the path
`secret/credentials`. When Vault is run in development a [KV secret
engine](https://www.vaultproject.io/docs/secrets/kv/kv-v2.html) is enabled at
the path `/secret`.

First, start an interactive shell session on the `vault-0` pod.

```shell
$ kubectl exec -it vault-0 -- /bin/sh
/ $
```

Your system prompt is replaced with a new prompt `/ $`. Commands issued at this
prompt are executed on the `vault-0` container.

Create a secret at the path `secret/credentials` with a `username` and
`password`.

```shell
/ $ vault kv put secret/credentials username="example-username" password="example-password"
## ...
```

### Configure Vault Kubernetes authentication method

Vault provides a [Kubernetes
authentication](https://www.vaultproject.io/docs/auth/kubernetes.html) method
that enables clients to authenticate with a Kubernetes Service Account
Token. The Kubernetes resources that access the secret and create the volume
authenticate through this method through a role.

Enable the Kubernetes authentication method.

```shell
/ $ vault auth enable kubernetes
Success! Enabled kubernetes auth method at: kubernetes/
```

Configure the Kubernetes authentication method to use the service account
token, the location of the Kubernetes host, and its certificate.

```shell
/ $ vault write auth/kubernetes/config \
        token_reviewer_jwt="$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
        kubernetes_host="https://$KUBERNETES_PORT_443_TCP_ADDR:443" \
        kubernetes_ca_cert=@/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
Success! Data written to: auth/kubernetes/config
```

The `token_reviewer_jwt` and `kubernetes_ca_cert` reference files written to the
container by Kubernetes. The environment variable `KUBERNETES_PORT_443_TCP_ADDR`
references the internal network address of the Kubernetes host.

For the Kubernetes-Secrets-Store-CSI-Driver to read the secrets requires that it
has read permissions of all mounts and access to the secret itself.

Write out the policy named `internal-app`.

```shell
/ $ vault policy write internal-app - <<EOF
path "sys/mounts" {
  capabilities = ["read"]
}

path "secret/data/credentials" {
  capabilities = ["read"]
}
EOF
Success! Uploaded policy: internal-app
```

Currently the Vault extension of the Kubernetes-Secrets-Store-CSI-Driver only
supports the [KV Secrets Engine](https://www.vaultproject.io/docs/secrets/kv/).
This extension verifies that the requested secret belongs to a supported engine
by reading the mounted secrets engines. The data of kv-v2 secret requires that
the after the mount the additional path element of `data` is included.

Finally, create a Kubernetes authentication role named `internal-app-role` that
binds this policy with a Kubernetes service account named
`secrets-store-csi-driver`.

```shell
/ $ vault write auth/kubernetes/role/internal-app-role \
  bound_service_account_names=secrets-store-csi-driver \
  bound_service_account_namespaces=default \
  policies=internal-app \
  ttl=20m
Success! Data written to: auth/kubernetes/role/internal-app-role
```

The role connects the Kubernetes service account, `secrets-store-csi-driver`, in
the namespace, `default`, with the Vault policy, `internal-app`. The tokens
returned after authentication are valid for 20 minutes. This Kubernetes service
account name, `secrets-store-csi-driver`, is created in the next section when
the secrets store CSI driver Helm chart is installed.

Lastly, exit the the `vault-0` pod.

```shell
/ $ exit
$
```

### Install the Secrets Store CSI Driver Helm chart

The [secrets Store CSI driver](https://github.com/kubernetes-sigs/secrets-store-csi-driver#install-the-secrets-store-csi-driver
) repository contains a Helm chart. This project has not created
releases of this Helm chart so you are required to clone or download the
repository.

First, clone the the secrets-store-csi-driver repository.

```shell
$ git clone https://github.com/kubernetes-sigs/secrets-store-csi-driver.git
## ...
```

Next, install the Kubernetes-Secrets-Store-CSI-Driver Helm chart at the path
secrets-store-csi-driver/charts/secrets-store-csi-driver with pods prefixed with
the name csi.

```shell
$ helm install csi secrets-store-csi-driver/charts/secrets-store-csi-driver

NAME: csi
## ...
```

### Install the Vault Provider for Secret Store CSI Driver

The Secrets Store CSI driver enables extension through providers. A provider is
launched as a Kubernetes DaemonSet alongside of Secrets Store CSI driver
DaemonSet.

First, define a DaemonSet to install the provider-vault executable for the Kubernetes-Secrets-Store-CSI-Driver.

```shell
$ cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: DaemonSet
metadata:
  labels:
    app: csi-secrets-store-provider-vault
  name: csi-secrets-store-provider-vault
spec:
  updateStrategy:
    type: RollingUpdate
  selector:
    matchLabels:
      app: csi-secrets-store-provider-vault
  template:
    metadata:
      labels:
        app: csi-secrets-store-provider-vault
    spec:
      serviceAccount: secrets-store-csi-driver
      tolerations:
      containers:
        - name: provider-vault-installer
          image: hashicorp/secrets-store-csi-driver-provider-vault:0.0.4
          imagePullPolicy: Always
          resources:
            requests:
              cpu: 50m
              memory: 100Mi
            limits:
              cpu: 50m
              memory: 100Mi
          env:
            - name: TARGET_DIR
              value: "/etc/kubernetes/secrets-store-csi-providers"
          volumeMounts:
            - mountPath: "/etc/kubernetes/secrets-store-csi-providers"
              name: providervol
      volumes:
        - name: providervol
          hostPath:
              path: "/etc/kubernetes/secrets-store-csi-providers"
      nodeSelector:
        beta.kubernetes.io/os: linux
EOF
daemonset.apps/csi-secrets-store-provider-vault created
```

This DaemonSet launches its own provider pod with the name prefixed with csi-secrets-store-provider-vault and mounts the executable in the existing csi-secrets-store-csi-driver pod.

### Create a SecretProviderClass resource

The Secrets-Store-CSI-Driver Helm chart creates a definition for a
`SecretProviderClass` resource. This resource describes the parameters that are
given to the executable. To configure it requires the IP address of the Vault
server, the name of the Vault Kubernetes authentication role, and the secrets.

```shell
$ cat <<EOF | kubectl apply -f -
apiVersion: secrets-store.csi.x-k8s.io/v1alpha1
kind: SecretProviderClass
metadata:
  name: vault-internal-app-secret
spec:
  provider: vault
  parameters:
    vaultAddress: "http://vault.default:8200"
    roleName: "internal-app-role"
    vaultSkipTLSVerify: "true"
    objects:  |
      array:
        - |
          objectPath: "/secret/credentials"
          objectName: "username"
          objectVersion: ""
        - |
          objectPath: "/secret/credentials"
          objectName: "password"
          objectVersion: ""
EOF
```

- `vaultAddress` in this example definition targets a Kubernetes service
  named `vault` defined in the `default` namespace.
- `roleName` is set to the Vault Kubernetes authentication role.

The `objects` defines an array of secrets to render. Each secret defines:

- `objectPath` is the path prefixed for the Vault secret. KV-V2 secret paths
  automatically add the `data` element to the requested path (i.e.
  `/secret/credentials` becomes `/secret/data/credentials`)
- `objectName` is the key defined within the Vault secret at the path
- `objectVersion` is the version of the secret to retrieve. This is for kv-v2
  secrets. When empty or not specified it defaults to the latest version.

### Create a pod that mounts the secret volume

With the secret stored in Vault, the authentication configured and role created,
the provider-vault extension installed and the SecretProviderClass defined it is
finally time to create a pod that mounts the desired secret.

Apply a pod, named `nginx-secrets-store-inline`, that mounts the volume, named
`secrets-store-inline`, using the configuration defined in the
secretProviderClass `vault-internal-app-secret`.

```shell
$ cat <<EOF | kubectl apply -f -
kind: Pod
apiVersion: v1
metadata:
  name: nginx-secrets-store-inline
spec:
  containers:
  - image: nginx
    name: nginx
    volumeMounts:
    - name: secrets-store-inline
      mountPath: "/mnt/secrets-store"
      readOnly: true
  volumes:
    - name: secrets-store-inline
      csi:
        driver: secrets-store.csi.k8s.io
        readOnly: true
        volumeAttributes:
          secretProviderClass: "vault-internal-app-secret"
EOF
pod/nginx-secrets-store-inline created
```

Read the username secret written to the file system at
`/mnt/secrets-store/username` on the nginx pod.

```shell
$ kubectl exec -it nginx-secrets-store-inline cat /mnt/secrets-store/username
example-username
```

The value displayed matches the username value for the secret
`secret/credentials`.

Finally, read the password secret written to the file system at
`/mnt/secrets-store/password` on the nginx pod.

```shell
$ kubectl exec nginx-secrets-store-inline -- cat /mnt/secrets-store/password
example-password
```
