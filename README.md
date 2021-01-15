# HashiCorp Vault Provider for Secrets Store CSI Driver

HashiCorp [Vault](https://vaultproject.io) provider for the [Secrets Store CSI driver](https://github.com/kubernetes-sigs/secrets-store-csi-driver) allows you to get secrets stored in
Vault and use the Secrets Store CSI driver interface to mount them into Kubernetes pods.

**This is an experimental project. This project isn't production ready.**

## Attribution

This project is forked from and initially developed by our awesome partners at Microsoft ([https://github.com/deislabs/secrets-store-csi-driver]). Thank you to [Rita](https://github.com/deislabs/secrets-store-csi-driver/commits?author=ritazh) and [Mishra](https://github.com/deislabs/secrets-store-csi-driver/commits?author=anubhavmishra) for pushing this great project forward.

## Demo

![Secret Store CSI Driver Vault Provider Demo](./images/secret-store-csi-driver-vault-provider-demo.gif "Secret Store CSI Driver Vault Provider Demo")

## Prerequisites

The guide assumes the following:

* A Kubernetes v1.16.0+ cluster up and running.
* [Vault CLI](https://www.vaultproject.io/docs/install)
* A Vault cluster up and running. Instructions for spinning up a *development* Vault cluster in Kubernetes can be
found [here](./docs/vault-setup.md).
* [kubectl](https://kubernetes.io/docs/tasks/tools/install-kubectl/#install-kubectl) installed.

## Usage

This guide will walk you through the steps to configure and run the Vault provider for Secret Store CSI
driver on Kubernetes.

Make sure you have followed the [prerequisites](#prerequisites) specified above before you continue with this guide.
You should have a development Vault cluster up and running using the [guide](./docs/vault-setup.md) specified above.

### Install the Secrets Store CSI Driver (Kubernetes Version 1.16.0+)

Make sure you have followed the [Installation guide for the Secrets Store CSI Driver](https://github.com/deislabs/secrets-store-csi-driver#usage),
and have installed at least v0.0.17 of the driver. For version 0.0.7 onwards of the provider, the driver must have
`vault` in the list of `--grpc-supported-providers`, which can be set in the helm chart via `grpcSupportedProviders`.

To validate the driver is running as expected, run the following commands:

```bash
kubectl get pods -l app=csi-secrets-store
```

You should see the driver pods running on each agent node:

```bash
NAME                                     READY   STATUS    RESTARTS   AGE
csi-secrets-store-jlls6                  3/3     Running   0          10s
csi-secrets-store-qt2l7                  3/3     Running   0          10s
```

Check the version, which should return something like `k8s.gcr.io/csi-secrets-store/driver:v0.0.18`:

```bash
kubectl get daemonset -l app=secrets-store-csi-driver -o jsonpath="{.items[0].spec.template.spec.containers[1].image}"
```

### Install the HashiCorp Vault Provider

For linux nodes

```bash
kubectl apply -f https://raw.githubusercontent.com/hashicorp/secrets-store-csi-driver-provider-vault/master/deployment/provider-vault-installer.yaml
```

To validate the provider's installer is running as expected, run the following commands:

```bash
kubectl get pods -l app=csi-secrets-store-provider-vault
```

You should see the provider pods running on each agent node:

```bash
NAME                                     READY   STATUS    RESTARTS   AGE
csi-secrets-store-provider-vault-4ngf4   1/1     Running   0          8s
csi-secrets-store-provider-vault-bxr5k   1/1     Running   0          8s
```

### Create a SecretProviderClass Resource

Update [this sample deployment](examples/v1alpha1_secretproviderclass.yaml) to create a `SecretProviderClass` resource to provide Vault-specific parameters for the Secrets Store CSI driver.

```yaml
apiVersion: secrets-store.csi.x-k8s.io/v1alpha1
kind: SecretProviderClass
metadata:
  name: vault-foo
spec:
  provider: vault
  parameters:
    roleName: "example-role"                    # Vault role created in prerequisite steps
    vaultAddress: "http://10.0.38.189:8200"     # Kubernetes Vault service endpoint
    vaultSkipTLSVerify: "true"
    objects:  |
      array:
        - |
          objectPath: "v1/secret/foo"           # secret path in the Vault Key-Value store e.g. vault kv put secret/foo bar=hello
          objectName: "bar"
          objectVersion: ""
```

> NOTE: Make sure the `vaultAddress` is pointing to the Kubernetes `vault` service that is running in your cluster from the previous [Prerequisites](#Prerequisites) section.
You can get the `vault` service address using the following command.

```bash
kubectl get service vault
```

Deploy the SecretProviderClass yaml created previously. For example:

```bash
kubectl apply -f ./examples/v1alpha1_secretproviderclass.yaml
```

### Update your Application Deployment Yaml

To ensure your application is using the Secrets Store CSI driver, update your deployment yaml to use the `secrets-store.csi.k8s.io` driver and reference the `SecretProviderClass` resource created in the previous step.

We will use an NGINX deployment to showcase accessing the secret mounted by the Secrets Store CSI Driver.
The mount point and the `SecretProviderClass` configuration for the secret will be in the [pod deployment specification](./examples/nginx-pod-vault-inline-volume-secretproviderclass.yaml) file.

```yaml
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
          secretProviderClass: "vault-foo"
```

Deploy the application

```bash
kubectl apply -f examples/nginx-pod-vault-inline-volume-secretproviderclass.yaml
```

### Validate the secret

To validate, once the pod is started, you should see the new mounted content at the volume path specified in your deployment yaml.

```bash
kubectl exec -it nginx-secrets-store-inline cat /mnt/secrets-store/bar
hello
```

> **Breaking change in Vault provider v0.0.5** NOTE: The name of the secret file is now equal to `objectName` (e.g `bar`), it used to be the `objectPath` (e.g `foo`). This breaking change enables to access multiple values within a single key (e.g both `bar` and `baz` within the `/foo` key).

## Troubleshooting

To troubleshoot issues with the csi driver and the provider, you can look at logs from the `secrets-store` container of the csi driver pod running on the same node as your application pod:

  ```bash
  kubectl get pod -o wide
  # find the secrets store csi driver pod running on the same node as your application pod

  kubectl logs csi-secrets-store-secrets-store-csi-driver-7x44t secrets-store
  ```
