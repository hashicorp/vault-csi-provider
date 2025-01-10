# HashiCorp Vault Provider for Secrets Store CSI Driver

> :warning: **Please note**: We take Vault's security and our users' trust very seriously. If
you believe you have found a security issue in Vault CSI Provider, _please responsibly disclose_
by contacting us at [security@hashicorp.com](mailto:security@hashicorp.com).

HashiCorp [Vault](https://vaultproject.io) provider for the [Secrets Store CSI driver](https://github.com/kubernetes-sigs/secrets-store-csi-driver) allows you to get secrets stored in
Vault and use the Secrets Store CSI driver interface to mount them into Kubernetes pods.

## Installation

### Prerequisites

* Supported Kubernetes version, see the [documentation](https://developer.hashicorp.com/vault/docs/platform/k8s/csi#supported-kubernetes-versions) (runs on Linux nodes only)
* [Secrets store CSI driver](https://secrets-store-csi-driver.sigs.k8s.io/getting-started/installation.html) installed

### Using helm

The recommended installation method is via helm 3:

```bash
helm repo add hashicorp https://helm.releases.hashicorp.com
# Just installs Vault CSI provider. Adjust `server.enabled` and `injector.enabled`
# if you also want helm to install Vault and the Vault Agent injector.
helm install vault hashicorp/vault \
  --set "server.enabled=false" \
  --set "injector.enabled=false" \
  --set "csi.enabled=true"
```

### Using yaml

You can also install using the deployment config in the `deployment` folder:

```bash
kubectl apply -f deployment/vault-csi-provider.yaml
```

## Usage

See the [learn tutorial](https://learn.hashicorp.com/tutorials/vault/kubernetes-secret-store-driver)
and [documentation pages](https://www.vaultproject.io/docs/platform/k8s/csi) for
full details of deploying, configuring and using Vault CSI provider. The
integration tests in [test/bats/provider.bats](./test/bats/provider.bats) also
provide a good set of fully worked and tested examples to build on.

For details on different SecretProviderClass configurations, see [examples](./examples).

## Troubleshooting

To troubleshoot issues with Vault CSI provider, look at logs from the Vault CSI
provider pod running on the same node as your application pod:

  ```bash
  kubectl get pods -o wide
  # find the Vault CSI provider pod running on the same node as your application pod

  kubectl logs vault-csi-provider-7x44t
  ```

**Warning**
The `-debug=true` flag has been deprecated, please use `-log-level=debug` instead. 
Available log levels are `info`, `debug`, `trace`, `warn`, `error`, and `off`.

## Developing

The Makefile has targets to automate building and testing:

```bash
make build test
```

The project also uses some linting and formatting tools. To install the tools:

```bash
make bootstrap
```

You can then run the additional checks:

```bash
make fmt lint mod
```

To run a full set of integration tests on a local kind cluster, ensure you have
the following additional dependencies installed:

* `docker`
* [`kind`](https://github.com/kubernetes-sigs/kind)
* [`kubectl`](https://kubernetes.io/docs/tasks/tools/)
* [`helm`](https://helm.sh/docs/intro/install/)
* [`bats`](https://bats-core.readthedocs.io/en/stable/installation.html)

You can then run:

```bash
make setup-kind e2e-image e2e-setup e2e-test
```

Finally tidy up the resources created in the kind cluster with:

```bash
make e2e-teardown
```
