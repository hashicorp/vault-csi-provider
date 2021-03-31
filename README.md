# HashiCorp Vault Provider for Secrets Store CSI Driver

HashiCorp [Vault](https://vaultproject.io) provider for the [Secrets Store CSI driver](https://github.com/kubernetes-sigs/secrets-store-csi-driver) allows you to get secrets stored in
Vault and use the Secrets Store CSI driver interface to mount them into Kubernetes pods.

**This project is currently supported as a Beta product, but relies on Alpha
Kubernetes APIs and the CSI secrets store driver which is also Alpha. Where
possible we will provide upgrade paths and deprecation notices for future
releases, but cannot guarantee a stable API.**

## Installation

### Prerequisites

* Kubernetes 1.16+ for both the master and worker nodes (Linux-only)
* [Secrets store CSI driver](https://secrets-store-csi-driver.sigs.k8s.io/getting-started/installation.html) installed
* `TokenRequest` endpoint available, which requires setting the flags
  `--service-account-signing-key-file` and `--service-account-issuer` for
  `kube-apiserver`. Set by default from 1.20+ and earlier in most managed services.

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

## Troubleshooting

To troubleshoot issues with Vault CSI provider, look at logs from the Vault CSI
provider pod running on the same node as your application pod:

  ```bash
  kubectl get pods -o wide
  # find the Vault CSI provider pod running on the same node as your application pod

  kubectl logs vault-csi-provider-7x44t
  ```

Pass `--debug=true` to the provider to get more detailed logs. When installing
via helm, you can achieve this with `--set "csi.debug=true"`.
