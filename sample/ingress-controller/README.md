# Using Secrets Store CSI and Vault Provider to Enable NGINX Ingress Controller with TLS

This guide demonstrates steps required to setup Secrets Store CSI driver to enable applications to work with NGINX Ingress Controller with TLS stored in an external Secrets store. 
For more information on securing an Ingress with TLS, refer to: https://kubernetes.io/docs/concepts/services-networking/ingress/#tls

# Generate a TLS Cert

```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -out ingress-tls.crt \
    -keyout ingress-tls.key \
    -subj "/CN=demo.test.com/O=ingress-tls"
```

## Deploy Secrets-store CSI and the Vault Provider
https://github.com/kubernetes-sigs/secrets-store-csi-driver#usage

## Deploy Ingress Controller

**Create a namespace**

```bash
kubectl create ns ingress-test
```

**Helm install ingress-controller**

```bash
helm install stable/nginx-ingress --generate-name \
    --namespace ingress-test \
    --set controller.replicaCount=2 \
    --set controller.nodeSelector."beta\.kubernetes\.io/os"=linux \
    --set defaultBackend.nodeSelector."beta\.kubernetes\.io/os"=linux
```

## Setup Development Vault Cluster

Follow this [guide](https://github.com/hashicorp/secrets-store-csi-driver-provider-vault/blob/master/docs/vault-setup.md#setting-up-a-development-vault-cluster) to setup development vault cluster that will be used to store the secrets.


**Write the certificate in the Vault key-value store**

```bash
vault kv put secret/tlscrt tlscrt="$(cat ingress-tls.crt)"
vault kv put secret/tlskey tlskey="$(cat ingress-tls.key)"
```

**Create a vault policy**

```bash
echo 'path "secret/data/tlscrt" {
  capabilities = ["read", "list"]
}

path "secret/data/tlskey" {
  capabilities = ["read", "list"]
}

path "sys/renew/*" {
  capabilities = ["update"]
}

path "sys/mounts" {
  capabilities = ["read"]
}' | vault policy write ingress-readonly -
```

**Create a Vault role**

```bash
vault write auth/kubernetes/role/ingress-role \
  bound_service_account_names=secrets-store-csi-driver \
  bound_service_account_namespaces=<SECRETS-STORE-CSI-DRIVER NAMESPACE> \
  policies=default,ingress-readonly \
  ttl=20m
```

## Deploy a SecretsProviderClass Resource

```bash
$ VAULT_SERVICE_ADDR=$(kubectl get svc vault -o jsonpath="{.spec.clusterIP}")

$ cat <<EOF | kubectl apply -f -
apiVersion: secrets-store.csi.x-k8s.io/v1alpha1
kind: SecretProviderClass
metadata:
  name: vault-tls
spec:
  secretObjects:
  - secretName: ingress-tls-csi
    type: kubernetes.io/tls
    data: 
    - objectName: tlskey
      key: tls.key
    - objectName: tlscrt
      key: tls.crt
  provider: vault
  parameters:
    vaultAddress: "http://$VAULT_SERVICE_ADDR:8200"  # Kubernetes Vault service endpoint
    roleName: "ingress-role"                        # Vault role created in prerequisite steps
    vaultSkipTLSVerify: "true"
    objects:  |
      array:
        - |
          objectPath: "/tlscrt"
          objectName: "tlscrt"
          objectVersion: ""
        - |
          objectPath: "/tlskey"
          objectName: "tlskey"
          objectVersion: ""
EOF
```

## Deploy Test Apps with Reference to Secrets Store CSI

> NOTE: These apps reference a Secrets Store CSI volume and a `secretProviderClass` object created earlier. A Kubernetes secret `ingress-tls-csi` will be created by the CSI driver as a result of the app creation.

```yaml
      volumes:
        - name: secrets-store-inline
          csi:
            driver: secrets-store.csi.k8s.io
            readOnly: true
            volumeAttributes:
              secretProviderClass: "vaults-tls"
```

```bash
kubectl apply -f sample/ingress-controller-tls/vault/deployment-app-one.yaml -n ingress-test
kubectl apply -f sample/ingress-controller-tls/vault/deployment-app-two.yaml -n ingress-test
```

## Check for the Kubernetes Secret created by the CSI driver
```bash
kubectl get secret -n ingress-test

NAME                                             TYPE                                  DATA   AGE
ingress-tls-csi                                  kubernetes.io/tls                     2      1m34s
```

## Deploy an Ingress Resource referencing the Secret created by the CSI driver

> NOTE: The ingress resource references the Kubernetes secret `ingress-tls-csi` created by the CSI driver as a result of the app creation.

```yaml
tls:
  - hosts:
    - demo.test.com
    secretName: ingress-tls-csi
```

```bash
kubectl apply -f sample/ingress-controller-tls/vault/ingress.yaml -n ingress-test
```

## Get the External IP of the Ingress Controller

```bash
kubectl get service -l app=nginx-ingress --namespace ingress-test 
NAME                                       TYPE           CLUSTER-IP     EXTERNAL-IP      PORT(S)                      AGE
nginx-ingress-1588032400-controller        LoadBalancer   10.0.255.157   52.xx.xx.xx      80:31293/TCP,443:31265/TCP   19m
nginx-ingress-1588032400-default-backend   ClusterIP      10.0.223.214   <none>           80/TCP                       19m
```

## Test Ingress with TLS
Using `curl` to verify ingress configuration using TLS. 
Replace the public IP with the external IP of the ingress controller service from the previous step.  

```bash
curl -v -k --resolve demo.test.com:443:52.xx.xx.xx https://demo.test.com

# You should see the following in your output
*  subject: CN=demo.test.com; O=ingress-tls
*  start date: Apr 15 04:23:46 2020 GMT
*  expire date: Apr 15 04:23:46 2021 GMT
*  issuer: CN=demo.test.com; O=ingress-tls
*  SSL certificate verify result: self signed certificate (18), continuing anyway.
```
