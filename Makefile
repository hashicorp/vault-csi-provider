REGISTRY_NAME?=docker.io/hashicorp
IMAGE_NAME=secrets-store-csi-driver-provider-vault
IMAGE_VERSION?=$(shell git tag | tail -1)
IMAGE_TAG=$(REGISTRY_NAME)/$(IMAGE_NAME):$(IMAGE_VERSION)
IMAGE_TAG_LATEST=$(REGISTRY_NAME)/$(IMAGE_NAME):latest
BUILD_DATE=$$(date +%Y-%m-%d-%H:%M)
LDFLAGS?="-X main.BuildVersion=$(IMAGE_VERSION) -X main.BuildDate=$(BUILD_DATE) -extldflags "-static""
GOOS=linux
GOARCH=amd64

.PHONY: all build image clean test-style

GO111MODULE ?= on
export GO111MODULE

HAS_GOLANGCI := $(shell command -v golangci-lint;)

all: build

test: test-style
	go test sigs.k8s.io/secrets-store-csi-driver/pkg/... -cover
	go vet sigs.k8s.io/secrets-store-csi-driver/pkg/...

test-style: setup
	@echo "==> Running static validations and linters <=="
	golangci-lint run

build: setup
	GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=0 go build -a -ldflags $(LDFLAGS) -o _output/secrets-store-csi-driver-provider-vault_$(GOOS)_$(GOARCH)_$(IMAGE_VERSION) .

image: build 
	docker build --build-arg VERSION=$(IMAGE_VERSION) -t $(IMAGE_TAG) .

e2e-container:
	REGISTRY_NAME="e2e" IMAGE_VERSION="latest" make image
	kind load docker-image e2e/secrets-store-csi-driver-provider-vault:latest

docker-push: image
	docker push $(IMAGE_TAG)
	docker tag $(IMAGE_TAG) $(IMAGE_TAG_LATEST)
	docker push $(IMAGE_TAG_LATEST)

e2e-setup: e2e-container
	kubectl create namespace csi
	helm install secrets-store-csi-driver https://github.com/kubernetes-sigs/secrets-store-csi-driver/blob/master/charts/secrets-store-csi-driver-0.0.19.tgz?raw=true \
		--wait --timeout=5m \
		--namespace=csi \
		--set linux.image.pullPolicy="IfNotPresent" \
		--set grpcSupportedProviders="azure;gcp;vault"
	kubectl apply -f test/bats/configs/vault-auth-serviceaccount.yaml
	kubectl apply --namespace=csi -f test/bats/configs/vault.yaml
	kubectl apply --namespace=csi -f test/bats/configs/secrets-store-csi-driver-provider-vault.yaml
	kubectl wait --namespace=csi --for=condition=Ready --timeout=5m pod -l app=vault
	kubectl wait --namespace=csi --for=condition=Ready --timeout=5m pod -l app=secrets-store-csi-driver-provider-vault

e2e-teardown:
	kubectl delete -f test/bats/configs/vault-auth-serviceaccount.yaml
	kubectl delete --namespace=csi -f test/bats/configs/vault.yaml
	kubectl delete --namespace=csi -f test/bats/configs/secrets-store-csi-driver-provider-vault.yaml
	helm uninstall --namespace=csi secrets-store-csi-driver
	kubectl delete namespace csi

e2e-test:
	bats test/bats/provider.bats

clean:
	-rm -rf _output

setup: clean
	@echo "Setup..."
	$Q go env

.PHONY: mod
mod:
	@go mod tidy
