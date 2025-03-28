BUILD_DIR ?= dist
REGISTRY_NAME?=docker.io/hashicorp
IMAGE_NAME=vault-csi-provider
VERSION?=0.0.0-dev
IMAGE_TAG=$(REGISTRY_NAME)/$(IMAGE_NAME):$(VERSION)
IMAGE_TAG_LATEST=$(REGISTRY_NAME)/$(IMAGE_NAME):latest
# https://reproducible-builds.org/docs/source-date-epoch/
DATE_FMT=+%Y-%m-%d-%H:%M
SOURCE_DATE_EPOCH ?= $(shell git log -1 --pretty=%ct)
ifdef SOURCE_DATE_EPOCH
  BUILD_DATE ?= $(shell date -u -d "@$(SOURCE_DATE_EPOCH)" $(DATE_FMT) 2>/dev/null || date -u -r "$(SOURCE_DATE_EPOCH)" $(DATE_FMT) 2>/dev/null || date -u $(DATE_FMT))
else
    BUILD_DATE ?= $(shell date $(DATE_FMT))
endif
PKG=github.com/hashicorp/vault-csi-provider/internal/version
LDFLAGS?="-X '$(PKG).BuildVersion=$(VERSION)' \
	-X '$(PKG).BuildDate=$(BUILD_DATE)' \
	-X '$(PKG).GoVersion=$(shell go version)'"
CSI_DRIVER_VERSION=1.4.8
VAULT_HELM_VERSION=0.29.1
VAULT_VERSION=1.19.0
GOLANGCI_LINT_FORMAT?=colored-line-number

VAULT_VERSION_ARGS=--set server.image.tag=$(VAULT_VERSION) --set csi.agent.image.tag=$(VAULT_VERSION)
ifdef VAULT_LICENSE
	VAULT_VERSION_ARGS=--set server.image.repository=docker.mirror.hashicorp.services/hashicorp/vault-enterprise \
		--set server.image.tag=$(VAULT_VERSION)-ent \
		--set server.enterpriseLicense.secretName=vault-ent-license \
		--set csi.agent.image.repository=docker.mirror.hashicorp.services/hashicorp/vault-enterprise \
		--set csi.agent.image.tag=$(VAULT_VERSION)-ent

endif

.PHONY: default build test bootstrap fmt lint image e2e-image e2e-setup e2e-teardown e2e-test mod setup-kind promote-staging-manifest copyright clean

GO111MODULE?=on
export GO111MODULE

default: test

bootstrap:
	@echo "Downloading tools..."
	@go generate -tags tools tools/tools.go

fmt:
	gofumpt -l -w .

lint:
	golangci-lint run \
		--disable-all \
		--timeout=10m \
		--out-format=$(GOLANGCI_LINT_FORMAT) \
		--enable=gofmt \
		--enable=gosimple \
		--enable=govet \
		--enable=errcheck \
		--enable=ineffassign \
		--enable=unused

build: clean
	CGO_ENABLED=0 go build \
		-ldflags $(LDFLAGS) \
		-o $(BUILD_DIR)/ \
		.

test:
	go test ./...

image:
	docker build \
		--build-arg GO_VERSION=$(shell cat .go-version) \
		--target dev \
		--no-cache \
		--tag $(IMAGE_TAG) \
		.

e2e-image:
	REGISTRY_NAME="e2e" VERSION="latest" make image

setup-kind:
	kind create cluster

e2e-setup:
	kind load docker-image e2e/vault-csi-provider:latest
	kubectl apply -f test/bats/configs/cluster-resources.yaml
	helm install secrets-store-csi-driver secrets-store-csi-driver \
		--repo https://kubernetes-sigs.github.io/secrets-store-csi-driver/charts --version=$(CSI_DRIVER_VERSION) \
		--wait --timeout=5m \
		--namespace=csi \
		--set linux.image.pullPolicy="IfNotPresent" \
		--set syncSecret.enabled=true \
		--set tokenRequests[0].audience="vault"
	@if [ -n "$(VAULT_LICENSE)" ]; then\
        kubectl create --namespace=csi secret generic vault-ent-license --from-literal="license=$(VAULT_LICENSE)";\
    fi
	helm install vault-bootstrap test/bats/configs/vault \
		--namespace=csi
	helm install vault vault \
		--repo https://helm.releases.hashicorp.com --version=$(VAULT_HELM_VERSION) \
		--wait --timeout=5m \
		--namespace=csi \
		--values=test/bats/configs/vault/vault.values.yaml \
		$(VAULT_VERSION_ARGS)
	kubectl wait --namespace=csi --for=condition=Ready --timeout=5m pod -l app.kubernetes.io/name=vault
	kubectl exec -i --namespace=csi vault-0 -- /bin/sh /mnt/bootstrap/bootstrap.sh
	kubectl wait --namespace=csi --for=condition=Ready --timeout=5m pod -l app.kubernetes.io/name=vault-csi-provider

e2e-teardown:
	helm uninstall --namespace=csi vault || true
	helm uninstall --namespace=csi vault-bootstrap || true
	helm uninstall --namespace=csi secrets-store-csi-driver || true
	kubectl delete --ignore-not-found -f test/bats/configs/cluster-resources.yaml

e2e-test:
	bats test/bats/provider.bats

mod:
	@go mod tidy

promote-staging-manifest: #promote staging manifests to release dir
	@rm -rf deployment
	@cp -r manifest_staging/deployment .

copyright:
	copywrite headers

clean:
	-rm -rf $(BUILD_DIR)
