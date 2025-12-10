BUILD_DIR ?= dist
REGISTRY_NAME?=docker.io/hashicorp
IMAGE_NAME=vault-csi-provider
VERSION?=0.0.0-dev
IMAGE_TAG=$(REGISTRY_NAME)/$(IMAGE_NAME):$(VERSION)
IMAGE_TAG_LATEST=$(REGISTRY_NAME)/$(IMAGE_NAME):latest
GOOS ?=linux
GOARCH ?=amd64
# https://reproducible-builds.org/docs/source-date-epoch/
DATE_FMT=+%Y-%m-%d-%H:%M
SOURCE_DATE_EPOCH ?= $(shell git log -1 --pretty=%ct)
ifdef SOURCE_DATE_EPOCH
  BUILD_DATE ?= $(shell date -u -d "@$(SOURCE_DATE_EPOCH)" $(DATE_FMT) 2>/dev/null || date -u -r "$(SOURCE_DATE_EPOCH)" $(DATE_FMT) 2>/dev/null || date -u $(DATE_FMT))
else
    BUILD_DATE ?= $(shell date $(DATE_FMT))
endif
PKG=github.com/hashicorp/vault-csi-provider/internal/version
LDFLAGS?="-buildid= -s -w -X '$(PKG).BuildVersion=$(VERSION)' \
	-X '$(PKG).BuildDate=$(BUILD_DATE)' \
	-X '$(PKG).GoVersion=$(shell go version)'"
CSI_DRIVER_VERSION=1.5.3
VAULT_HELM_VERSION=0.31.0
VAULT_VERSION=1.20.4
GOLANGCI_LINT_FORMAT?=colored-line-number

VAULT_VERSION_ARGS=--set server.image.tag=$(VAULT_VERSION) --set csi.agent.image.tag=$(VAULT_VERSION)
ifdef VAULT_LICENSE
	VAULT_VERSION_ARGS=--set server.image.repository=docker.mirror.hashicorp.services/hashicorp/vault-enterprise \
		--set server.image.tag=$(VAULT_VERSION)-ent \
		--set server.enterpriseLicense.secretName=vault-ent-license \
		--set csi.agent.image.repository=docker.mirror.hashicorp.services/hashicorp/vault-enterprise \
		--set csi.agent.image.tag=$(VAULT_VERSION)-ent

endif

OPENSHIFT_VAULT_VALUES=
ifdef OPENSHIFT
	OPENSHIFT_VAULT_VALUES=--set global.openshift=true
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
		-trimpath \
		-mod=readonly \
		-modcacherw \
		-ldflags $(LDFLAGS) \
		-o $(BUILD_DIR)/ \
		.

ci-build: clean
	CGO_ENABLED=0 go build \
		-ldflags $(LDFLAGS) \
		-o $(BUILD_DIR)/ \
		.
	mkdir -p dist/$(GOOS)/$(GOARCH)
	cp $(BUILD_DIR)/$(IMAGE_NAME) dist/$(GOOS)/$(GOARCH)/$(IMAGE_NAME)

test:
	go test ./...

image:
	docker build \
		--build-arg GO_VERSION=$(shell cat .go-version) \
		--target dev \
		--no-cache \
		--tag $(IMAGE_TAG) \
		.

image-ubi:
	docker build \
		--build-arg PRODUCT_VERSION=$(VERSION) \
		--build-arg PRODUCT_REVISION=$(VERSION) \
		--target release-ubi \
		--no-cache \
		--tag $(IMAGE_TAG) \
		.

e2e-image:
	REGISTRY_NAME="e2e" VERSION="latest" make image

e2e-image-ubi:
	REGISTRY_NAME="e2e" VERSION="latest" make image-ubi

setup-kind:
	kind create cluster

e2e-setup-driver:
	kubectl apply -f test/bats/configs/cluster-resources.yaml
	helm install secrets-store-csi-driver secrets-store-csi-driver \
		--repo https://kubernetes-sigs.github.io/secrets-store-csi-driver/charts --version=$(CSI_DRIVER_VERSION) \
		--wait --timeout=5m \
		--namespace=csi \
		--set linux.image.pullPolicy="IfNotPresent" \
		--set syncSecret.enabled=true \
		--set tokenRequests[0].audience="vault"

e2e-setup-provider:
	kubectl apply -f test/bats/configs/cluster-resources.yaml
	@if [ -n "$(OPENSHIFT)" ]; then\
		oc adm policy add-scc-to-user privileged system:serviceaccount:csi:vault-csi-provider;\
		oc apply -f test/bats/configs/scc.yaml;\
	else\
		kind load docker-image e2e/vault-csi-provider:latest;\
	fi

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
		$(VAULT_VERSION_ARGS) $(OPENSHIFT_VAULT_VALUES) $(EXTRA_VAULT_VALUES)
	kubectl wait --namespace=csi --for=condition=Ready --timeout=5m pod -l app.kubernetes.io/name=vault
	kubectl exec -i --namespace=csi vault-0 -- /bin/sh /mnt/bootstrap/bootstrap.sh
	kubectl wait --namespace=csi --for=condition=Ready --timeout=5m pod -l app.kubernetes.io/name=vault-csi-provider

e2e-setup: e2e-setup-driver e2e-setup-provider

e2e-setup-openshift:
	make e2e-setup-provider OPENSHIFT=true

e2e-teardown-provider:
	helm uninstall --namespace=csi vault || true
	helm uninstall --namespace=csi vault-bootstrap || true
	@if [ -n "$(OPENSHIFT)" ]; then\
		oc adm policy remove-scc-from-user privileged system:serviceaccount:csi:vault-csi-provider || true;\
		oc delete -f test/bats/configs/scc.yaml || true;\
	fi

e2e-teardown-driver:
	helm uninstall --namespace=csi secrets-store-csi-driver || true

e2e-teardown: e2e-teardown-provider e2e-teardown-driver
	kubectl delete --ignore-not-found -f test/bats/configs/cluster-resources.yaml

e2e-teardown-openshift:
	make e2e-teardown-provider OPENSHIFT=true
	kubectl delete --ignore-not-found -f test/bats/configs/cluster-resources.yaml

e2e-test:
	bats test/bats/provider.bats

e2e-test-openshift:
	make e2e-test OPENSHIFT=true

mod:
	@go mod tidy

promote-staging-manifest: #promote staging manifests to release dir
	@rm -rf deployment
	@cp -r manifest_staging/deployment .

copyright:
	copywrite headers

clean:
	-rm -rf $(BUILD_DIR)
