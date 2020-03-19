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
	CGO_ENABLED=0 go build -a -ldflags $(LDFLAGS) -o _output/secrets-store-csi-driver-provider-vault_$(GOOS)_$(GOARCH)_$(IMAGE_VERSION) .

image: build 
	docker build --build-arg VERSION=$(IMAGE_VERSION) --no-cache -t $(IMAGE_TAG) .

docker-push: image
	docker push $(IMAGE_TAG)
	docker tag $(IMAGE_TAG) $(IMAGE_TAG_LATEST)
	docker push $(IMAGE_TAG_LATEST)

clean:
	-rm -rf _output

setup: clean
	@echo "Setup..."
	$Q go env

.PHONY: mod
mod:
	@go mod tidy
