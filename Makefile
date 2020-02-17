SHELL=/bin/bash -o pipefail

GO ?= go
DOCKER ?= docker

COMMIT_NO := $(shell git rev-parse HEAD 2> /dev/null || true)
GIT_COMMIT := $(if $(shell git status --porcelain --untracked-files=no),${COMMIT_NO}-dirty,${COMMIT_NO})
GIT_BRANCH ?= $(shell git rev-parse --abbrev-ref HEAD 2>/dev/null)
GIT_BRANCH_CLEAN := $(shell echo $(GIT_BRANCH) | sed -e "s/[^[:alnum:]]/-/g")

IMAGE_NAME_BUILDER_BASE ?= docker.io/falcosecurity/falco-builder-service-base

IMAGE_NAME_BUILDER_BASE_BRANCH := $(IMAGE_NAME_BUILDER_BASE):$(GIT_BRANCH_CLEAN)
IMAGE_NAME_BUILDER_BASE_COMMIT := $(IMAGE_NAME_BUILDER_BASE):$(GIT_COMMIT)
IMAGE_NAME_BUILDER_BASE_LATEST := $(IMAGE_NAME_BUILDER_BASE):latest

LDFLAGS := -ldflags '-X github.com/falcosecurity/build-service/pkg/version.buildTime=$(shell date +%s) -X github.com/falcosecurity/build-service/pkg/version.gitCommit=${GIT_COMMIT} -X github.com/falcosecurity/build-service/pkg/modulebuilder.builderBaseImage=${IMAGE_NAME_BUILDER_BASE_COMMIT}'

TESTPACKAGES := $(shell go list ./...)

build_service ?= _output/bin/build-service

.PHONY: build
build: clean ${build_service}

${build_service}:
	CGO_ENABLED=0 $(GO) build ${LDFLAGS} -o $@ .

.PHONY: clean
clean:
	$(RM) -R _output

.PHONY: image/build
image/build:
	$(DOCKER) build \
		-t "$(IMAGE_NAME_BUILDER_BASE_BRANCH)" \
		-f build/Dockerfile.builderbase .
	$(DOCKER) tag $(IMAGE_NAME_BUILDER_BASE_BRANCH) $(IMAGE_NAME_BUILDER_BASE_COMMIT)
	$(DOCKER) tag "$(IMAGE_NAME_BUILDER_BASE_BRANCH)" $(IMAGE_NAME_BUILDER_BASE_COMMIT)


.PHONY: image/push
image/push:
	$(DOCKER) push $(IMAGE_NAME_BUILDER_BASE_BRANCH)
	$(DOCKER) push $(IMAGE_NAME_BUILDER_BASE_COMMIT)

.PHONY: image/latest
image/latest:
	$(DOCKER) tag $(IMAGE_NAME_BUILDER_BASE_COMMIT) $(IMAGE_NAME_BUILDER_BASE_LATEST)
	$(DOCKER) push $(IMAGE_NAME_BUILDER_BASE_LATEST)

.PHONY: test
test:
	$(GO) test -v -race $(TESTPACKAGES)
