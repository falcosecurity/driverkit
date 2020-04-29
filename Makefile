SHELL=/bin/bash -o pipefail

DOCKER ?= docker
GORELEASER ?= goreleaser

GIT_TAG ?= $(shell git describe --tags --abbrev=0 2> /dev/null)
COMMITS_FROM_GIT_TAG := $(shell git rev-list ${GIT_TAG}.. --count 2> /dev/null || echo "0")
COMMIT_NO := $(shell git rev-parse --short HEAD 2> /dev/null || true)
GIT_COMMIT := $(if $(shell git status --porcelain --untracked-files=no),${COMMIT_NO}.dirty,${COMMIT_NO})
GIT_BRANCH ?= $(shell git rev-parse --abbrev-ref HEAD 2>/dev/null)
GIT_BRANCH_CLEAN := $(shell echo $(GIT_BRANCH) | sed -e "s/[^[:alnum:]]/-/g")
GIT_REF := ${GIT_BRANCH_CLEAN}
ifeq ($(COMMITS_FROM_GIT_TAG),0)
	ifneq ($(GIT_TAG),)
		GIT_REF := ${GIT_TAG}
	endif
endif

IMAGE_NAME_BUILDER ?= docker.io/falcosecurity/driverkit-builder

IMAGE_NAME_BUILDER_REF := $(IMAGE_NAME_BUILDER):$(GIT_REF)
IMAGE_NAME_BUILDER_COMMIT := $(IMAGE_NAME_BUILDER):$(GIT_COMMIT)
IMAGE_NAME_BUILDER_LATEST := $(IMAGE_NAME_BUILDER):latest

IMAGE_NAME_DRIVERKIT ?= docker.io/falcosecurity/driverkit

IMAGE_NAME_DRIVERKIT_REF := $(IMAGE_NAME_DRIVERKIT):$(GIT_REF)
IMAGE_NAME_DRIVERKIT_COMMIT := $(IMAGE_NAME_DRIVERKIT):$(GIT_COMMIT)
IMAGE_NAME_DRIVERKIT_LATEST := $(IMAGE_NAME_DRIVERKIT):latest

LDFLAGS := -X github.com/falcosecurity/driverkit/pkg/version.buildTime=$(shell date +%s) -X github.com/falcosecurity/driverkit/pkg/version.gitCommit=${GIT_COMMIT} -X github.com/falcosecurity/driverkit/pkg/version.gitTag=$(if ${GIT_TAG},${GIT_TAG},v0.0.0) -X github.com/falcosecurity/driverkit/pkg/version.commitsFromGitTag=${COMMITS_FROM_GIT_TAG} -X github.com/falcosecurity/driverkit/pkg/driverbuilder.builderBaseImage=${IMAGE_NAME_BUILDER_COMMIT}

OS_NAME := $(shell uname -s | tr A-Z a-z)
SQLITE_TAGS :=
ifeq ($(OS_NAME),darwin)
	SQLITE_TAGS +=sqlite_omit_load_extension libsqlite3 darwin
else ifeq ($(OS_NAME),linux)
	SQLITE_TAGS +=sqlite_omit_load_extension linux
endif

GOTAGS := ${SQLITE_TAGS}

driverkit ?= _output/bin/driverkit
driverkit_docgen ?= _output/bin/docgen

.PHONY: build
build: clean ${driverkit}

${driverkit}:
	CGO_ENABLED=1 go build -v -ldflags '${LDFLAGS}' -tags '${GOTAGS}' -o $@ .

.PHONY: release
release: clean
	CGO_ENABLED=1 LDFLAGS="${LDFLAGS}" GOTAGS="${GOTAGS}" $(GORELEASER) release

.PHONY: clean
clean:
	$(RM) -R dist
	$(RM) -R _output

image/all: image/builder image/driverkit

.PHONY: image/builder
image/builder:
	$(DOCKER) build \
		-t "$(IMAGE_NAME_BUILDER_REF)" \
		-t "$(IMAGE_NAME_BUILDER_COMMIT)" \
		-f build/builder.Dockerfile .

.PHONY: image/driverkit
image/driverkit:
	$(DOCKER) build \
		-t "$(IMAGE_NAME_DRIVERKIT_REF)" \
		-t "$(IMAGE_NAME_DRIVERKIT_COMMIT)" \
		-f build/driverkit.Dockerfile .

push/all: push/builder push/driverkit

.PHONY: push/builder
push/builder:
	$(DOCKER) push $(IMAGE_NAME_BUILDER_REF)
	$(DOCKER) push $(IMAGE_NAME_BUILDER_COMMIT)

.PHONY: push/driverkit
push/driverkit:
	$(DOCKER) push $(IMAGE_NAME_DRIVERKIT_REF)
	$(DOCKER) push $(IMAGE_NAME_DRIVERKIT_COMMIT)

.PHONY: push/latest
push/latest:
	$(DOCKER) tag $(IMAGE_NAME_BUILDER_COMMIT) $(IMAGE_NAME_BUILDER_LATEST)
	$(DOCKER) push $(IMAGE_NAME_BUILDER_LATEST)
	$(DOCKER) tag $(IMAGE_NAME_DRIVERKIT_COMMIT) $(IMAGE_NAME_DRIVERKIT_LATEST)
	$(DOCKER) push $(IMAGE_NAME_DRIVERKIT_LATEST)

.PHONY: test
test:
	go test -v -race ./...
	go test -v ./cmd

.PHONY: ${driverkit_docgen}
${driverkit_docgen}: ${PWD}/docgen
	go build -v -o $@ $^

.PHONY: docs
docs: ${driverkit_docgen}
	$(RM) -R docs/*
	@mkdir -p docs
	${driverkit_docgen}