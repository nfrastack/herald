BINARY_NAME := herald
SRC_DIR := src
BUILD_DIR := ./cmd/herald
GO := go
LDFLAGS := -s -w
VERSION := $(shell [ -n "$$HERALD_VERSION" ] && echo "$$HERALD_VERSION" || (git describe --tags --exact-match 2>/dev/null || git describe --always --dirty || echo "dev"))
GIT_COMMIT ?= $(shell if [ -n "$$HERALD_COMMIT" ]; then echo "$$HERALD_COMMIT"; else git rev-parse --short HEAD 2>/dev/null; fi)
# auto (default: infer from version) | edge | beta | stable
CHANNEL ?= auto
BUILD_TIME := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
BUILD_FLAGS := -X main.Version=$(VERSION) -X main.buildChannel=$(CHANNEL) -X main.buildCommit=$(GIT_COMMIT) -X main.BuildTime=$(BUILD_TIME)

all: build

build:
	cd $(SRC_DIR) && CGO_ENABLED=0 $(GO) build -trimpath -mod=mod -ldflags "$(BUILD_FLAGS)" -o ../$(BINARY_NAME) $(BUILD_DIR)

build-release:
	cd $(SRC_DIR) && CGO_ENABLED=0 $(GO) build -trimpath -mod=mod -ldflags "$(LDFLAGS) $(BUILD_FLAGS)" -o ../$(BINARY_NAME) $(BUILD_DIR)

build-all:
	cd $(SRC_DIR) && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -mod=mod -ldflags "$(LDFLAGS) $(BUILD_FLAGS)" -o ../$(BINARY_NAME)_x86_64 $(BUILD_DIR)
	cd $(SRC_DIR) && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath -mod=mod -ldflags "$(LDFLAGS) $(BUILD_FLAGS)" -o ../$(BINARY_NAME)_aarch64 $(BUILD_DIR)

clean:
	rm -f $(BINARY_NAME) $(BINARY_NAME)_x86_64 $(BINARY_NAME)_aarch64

test:
	cd $(SRC_DIR) && CGO_ENABLED=0 $(GO) test -count=1 -short ./...

clean-vendor:
	rm -rf vendor

install:
	mkdir -p /usr/local/bin
	cp $(BINARY_NAME) /usr/local/bin/$(BINARY_NAME)

release: clean build-all
	@echo "Binaries built with version: $(VERSION) and ready for release: $(BINARY_NAME)_x86_64, $(BINARY_NAME)_aarch64"

check-release:
	@if git describe --tags --exact-match >/dev/null 2>&1; then \
		if git diff-index --quiet HEAD --; then \
			GIT_TAG=$$(git describe --tags --exact-match); \
			if grep -q "version = \"$$GIT_TAG\"" flake.nix; then \
				echo "Repository is clean and tagged. Tag $$GIT_TAG matches version in flake.nix. Ready for release."; \
			else \
				FLAKE_VERSION=$$(grep -o 'version = "[^"]*"' flake.nix | cut -d'"' -f2); \
				echo "Error: Git tag ($$GIT_TAG) does not match version in flake.nix ($$FLAKE_VERSION)"; \
				exit 1; \
			fi; \
		else \
			echo "Repository is tagged but has uncommitted changes. Please commit or stash changes before release."; \
			exit 1; \
		fi; \
	else \
		echo "Repository is not tagged. Please create a tag before release."; \
		exit 1; \
	fi

container-build:
	docker build --build-arg HERALD_VERSION=$(VERSION) -t nfrastack/$(BINARY_NAME):$(VERSION) -f container/Containerfile .
	docker tag nfrastack/$(BINARY_NAME):$(VERSION) nfrastack/$(BINARY_NAME):latest

version:
	@if [ -n "$(V)" ]; then \
		sed -i 's/^\(      version = "\)[^"]*"/\1$(V)"/' flake.nix; \
		echo "version set to $(V): flake.nix"; \
	else \
		echo "flake.nix:  $$(grep -o 'version = "[^"$$][^"]*"' flake.nix | head -1 | cut -d'"' -f2)"; \
		echo "git:        $$(git describe --tags --exact-match 2>/dev/null || git describe --always --dirty 2>/dev/null || echo dev)"; \
	fi

go-version:
	@if [ -n "$(V)" ]; then \
		echo "$(V)" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$$' || { echo "error: V must be full X.Y.Z (got '$(V)')"; exit 1; }; \
		MAJMIN=$$(echo "$(V)" | cut -d. -f1,2); \
		ATTR=$$(echo "$$MAJMIN" | tr . _); \
		sed -i "s/expectedGoVersion = \"[^\"]*\"/expectedGoVersion = \"$(V)\"/" flake.nix; \
		sed -i "s/goOverrideVersion = \"[^\"]*\"/goOverrideVersion = \"$(V)\"/" flake.nix; \
		sed -i "s/go_[0-9_]*/go_$$ATTR/g" flake.nix; \
		for f in .github/workflows/branch-build.yml .github/workflows/release.yml; do \
			[ -f "$$f" ] && sed -i "s/GO_VERSION: '[^']*'/GO_VERSION: '$(V)'/" "$$f"; \
		done; \
		[ -f container/Containerfile ] && sed -i 's/GOLANG_VERSION="[^"]*"/GOLANG_VERSION="$(V)"/' container/Containerfile; \
		if grep -q 'GoLang [0-9][0-9]*\.[0-9][0-9]*' README.md 2>/dev/null; then \
			sed -i "s/GoLang [0-9][0-9]*\.[0-9][0-9]*/GoLang $$MAJMIN/" README.md; \
		fi; \
		(cd $(SRC_DIR) && $(GO) mod edit -go=$(V)); \
		echo "go $(V): go.mod + flake + gha + container + README"; \
		HASH=$$(nix store prefetch-file --json "https://go.dev/dl/go$(V).src.tar.gz" 2>/dev/null | grep -o '"hash": *"[^"]*"' | cut -d'"' -f4); \
		if [ -n "$$HASH" ]; then \
			sed -i "s|goOverrideHash = \"[^\"]*\"|goOverrideHash = \"$$HASH\"|" flake.nix; \
			echo "goOverrideHash auto-set to $$HASH"; \
		else \
			echo "WARN: auto-prefetch failed - update goOverrideHash in flake.nix manually:"; \
			echo "  nix store prefetch-file --json https://go.dev/dl/go$(V).src.tar.gz"; \
		fi; \
	else \
		echo "go.mod:     $$(grep -o '^go [0-9.]*' $(SRC_DIR)/go.mod)"; \
		echo "flake:      $$(grep -o 'expectedGoVersion = "[^"]*"' flake.nix) + $$(grep -o 'go_[0-9_]*' flake.nix | head -1) + override $$(grep -o 'goOverrideVersion = "[^"]*"' flake.nix)"; \
		echo "gha branch: $$(grep -o "GO_VERSION: '[^']*'" .github/workflows/branch-build.yml)"; \
		echo "gha release:$$(grep -o "GO_VERSION: '[^']*'" .github/workflows/release.yml)"; \
		echo "container:  $$(grep -o 'GOLANG_VERSION="[^"]*"' container/Containerfile)"; \
		echo "readme:     $$(grep -o 'GoLang [0-9.]*' README.md | head -1)"; \
	fi

help:
	@echo "make build              Build the binary"
	@echo "make build-release      Build the binary with version information"
	@echo "make build-all          Build binaries for x86_64 and aarch64"
	@echo "make clean              Clean up build artifacts"
	@echo "make test               Run unit tests"
	@echo "make install            Install the binary locally"
	@echo "make release            Build and prepare for release"
	@echo "make check-release      Verify if the repository is tagged and clean"
	@echo "make container-build    Build the Container image with HERALD_VERSION as build-arg and tag"
	@echo "make version [V=x]      Show app version, or set it (flake.nix)"
	@echo "make go-version [V=x]   Show Go version, or set it (go.mod + flake + gha + container + README)"
	@echo "make help               Show this message"
