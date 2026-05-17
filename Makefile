BINARY := davoid
VERSION := $(shell cat version.txt 2>/dev/null || echo "2.0.0")
LDFLAGS := -ldflags "-s -w -X main.version=$(VERSION)"
BUILD_DIR := dist

.PHONY: build clean install release linux-amd64 linux-arm64 darwin-amd64 darwin-arm64

build:
	go build $(LDFLAGS) -o $(BINARY) ./cmd/davoid/

install: build
	@if [ "$$(uname -s)" = "Darwin" ] && [ -d /opt/homebrew/bin ]; then \
		mv $(BINARY) /opt/homebrew/bin/$(BINARY); \
		echo "Installed: /opt/homebrew/bin/$(BINARY)"; \
	else \
		sudo mv $(BINARY) /usr/local/bin/$(BINARY); \
		echo "Installed: /usr/local/bin/$(BINARY)"; \
	fi

clean:
	rm -rf $(BUILD_DIR) $(BINARY)

release: linux-amd64 linux-arm64 darwin-amd64 darwin-arm64
	@cd $(BUILD_DIR) && \
	  if command -v sha256sum >/dev/null 2>&1; then \
	    sha256sum davoid-* > checksums.txt; \
	  else \
	    shasum -a 256 davoid-* > checksums.txt; \
	  fi
	@echo "\nBuilt releases in $(BUILD_DIR)/"
	@ls -lh $(BUILD_DIR)/

linux-amd64:
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/davoid-linux-amd64 ./cmd/davoid/

linux-arm64:
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/davoid-linux-arm64 ./cmd/davoid/

darwin-amd64:
	@mkdir -p $(BUILD_DIR)
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/davoid-darwin-amd64 ./cmd/davoid/

darwin-arm64:
	@mkdir -p $(BUILD_DIR)
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/davoid-darwin-arm64 ./cmd/davoid/

test:
	go test ./...

vet:
	go vet ./...
