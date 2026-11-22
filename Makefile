VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/zyvorai/zyvor-setura-gateway/internal/setura.Version=$(VERSION)
PLATFORMS := darwin/arm64 darwin/amd64 linux/amd64 linux/arm64

.PHONY: build test vet cover dist social clean
build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/setura ./cmd/setura

test:
	go test -race -count=1 ./...

vet:
	go vet ./... && test -z "$$(gofmt -l .)"

cover:
	go test -coverprofile=coverage.txt ./... && go tool cover -func=coverage.txt | tail -1

# Cross-compiled release archives with checksums.
dist:
	rm -rf dist && mkdir -p dist
	@for p in $(PLATFORMS); do \
	  os=$${p%/*}; arch=$${p#*/}; name=setura_$(VERSION)_$${os}_$${arch}; \
	  mkdir -p dist/$$name && \
	  CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$$name/setura ./cmd/setura && \
	  cp LICENSE NOTICE README.md dist/$$name/ && \
	  tar -C dist -czf dist/$$name.tar.gz $$name && rm -rf dist/$$name; \
	done
	cd dist && shasum -a 256 *.tar.gz > checksums.txt

# Re-render the PNG social images from their SVG sources (needs rsvg-convert).
social:
	sh scripts/render-social.sh

clean:
	rm -rf bin dist coverage.txt
