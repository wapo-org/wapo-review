GO := /var/lib/t3-server/.local/go/bin/go
CGO_ENABLED := 0

.PHONY: build test vet clean

build:
	CGO_ENABLED=$(CGO_ENABLED) $(GO) build -o bin/wapo-review ./cmd/wapo-review

test:
	CGO_ENABLED=$(CGO_ENABLED) $(GO) test ./...

vet:
	CGO_ENABLED=$(CGO_ENABLED) $(GO) vet ./...

clean:
	rm -rf bin
