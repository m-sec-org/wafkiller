GOCACHE := $(CURDIR)/.gocache
GOMODCACHE := $(CURDIR)/.gomodcache
GOFLAGS := -mod=vendor

.PHONY: run build tidy vendor clean

run:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) go run $(GOFLAGS) .

build:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) go build $(GOFLAGS) ./...

tidy:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) go mod tidy

vendor:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) go mod vendor

clean:
	rm -rf $(GOCACHE)
