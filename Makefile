APP := secretproxy
PKG := ./cmd/secretproxy
DIST := dist
export GOCACHE := $(CURDIR)/.gocache

.PHONY: build test test-race vet bench install clean

build:
	mkdir -p $(DIST)
	go build -o $(DIST)/$(APP) $(PKG)

test:
	go test ./...

test-race:
	go test -race -count=1 ./...

vet:
	go vet ./...

bench:
	go test -run ^$$ -bench . -benchmem ./internal/app

install:
	go install ./cmd/secretproxy

clean:
	rm -rf $(DIST) coverage.out
