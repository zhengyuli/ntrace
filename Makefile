OS := $(shell uname)
ARCH := $(shell uname -m)

.PHONY: all

all: build

.PHONY: build
build:
	@echo "Building nTrace... .. ."
	@go build -o ntrace bitbucket.org/zhengyuli/ntrace

clean:
	@rm -rf ntrace

check: fmt vet test test-race

fmt:
	@gofmt -d -e -l ./

vet:
	@go vet ./...

test:
	@go test ./...

test-race:
	@go test -race ./...

lint:
	@golint ./...
