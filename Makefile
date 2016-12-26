OS := $(shell uname)
ARCH := $(shell uname -m)

.PHONY: all

all: build

.PHONY: build
build:
	@echo "Building nTrace... .. ."
	@make -C proto/analyzer/http/http_parser/
	@CGO_ENABLED=1  go build -v -o ntrace github.com/zhengyuli/ntrace

.PHONY: debug
debug:
	@echo "Building nTrace debug version... .. ."
	@make -C proto/analyzer/http/http_parser/ debug
	@CGO_ENABLED=1 go build -gcflags '-N -l' -v -o ntrace github.com/zhengyuli/ntrace

clean:
	@make -C proto/analyzer/http/http_parser/ clean
	rm -rf ntrace

check: fmt vet test test-race

fmt:
	@gofmt -d -e -l ./

vet:
	@go vet ./...

test:
	@go test -v ./...

test-race:
	@go test -race ./...

lint:
	@golint ./...
