OS := $(shell uname)
ARCH := $(shell uname -m)

.PHONY: all

all: build

.PHONY: build
build:
	@echo "Building nTrace... .. ."
	@make -C analyzer/http/http_parser/
	@go build -v -o ntrace github.com/zhengyuli/ntrace

.PHONY: debug
debug:
	@echo "Building nTrace debug version... .. ."
	@make -C analyzer/http/http_parser/
	@go build -gcflags '-N -l' -v -o ntrace github.com/zhengyuli/ntrace

clean:
	@rm -rf ntrace

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
