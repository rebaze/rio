VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT    ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE      ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS   := -X github.com/rebaze/rio/cmd.version=$(VERSION) \
             -X github.com/rebaze/rio/cmd.commit=$(COMMIT) \
             -X github.com/rebaze/rio/cmd.date=$(DATE)
BIN       := rio

.PHONY: build run test vet tidy clean

## build: compile the rio binary
build:
	go build -ldflags "$(LDFLAGS)" -o $(BIN) .

## run: build then run (pass arguments via ARGS)
##   example: make run ARGS="--version"
run: build
	./$(BIN) $(ARGS)

## test: run the test suite
test:
	go test ./...

## vet: run go vet
vet:
	go vet ./...

## tidy: tidy and verify module dependencies
tidy:
	go mod tidy

## clean: remove build artifacts
clean:
	rm -f $(BIN)
	rm -rf dist/
