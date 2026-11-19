.PHONY: test vet fmt build demo check

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

build:
	mkdir -p bin
	go build -o bin/gsg ./cmd/gsg

demo:
	go run ./cmd/gsg scan ./examples/risky-checkout --no-color --fail-on none

check: fmt vet test
