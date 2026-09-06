.PHONY: run build test fmt vet

run:
	go run ./cmd/idp

build:
	go build -trimpath -ldflags="-s -w" -o bin/idp ./cmd/idp

test:
	go test ./...

fmt:
	gofmt -l .

vet:
	go vet ./...
