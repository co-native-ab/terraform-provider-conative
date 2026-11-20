default: build

.PHONY: build fmt lint test testacc docs

build:
	go build ./...

fmt:
	gofmt -s -w .

lint:
	golangci-lint run

test:
	go test ./...

# Acceptance tests need Docker and Terraform; see CONTRIBUTING.md.
testacc:
	TF_ACC=1 go test ./internal/provider/... -run TestAcc -timeout 30m -v

docs:
	go generate ./...
