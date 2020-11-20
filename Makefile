.PHONY: all test lint proto

GOPATH=$(shell go env GOPATH)

all: $(GOPATH)/bin/voucher test lint

$(GOPATH)/bin/voucher: *
	go install .

test:
	go test -v .

lint: bin/golangci-lint-1.23.8
	./bin/golangci-lint-1.23.8 -c .golangci.yml run ./...

bin/golangci-lint-1.23.8:
	./hack/fetch-golangci-lint.sh
