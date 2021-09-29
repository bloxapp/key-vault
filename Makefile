ifndef $(GOPATH)
    GOPATH=$(shell go env GOPATH)
    export GOPATH
endif

UNFORMATTED=$(shell gofmt -s -l .)
#Lint
.PHONY: lint-prepare
lint-prepare:
	@echo "Preparing Linter"
	curl -sfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh| sh -s latest

.PHONY: lint
lint:
	./bin/golangci-lint run -v ./...
	@echo "Checking for unformatted files"
	if [ ! -z "${UNFORMATTED}" ]; then \
		echo "The following files are not formatted: \n${UNFORMATTED}"; \
	fi

#Test
.PHONY: full-test
full-test:
	@echo "Running the full test..."
	@go test -tags blst_enabled -timeout 20m ${COV_CMD} -race -p 1 -v ./...