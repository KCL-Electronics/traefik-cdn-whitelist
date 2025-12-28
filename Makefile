.PHONY: lint test vendor clean

export GO111MODULE=on

YAEGI_GOPATH ?= $(PWD)/.yaegi-gopath
YAEGI_MODULE ?= github.com/KCL-Electronics/traefik-cdn-whitelist

default: lint test

lint:
	GOROOT=$$(go env GOROOT) golangci-lint run

test:
	go test -v -cover ./...

yaegi_test:
	mkdir -p $(YAEGI_GOPATH)/src/github.com/KCL-Electronics
	rm -rf $(YAEGI_GOPATH)/src/github.com/KCL-Electronics/traefik-cdn-whitelist
	ln -s $(PWD) $(YAEGI_GOPATH)/src/github.com/KCL-Electronics/traefik-cdn-whitelist
	GOPATH=$(YAEGI_GOPATH) YAEGI_YAEGIPATH=$(PWD) yaegi test $(YAEGI_MODULE)

vendor:
	go mod vendor

clean:
	rm -rf ./vendor $(YAEGI_GOPATH)
