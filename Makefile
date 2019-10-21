.PHONY: default
default: build

REPO_LOCAL=localhost/haproxy-ingress
REPO_PUBLIC=truealex81/haproxy-ingress
DOCKER_HUB=hub.docker.com
include container.mk

GOOS=linux
GOARCH=amd64
GIT_REPO=$(shell git config --get remote.origin.url)
ROOT_PKG=github.com/truealex81/haproxy-ingress/pkg

.PHONY: build
build:
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build \
	  -installsuffix cgo \
	  -ldflags "-s -w -X $(ROOT_PKG)/version.RELEASE=$(TAG) -X $(ROOT_PKG)/version.COMMIT=$(GIT_COMMIT) -X $(ROOT_PKG)/version.REPO=$(GIT_REPO)" \
	  -o rootfs/haproxy-ingress-controller \
	  $(ROOT_PKG)

.PHONY: test
test:
	## fix race and add -race param
	go test -tags cgo $(ROOT_PKG)/...

.PHONY: install
install:
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go install \
	  -v -installsuffix cgo \
	  $(ROOT_PKG)
