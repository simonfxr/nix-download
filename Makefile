.PHONY: build docker

build:
	CGO_ENABLED=0 go build -o nix-download

docker: build
	docker build -t nix-download .

