.PHONY: build docker

nix-download:
	CGO_ENABLED=0 go build -o $@

container: nix-download
	docker build -t nix-download --iidfile $@ .
