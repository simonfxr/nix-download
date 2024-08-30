.PHONY: build docker

nix-download:
	CGO_ENABLED=0 go build -o $@

container: nix-download test.sh
	docker build -t nix-download --iidfile $@ .

test: container test.sh
	docker run --rm -it $$(cat container) /test.sh nix-download
