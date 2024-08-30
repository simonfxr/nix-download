FROM ubuntu:noble

WORKDIR /app

COPY nix-download /usr/bin/
COPY test.sh /
