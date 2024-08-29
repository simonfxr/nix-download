FROM ubuntu:noble

WORKDIR /app

COPY nix-download /app/

CMD ["/app/nix-download"]
