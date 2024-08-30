# nix-download

 is a standalone tool for fetching Nix store paths and their dependencies from binary caches. It's designed to be easily deployable and allows for quick fetching of one-off binaries from Nix on any Linux system.

## Features

- Fully standalone: can be statically linked with CA certificates baked in
- Easy deployment: single binary with no external dependencies
- Quick fetching: efficiently downloads Nix store paths and their dependencies
- Supports multiple substituters (binary caches)
- Verifies narinfo signatures

## Usage

Basic usage:

```
nix-download /nix/store/39z5zpb72qrnxl832nwphcd4ihfhix3j-hello-2.12.1
```

This will download the specified store path and all its dependencies.

### Options

- `-store string`: Nix store root directory (default "/nix/store")
- `-substituter value`: URL of a binary cache (can be specified multiple times)
- `-public-key value`: Public key in the format name:base64pubkey (can be specified multiple times)

By default cache.nixos.org is used and its binary-cache-key are used.

Example with options:

```
nix-download -store /custom/nix/store -substituter https://cache.nixos.org -public-key cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY= /nix/store/39z5zpb72qrnxl832nwphcd4ihfhix3j-hello-2.12.1
```

## Building

To build a fully standalone binary with CA certificates baked in:

```
CGO_ENABLED=0 go build
```

## Use Cases

- Quickly fetch Nix packages on systems without Nix installed
- Integrate Nix package fetching into CI/CD pipelines
- Download specific versions of tools or libraries in containerized environments

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the [MIT License](LICENSE).
