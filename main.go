package main

import (
	"bufio"
	"compress/gzip"
	"crypto/ed25519"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	_ "github.com/breml/rootcerts"
	"github.com/klauspost/compress/zstd"
	"github.com/simonfxr/nix-download/narextract"
	"github.com/ulikunitz/xz"
)

var (
	nixStore     = ""
	substituters = []string{}
	knownKeys    = map[string]ed25519.PublicKey{}
)

type StorePath struct {
	Path        string
	References  []string
	NarURL      string
	Compression string
}

func main() {
	var publicKeys stringSliceFlag

	flag.StringVar(&nixStore, "store", "/nix/store", "Nix store root directory")
	flag.Var((*stringSliceFlag)(&substituters), "substituter", "URL of a binary cache (can be specified multiple times)")
	flag.Var(&publicKeys, "public-key", "Public key in the format name:base64pubkey (can be specified multiple times)")

	flag.Parse()

	if len(substituters) == 0 {
		substituters = append(substituters, "https://cache.nixos.org")
	}

	if len(publicKeys) == 0 {
		publicKeys = append(publicKeys, "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=")
	}

	err := error(nil)
	nixStore, err = filepath.Abs(nixStore)
	if err != nil {
		log.Fatalf("Bad nix store path: %v", err)
	}

	// Process public keys
	for _, keyPair := range publicKeys {
		parts := strings.SplitN(keyPair, ":", 2)
		if len(parts) != 2 {
			log.Fatalf("Invalid public key format: %s", keyPair)
		}
		name, keyBase64 := parts[0], parts[1]
		pubKey, err := base64.StdEncoding.DecodeString(keyBase64)
		if err != nil {
			log.Fatalf("Invalid base64 encoding for public key %s: %v", name, err)
		}
		knownKeys[name] = ed25519.PublicKey(pubKey)
	}

	// Get all non-flag arguments as paths to download
	for _, path := range flag.Args() {
		fmt.Printf("Processing path: %s\n", path)

		// Phase 1: Discovery
		storePaths, err := discoverDependencies(path)
		if err != nil {
			log.Printf("Error during discovery for %s: %v", path, err)
			continue
		}

		// Phase 2 & 3: Fetching and Manifestation
		err = fetchAndManifestStorePaths(storePaths)
		if err != nil {
			log.Printf("Error during fetching and manifestation for %s: %v", path, err)
			continue
		}
	}
}

func discoverDependencies(initialPath string) ([]StorePath, error) {
	visited := make(map[string]bool)
	toVisit := []string{initialPath}
	var result []StorePath

	for len(toVisit) > 0 {
		path := toVisit[0]
		toVisit = toVisit[1:]

		if visited[path] {
			continue
		}
		visited[path] = true

		// Check if the path already exists on disk
		if _, err := os.Stat(filepath.Join(nixStore, path)); err == nil {
			fmt.Printf("Path %s already exists on disk, skipping\n", path)
			continue
		}

		storePath, err := fetchNarInfo(path)
		if err != nil {
			return nil, fmt.Errorf("error fetching narinfo for %s: %w", path, err)
		}

		result = append(result, storePath)

		// Add references to toVisit
		for _, ref := range storePath.References {
			if !visited[ref] {
				toVisit = append(toVisit, ref)
			}
		}
	}

	return result, nil
}

func fetchNarInfo(storePath string) (StorePath, error) {
	hash, _, _ := strings.Cut(filepath.Base(storePath), "-")
	var resp *http.Response
	var err error
	var substituter string

	for _, substituter = range substituters {
		resp, err = http.Get(fmt.Sprintf("%s/%s.narinfo", substituter, hash))
		if err == nil && resp.StatusCode == http.StatusOK {
			break
		}
		if resp != nil {
			resp.Body.Close()
		}
	}

	if err != nil {
		return StorePath{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return StorePath{}, fmt.Errorf("failed to fetch narinfo: %s", resp.Status)
	}

	narInfo := make(map[string]string)
	var references []string
	var narURL string

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		key, value, ok := strings.Cut(line, ":")
		if ok {
			value = value[min(1, len(value)):]
			narInfo[key] = value

			switch key {
			case "References":
				references = strings.Fields(value)
			case "URL":
				narURL = fmt.Sprintf("%s/%s", substituter, value)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return StorePath{}, err
	}

	// Verify the signature
	if err := verifyNarInfoSignature(narInfo); err != nil {
		return StorePath{}, fmt.Errorf("signature verification failed: %w", err)
	}

	return StorePath{
		Path:        storePath,
		References:  references,
		NarURL:      narURL,
		Compression: narInfo["Compression"],
	}, nil
}

func verifyNarInfoSignature(narInfo map[string]string) error {
	sig, ok := narInfo["Sig"]
	if !ok {
		return fmt.Errorf("no signature found in narinfo")
	}

	sigParts := strings.SplitN(sig, ":", 2)
	if len(sigParts) != 2 {
		return fmt.Errorf("invalid signature format")
	}

	keyName, sigBase64 := sigParts[0], sigParts[1]
	publicKey, ok := knownKeys[keyName]
	if !ok {
		return fmt.Errorf("unknown key: %s", keyName)
	}

	signature, err := base64.StdEncoding.DecodeString(sigBase64)
	if err != nil {
		return fmt.Errorf("invalid signature encoding: %w", err)
	}

	message := buildSignatureMessage(narInfo)

	if !ed25519.Verify(publicKey, []byte(message), signature) {
		return fmt.Errorf("invalid signature")
	}

	return nil
}

func buildSignatureMessage(narInfo map[string]string) string {
	refs := strings.Fields(narInfo["References"])
	paths := make([]string, len(refs))
	for i, ref := range refs {
		paths[i] = "/nix/store/" + ref
	}
	return fmt.Sprintf("1;%s;%s;%s;%s",
		narInfo["StorePath"],
		narInfo["NarHash"],
		narInfo["NarSize"],
		strings.Join(paths, ","))
}

func fetchAndManifestStorePaths(storePaths []StorePath) error {
	var wg sync.WaitGroup
	errors := make(chan error, len(storePaths))

	for _, sp := range storePaths {
		wg.Add(1)
		go func(sp StorePath) {
			defer wg.Done()
			if err := fetchAndManifestStorePath(sp); err != nil {
				errors <- fmt.Errorf("error processing %s: %w", sp.Path, err)
			}
		}(sp)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		if err != nil {
			return err
		}
	}

	return nil
}

func fetchAndManifestStorePath(sp StorePath) error {
	// Fetch the NAR
	resp, err := http.Get(sp.NarURL)
	if err != nil {
		return fmt.Errorf("failed to fetch NAR: %w", err)
	}
	defer resp.Body.Close()

	// Create a reader based on the compression type
	var reader io.Reader
	compression := sp.Compression
	switch compression {
	case "none":
		reader = resp.Body
	case "gzip":
		gzReader, err := gzip.NewReader(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to create gzip reader: %w", err)
		}
		defer gzReader.Close()
		reader = gzReader
	case "xz":
		xzReader, err := xz.NewReader(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to create xz reader: %w", err)
		}
		reader = xzReader
	case "zstd":
		zstdReader, err := zstd.NewReader(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to create zstd reader: %w", err)
		}
		defer zstdReader.Close()
		reader = zstdReader
	default:
		return fmt.Errorf("unsupported compression type: %s", compression)
	}

	// Create the destination directory
	destPath := filepath.Join(nixStore, filepath.Base(sp.Path))
	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return fmt.Errorf("failed to create destination directory: %w", err)
	}

	// Extract the NAR
	extractor, err := narextract.NewNarExtractor(reader, destPath)
	if err != nil {
		return fmt.Errorf("failed to create NAR extractor: %w", err)
	}
	if err := extractor.Extract(); err != nil {
		return fmt.Errorf("failed to extract NAR: %w", err)
	}

	fmt.Printf("%s\n", destPath)
	return nil
}

// stringSliceFlag is a custom flag type that allows for multiple string values
type stringSliceFlag []string

func (s *stringSliceFlag) String() string {
	return strings.Join(*s, ", ")
}

func (s *stringSliceFlag) Set(value string) error {
	*s = append(*s, value)
	return nil
}
