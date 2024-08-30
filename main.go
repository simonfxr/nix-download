package main

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/breml/rootcerts"
	"github.com/klauspost/compress/zstd"
	"github.com/simonfxr/nix-download/narextract"
	"github.com/ulikunitz/xz"
)

var (
	nixStore     = ""
	substituters = []string{}
	knownKeys    = map[string]ed25519.PublicKey{}
	transport    = func() http.RoundTripper {
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.ResponseHeaderTimeout = 30 * time.Second
		return t
	}()
	narInfoClient = http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}
	narClient = http.Client{
		Transport: transport,
		Timeout:   10 * time.Minute,
	}
)

type StorePath struct {
	BasePath    string
	References  []string
	NarURL      string
	Compression string
	NarSize     int64
	NarHash     string // Add this field
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
		if len(pubKey) != ed25519.PublicKeySize {
			log.Fatalf("Invalid public key: %s", keyPair)
		}
		knownKeys[name] = ed25519.PublicKey(pubKey)
	}

	// Get all non-flag arguments as paths to download
	for _, path := range flag.Args() {

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
	initialPath = strings.TrimPrefix(initialPath, "/nix/store/")
	visited := make(map[string]struct{})
	toVisit := []string{initialPath}
	var result []StorePath

	for len(toVisit) > 0 {
		path := toVisit[0]
		toVisit = toVisit[1:]

		if _, ok := visited[path]; ok {
			continue
		}
		visited[path] = struct{}{}

		// Check if the path already exists on disk
		if _, err := os.Stat(filepath.Join(nixStore, path)); err == nil {
			continue
		}

		storePath, err := fetchNarInfo(path)
		if err != nil {
			return nil, fmt.Errorf("error fetching narinfo for %s: %w", path, err)
		}

		result = append(result, storePath)

		// Add references to toVisit
		for _, ref := range storePath.References {
			if _, ok := visited[ref]; !ok {
				toVisit = append(toVisit, ref)
			}
		}
	}

	// Reverse to get a proper topological sorted order
	slices.Reverse(result)

	return result, nil
}

func fetchNarInfo(storeBase string) (StorePath, error) {
	hash, _, _ := strings.Cut(filepath.Base(storeBase), "-")
	var resp *http.Response
	var err error
	var substituter string

	for _, substituter = range substituters {
		resp, err = narInfoClient.Get(fmt.Sprintf("%s/%s.narinfo", substituter, hash))
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

	infoStorePath := ""
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		key, value, ok := strings.Cut(line, ": ")
		if ok {
			narInfo[key] = value
			switch key {
			case "References":
				references = strings.Fields(value)
			case "URL":
				narURL = fmt.Sprintf("%s/%s", substituter, value)
			case "StorePath":
				infoStorePath = value
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return StorePath{}, err
	}

	storePath := "/nix/store/" + storeBase
	if storePath != infoStorePath {
		return StorePath{}, fmt.Errorf("unexpected narinfo store path expected: %s, got: %s", storePath, infoStorePath)
	}

	// Verify the signature
	if err := verifyNarInfoSignature(narInfo); err != nil {
		return StorePath{}, fmt.Errorf("signature verification failed: %w", err)
	}

	narSize, err := strconv.ParseInt(narInfo["NarSize"], 10, 64)
	if err != nil {
		return StorePath{}, fmt.Errorf("invalid NarSize: %w", err)
	}

	narHash := narInfo["NarHash"]
	if !strings.HasPrefix(narHash, "sha256:") {
		return StorePath{}, fmt.Errorf("unsupported hash algorithm: %s", narHash)
	}

	sort.Strings(references)

	return StorePath{
		BasePath:    storeBase,
		References:  references,
		NarURL:      narURL,
		Compression: narInfo["Compression"],
		NarSize:     narSize,
		NarHash:     narHash,
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
	n := min(8, len(storePaths))
	ch := make(chan func() error)
	errors := make(chan error, n)

	go func() {
		defer close(ch)
		for _, sp := range storePaths {
			destPath := filepath.Join(nixStore, sp.BasePath)
			ch <- func() error {
				if err := fetchAndManifestStorePath(destPath, sp); err != nil {
					return fmt.Errorf("error processing %s: %w", destPath, err)
				}
				return nil
			}
			fmt.Printf("%s\n", destPath)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for f := range ch {
				if ctx.Err() != nil {
					return
				}
				if err := f(); err != nil {
					cancel()
					errors <- err
					return
				}
			}
		}()
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

func fetchAndManifestStorePath(destPath string, sp StorePath) error {
	// Create a temporary directory
	tempDir := filepath.Join(nixStore, ".nix-download_"+sp.BasePath)
	defer func() {
		// Clean up the temporary directory if something goes wrong
		if _, err := os.Stat(tempDir); err == nil {
			os.RemoveAll(tempDir)
		}
	}()

	// Fetch the NAR
	resp, err := narClient.Get(sp.NarURL)
	if err != nil {
		return fmt.Errorf("failed to fetch NAR: %w", err)
	}
	defer resp.Body.Close()

	reader := io.Reader(bufio.NewReaderSize(resp.Body, 64*1024))
	switch sp.Compression {
	case "none":
	case "gzip":
		gzReader, err := gzip.NewReader(reader)
		if err != nil {
			return fmt.Errorf("failed to create gzip reader: %w", err)
		}
		defer gzReader.Close()
		reader = gzReader
	case "xz":
		xzReader, err := xz.NewReader(reader)
		if err != nil {
			return fmt.Errorf("failed to create xz reader: %w", err)
		}
		reader = xzReader
	case "zstd":
		zstdReader, err := zstd.NewReader(reader)
		if err != nil {
			return fmt.Errorf("failed to create zstd reader: %w", err)
		}
		defer zstdReader.Close()
		reader = zstdReader
	default:
		return fmt.Errorf("unsupported compression type: %s", sp.Compression)
	}

	// Wrap the reader with a LimitReader to avoid DOS
	limitedReader := io.LimitReader(reader, sp.NarSize)

	narHasher := sha256.New()

	teeReader := io.TeeReader(limitedReader, narHasher)

	// Extract the NAR to the temporary directory
	extractor, err := narextract.NewNarExtractor(teeReader, tempDir)
	if err != nil {
		return fmt.Errorf("failed to create NAR extractor: %w", err)
	}
	if err := extractor.Extract(); err != nil {
		return fmt.Errorf("failed to extract NAR: %w", err)
	}

	// Verify the hash
	computedHash := "sha256:" + nixBase32Encode(narHasher.Sum(nil))
	if computedHash != sp.NarHash {
		return fmt.Errorf("hash mismatch: expected %s, got %s", sp.NarHash, computedHash)
	}

	// Move the temporary directory to the final destination
	if err := os.Rename(tempDir, destPath); err != nil {
		return fmt.Errorf("failed to move temporary directory to final destination: %w", err)
	}

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

const nix32Chars = "0123456789abcdfghijklmnpqrsvwxyz"

func nixBase32Encode(hash []byte) string {
	hashSize := len(hash)
	len := (hashSize*8-1)/5 + 1 // equivalent to base32Len() in Nix

	s := make([]byte, len)

	for n := len - 1; n >= 0; n-- {
		b := n * 5
		i := b / 8
		j := b % 8
		var c byte
		if i < hashSize {
			c = hash[i] >> j
		}
		if i+1 < hashSize {
			c |= hash[i+1] << (8 - j)
		}
		s[len-1-n] = nix32Chars[c&0x1f]
	}

	return string(s)
}
