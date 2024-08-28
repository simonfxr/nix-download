package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	nixStore       = "/nix/store"
	binaryCacheURL = "https://cache.nixos.org"
)

type StorePath struct {
	Path       string
	References []string
	NarInfoURL string
	NarURL     string
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
	hash := filepath.Base(storePath)
	narInfoURL := fmt.Sprintf("%s/%s.narinfo", binaryCacheURL, hash)

	resp, err := http.Get(narInfoURL)
	if err != nil {
		return StorePath{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return StorePath{}, fmt.Errorf("failed to fetch narinfo: %s", resp.Status)
	}

	var references []string
	var narURL string

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "References:") {
			refs := strings.TrimPrefix(line, "References:")
			references = strings.Fields(refs)
		} else if strings.HasPrefix(line, "URL:") {
			narURL = strings.TrimSpace(strings.TrimPrefix(line, "URL:"))
			if !strings.HasPrefix(narURL, "http") {
				narURL = binaryCacheURL + "/" + narURL
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return StorePath{}, err
	}

	return StorePath{
		Path:       storePath,
		References: references,
		NarInfoURL: narInfoURL,
		NarURL:     narURL,
	}, nil
}

func main() {
	storePath := flag.String("path", "", "Nix store path to fetch")
	flag.Parse()

	if *storePath == "" {
		log.Fatal("Please provide a Nix store path using the -path flag")
	}

	// Phase 1: Discovery
	storePaths, err := discoverDependencies(*storePath)
	if err != nil {
		log.Fatalf("Error during discovery: %v", err)
	}

	// Phase 2 & 3: Fetching and Manifestation
	err = fetchAndManifestStorePaths(storePaths)
	if err != nil {
		log.Fatalf("Error during fetching and manifestation: %v", err)
	}

	fmt.Println("Successfully fetched and manifested the Nix store path and its dependencies")
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
	// Create a temporary file to store the NAR
	tempFile, err := os.CreateTemp("", "nar-*")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()

	// Fetch the NAR
	resp, err := http.Get(sp.NarURL)
	if err != nil {
		return fmt.Errorf("failed to fetch NAR: %w", err)
	}
	defer resp.Body.Close()

	r := bufio.NewReaderSize(resp.Body, 64*1024)

	// Create the destination directory
	destPath := filepath.Join(nixStore, filepath.Base(sp.Path))
	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return fmt.Errorf("failed to create destination directory: %w", err)
	}

	// Extract the NAR
	extractor := NewNarExtractor(r)
	if err := extractor.Extract(destPath); err != nil {
		return fmt.Errorf("failed to extract NAR: %w", err)
	}

	fmt.Printf("Successfully manifested %s\n", sp.Path)
	return nil
}
