package main

import (
	"fmt"
	"os"

	"github.com/simonfxr/nix-download/narextract"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <output_directory>\n", os.Args[0])
		os.Exit(1)
	}

	outputDir := os.Args[1]

	extractor, err := narextract.NewNarExtractor(os.Stdin, outputDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating extractor: %v\n", err)
		os.Exit(1)
	}

	if err := extractor.Extract(); err != nil {
		fmt.Fprintf(os.Stderr, "Error extracting NAR: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("NAR extracted successfully.")
}
