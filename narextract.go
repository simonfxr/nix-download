package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

type NarExtractor struct {
	reader io.Reader
}

func NewNarExtractor(reader io.Reader) *NarExtractor {
	return &NarExtractor{reader: reader}
}

func (ne *NarExtractor) Extract(destPath string) error {
	magic := make([]byte, 8)
	if _, err := io.ReadFull(ne.reader, magic); err != nil {
		return fmt.Errorf("failed to read NAR magic: %w", err)
	}
	if string(magic) != "nix-archive-1" {
		return fmt.Errorf("invalid NAR magic: %s", magic)
	}

	return ne.extractDir(destPath)
}

func (ne *NarExtractor) extractDir(path string) error {
	for {
		entryType, err := ne.readString()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}

		switch entryType {
		case "directory":
			if err := os.MkdirAll(path, 0755); err != nil {
				return fmt.Errorf("failed to create directory %s: %w", path, err)
			}
			if err := ne.extractDir(path); err != nil {
				return err
			}
		case "file":
			if err := ne.extractFile(path); err != nil {
				return err
			}
		case "symlink":
			if err := ne.extractSymlink(path); err != nil {
				return err
			}
		case "":
			return nil
		default:
			return fmt.Errorf("unknown entry type: %s", entryType)
		}
	}
}

func (ne *NarExtractor) extractFile(path string) error {
	// Read and discard "contents" marker
	if _, err := ne.readString(); err != nil {
		return err
	}

	size, err := ne.readInt64()
	if err != nil {
		return err
	}

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", path, err)
	}
	defer f.Close()

	if _, err := io.CopyN(f, ne.reader, size); err != nil {
		return fmt.Errorf("failed to write file contents: %w", err)
	}

	return nil
}

func (ne *NarExtractor) extractSymlink(path string) error {
	target, err := ne.readString()
	if err != nil {
		return err
	}

	if err := os.Symlink(target, path); err != nil {
		return fmt.Errorf("failed to create symlink %s -> %s: %w", path, target, err)
	}

	return nil
}

func (ne *NarExtractor) readString() (string, error) {
	length, err := ne.readInt64()
	if err != nil {
		return "", err
	}

	data := make([]byte, length)
	if _, err := io.ReadFull(ne.reader, data); err != nil {
		return "", fmt.Errorf("failed to read string data: %w", err)
	}

	// Strings in NAR are null-terminated
	return string(data[:len(data)-1]), nil
}

func (ne *NarExtractor) readInt64() (int64, error) {
	var value int64
	if err := binary.Read(ne.reader, binary.LittleEndian, &value); err != nil {
		return 0, fmt.Errorf("failed to read int64: %w", err)
	}
	return value, nil
}
