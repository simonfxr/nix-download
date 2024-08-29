package narextract

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type NarExtractor struct {
	reader io.Reader
	topDir string

	nextString string
	haveNext   bool
}

func NewNarExtractor(reader io.Reader, topDir string) (*NarExtractor, error) {
	absPath, err := filepath.Abs(topDir)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path: %w", err)
	}
	return &NarExtractor{reader: reader, topDir: absPath}, nil
}

func (ne *NarExtractor) Extract() error {
	magic, err := ne.readString()
	if err != nil {
		return fmt.Errorf("failed to read NAR magic: %w", err)
	}
	if magic != "nix-archive-1" {
		return fmt.Errorf("invalid NAR magic: %s", magic)
	}

	return ne.extractNarObj(".")
}

func (ne *NarExtractor) extractNarObj(path string) error {
	if err := ne.expectString("("); err != nil {
		return err
	}

	if err := ne.expectString("type"); err != nil {
		return err
	}

	objType, err := ne.readString()
	if err != nil {
		return err
	}

	var extractErr error
	switch objType {
	case "regular":
		extractErr = ne.extractRegular(path)
	case "symlink":
		extractErr = ne.extractSymlink(path)
	case "directory":
		extractErr = ne.extractDirectory(path)
	default:
		extractErr = fmt.Errorf("unknown object type: %s", objType)
	}

	if extractErr != nil {
		return extractErr
	}

	return ne.expectString(")")
}

func (ne *NarExtractor) extractRegular(path string) error {
	executable := false
	nextField, err := ne.readString()
	if err != nil {
		return err
	}

	if nextField == "executable" {
		executable = true
		if err := ne.expectString(""); err != nil {
			return err
		}
		nextField, err = ne.readString()
		if err != nil {
			return err
		}
	}

	if nextField != "contents" {
		return fmt.Errorf("expected 'contents', got %s", nextField)
	}

	contents, err := ne.readString()
	if err != nil {
		return err
	}

	fullPath := filepath.Join(ne.topDir, path)
	if err := os.WriteFile(fullPath, []byte(contents), 0644); err != nil {
		return fmt.Errorf("failed to write file %s: %w", fullPath, err)
	}

	if executable {
		if err := os.Chmod(fullPath, 0755); err != nil {
			return fmt.Errorf("failed to set executable permission on %s: %w", fullPath, err)
		}
	}

	return nil
}

func (ne *NarExtractor) extractSymlink(path string) error {
	if err := ne.expectString("target"); err != nil {
		return err
	}

	target, err := ne.readString()
	if err != nil {
		return err
	}

	fullPath := filepath.Join(ne.topDir, path)
	if err := os.Symlink(target, fullPath); err != nil {
		return fmt.Errorf("failed to create symlink %s -> %s: %w", fullPath, target, err)
	}

	return nil
}

func (ne *NarExtractor) extractDirectory(path string) error {
	fullPath := filepath.Join(ne.topDir, path)
	if err := os.MkdirAll(fullPath, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", fullPath, err)
	}

	prev := ""
	for {
		entry, err := ne.readString()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if entry != "entry" {
			ne.unread(entry)
			break
		}

		if err := ne.expectString("("); err != nil {
			return err
		}
		if err := ne.expectString("name"); err != nil {
			return err
		}

		name, err := ne.readString()
		if err != nil {
			return err
		}

		if !isValidPathComponent(name) {
			return fmt.Errorf("invalid path component: %s", name)
		}

		if prev != "" && bytes.Compare([]byte(prev), []byte(name)) >= 0 {
			return fmt.Errorf("path components not sorted, %s >= %s", prev, name)
		}

		if err := ne.expectString("node"); err != nil {
			return err
		}

		if err := ne.extractNarObj(filepath.Join(path, name)); err != nil {
			return err
		}

		if err := ne.expectString(")"); err != nil {
			return err
		}

		prev = name
	}

	return nil
}

func (ne *NarExtractor) unread(str string) {
	ne.nextString, ne.haveNext = str, true
}

func (ne *NarExtractor) readString() (str string, err error) {
	if ne.haveNext {
		str = ne.nextString
		ne.nextString, ne.haveNext = "", false
		return str, nil
	}
	length, err := ne.readInt64()
	if err != nil {
		return "", err
	}

	padding := int((8 - (length % 8)) % 8)
	data := make([]byte, length+int64(padding))
	if _, err := io.ReadFull(ne.reader, data); err != nil {
		return "", fmt.Errorf("failed to read string data: %w", err)
	}

	// Remove null terminator
	data = data[:len(data)-padding]

	str = string(data)
	return str, nil
}

func (ne *NarExtractor) readInt64() (int64, error) {
	var value int64
	if err := binary.Read(ne.reader, binary.LittleEndian, &value); err != nil {
		return 0, fmt.Errorf("failed to read int64: %w", err)
	}
	return value, nil
}

func (ne *NarExtractor) expectString(expected string) error {
	s, err := ne.readString()
	if err != nil {
		return err
	}
	if s != expected {
		return fmt.Errorf("expected %q, got %q", expected, s)
	}
	return nil
}

func isValidPathComponent(name string) bool {
	return name != "" &&
		name != "." &&
		name != ".." &&
		!strings.Contains(name, "/")
}
