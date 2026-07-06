package tests

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/HORNET-Storage/Scionic-Merkle-Tree/v2/dag"
)

// TestCreateDirectoryRejectsPathTraversal ensures that reconstructing a DAG whose
// ItemName tries to escape the target directory (e.g. "../escaped.txt") is
// rejected rather than writing outside the target. ItemName is attacker-
// controlled in a downloaded DAG, so this must be sanitized.
func TestCreateDirectoryRejectsPathTraversal(t *testing.T) {
	inputDir, err := os.MkdirTemp("", "trav_input_*")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	defer os.RemoveAll(inputDir)
	if err := os.WriteFile(filepath.Join(inputDir, "safe.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	d, err := dag.CreateDag(inputDir, false)
	if err != nil {
		t.Fatalf("CreateDag: %v", err)
	}

	// Tamper: point the file leaf's ItemName outside the target directory.
	for _, leaf := range d.Leafs {
		if leaf.Type == dag.FileLeafType {
			leaf.ItemName = "../escaped.txt"
		}
	}

	outputParent, err := os.MkdirTemp("", "trav_out_*")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	defer os.RemoveAll(outputParent)
	target := filepath.Join(outputParent, "repo")

	if err := d.CreateDirectory(target); err == nil {
		t.Fatal("expected CreateDirectory to reject a traversal ItemName, but it succeeded")
	}

	// The escaped file must NOT have been written outside the target.
	if _, statErr := os.Stat(filepath.Join(outputParent, "escaped.txt")); statErr == nil {
		t.Fatal("path traversal wrote a file outside the target directory")
	}
}

// TestGetContentFromLeafStreamingDetectsContentTampering ensures the streaming
// content path re-verifies chunk content against its committed ContentHash
// (streaming verification loads leaves without content, so the check must live
// on the content-loading path).
func TestGetContentFromLeafStreamingDetectsContentTampering(t *testing.T) {
	dag.SetChunkSize(64 * 1024)
	defer dag.SetDefaultChunkSize()

	// Multi-chunk file so the streaming path concatenates chunk content.
	content := bytes.Repeat([]byte("x"), 200*1024)
	inputDir, err := os.MkdirTemp("", "s2_input_*")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	defer os.RemoveAll(inputDir)
	if err := os.WriteFile(filepath.Join(inputDir, "big.bin"), content, 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	d, err := dag.CreateDag(inputDir, false)
	if err != nil {
		t.Fatalf("CreateDag: %v", err)
	}

	var fileHash, chunkHash string
	for hash, leaf := range d.Leafs {
		if leaf.Type == dag.FileLeafType && len(leaf.Links) > 0 {
			fileHash = hash
			chunkHash = leaf.Links[0]
		}
	}
	if fileHash == "" {
		t.Fatal("no chunked file leaf found")
	}

	// Build a store where one chunk's content is tampered while its Hash and
	// ContentHash are left intact (so structural verification still passes).
	store := dag.NewEmptyDagStore(nil, nil)
	for hash, leaf := range d.Leafs {
		if hash == chunkHash {
			tampered := leaf.Clone()
			if len(tampered.Content) > 0 {
				flipped := append([]byte(nil), tampered.Content...)
				flipped[0] ^= 0xFF
				tampered.Content = flipped
			}
			if err := store.StoreLeaf(tampered); err != nil {
				t.Fatalf("StoreLeaf: %v", err)
			}
		} else {
			if err := store.StoreLeaf(leaf); err != nil {
				t.Fatalf("StoreLeaf: %v", err)
			}
		}
	}
	store.SetRoot(d.Root)

	_, err = store.GetContentFromLeafStreaming(fileHash)
	if err == nil {
		t.Fatal("expected a content-hash mismatch error, got nil")
	}
	if !strings.Contains(err.Error(), "content does not match its content hash") {
		t.Fatalf("expected a content-hash mismatch error, got: %v", err)
	}
}
