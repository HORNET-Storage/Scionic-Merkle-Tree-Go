package tests

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/HORNET-Storage/Scionic-Merkle-Tree/v2/dag"
)

// TestChunkOrderPreservedThroughTransmission is a regression test for chunk
// reordering. A multi-chunk file transmitted via batched packets and then
// reconstructed to disk must reproduce the original bytes exactly. Link order
// is NOT part of a leaf's CID, so a reordering passes verification yet corrupts
// content unless every reconstruction path honours chunk order.
func TestChunkOrderPreservedThroughTransmission(t *testing.T) {
	// Small chunk size so a modest file splits into many chunks.
	dag.SetChunkSize(64 * 1024)
	defer dag.SetDefaultChunkSize()
	dag.SetBatchSize(128 * 1024)
	defer dag.SetDefaultBatchSize()

	const numChunks = 10
	const chunkSize = 64 * 1024

	// Deterministic content where each chunk is filled with a distinct byte
	// value, so ANY reordering of chunks is detectable.
	original := make([]byte, 0, numChunks*chunkSize)
	for i := 0; i < numChunks; i++ {
		original = append(original, bytes.Repeat([]byte{byte(i)}, chunkSize)...)
	}

	inputDir, err := os.MkdirTemp("", "chunk_order_input_*")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	defer os.RemoveAll(inputDir)

	if err := os.WriteFile(filepath.Join(inputDir, "big.bin"), original, 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	d, err := dag.CreateDag(inputDir, false)
	if err != nil {
		t.Fatalf("CreateDag: %v", err)
	}
	if err := d.Verify(); err != nil {
		t.Fatalf("original DAG verify: %v", err)
	}

	// Transmit via batched packets: serialize each batch, deserialize, apply.
	receiver := &dag.Dag{Root: d.Root, Leafs: make(map[string]*dag.DagLeaf)}
	for i, batch := range d.GetBatchedLeafSequence() {
		encoded, err := batch.ToCBOR()
		if err != nil {
			t.Fatalf("batch %d ToCBOR: %v", i, err)
		}
		decoded, err := dag.BatchedTransmissionPacketFromCBOR(encoded)
		if err != nil {
			t.Fatalf("batch %d FromCBOR: %v", i, err)
		}
		if err := receiver.ApplyAndVerifyBatchedTransmissionPacket(decoded); err != nil {
			t.Fatalf("batch %d apply: %v", i, err)
		}
	}
	if err := receiver.Verify(); err != nil {
		t.Fatalf("receiver DAG verify: %v", err)
	}

	// Reconstruct to disk and compare bytes (exercises CreateDirectoryLeaf).
	outputDir, err := os.MkdirTemp("", "chunk_order_output_*")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	defer os.RemoveAll(outputDir)

	if err := receiver.CreateDirectory(outputDir); err != nil {
		t.Fatalf("CreateDirectory: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(outputDir, "big.bin"))
	if err != nil {
		t.Fatalf("read reconstructed file: %v", err)
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("reconstructed-to-disk content does not match original: chunk order corrupted (got %d bytes, want %d)", len(got), len(original))
	}

	// In-memory reconstruction must also match.
	rootLeaf := receiver.Leafs[receiver.Root]
	var fileLeaf *dag.DagLeaf
	for _, link := range rootLeaf.Links {
		if l := receiver.Leafs[link]; l != nil && l.Type == dag.FileLeafType {
			fileLeaf = l
			break
		}
	}
	if fileLeaf == nil {
		t.Fatal("could not find file leaf in receiver DAG")
	}
	content, err := receiver.GetContentFromLeaf(fileLeaf)
	if err != nil {
		t.Fatalf("GetContentFromLeaf: %v", err)
	}
	if !bytes.Equal(content, original) {
		t.Fatalf("in-memory GetContentFromLeaf content mismatch")
	}
}
