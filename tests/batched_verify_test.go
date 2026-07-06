package tests

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/HORNET-Storage/Scionic-Merkle-Tree/v2/dag"
)

// TestBatchedVerifyCatchesForgedChildInCompleteParent proves that per-packet
// batched verification rejects a forged child of a fully-present parent via the
// parent's Merkle root, rather than deferring solely to a later Dag.Verify().
// Link order/membership is NOT part of a leaf's CID, so a swapped child link
// passes structural leaf verification and must be caught by the Merkle-root
// check.
func TestBatchedVerifyCatchesForgedChildInCompleteParent(t *testing.T) {
	inputDir, err := os.MkdirTemp("", "s3_input_*")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	defer os.RemoveAll(inputDir)
	for i := 0; i < 3; i++ {
		if err := os.WriteFile(filepath.Join(inputDir, fmt.Sprintf("f%d.txt", i)), []byte{byte('a' + i)}, 0o644); err != nil {
			t.Fatalf("write file: %v", err)
		}
	}

	d, err := dag.CreateDag(inputDir, false)
	if err != nil {
		t.Fatalf("CreateDag: %v", err)
	}

	batches := d.GetBatchedLeafSequence()
	if len(batches) == 0 {
		t.Fatal("no batches produced")
	}
	batch := batches[0]

	// Forge one of the root leaf's child links (all children are present in this
	// batch, so the root has no proofs and the Merkle-root path is exercised).
	forged := false
	for _, leaf := range batch.Leaves {
		if batch.Relationships[leaf.Hash] == "" && len(leaf.Links) > 1 {
			leaf.Links[0] = "bafkreiforgedchildhashaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			forged = true
			break
		}
	}
	if !forged {
		t.Fatal("could not find a multi-child root leaf in the batch")
	}

	receiver := &dag.Dag{Root: d.Root, Leafs: make(map[string]*dag.DagLeaf)}
	err = receiver.VerifyBatchedTransmissionPacket(batch)
	if err == nil {
		t.Fatal("expected batched verify to reject a forged child via the Merkle-root check, got nil")
	}
	if !strings.Contains(err.Error(), "merkle root") {
		t.Fatalf("expected a merkle-root verification error, got: %v", err)
	}
}
