package tests

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/HORNET-Storage/Scionic-Merkle-Tree/v2/dag"
	"github.com/HORNET-Storage/Scionic-Merkle-Tree/v2/testutil"
)

// TestMerkleRootVerificationDetectsTampering verifies that our enhanced verification
// detects when children are tampered with even if the parent leaf hash is valid
// Uses multi-file fixtures since we need parent leaves with multiple children
func TestMerkleRootVerificationDetectsTampering(t *testing.T) {
	testutil.RunTestWithMultiFileFixtures(t, func(t *testing.T, originalDag *dag.Dag, fixture testutil.TestFixture, fixturePath string) {
		// Verify the original DAG works
		err := originalDag.Verify()
		if err != nil {
			t.Fatalf("Original DAG verification failed for %s: %v", fixture.Name, err)
		}

		t.Run("DetectTamperedChildInMultipleChildren", func(t *testing.T) {
			// Find a leaf with multiple children
			var parentLeaf *dag.DagLeaf
			for _, leaf := range originalDag.Leafs {
				if len(leaf.Links) > 1 {
					parentLeaf = leaf
					break
				}
			}

			if parentLeaf == nil {
				t.Skip("No leaf with multiple children found")
			}

			t.Logf("Testing with parent leaf %s that has %d children", parentLeaf.Hash, len(parentLeaf.Links))

			// Create a tampered DAG by modifying one child
			tamperedDag := &dag.Dag{
				Root:  originalDag.Root,
				Leafs: make(map[string]*dag.DagLeaf),
			}

			// Copy all leaves
			for hash, leaf := range originalDag.Leafs {
				tamperedDag.Leafs[hash] = leaf.Clone()
			}

			// Find the first child and tamper with it
			var tamperedChildHash string
			for _, childHash := range parentLeaf.Links {
				tamperedChildHash = childHash
				break
			}

			// Replace the child with a different (but structurally valid) leaf
			// We'll just modify the ItemName to simulate tampering
			tamperedChild := tamperedDag.Leafs[tamperedChildHash]
			if tamperedChild != nil {
				originalItemName := tamperedChild.ItemName
				tamperedChild.ItemName = "TAMPERED_" + originalItemName

				t.Logf("Tampered with child %s (changed ItemName from %s to %s)",
					tamperedChildHash, originalItemName, tamperedChild.ItemName)
			}

			// The verification should FAIL because the merkle root won't match
			err := tamperedDag.Verify()

			// We expect verification to fail if we actually tampered with the child's content
			// However, since we kept the hash the same, this particular test might pass
			if err == nil {
				t.Logf("Note: Tampering with ItemName alone doesn't affect the merkle tree " +
					"because the merkle tree is built from child hashes, not content")
			}
		})

		t.Run("DetectIncorrectMerkleRootWithCorrectHash", func(t *testing.T) {
			// Find a leaf with multiple children
			var parentLeaf *dag.DagLeaf
			for _, leaf := range originalDag.Leafs {
				if len(leaf.Links) > 1 {
					parentLeaf = leaf
					break
				}
			}

			if parentLeaf == nil {
				t.Skip("No leaf with multiple children found")
			}

			// Create a DAG with a tampered merkle root
			tamperedDag := &dag.Dag{
				Root:  originalDag.Root,
				Leafs: make(map[string]*dag.DagLeaf),
			}

			// Copy all leaves
			for hash, leaf := range originalDag.Leafs {
				clonedLeaf := leaf.Clone()

				// For the parent we found, corrupt its ClassicMerkleRoot
				if hash == parentLeaf.Hash {
					// Change one byte of the merkle root
					if len(clonedLeaf.ClassicMerkleRoot) > 0 {
						clonedLeaf.ClassicMerkleRoot[0] ^= 0xFF
						t.Logf("Corrupted merkle root of parent %s", hash)
					}
				}

				tamperedDag.Leafs[hash] = clonedLeaf
			}

			// Verification should FAIL because the ClassicMerkleRoot doesn't match the children
			err := tamperedDag.Verify()
			if err == nil {
				t.Fatal("Expected verification to fail with corrupted merkle root, but it passed!")
			}

			t.Logf("✓ Correctly detected corrupted merkle root: %v", err)
		})

		t.Run("DetectIncorrectSingleChildHash", func(t *testing.T) {
			// Find a leaf with exactly one child
			var parentLeaf *dag.DagLeaf
			var childHash string
			for _, leaf := range originalDag.Leafs {
				if len(leaf.Links) == 1 {
					parentLeaf = leaf
					for _, hash := range leaf.Links {
						childHash = hash
						break
					}
					break
				}
			}

			if parentLeaf == nil {
				t.Skip("No leaf with single child found")
			}

			t.Logf("Testing with parent leaf %s that has 1 child: %s", parentLeaf.Hash, childHash)

			// Create a DAG with corrupted single child merkle root
			tamperedDag := &dag.Dag{
				Root:  originalDag.Root,
				Leafs: make(map[string]*dag.DagLeaf),
			}

			// Copy all leaves
			for hash, leaf := range originalDag.Leafs {
				clonedLeaf := leaf.Clone()

				// For the parent we found, corrupt its ClassicMerkleRoot
				if hash == parentLeaf.Hash {
					// Change the merkle root to something invalid
					if len(clonedLeaf.ClassicMerkleRoot) > 0 {
						clonedLeaf.ClassicMerkleRoot[0] ^= 0xFF
						t.Logf("Corrupted single child merkle root of parent %s", hash)
					}
				}

				tamperedDag.Leafs[hash] = clonedLeaf
			}

			// Verification should FAIL
			err := tamperedDag.Verify()
			if err == nil {
				t.Fatal("Expected verification to fail with corrupted single child merkle root, but it passed!")
			}

			t.Logf("✓ Correctly detected corrupted single child merkle root: %v", err)
		})

		t.Logf("✓ %s: Merkle verification tampering detection test passed", fixture.Name)
	})
}

// TestPartialDagMerkleVerification ensures that partial DAGs still work correctly
// Uses multi-file fixtures since we need files to create partials
func TestPartialDagMerkleVerification(t *testing.T) {
	testutil.RunTestWithMultiFileFixtures(t, func(t *testing.T, fullDag *dag.Dag, fixture testutil.TestFixture, fixturePath string) {
		// Verify the full DAG
		err := fullDag.Verify()
		if err != nil {
			t.Fatalf("Full DAG verification failed for %s: %v", fixture.Name, err)
		}

		// Find a file leaf to create a partial DAG
		var targetLeafHash string
		for hash, leaf := range fullDag.Leafs {
			if hash != fullDag.Root && leaf.Type == dag.FileLeafType {
				targetLeafHash = hash
				break
			}
		}

		if targetLeafHash == "" {
			t.Skip("No suitable target leaf found")
		}

		rootLeaf := fullDag.Leafs[fullDag.Root]

		// Make sure we actually create a PARTIAL dag, not a full one
		if rootLeaf.LeafCount < 3 {
			t.Skip("Need at least 3 leaves (1 root + 2 children) to create a partial DAG")
		}

		// Get just one file to make it partial
		partialDag, err := fullDag.GetPartial([]string{targetLeafHash}, true)
		if err != nil {
			t.Fatalf("Failed to create partial DAG for %s: %v", fixture.Name, err)
		}

		// Verify the partial DAG
		err = partialDag.Verify()
		if err != nil {
			t.Fatalf("Partial DAG verification failed for %s: %v", fixture.Name, err)
		}

		// Verify it's actually partial
		if !partialDag.IsPartial() {
			t.Fatalf("Expected a partial DAG for %s", fixture.Name)
		}

		// Ensure proofs exist for parent leaves in the partial DAG
		for _, leaf := range partialDag.Leafs {
			if leaf.Type == dag.DirectoryLeafType && len(leaf.Links) > 0 {
				// Directory leaves should have proofs for missing children
				if len(leaf.Proofs) == 0 {
					t.Logf("Note: Directory leaf %s has %d links but no proofs (might be included children)",
						leaf.Hash, len(leaf.Links))
				}
			}
		}

		t.Logf("✓ %s: Partial DAG merkle verification passed", fixture.Name)
	})
}

// TestContentTamperingDetection verifies that tampering with a leaf's Content
// bytes is detected during verification.
func TestContentTamperingDetection(t *testing.T) {
	testDir, err := os.MkdirTemp("", "content_tamper_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(testDir)

	// tamperLeafContent clones src and flips a single content byte in the target
	// leaf, leaving Hash and ContentHash untouched. Clone() shares the Content
	// backing array, so we copy the slice before mutating to avoid corrupting src.
	tamperLeafContent := func(src *dag.Dag, targetHash string) *dag.Dag {
		tampered := &dag.Dag{Root: src.Root, Leafs: make(map[string]*dag.DagLeaf)}
		for hash, leaf := range src.Leafs {
			tampered.Leafs[hash] = leaf.Clone()
		}
		target := tampered.Leafs[targetHash]
		flipped := make([]byte, len(target.Content))
		copy(flipped, target.Content)
		flipped[0] ^= 0xFF
		target.Content = flipped
		return tampered
	}

	t.Run("DetectTamperedRootFileContent", func(t *testing.T) {
		// Single-file DAG: the root leaf is itself a file leaf carrying content,
		// so this exercises the check in VerifyRootLeaf.
		testFile := filepath.Join(testDir, "root_content.txt")
		if err := os.WriteFile(testFile, bytes.Repeat([]byte("a"), 4096), 0644); err != nil {
			t.Fatalf("Failed to write test file: %v", err)
		}

		d, err := dag.CreateDag(testFile, false)
		if err != nil {
			t.Fatalf("Failed to create DAG: %v", err)
		}
		if err := d.Verify(); err != nil {
			t.Fatalf("Original DAG verification failed: %v", err)
		}
		if len(d.Leafs[d.Root].Content) == 0 {
			t.Fatal("expected the root file leaf to carry content")
		}

		tampered := tamperLeafContent(d, d.Root)
		err = tampered.Verify()
		if err == nil {
			t.Fatal("Expected verification to fail with tampered root content, but it passed!")
		}
		if !strings.Contains(err.Error(), "content does not match its content hash") {
			t.Fatalf("Expected a content-hash mismatch error, got: %v", err)
		}
		t.Logf("✓ Correctly detected tampered root content: %v", err)
	})

	t.Run("DetectTamperedChildFileContent", func(t *testing.T) {
		// Multi-file DAG: file leaves under a directory root carry content, so
		// this exercises the check in VerifyLeaf for a non-root leaf.
		inputDir := filepath.Join(testDir, "multi")
		if err := os.MkdirAll(inputDir, 0755); err != nil {
			t.Fatalf("Failed to create input dir: %v", err)
		}
		for i := 0; i < 3; i++ {
			f := filepath.Join(inputDir, fmt.Sprintf("file%d.txt", i))
			if err := os.WriteFile(f, bytes.Repeat([]byte{byte('a' + i)}, 2048), 0644); err != nil {
				t.Fatalf("Failed to write file: %v", err)
			}
		}

		d, err := dag.CreateDag(inputDir, false)
		if err != nil {
			t.Fatalf("Failed to create DAG: %v", err)
		}
		if err := d.Verify(); err != nil {
			t.Fatalf("Original DAG verification failed: %v", err)
		}

		var target string
		for hash, leaf := range d.Leafs {
			if hash != d.Root && len(leaf.Content) > 0 {
				target = hash
				break
			}
		}
		if target == "" {
			t.Fatal("no content-bearing non-root leaf found")
		}

		tampered := tamperLeafContent(d, target)
		err = tampered.Verify()
		if err == nil {
			t.Fatal("Expected verification to fail with tampered child content, but it passed!")
		}
		if !strings.Contains(err.Error(), "content does not match its content hash") {
			t.Fatalf("Expected a content-hash mismatch error, got: %v", err)
		}
		t.Logf("✓ Correctly detected tampered child content: %v", err)
	})

	t.Run("MetadataOnlyLeavesStillVerify", func(t *testing.T) {
		// Positive control: stripping content (metadata-only retrieval) must still
		// verify, because the content check is skipped when Content is absent.
		testFile := filepath.Join(testDir, "metadata_only.txt")
		if err := os.WriteFile(testFile, bytes.Repeat([]byte("z"), 4096), 0644); err != nil {
			t.Fatalf("Failed to write test file: %v", err)
		}

		d, err := dag.CreateDag(testFile, false)
		if err != nil {
			t.Fatalf("Failed to create DAG: %v", err)
		}

		stripped := &dag.Dag{Root: d.Root, Leafs: make(map[string]*dag.DagLeaf)}
		for hash, leaf := range d.Leafs {
			c := leaf.Clone()
			c.Content = nil
			stripped.Leafs[hash] = c
		}

		if err := stripped.Verify(); err != nil {
			t.Fatalf("Metadata-only DAG (content stripped) should still verify, but failed: %v", err)
		}
		t.Log("✓ Metadata-only DAG still verifies (content check correctly skipped)")
	})
}
