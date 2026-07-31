package tests

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/HORNET-Storage/Scionic-Merkle-Tree/v2/dag"
)

// TestCloneIndependence pins the mutation contract of DagLeaf.Clone.
//
// Clone shares exactly one field with the original -- Content -- and that is a
// deliberate performance decision, not an oversight: the transmission paths
// clone every leaf in the DAG, and deep-copying multi-megabyte content there
// measured roughly 25x slower on GetBatchedLeafSequence.
//
// Every other field must be independent. ClassicMerkleRoot in particular was
// NOT independent before, and that was a live defect rather than a theoretical
// one: index-writing a clone's merkle root corrupted the DAG it came from. That
// silently hollowed out a subtest in merkle_verification_test.go, which went on
// asserting "Verify() failed" against damage inherited from an earlier subtest
// instead of damage it had caused itself -- an assertion that could no longer
// fail for its stated reason.
//
// These subtests are written so they FAIL if Clone goes back to sharing.
func TestCloneIndependence(t *testing.T) {
	t.Run("ClassicMerkleRootIsIndependent", func(t *testing.T) {
		d := buildCloneFixture(t)
		target := findLeaf(t, d, func(leaf *dag.DagLeaf) bool {
			return len(leaf.ClassicMerkleRoot) > 0 && len(leaf.Links) > 1
		}, "a multi-link leaf carrying a merkle root")

		before := append([]byte(nil), target.ClassicMerkleRoot...)
		clone := target.Clone()
		clone.ClassicMerkleRoot[0] ^= 0xFF

		if !bytes.Equal(target.ClassicMerkleRoot, before) {
			t.Fatal("writing a clone's ClassicMerkleRoot mutated the source leaf")
		}
		if err := d.Verify(); err != nil {
			t.Fatalf("source DAG must still verify after mutating only a clone: %v", err)
		}
	})

	t.Run("ContentHashIsIndependent", func(t *testing.T) {
		d := buildCloneFixture(t)
		target := findLeaf(t, d, func(leaf *dag.DagLeaf) bool {
			return len(leaf.ContentHash) > 0
		}, "a leaf carrying a content hash")

		before := append([]byte(nil), target.ContentHash...)
		clone := target.Clone()
		clone.ContentHash[0] ^= 0xFF

		if !bytes.Equal(target.ContentHash, before) {
			t.Fatal("writing a clone's ContentHash mutated the source leaf")
		}
		if err := d.Verify(); err != nil {
			t.Fatalf("source DAG must still verify after mutating only a clone: %v", err)
		}
	})

	t.Run("ProofBranchesAreIndependent", func(t *testing.T) {
		d := buildCloneFixture(t)
		var fileHashes []string
		for hash, leaf := range d.Leafs {
			if leaf.Type == dag.FileLeafType {
				fileHashes = append(fileHashes, hash)
			}
		}
		sort.Strings(fileHashes)
		if len(fileHashes) < 2 {
			t.Fatal("fixture must contain at least two file leaves")
		}

		// A partial DAG is the shape that actually carries stored proofs.
		partial, err := d.GetPartial(fileHashes[:1], true)
		if err != nil {
			t.Fatalf("GetPartial: %v", err)
		}

		checked := 0
		for _, leaf := range partial.Leafs {
			if len(leaf.Proofs) == 0 {
				continue
			}
			clone := leaf.Clone()
			for key, cloned := range clone.Proofs {
				original := leaf.Proofs[key]
				if original == nil {
					t.Fatalf("clone invented a proof for %s", key)
				}
				if cloned == original {
					t.Fatal("clone shares the proof branch pointer with the source leaf")
				}

				cloned.Leaf = "tampered"
				if original.Leaf == "tampered" {
					t.Fatal("writing a clone's proof branch mutated the source leaf")
				}

				if cloned.Proof != nil && len(cloned.Proof.Siblings) > 0 {
					if cloned.Proof == original.Proof {
						t.Fatal("clone shares the merkle Proof pointer with the source leaf")
					}
					cloned.Proof.Siblings[0][0] ^= 0xFF
					if original.Proof.Siblings[0][0] == cloned.Proof.Siblings[0][0] {
						t.Fatal("writing a clone's proof siblings mutated the source leaf")
					}
				}
				checked++
			}
		}
		if checked == 0 {
			t.Fatal("no stored proofs were exercised; this subtest would prove nothing")
		}
	})

	t.Run("ContentIsSharedByDesign", func(t *testing.T) {
		// Content is the single field Clone shares. Pinning that here means any
		// future change to the trade-off has to be a decision somebody makes on
		// purpose -- in either direction -- rather than a silent drift.
		d := buildCloneFixture(t)
		target := findLeaf(t, d, func(leaf *dag.DagLeaf) bool {
			return len(leaf.Content) > 0
		}, "a leaf carrying content")

		clone := target.Clone()
		if &clone.Content[0] != &target.Content[0] {
			t.Fatal("Content is documented as shared with the original; if that changed " +
				"deliberately, update Clone's doc comment and the performance note that " +
				"justifies it")
		}

		// Reassignment is the supported way to give a clone different bytes, and
		// it must leave the source DAG intact.
		clone.Content = []byte("totally different bytes")
		if bytes.Equal(target.Content, clone.Content) {
			t.Fatal("reassigning a clone's Content changed the source leaf")
		}
		if err := d.Verify(); err != nil {
			t.Fatalf("source DAG must still verify after reassigning a clone's Content: %v", err)
		}
	})

	t.Run("TamperingACloneNeverDamagesTheSourceDag", func(t *testing.T) {
		// This is the exact pattern merkle_verification_test.go uses: clone every
		// leaf into a new DAG, corrupt one clone, assert the new DAG fails. The
		// part that was missing is the other half -- that the ORIGINAL survives.
		// Without it, one subtest's damage leaked into every later subtest that
		// cloned from the same DAG.
		d := buildCloneFixture(t)
		target := findLeaf(t, d, func(leaf *dag.DagLeaf) bool {
			return len(leaf.ClassicMerkleRoot) > 0 && len(leaf.Links) > 1
		}, "a multi-link leaf carrying a merkle root")

		tampered := cloneEveryLeaf(d)
		tampered.Leafs[target.Hash].ClassicMerkleRoot[0] ^= 0xFF
		if err := tampered.Verify(); err == nil {
			t.Fatal("a DAG with a corrupted merkle root must fail verification")
		}

		if err := d.Verify(); err != nil {
			t.Fatalf("the source DAG must be untouched by tampering with a clone: %v", err)
		}

		// The decisive check: a fresh, UNtampered clone of the source must still
		// verify. If it does not, the source was damaged and any later assertion
		// of "Verify() failed" would hold without the test doing anything.
		if err := cloneEveryLeaf(d).Verify(); err != nil {
			t.Fatalf("an untampered clone of the source must verify, otherwise later "+
				"tampering subtests cannot fail for their own stated reason: %v", err)
		}
	})
}

func buildCloneFixture(t *testing.T) *dag.Dag {
	t.Helper()
	dir := t.TempDir()
	for i := 0; i < 3; i++ {
		name := filepath.Join(dir, fmt.Sprintf("file%d.txt", i))
		content := bytes.Repeat([]byte{byte('a' + i)}, 2048)
		if err := os.WriteFile(name, content, 0o644); err != nil {
			t.Fatalf("write fixture file: %v", err)
		}
	}
	d, err := dag.CreateDag(dir, false)
	if err != nil {
		t.Fatalf("CreateDag: %v", err)
	}
	if err := d.Verify(); err != nil {
		t.Fatalf("fixture DAG must verify before any tampering: %v", err)
	}
	return d
}

func cloneEveryLeaf(src *dag.Dag) *dag.Dag {
	out := &dag.Dag{Root: src.Root, Leafs: make(map[string]*dag.DagLeaf, len(src.Leafs))}
	for hash, leaf := range src.Leafs {
		out.Leafs[hash] = leaf.Clone()
	}
	return out
}

func findLeaf(t *testing.T, d *dag.Dag, match func(*dag.DagLeaf) bool, describe string) *dag.DagLeaf {
	t.Helper()
	// Map order is unspecified, so pick deterministically by hash. A subtest that
	// silently exercises a different leaf on each run is not a fixed test.
	var hashes []string
	for hash, leaf := range d.Leafs {
		if match(leaf) {
			hashes = append(hashes, hash)
		}
	}
	if len(hashes) == 0 {
		t.Fatalf("fixture contains no %s", describe)
	}
	sort.Strings(hashes)
	return d.Leafs[hashes[0]]
}

