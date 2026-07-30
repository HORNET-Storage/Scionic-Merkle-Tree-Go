package tests

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/HORNET-Storage/Scionic-Merkle-Tree/v2/dag"
	"github.com/HORNET-Storage/Scionic-Merkle-Tree/v2/testutil"
)

// A Scionic DAG is content addressed, so two byte-identical chunks at the same
// index collapse into a single leaf linked by several parents. Every
// child->parent lookup in this library used to keep whichever parent Go's
// randomized map iteration yielded first, so merkle proofs, partial DAGs and
// reconstructed parent hashes silently differed from one run to the next and
// verification failed only intermittently -- roughly once in thirty runs, which
// reads as flakiness rather than as the correctness bug it was.
//
// These tests re-run each of those paths many times inside one process, where
// map order is reshuffled on every range statement, so a reintroduced
// first-wins lookup fails reliably instead of occasionally.
const determinismIterations = 64

// buildSharedChunkDag builds the mixed_sizes fixture at a 4KB chunk size.
// Fixture content is a function of absolute byte offset, so medium.txt and
// large.txt open with the same 4096 bytes and share their first chunk leaf.
func buildSharedChunkDag(t *testing.T) *dag.Dag {
	t.Helper()

	previous := dag.ChunkSize
	dag.SetChunkSize(4096)
	t.Cleanup(func() { dag.SetChunkSize(previous) })

	tmpDir, err := os.MkdirTemp("", "shared_chunk_*")
	if err != nil {
		t.Fatalf("failed to create temp directory: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(tmpDir) })

	fixture, ok := testutil.GetFixtureByName("mixed_sizes")
	if !ok {
		t.Fatal("fixture not found: mixed_sizes")
	}

	fixturePath, err := testutil.CreateFixture(tmpDir, fixture)
	if err != nil {
		t.Fatalf("failed to create fixture: %v", err)
	}

	d, err := dag.CreateDag(fixturePath, false)
	if err != nil {
		t.Fatalf("failed to create dag: %v", err)
	}
	return d
}

// parentsOf returns every leaf hash linking childHash, in sorted order.
func parentsOf(d *dag.Dag, childHash string) []string {
	var parents []string
	for hash, leaf := range d.Leafs {
		if leaf.HasLink(childHash) {
			parents = append(parents, hash)
		}
	}
	sort.Strings(parents)
	return parents
}

// sharedChunk returns a chunk leaf linked by more than one parent, failing if
// the fixture no longer produces one -- without that leaf every test below
// would pass vacuously.
func sharedChunk(t *testing.T, d *dag.Dag) string {
	t.Helper()

	var shared []string
	for hash, leaf := range d.Leafs {
		if leaf.Type == dag.ChunkLeafType && len(parentsOf(d, hash)) > 1 {
			shared = append(shared, hash)
		}
	}
	if len(shared) == 0 {
		t.Fatal("mixed_sizes produced no chunk leaf with multiple parents; " +
			"the fixture no longer exercises shared chunks and these tests prove nothing")
	}
	sort.Strings(shared)
	return shared[0]
}

// TestSharedChunkPartialCarriesEveryParentProof requests a shared chunk
// together with both of its parents, so both parents land in the partial and
// both must be able to prove the chunk. Carrying a proof on only one of them
// left the other unverifiable depending on which parent the walk reached.
func TestSharedChunkPartialCarriesEveryParentProof(t *testing.T) {
	d := buildSharedChunkDag(t)
	if err := d.Verify(); err != nil {
		t.Fatalf("full dag verification failed: %v", err)
	}

	chunkHash := sharedChunk(t, d)
	parents := parentsOf(d, chunkHash)
	t.Logf("shared chunk %s is linked by %d parents", chunkHash, len(parents))

	requested := append(append([]string{}, parents...), chunkHash)

	var first string
	for i := 0; i < determinismIterations; i++ {
		partial, err := d.GetPartial(requested, true)
		if err != nil {
			t.Fatalf("iteration %d: GetPartial failed: %v", i, err)
		}

		if err := partial.Verify(); err != nil {
			t.Fatalf("iteration %d: partial verification failed: %v", i, err)
		}

		for _, parentHash := range parents {
			parent, inPartial := partial.Leafs[parentHash]
			if !inPartial {
				t.Fatalf("iteration %d: requested parent %s is missing from the partial", i, parentHash)
			}
			if !parent.HasLink(chunkHash) || parent.CurrentLinkCount <= 1 {
				continue
			}
			if len(parent.Links) == parent.CurrentLinkCount {
				continue // holds every child, so it proves them directly
			}

			proof, ok := parent.Proofs[chunkHash]
			if !ok {
				t.Fatalf("iteration %d: parent %s links shared chunk %s but carries no proof for it",
					i, parentHash, chunkHash)
			}
			if err := parent.VerifyBranch(proof); err != nil {
				t.Fatalf("iteration %d: parent %s holds an invalid proof for shared chunk %s: %v",
					i, parentHash, chunkHash, err)
			}
		}

		// encoding/json sorts map keys, so equal partials encode to equal bytes.
		encoded, err := json.Marshal(partial.ToSerializable())
		if err != nil {
			t.Fatalf("iteration %d: failed to encode partial: %v", i, err)
		}
		if i == 0 {
			first = string(encoded)
			continue
		}
		if string(encoded) != first {
			t.Fatalf("iteration %d produced a different partial DAG than iteration 0; "+
				"a parent lookup is resolving in map order again", i)
		}
	}
}

// TestSharedChunkLeafSequenceIsDeterministic checks that each packet's proof is
// built against the parent the packet declares. A proof taken from a different
// parent of the same shared chunk still looks well formed but fails to verify.
func TestSharedChunkLeafSequenceIsDeterministic(t *testing.T) {
	d := buildSharedChunkDag(t)
	chunkHash := sharedChunk(t, d)

	var first string
	for i := 0; i < determinismIterations; i++ {
		sequence := d.GetLeafSequence()
		if len(sequence) == 0 {
			t.Fatalf("iteration %d: no transmission packets generated", i)
		}

		receiver := &dag.Dag{Root: d.Root, Leafs: make(map[string]*dag.DagLeaf)}
		sawChunk := false

		var canonical strings.Builder
		for j, p := range sequence {
			if p.Leaf.Hash == chunkHash {
				sawChunk = true
			}

			encodedProofs, err := json.Marshal(p.Proofs)
			if err != nil {
				t.Fatalf("iteration %d: failed to encode proofs for packet %d: %v", i, j, err)
			}
			fmt.Fprintf(&canonical, "%s<-%s|%s;", p.Leaf.Hash, p.ParentHash, encodedProofs)

			encoded, err := p.ToCBOR()
			if err != nil {
				t.Fatalf("iteration %d: failed to serialize packet %d: %v", i, j, err)
			}
			packet, err := dag.TransmissionPacketFromCBOR(encoded)
			if err != nil {
				t.Fatalf("iteration %d: failed to deserialize packet %d: %v", i, j, err)
			}

			if err := receiver.ApplyAndVerifyTransmissionPacket(packet); err != nil {
				t.Fatalf("iteration %d: packet %d (leaf %s under parent %s) failed verification: %v",
					i, j, packet.Leaf.Hash, packet.ParentHash, err)
			}
		}

		if !sawChunk {
			t.Fatalf("iteration %d: shared chunk %s never appeared in the sequence", i, chunkHash)
		}
		if len(receiver.Leafs) != len(d.Leafs) {
			t.Fatalf("iteration %d: receiver rebuilt %d leaves, want %d",
				i, len(receiver.Leafs), len(d.Leafs))
		}
		if err := receiver.Verify(); err != nil {
			t.Fatalf("iteration %d: rebuilt dag failed verification: %v", i, err)
		}

		if i == 0 {
			first = canonical.String()
			continue
		}
		if canonical.String() != first {
			t.Fatalf("iteration %d produced a different packet sequence than iteration 0; "+
				"proof construction is resolving a parent in map order again", i)
		}
	}
}

// TestSharedChunkParentHashRoundTripIsDeterministic checks that deserializing
// the same bytes twice assigns the same ParentHash to a shared chunk.
func TestSharedChunkParentHashRoundTripIsDeterministic(t *testing.T) {
	d := buildSharedChunkDag(t)
	chunkHash := sharedChunk(t, d)
	serialized := d.ToSerializable()

	var first string
	for i := 0; i < determinismIterations; i++ {
		restored := dag.FromSerializable(serialized)
		if err := restored.Verify(); err != nil {
			t.Fatalf("iteration %d: restored dag failed verification: %v", i, err)
		}

		hashes := make([]string, 0, len(restored.Leafs))
		for hash := range restored.Leafs {
			hashes = append(hashes, hash)
		}
		sort.Strings(hashes)

		var canonical strings.Builder
		for _, hash := range hashes {
			fmt.Fprintf(&canonical, "%s->%s;", hash, restored.Leafs[hash].ParentHash)
		}

		if i == 0 {
			first = canonical.String()
			continue
		}
		if canonical.String() != first {
			t.Fatalf("iteration %d reconstructed a different ParentHash for at least one leaf "+
				"(shared chunk %s); FromSerializable is resolving parents in map order again",
				i, chunkHash)
		}
	}
}

// TestIterateDagVisitsSharedChunkOnce guards the traversal visited set. Walking
// per link handed a shared chunk to the callback once per parent, inflating
// every count and label derived from the walk.
func TestIterateDagVisitsSharedChunkOnce(t *testing.T) {
	d := buildSharedChunkDag(t)
	chunkHash := sharedChunk(t, d)

	visits := make(map[string]int, len(d.Leafs))
	err := d.IterateDag(func(leaf *dag.DagLeaf, parent *dag.DagLeaf) error {
		visits[leaf.Hash]++
		return nil
	})
	if err != nil {
		t.Fatalf("IterateDag failed: %v", err)
	}

	if got := visits[chunkHash]; got != 1 {
		t.Fatalf("shared chunk %s was visited %d times, want exactly 1", chunkHash, got)
	}
	if len(visits) != len(d.Leafs) {
		t.Fatalf("IterateDag reached %d distinct leaves, want %d", len(visits), len(d.Leafs))
	}
	for hash, count := range visits {
		if count != 1 {
			t.Fatalf("leaf %s was visited %d times, want exactly 1", hash, count)
		}
	}
}
