package tests

import (
	"testing"

	"github.com/HORNET-Storage/Scionic-Merkle-Tree/v2/dag"
)

// A shared chunk leaf has several parents, so "the" parent of that leaf is only
// well defined if every code path picks the same one.
//
// FromSerializable pinned it to the LOWEST parent hash, while the store index
// recorded whichever parent BFS happened to reach FIRST. The identical DAG
// therefore reported a different ParentHash depending on whether it had been
// deserialized or loaded from a store.
//
// ParentHash is absent from SerializableDagLeaf and so is never transmitted,
// which is exactly why the disagreement survived: nothing on the wire ever
// contradicted it.
func TestStoreIndexPicksTheLowestParentForASharedChunk(t *testing.T) {
	build := func(name string, leafType dag.LeafType, data []byte, links ...string) *dag.DagLeaf {
		t.Helper()
		b := dag.CreateDagLeafBuilder(name)
		b.SetType(leafType)
		if data != nil {
			b.SetData(data)
		}
		for _, link := range links {
			b.AddLink(link)
		}
		leaf, err := b.BuildLeaf(nil)
		if err != nil {
			t.Fatalf("failed to build leaf %s: %v", name, err)
		}
		return leaf
	}

	shared := build("0", dag.ChunkLeafType, []byte("shared"))
	extraA := build("1", dag.ChunkLeafType, []byte("extra-a"))
	extraB := build("2", dag.ChunkLeafType, []byte("extra-b"))

	parentA := build("a.bin", dag.FileLeafType, nil, shared.Hash, extraA.Hash)
	parentB := build("b.bin", dag.FileLeafType, nil, shared.Hash, extraB.Hash)

	lower, higher := parentA, parentB
	if higher.Hash < lower.Hash {
		lower, higher = parentB, parentA
	}

	// The root is a FILE leaf on purpose. BuildLeaf sorts links only for DIRECTORY
	// leaves, so listing the higher parent first survives into root.Links and BFS
	// reaches the higher parent before the lower one. With a directory root the
	// links would be sorted by hash, BFS would arrive at the lowest parent first
	// anyway, and this test would pass against the very bug it exists to catch.
	root := build("root", dag.FileLeafType, nil, higher.Hash, lower.Hash)

	d := &dag.Dag{
		Root: root.Hash,
		Leafs: map[string]*dag.DagLeaf{
			shared.Hash: shared,
			extraA.Hash: extraA,
			extraB.Hash: extraB,
			lower.Hash:  lower,
			higher.Hash: higher,
			root.Hash:   root,
		},
	}

	// Vacuity guards. Without these the assertions below can pass for reasons
	// that have nothing to do with the rule under test.
	if len(root.Links) != 2 || root.Links[0] != higher.Hash {
		t.Fatalf("fixture no longer lists the higher parent first (links=%v); BFS would "+
			"reach the lowest parent first and this test would prove nothing", root.Links)
	}
	if got := parentsOf(d, shared.Hash); len(got) != 2 {
		t.Fatalf("expected the shared chunk to have exactly 2 parents, got %d (%v)", len(got), got)
	}

	store := dag.NewDagStore(d)
	if err := store.BuildIndex(); err != nil {
		t.Fatalf("BuildIndex failed: %v", err)
	}
	index := store.GetIndex()
	if index == nil {
		t.Fatal("BuildIndex produced no index")
	}

	if got := index.Parents[shared.Hash]; got != lower.Hash {
		t.Fatalf("store index chose parent %s for the shared chunk; want the lowest parent %s "+
			"(BFS reaches %s first, which is what the index used to record)",
			got, lower.Hash, higher.Hash)
	}

	// The store index and the deserialization path must agree, leaf for leaf.
	encoded, err := d.ToCBOR()
	if err != nil {
		t.Fatalf("ToCBOR failed: %v", err)
	}
	decoded, err := dag.FromCBOR(encoded)
	if err != nil {
		t.Fatalf("FromCBOR failed: %v", err)
	}
	for hash, leaf := range decoded.Leafs {
		if hash == decoded.Root {
			continue
		}
		if index.Parents[hash] != leaf.ParentHash {
			t.Fatalf("leaf %s: store index says parent %q, deserialization says %q",
				hash, index.Parents[hash], leaf.ParentHash)
		}
	}

	// UpdateParentHashesStreaming persists whatever the index decided, so it has
	// to land on the same answer rather than re-deriving its own.
	if err := store.UpdateParentHashesStreaming(2); err != nil {
		t.Fatalf("UpdateParentHashesStreaming failed: %v", err)
	}
	stored, err := store.RetrieveLeafWithoutContent(shared.Hash)
	if err != nil {
		t.Fatalf("RetrieveLeafWithoutContent failed: %v", err)
	}
	if stored == nil {
		t.Fatal("shared chunk missing from the store after UpdateParentHashesStreaming")
	}
	if stored.ParentHash != lower.Hash {
		t.Fatalf("persisted ParentHash is %s, want the lowest parent %s", stored.ParentHash, lower.Hash)
	}
}
