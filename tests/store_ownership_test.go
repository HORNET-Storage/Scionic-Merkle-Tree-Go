package tests

import (
	"bytes"
	"testing"

	"github.com/HORNET-Storage/Scionic-Merkle-Tree/v2/dag"
)

// A store that keeps -- or hands back -- the caller's *DagLeaf is a store the
// caller can edit by accident, in both directions.
//
// The egress half was fixed first and is the obvious one. The ingress half is
// not symmetric decoration: DagStore.RetrieveLeaf re-attaches separately stored
// content by assigning leaf.Content, and UpdateParentHashesStreaming assigns
// leaf.ParentHash. Both of those write through whatever the leaf store returned,
// so against an aliasing store they mutate stored state -- and the content case
// silently re-inlines every payload into the metadata store whose entire purpose
// is to stay small.
//
// Content itself stays shared, by the same documented rule Clone() follows: a
// leaf's CID commits to sha256(Content), so those bytes are immutable and
// copying them at the store boundary would be pure memory traffic.
func TestStoreBoundaryDoesNotAliasCallerLeaves(t *testing.T) {
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

	t.Run("StoringALeafDoesNotRetainTheCallersPointer", func(t *testing.T) {
		leaf := build("payload.bin", dag.FileLeafType, []byte("original"))
		store := dag.NewMemoryLeafStore()
		if err := store.StoreLeaf(leaf); err != nil {
			t.Fatalf("StoreLeaf failed: %v", err)
		}

		// The caller still owns its leaf and is entitled to keep working on it.
		leaf.ParentHash = "tampered"
		leaf.Links = []string{"injected"}
		leaf.ClassicMerkleRoot = bytes.Repeat([]byte{0xff}, 32)

		stored, err := store.RetrieveLeaf(leaf.Hash)
		if err != nil {
			t.Fatalf("RetrieveLeaf failed: %v", err)
		}
		if stored == nil {
			t.Fatal("the leaf vanished from the store")
		}
		if stored.ParentHash != "" {
			t.Fatalf("the caller's edit reached the store: ParentHash is %q", stored.ParentHash)
		}
		if len(stored.Links) != 0 {
			t.Fatalf("the caller's edit reached the store: Links are %v", stored.Links)
		}
		if len(stored.ClassicMerkleRoot) != 0 {
			t.Fatalf("the caller's edit reached the store: ClassicMerkleRoot is %x",
				stored.ClassicMerkleRoot)
		}
		if err := stored.VerifyLeaf(); err != nil {
			t.Fatalf("the stored leaf no longer verifies: %v", err)
		}
	})

	t.Run("ReadingALeafDoesNotReInlineSeparatelyStoredContent", func(t *testing.T) {
		payload := []byte("payload-bytes-that-belong-in-the-content-store")
		chunk := build("0", dag.ChunkLeafType, payload)
		root := build("file.bin", dag.FileLeafType, nil, chunk.Hash)
		d := &dag.Dag{
			Root: root.Hash,
			Leafs: map[string]*dag.DagLeaf{
				root.Hash:  root,
				chunk.Hash: chunk,
			},
		}

		store := dag.NewDagStoreWithStorage(d, dag.NewMemoryLeafStore(), dag.NewMemoryContentStore())

		// Vacuity guard: if the split never happened there is nothing to re-inline
		// and every assertion below would hold for the wrong reason.
		before, err := store.RetrieveLeafWithoutContent(chunk.Hash)
		if err != nil {
			t.Fatalf("RetrieveLeafWithoutContent failed: %v", err)
		}
		if before == nil {
			t.Fatal("the chunk is missing from the metadata store")
		}
		if len(before.Content) != 0 {
			t.Fatalf("content was never split out; the metadata leaf already carries %d bytes",
				len(before.Content))
		}

		full, err := store.RetrieveLeaf(chunk.Hash)
		if err != nil {
			t.Fatalf("RetrieveLeaf failed: %v", err)
		}
		if !bytes.Equal(full.Content, payload) {
			t.Fatalf("RetrieveLeaf did not re-attach the payload; got %d bytes", len(full.Content))
		}

		after, err := store.RetrieveLeafWithoutContent(chunk.Hash)
		if err != nil {
			t.Fatalf("RetrieveLeafWithoutContent failed: %v", err)
		}
		if len(after.Content) != 0 {
			t.Fatalf("merely reading a leaf pushed %d bytes of payload back into the metadata "+
				"store, which exists precisely to stay small", len(after.Content))
		}
	})

	t.Run("AStoreBuiltFromADagDoesNotWriteBackIntoThatDag", func(t *testing.T) {
		chunk := build("0", dag.ChunkLeafType, []byte("chunk-zero"))
		root := build("file.bin", dag.FileLeafType, nil, chunk.Hash)
		d := &dag.Dag{
			Root: root.Hash,
			Leafs: map[string]*dag.DagLeaf{
				root.Hash:  root,
				chunk.Hash: chunk,
			},
		}

		store := dag.NewDagStore(d)
		if err := store.UpdateParentHashesStreaming(2); err != nil {
			t.Fatalf("UpdateParentHashesStreaming failed: %v", err)
		}

		// The store recorded the parent for its own copy. The caller's DAG was
		// never handed to the store as something it may write to.
		if chunk.ParentHash != "" {
			t.Fatalf("the store wrote ParentHash %q into the caller's DAG", chunk.ParentHash)
		}
		stored, err := store.RetrieveLeafWithoutContent(chunk.Hash)
		if err != nil {
			t.Fatalf("RetrieveLeafWithoutContent failed: %v", err)
		}
		if stored.ParentHash != root.Hash {
			t.Fatalf("the store did not record the parent for its own copy: %q", stored.ParentHash)
		}
	})
}
