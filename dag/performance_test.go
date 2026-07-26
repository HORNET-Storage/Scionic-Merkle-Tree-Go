package dag

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestStreamFileChunksAllocatesExactBuffers(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "chunks.bin")
	if err := os.WriteFile(filePath, []byte("0123456789"), 0600); err != nil {
		t.Fatal(err)
	}

	type dimensions struct {
		length   int
		capacity int
	}
	var got []dimensions
	if err := streamFileChunks(filePath, 4, func(chunk []byte, _ int) error {
		got = append(got, dimensions{length: len(chunk), capacity: cap(chunk)})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	want := []dimensions{{4, 4}, {4, 4}, {2, 2}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected chunk allocations: got %#v, want %#v", got, want)
	}
}

func TestDagBuilderRunningStatsDeduplicate(t *testing.T) {
	leafBuilder := CreateDagLeafBuilder("same.txt")
	leafBuilder.SetType(FileLeafType)
	leafBuilder.SetData([]byte("identical content"))
	leaf, err := leafBuilder.BuildLeaf(map[string]string{"kind": "test"})
	if err != nil {
		t.Fatal(err)
	}
	expectedDagSize, err := SerializedLeafSize(leaf)
	if err != nil {
		t.Fatal(err)
	}

	dagBuilder := CreateDagBuilder()
	if err := dagBuilder.AddLeaf(leaf, nil); err != nil {
		t.Fatal(err)
	}
	if err := dagBuilder.AddLeaf(leaf.Clone(), nil); err != nil {
		t.Fatal(err)
	}
	stats := dagBuilder.Stats()
	if stats.LeafCount != 1 {
		t.Fatalf("duplicate leaf counted %d times", stats.LeafCount)
	}
	if stats.ContentSize != int64(len(leaf.Content)) {
		t.Fatalf("content size = %d, want %d", stats.ContentSize, len(leaf.Content))
	}
	if stats.DagSize != expectedDagSize {
		t.Fatalf("dag size = %d, want %d", stats.DagSize, expectedDagSize)
	}
}

func TestBuildRootLeafWithStatsMatchesBuilder(t *testing.T) {
	dagBuilder := CreateDagBuilder()
	rootBuilder := CreateDagLeafBuilder("archive")
	rootBuilder.SetType(DirectoryLeafType)
	for _, name := range []string{"a.txt", "b.txt"} {
		leafBuilder := CreateDagLeafBuilder(name)
		leafBuilder.SetType(FileLeafType)
		leafBuilder.SetData([]byte(name))
		leaf, err := leafBuilder.BuildLeaf(nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := dagBuilder.AddLeaf(leaf, nil); err != nil {
			t.Fatal(err)
		}
		rootBuilder.AddLink(leaf.Hash)
	}
	metadata := map[string]string{"archive_builder": "test"}
	fromBuilder, err := rootBuilder.BuildRootLeaf(dagBuilder, metadata)
	if err != nil {
		t.Fatal(err)
	}
	fromStats, err := rootBuilder.BuildRootLeafWithStats(dagBuilder.Stats(), metadata)
	if err != nil {
		t.Fatal(err)
	}
	if fromBuilder.Hash != fromStats.Hash {
		t.Fatalf("root mismatch: builder=%s stats=%s", fromBuilder.Hash, fromStats.Hash)
	}
	if fromStats.LeafCount != 3 {
		t.Fatalf("root leaf count = %d, want 3", fromStats.LeafCount)
	}
	if err := fromStats.VerifyRootLeaf(nil); err != nil {
		t.Fatalf("root failed verification: %v", err)
	}
}
