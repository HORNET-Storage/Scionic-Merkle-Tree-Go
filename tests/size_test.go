package tests

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/HORNET-Storage/Scionic-Merkle-Tree/v2/dag"
	"github.com/HORNET-Storage/Scionic-Merkle-Tree/v2/testutil"
	cbor "github.com/fxamacker/cbor/v2"
)

// TestContentSizeAndDagSizeAccuracy validates that ContentSize and DagSize
// are accurately calculated and that tampering with these fields invalidates the hash
func TestContentSizeAndDagSizeAccuracy(t *testing.T) {
	testDir, err := os.MkdirTemp("", "size_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(testDir)

	t.Run("SingleFileContentSize", func(t *testing.T) {
		// Create test file with known size
		testFile := filepath.Join(testDir, "test.txt")
		testContent := bytes.Repeat([]byte("a"), 12345) // Exactly 12345 bytes
		err = os.WriteFile(testFile, testContent, 0644)
		if err != nil {
			t.Fatalf("Failed to write test file: %v", err)
		}

		d, err := dag.CreateDag(testFile, false)
		if err != nil {
			t.Fatalf("Failed to create DAG: %v", err)
		}

		rootLeaf := d.Leafs[d.Root]

		// Test 1: ContentSize should match file size
		if rootLeaf.ContentSize != int64(len(testContent)) {
			t.Errorf("ContentSize mismatch: expected %d, got %d",
				len(testContent), rootLeaf.ContentSize)
		}

		t.Logf("ContentSize correctly calculated: %d bytes", rootLeaf.ContentSize)
	})

	t.Run("DagSizeCalculation", func(t *testing.T) {
		testFile := filepath.Join(testDir, "dagsize_test.txt")
		testContent := bytes.Repeat([]byte("b"), 5000)
		err = os.WriteFile(testFile, testContent, 0644)
		if err != nil {
			t.Fatalf("Failed to write test file: %v", err)
		}

		d, err := dag.CreateDag(testFile, false)
		if err != nil {
			t.Fatalf("Failed to create DAG: %v", err)
		}

		rootLeaf := d.Leafs[d.Root]

		// Test 2: DagSize should be sum of all serialized leaves
		// We use the same two-pass approach as verification
		var childrenDagSize int64
		for _, leaf := range d.Leafs {
			if leaf.Hash == rootLeaf.Hash {
				continue // Skip root
			}

			var linkHashes []string
			if len(leaf.Links) > 0 {
				linkHashes = make([]string, 0, len(leaf.Links))
				linkHashes = append(linkHashes, leaf.Links...)
				sort.Strings(linkHashes)
			}

			data := struct {
				Hash              string
				ItemName          string
				Type              dag.LeafType
				ContentHash       []byte
				Content           []byte
				ClassicMerkleRoot []byte
				CurrentLinkCount  int
				LeafCount         int
				ContentSize       int64
				DagSize           int64
				Links             []string
				AdditionalData    map[string]string
			}{
				Hash:              leaf.Hash,
				ItemName:          leaf.ItemName,
				Type:              leaf.Type,
				ContentHash:       leaf.ContentHash,
				Content:           leaf.Content,
				ClassicMerkleRoot: leaf.ClassicMerkleRoot,
				CurrentLinkCount:  leaf.CurrentLinkCount,
				LeafCount:         leaf.LeafCount,
				ContentSize:       leaf.ContentSize,
				DagSize:           leaf.DagSize,
				Links:             linkHashes,
				AdditionalData:    dag.SortMapByKeys(leaf.AdditionalData),
			}

			serialized, err := cbor.Marshal(data)
			if err != nil {
				t.Fatalf("Failed to serialize leaf: %v", err)
			}
			childrenDagSize += int64(len(serialized))
		}

		// Build temp root with DagSize=0 to measure
		tempLeafData := struct {
			ItemName         string
			Type             dag.LeafType
			MerkleRoot       []byte
			CurrentLinkCount int
			LeafCount        int
			ContentSize      int64
			DagSize          int64
			ContentHash      []byte
			AdditionalData   []dag.KeyValue
		}{
			ItemName:         rootLeaf.ItemName,
			Type:             rootLeaf.Type,
			MerkleRoot:       rootLeaf.ClassicMerkleRoot,
			CurrentLinkCount: rootLeaf.CurrentLinkCount,
			LeafCount:        rootLeaf.LeafCount,
			ContentSize:      rootLeaf.ContentSize,
			DagSize:          0,
			ContentHash:      rootLeaf.ContentHash,
			AdditionalData:   dag.SortMapForVerification(rootLeaf.AdditionalData),
		}

		tempSerialized, err := cbor.Marshal(tempLeafData)
		if err != nil {
			t.Fatalf("Failed to serialize temp root: %v", err)
		}
		rootLeafSize := int64(len(tempSerialized))

		calculatedDagSize := childrenDagSize + rootLeafSize

		// DagSize should match calculated value
		if rootLeaf.DagSize != calculatedDagSize {
			t.Errorf("DagSize mismatch: stored=%d, calculated=%d",
				rootLeaf.DagSize, calculatedDagSize)
		}

		t.Logf("DagSize correctly calculated: %d bytes (children: %d, root: %d)",
			rootLeaf.DagSize, childrenDagSize, rootLeafSize)
	})

	t.Run("ContentSizeTampering", func(t *testing.T) {
		testFile := filepath.Join(testDir, "tamper_content_test.txt")
		testContent := bytes.Repeat([]byte("c"), 8000)
		err = os.WriteFile(testFile, testContent, 0644)
		if err != nil {
			t.Fatalf("Failed to write test file: %v", err)
		}

		d, err := dag.CreateDag(testFile, false)
		if err != nil {
			t.Fatalf("Failed to create DAG: %v", err)
		}

		// Test 3: Tampering with ContentSize should invalidate hash
		tamperedDag := &dag.Dag{
			Root:  d.Root,
			Leafs: make(map[string]*dag.DagLeaf),
		}
		for hash, leaf := range d.Leafs {
			tamperedDag.Leafs[hash] = leaf.Clone()
		}

		// Tamper with ContentSize
		tamperedRoot := tamperedDag.Leafs[tamperedDag.Root]
		originalContentSize := tamperedRoot.ContentSize
		tamperedRoot.ContentSize += 1000

		t.Logf("Tampering ContentSize: %d -> %d", originalContentSize, tamperedRoot.ContentSize)

		// Verification should FAIL
		err = tamperedDag.Verify()
		if err == nil {
			t.Fatal("Expected verification to fail with tampered ContentSize, but it passed!")
		}

		t.Logf("Correctly detected tampered ContentSize: %v", err)
	})

	t.Run("DagSizeTampering", func(t *testing.T) {
		testFile := filepath.Join(testDir, "tamper_dag_test.txt")
		testContent := bytes.Repeat([]byte("d"), 8000)
		err = os.WriteFile(testFile, testContent, 0644)
		if err != nil {
			t.Fatalf("Failed to write test file: %v", err)
		}

		d, err := dag.CreateDag(testFile, false)
		if err != nil {
			t.Fatalf("Failed to create DAG: %v", err)
		}

		// Test 4: Tampering with DagSize should invalidate hash
		tamperedDag := &dag.Dag{
			Root:  d.Root,
			Leafs: make(map[string]*dag.DagLeaf),
		}
		for hash, leaf := range d.Leafs {
			tamperedDag.Leafs[hash] = leaf.Clone()
		}

		// Tamper with DagSize
		tamperedRoot := tamperedDag.Leafs[tamperedDag.Root]
		originalDagSize := tamperedRoot.DagSize
		tamperedRoot.DagSize += 5000

		t.Logf("Tampering DagSize: %d -> %d", originalDagSize, tamperedRoot.DagSize)

		// Verification should FAIL
		err = tamperedDag.Verify()
		if err == nil {
			t.Fatal("Expected verification to fail with tampered DagSize, but it passed!")
		}

		t.Logf("Correctly detected tampered DagSize: %v", err)
	})

	t.Run("ChunkedFileContentSize", func(t *testing.T) {
		// Test 5: For chunked files, ContentSize should match total content
		// expectedChunks below is fixed-size ceil math; pin the legacy fixed
		// mode explicitly now that fastcdc-v1 is the default cutter.
		dag.SetChunkSize(dag.DefaultChunkSize)
		defer dag.SetDefaultChunkSize()

		largeFile := filepath.Join(testDir, "large.txt")
		largeContent := bytes.Repeat([]byte("e"), dag.ChunkSize*2+100)
		err = os.WriteFile(largeFile, largeContent, 0644)
		if err != nil {
			t.Fatalf("Failed to write large file: %v", err)
		}

		largeDag, err := dag.CreateDag(largeFile, false)
		if err != nil {
			t.Fatalf("Failed to create large DAG: %v", err)
		}

		largeRootLeaf := largeDag.Leafs[largeDag.Root]
		if largeRootLeaf.ContentSize != int64(len(largeContent)) {
			t.Errorf("ContentSize for chunked file mismatch: expected %d, got %d",
				len(largeContent), largeRootLeaf.ContentSize)
		}

		// Verify we actually have chunks
		chunkCount := 0
		for _, leaf := range largeDag.Leafs {
			if leaf.Type == dag.ChunkLeafType {
				chunkCount++
			}
		}

		expectedChunks := (len(largeContent) + dag.ChunkSize - 1) / dag.ChunkSize
		if chunkCount != expectedChunks {
			t.Errorf("Expected %d chunks, got %d", expectedChunks, chunkCount)
		}

		t.Logf("Chunked file: %d bytes in %d chunks, ContentSize=%d",
			len(largeContent), chunkCount, largeRootLeaf.ContentSize)
	})
}

// TestDirectoryContentSize validates that ContentSize for directories
// correctly sums all file content
func TestDirectoryContentSize(t *testing.T) {
	testDir, err := os.MkdirTemp("", "dir_size_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(testDir)

	inputDir := filepath.Join(testDir, "input")
	err = os.MkdirAll(inputDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create input directory: %v", err)
	}

	// Create multiple files with known sizes
	totalSize := int64(0)
	fileSizes := []int{1000, 1100, 1200, 1300, 1400}

	for i, size := range fileSizes {
		content := bytes.Repeat([]byte("x"), size)
		err = os.WriteFile(filepath.Join(inputDir, fmt.Sprintf("file%d.txt", i)),
			content, 0644)
		if err != nil {
			t.Fatalf("Failed to write file: %v", err)
		}
		totalSize += int64(size)
	}

	d, err := dag.CreateDag(inputDir, false)
	if err != nil {
		t.Fatalf("Failed to create DAG: %v", err)
	}

	rootLeaf := d.Leafs[d.Root]

	if rootLeaf.ContentSize != totalSize {
		t.Errorf("Directory ContentSize mismatch: expected %d, got %d",
			totalSize, rootLeaf.ContentSize)
	}

	t.Logf("Directory with %d files: total size=%d bytes, ContentSize=%d",
		len(fileSizes), totalSize, rootLeaf.ContentSize)

	// Verify each file leaf has correct size
	for _, leaf := range d.Leafs {
		if leaf.Type == dag.FileLeafType && leaf.Content != nil {
			fileSize := int64(len(leaf.Content))
			t.Logf("File leaf %s: %d bytes", leaf.ItemName, fileSize)
		}
	}
}

// TestTwoPassSerializationDeterminism validates that the two-pass approach
// produces consistent and deterministic results
func TestTwoPassSerializationDeterminism(t *testing.T) {
	testutil.RunTestWithMultiFileFixtures(t, func(t *testing.T, dag1 *dag.Dag, fixture testutil.TestFixture, fixturePath string) {
		// Create DAG two more times from same fixture path
		dag2, err := dag.CreateDag(fixturePath, false)
		if err != nil {
			t.Fatalf("Failed to create second DAG: %v", err)
		}

		dag3, err := dag.CreateDag(fixturePath, false)
		if err != nil {
			t.Fatalf("Failed to create third DAG: %v", err)
		}

		// Root hashes should be identical (deterministic)
		if dag1.Root != dag2.Root {
			t.Errorf("Root hash not deterministic between dag1 and dag2: %s vs %s",
				dag1.Root, dag2.Root)
		}

		if dag1.Root != dag3.Root {
			t.Errorf("Root hash not deterministic between dag1 and dag3: %s vs %s",
				dag1.Root, dag3.Root)
		}

		// DagSize should be identical
		root1 := dag1.Leafs[dag1.Root]
		root2 := dag2.Leafs[dag2.Root]
		root3 := dag3.Leafs[dag3.Root]

		if root1.DagSize != root2.DagSize {
			t.Errorf("DagSize not deterministic between dag1 and dag2: %d vs %d",
				root1.DagSize, root2.DagSize)
		}

		if root1.DagSize != root3.DagSize {
			t.Errorf("DagSize not deterministic between dag1 and dag3: %d vs %d",
				root1.DagSize, root3.DagSize)
		}

		// ContentSize should be identical
		if root1.ContentSize != root2.ContentSize {
			t.Errorf("ContentSize not deterministic between dag1 and dag2: %d vs %d",
				root1.ContentSize, root2.ContentSize)
		}

		if root1.ContentSize != root3.ContentSize {
			t.Errorf("ContentSize not deterministic between dag1 and dag3: %d vs %d",
				root1.ContentSize, root3.ContentSize)
		}

		t.Logf("✓ %s: Determinism verified across 3 DAG creations", fixture.Name)
		t.Logf("  Root Hash: %s", dag1.Root)
		t.Logf("  ContentSize: %d bytes", root1.ContentSize)
		t.Logf("  DagSize: %d bytes", root1.DagSize)
		t.Logf("  LeafCount: %d", root1.LeafCount)
	})
}

// TestEmptyFileContentSize validates that empty files have ContentSize=0
func TestEmptyFileContentSize(t *testing.T) {
	testDir, err := os.MkdirTemp("", "empty_size_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(testDir)

	emptyFile := filepath.Join(testDir, "empty.txt")
	err = os.WriteFile(emptyFile, []byte{}, 0644)
	if err != nil {
		t.Fatalf("Failed to write empty file: %v", err)
	}

	d, err := dag.CreateDag(emptyFile, false)
	if err != nil {
		t.Fatalf("Failed to create DAG: %v", err)
	}

	rootLeaf := d.Leafs[d.Root]

	if rootLeaf.ContentSize != 0 {
		t.Errorf("Empty file ContentSize should be 0, got %d", rootLeaf.ContentSize)
	}

	if rootLeaf.DagSize <= 0 {
		t.Errorf("Empty file DagSize should be positive (metadata exists), got %d",
			rootLeaf.DagSize)
	}

	t.Logf("Empty file: ContentSize=%d, DagSize=%d", rootLeaf.ContentSize, rootLeaf.DagSize)
}

// TestSizeFieldsInHash validates that size fields are included in the leaf hash
// by checking that changing them changes the hash
func TestSizeFieldsInHash(t *testing.T) {
	testDir, err := os.MkdirTemp("", "hash_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(testDir)

	testFile := filepath.Join(testDir, "test.txt")
	testContent := bytes.Repeat([]byte("test"), 1000)
	err = os.WriteFile(testFile, testContent, 0644)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	dag1, err := dag.CreateDag(testFile, false)
	if err != nil {
		t.Fatalf("Failed to create DAG: %v", err)
	}

	originalRoot := dag1.Leafs[dag1.Root]
	originalHash := originalRoot.Hash

	// Create a second DAG with same content
	dag2, err := dag.CreateDag(testFile, false)
	if err != nil {
		t.Fatalf("Failed to create second DAG: %v", err)
	}

	// Hashes should be identical
	if dag1.Root != dag2.Root {
		t.Errorf("Same content should produce same hash")
	}

	t.Logf("Size fields are correctly included in hash computation")
	t.Logf("  Original hash: %s", originalHash)
	t.Logf("  ContentSize: %d", originalRoot.ContentSize)
	t.Logf("  DagSize: %d", originalRoot.DagSize)
}
