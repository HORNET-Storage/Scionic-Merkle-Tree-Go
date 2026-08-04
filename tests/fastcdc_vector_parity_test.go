package tests

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/HORNET-Storage/Scionic-Merkle-Tree/v2/dag"
)

// The fastcdc-v1 conformance corpus is the cross-language chunking fixture:
// seeded inputs are REGENERATED (never committed), cut with the fastcdc-v1
// boundary function, and compared against the committed manifest of chunk end
// offsets, chunk SHA-256s, edit-case reuse partitions, and single-file DAG
// roots. Go, Swift and Rust run the same assertions against the same
// manifest; a port that disagrees on ONE gear constant or one off-by-one
// fails here and nowhere else, because divergent chunking still produces
// valid-looking trees (docs/fastcdc-v1.md).
//
// A missing corpus is a hard failure, never a skip.

const fastCDCVectorsRoot = "../spec/fastcdc-vectors"

type fastCDCVectorCase struct {
	Name        string   `json:"name"`
	Kind        string   `json:"kind"`
	Seed        string   `json:"seed,omitempty"`
	Length      int      `json:"length"`
	Base        string   `json:"base,omitempty"`
	Op          string   `json:"op,omitempty"`
	Offset      int      `json:"offset,omitempty"`
	EditLength  int      `json:"edit_length,omitempty"`
	PayloadSeed string   `json:"payload_seed,omitempty"`
	Boundaries  []int    `json:"boundaries"`
	ChunkSHA256 []string `json:"chunk_sha256"`
	Reused      []bool   `json:"reused,omitempty"`
	RootHash    string   `json:"root_hash"`
	LeafCount   int      `json:"leaf_count"`
	ChunkLeaves int      `json:"chunk_leaves"`
}

type fastCDCManifest struct {
	Spec  string              `json:"spec"`
	Cases []fastCDCVectorCase `json:"cases"`
}

func loadFastCDCManifest(t *testing.T) fastCDCManifest {
	t.Helper()
	path := filepath.Join(fastCDCVectorsRoot, "manifest.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("fastcdc vector corpus missing at %s: %v\nRegenerate it with: go run ./tools/fastcdcvectors -out spec/fastcdc-vectors", path, err)
	}
	var manifest fastCDCManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("could not decode %s: %v", path, err)
	}
	if manifest.Spec != dag.ChunkingFastCDCV1 {
		t.Fatalf("manifest spec = %q, want %q", manifest.Spec, dag.ChunkingFastCDCV1)
	}
	if len(manifest.Cases) == 0 {
		t.Fatal("fastcdc vector manifest lists no cases; every assertion below would pass vacuously")
	}
	return manifest
}

// fastCDCCorpusBytes is the normative corpus generator from docs/fastcdc-v1.md:
// block k = SHA-256(seed ++ u64be(k)), concatenated and truncated to length.
func fastCDCCorpusBytes(seed string, length int) []byte {
	out := make([]byte, 0, length+sha256.Size)
	var counter [8]byte
	for block := uint64(0); len(out) < length; block++ {
		binary.BigEndian.PutUint64(counter[:], block)
		message := append([]byte(seed), counter[:]...)
		digest := sha256.Sum256(message)
		out = append(out, digest[:]...)
	}
	return out[:length]
}

func materializeFastCDCCase(t *testing.T, byName map[string]fastCDCVectorCase, vectorCase fastCDCVectorCase) []byte {
	t.Helper()
	switch vectorCase.Kind {
	case "corpus":
		return fastCDCCorpusBytes(vectorCase.Seed, vectorCase.Length)
	case "zeros":
		return make([]byte, vectorCase.Length)
	case "edit":
		base, ok := byName[vectorCase.Base]
		if !ok {
			t.Fatalf("%s: unknown base case %q", vectorCase.Name, vectorCase.Base)
		}
		baseBytes := materializeFastCDCCase(t, byName, base)
		switch vectorCase.Op {
		case "insert":
			payload := fastCDCCorpusBytes(vectorCase.PayloadSeed, vectorCase.EditLength)
			edited := make([]byte, 0, len(baseBytes)+len(payload))
			edited = append(edited, baseBytes[:vectorCase.Offset]...)
			edited = append(edited, payload...)
			edited = append(edited, baseBytes[vectorCase.Offset:]...)
			return edited
		case "delete":
			edited := make([]byte, 0, len(baseBytes)-vectorCase.EditLength)
			edited = append(edited, baseBytes[:vectorCase.Offset]...)
			edited = append(edited, baseBytes[vectorCase.Offset+vectorCase.EditLength:]...)
			return edited
		}
		t.Fatalf("%s: unknown edit op %q", vectorCase.Name, vectorCase.Op)
	default:
		t.Fatalf("%s: unknown case kind %q", vectorCase.Name, vectorCase.Kind)
	}
	return nil
}

func fastCDCCasesByName(manifest fastCDCManifest) map[string]fastCDCVectorCase {
	byName := make(map[string]fastCDCVectorCase, len(manifest.Cases))
	for _, vectorCase := range manifest.Cases {
		byName[vectorCase.Name] = vectorCase
	}
	return byName
}

func TestFastCDCVectorChunksMatch(t *testing.T) {
	// Other tests in this package flip to legacy fixed mode and do not always
	// restore; this corpus describes the default cutter.
	dag.SetDefaultChunkSize()
	manifest := loadFastCDCManifest(t)
	byName := fastCDCCasesByName(manifest)
	for _, vectorCase := range manifest.Cases {
		data := materializeFastCDCCase(t, byName, vectorCase)
		if len(data) != vectorCase.Length {
			t.Fatalf("%s: materialized %d bytes, manifest says %d", vectorCase.Name, len(data), vectorCase.Length)
		}
		chunks := dag.CutChunks(data)
		if len(chunks) != len(vectorCase.Boundaries) || len(chunks) != len(vectorCase.ChunkSHA256) {
			t.Fatalf("%s: cut %d chunks, manifest lists %d boundaries / %d hashes", vectorCase.Name, len(chunks), len(vectorCase.Boundaries), len(vectorCase.ChunkSHA256))
		}
		end := 0
		for index, chunk := range chunks {
			end += len(chunk)
			if end != vectorCase.Boundaries[index] {
				t.Fatalf("%s: chunk %d ends at %d, vector says %d — the boundary function diverged", vectorCase.Name, index, end, vectorCase.Boundaries[index])
			}
			digest := sha256.Sum256(chunk)
			if hex.EncodeToString(digest[:]) != vectorCase.ChunkSHA256[index] {
				t.Fatalf("%s: chunk %d content hash differs from the committed vector", vectorCase.Name, index)
			}
		}
	}
}

func TestFastCDCVectorEditReusePartitions(t *testing.T) {
	dag.SetDefaultChunkSize()
	manifest := loadFastCDCManifest(t)
	byName := fastCDCCasesByName(manifest)
	edits := 0
	for _, vectorCase := range manifest.Cases {
		if vectorCase.Kind != "edit" {
			continue
		}
		edits++
		base, ok := byName[vectorCase.Base]
		if !ok {
			t.Fatalf("%s: unknown base case %q", vectorCase.Name, vectorCase.Base)
		}
		baseHashes := make(map[string]bool, len(base.ChunkSHA256))
		for _, encoded := range base.ChunkSHA256 {
			baseHashes[encoded] = true
		}
		if len(vectorCase.Reused) != len(vectorCase.ChunkSHA256) {
			t.Fatalf("%s: reused list length %d does not match %d chunks", vectorCase.Name, len(vectorCase.Reused), len(vectorCase.ChunkSHA256))
		}
		reusedCount := 0
		for index, encoded := range vectorCase.ChunkSHA256 {
			reused := baseHashes[encoded]
			if reused != vectorCase.Reused[index] {
				t.Errorf("%s: chunk %d reused=%v, vector says %v", vectorCase.Name, index, reused, vectorCase.Reused[index])
			}
			if reused {
				reusedCount++
			}
		}
		if reusedCount == 0 {
			t.Errorf("%s: no chunk content reused; the delta property this corpus exists to prove is broken", vectorCase.Name)
		}
	}
	if edits == 0 {
		t.Fatal("no edit cases in the corpus; the delta property is untested")
	}
}

func TestFastCDCVectorDagRootsRebuild(t *testing.T) {
	dag.SetDefaultChunkSize()
	manifest := loadFastCDCManifest(t)
	byName := fastCDCCasesByName(manifest)
	tempDir := t.TempDir()
	for _, vectorCase := range manifest.Cases {
		data := materializeFastCDCCase(t, byName, vectorCase)
		inputPath := filepath.Join(tempDir, vectorCase.Name+".bin")
		if err := os.WriteFile(inputPath, data, 0o644); err != nil {
			t.Fatalf("%s: %v", vectorCase.Name, err)
		}
		built, err := dag.CreateDag(inputPath, false)
		if err != nil {
			t.Fatalf("%s: could not build DAG: %v", vectorCase.Name, err)
		}
		if built.Root != vectorCase.RootHash {
			t.Errorf("%s: root = %s, want %s", vectorCase.Name, built.Root, vectorCase.RootHash)
		}
		if len(built.Leafs) != vectorCase.LeafCount {
			t.Errorf("%s: leaf count = %d, want %d", vectorCase.Name, len(built.Leafs), vectorCase.LeafCount)
		}
		chunkLeaves := 0
		for _, leaf := range built.Leafs {
			if leaf.Type == dag.ChunkLeafType {
				chunkLeaves++
			}
		}
		if chunkLeaves != vectorCase.ChunkLeaves {
			t.Errorf("%s: chunk leaves = %d, want %d", vectorCase.Name, chunkLeaves, vectorCase.ChunkLeaves)
		}
		if err := built.Verify(); err != nil {
			t.Errorf("%s: rebuilt DAG does not verify: %v", vectorCase.Name, err)
		}
	}
}
