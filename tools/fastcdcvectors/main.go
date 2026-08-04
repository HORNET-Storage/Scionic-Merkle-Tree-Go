// Command fastcdcvectors generates the fastcdc-v1 conformance corpus:
// the committed vectors every SDK's CI runs to prove it cuts bit-identical
// chunk boundaries (docs/fastcdc-v1.md).
//
// Corpus INPUTS are regenerated from seeded deterministic generators, never
// committed — 16..40 MiB binaries have no business in a repository, and
// forcing every port to implement the tiny generator is itself a conformance
// check. What is committed is the manifest of expectations: chunk end
// offsets, chunk SHA-256s, the reused-vs-new partition for edit cases, and
// the root CID of the single-file DAG built from each input (which also pins
// the root chunking tag, chunk-leaf naming, and stats).
//
//	go run ./tools/fastcdcvectors -out spec/fastcdc-vectors
//
// The manifest is emitted twice from the same structs — manifest.json and
// manifest.cbor — for the same reason the spec-vector corpus does it: each
// port reads the corpus with a decoder it already ships.
//
// Generation fails loudly if the delta property itself regresses (an edit
// case producing more than a handful of unseen chunks), so the corpus cannot
// quietly stop testing the thing it exists to prove.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/HORNET-Storage/Scionic-Merkle-Tree/v2/dag"
	"github.com/fxamacker/cbor/v2"
)

type vectorCase struct {
	Name        string   `json:"name" cbor:"name"`
	Kind        string   `json:"kind" cbor:"kind"` // corpus | zeros | edit
	Seed        string   `json:"seed,omitempty" cbor:"seed,omitempty"`
	Length      int      `json:"length" cbor:"length"`
	Base        string   `json:"base,omitempty" cbor:"base,omitempty"`
	Op          string   `json:"op,omitempty" cbor:"op,omitempty"` // insert | delete
	Offset      int      `json:"offset,omitempty" cbor:"offset,omitempty"`
	EditLength  int      `json:"edit_length,omitempty" cbor:"edit_length,omitempty"`
	PayloadSeed string   `json:"payload_seed,omitempty" cbor:"payload_seed,omitempty"`
	Boundaries  []int    `json:"boundaries" cbor:"boundaries"` // chunk END offsets
	ChunkSHA256 []string `json:"chunk_sha256" cbor:"chunk_sha256"`
	Reused      []bool   `json:"reused,omitempty" cbor:"reused,omitempty"` // vs Base, edit cases
	RootHash    string   `json:"root_hash" cbor:"root_hash"`
	LeafCount   int      `json:"leaf_count" cbor:"leaf_count"`
	ChunkLeaves int      `json:"chunk_leaves" cbor:"chunk_leaves"`
}

type manifest struct {
	Spec  string       `json:"spec" cbor:"spec"`
	Cases []vectorCase `json:"cases" cbor:"cases"`
}

type caseSpec struct {
	name        string
	kind        string
	seed        string
	length      int
	base        string
	op          string
	offset      int
	editLength  int
	payloadSeed string
}

// The case list is NORMATIVE once committed: ports iterate the manifest, so
// adding a case extends coverage everywhere at once.
var caseSpecs = []caseSpec{
	{name: "below_min_256kib", kind: "corpus", seed: "scionic-fastcdc-v1:corpus:below_min_256kib", length: 256 << 10},
	{name: "exactly_min_512kib", kind: "corpus", seed: "scionic-fastcdc-v1:corpus:exactly_min_512kib", length: 512 << 10},
	{name: "min_plus_one", kind: "corpus", seed: "scionic-fastcdc-v1:corpus:min_plus_one", length: 512<<10 + 1},
	{name: "random_3mib", kind: "corpus", seed: "scionic-fastcdc-v1:corpus:random_3mib", length: 3 << 20},
	{name: "random_16mib", kind: "corpus", seed: "scionic-fastcdc-v1:corpus:random_16mib", length: 16 << 20},
	{name: "random_40mib", kind: "corpus", seed: "scionic-fastcdc-v1:corpus:random_40mib", length: 40 << 20},
	{name: "zeros_20mib", kind: "zeros", length: 20 << 20},
	{name: "edit_insert_4kib_mid", kind: "edit", base: "random_16mib", op: "insert", offset: 8 << 20, editLength: 4096, payloadSeed: "scionic-fastcdc-v1:corpus:edit_insert_4kib_mid"},
	{name: "edit_delete_64kib_mid", kind: "edit", base: "random_16mib", op: "delete", offset: 6 << 20, editLength: 64 << 10},
	{name: "edit_prepend_4kib", kind: "edit", base: "random_16mib", op: "insert", offset: 0, editLength: 4096, payloadSeed: "scionic-fastcdc-v1:corpus:edit_prepend_4kib"},
	{name: "edit_append_4kib", kind: "edit", base: "random_16mib", op: "insert", offset: 16 << 20, editLength: 4096, payloadSeed: "scionic-fastcdc-v1:corpus:edit_append_4kib"},
}

// corpusBytes is the normative corpus generator (docs/fastcdc-v1.md):
// block k = SHA-256(seed ++ u64be(k)), concatenated and truncated.
func corpusBytes(seed string, length int) []byte {
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

func materialize(spec caseSpec, byName map[string]caseSpec) ([]byte, error) {
	switch spec.kind {
	case "corpus":
		return corpusBytes(spec.seed, spec.length), nil
	case "zeros":
		return make([]byte, spec.length), nil
	case "edit":
		base, ok := byName[spec.base]
		if !ok {
			return nil, fmt.Errorf("edit case %s references unknown base %q", spec.name, spec.base)
		}
		baseBytes, err := materialize(base, byName)
		if err != nil {
			return nil, err
		}
		switch spec.op {
		case "insert":
			payload := corpusBytes(spec.payloadSeed, spec.editLength)
			edited := make([]byte, 0, len(baseBytes)+len(payload))
			edited = append(edited, baseBytes[:spec.offset]...)
			edited = append(edited, payload...)
			edited = append(edited, baseBytes[spec.offset:]...)
			return edited, nil
		case "delete":
			edited := make([]byte, 0, len(baseBytes)-spec.editLength)
			edited = append(edited, baseBytes[:spec.offset]...)
			edited = append(edited, baseBytes[spec.offset+spec.editLength:]...)
			return edited, nil
		}
		return nil, fmt.Errorf("edit case %s has unknown op %q", spec.name, spec.op)
	}
	return nil, fmt.Errorf("case %s has unknown kind %q", spec.name, spec.kind)
}

func main() {
	out := flag.String("out", "spec/fastcdc-vectors", "directory to write the corpus into")
	flag.Parse()
	if err := run(*out); err != nil {
		fmt.Fprintf(os.Stderr, "fastcdcvectors: %v\n", err)
		os.Exit(1)
	}
}

func run(out string) error {
	absOut, err := filepath.Abs(out)
	if err != nil {
		return err
	}
	if err := os.RemoveAll(absOut); err != nil {
		return err
	}
	if err := os.MkdirAll(absOut, 0o755); err != nil {
		return err
	}

	// The corpus describes the DEFAULT mode; make that explicit and
	// independent of whatever a prior caller left behind.
	dag.SetDefaultChunkSize()
	if !dag.FastCDCEnabled() {
		return fmt.Errorf("fastcdc-v1 is not the default chunking mode; the corpus would describe the wrong cutter")
	}

	byName := make(map[string]caseSpec, len(caseSpecs))
	for _, spec := range caseSpecs {
		byName[spec.name] = spec
	}

	tempDir, err := os.MkdirTemp("", "fastcdcvectors")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tempDir)

	hashesByCase := make(map[string]map[string]bool, len(caseSpecs))
	result := manifest{Spec: dag.ChunkingFastCDCV1}
	for _, spec := range caseSpecs {
		entry, chunkHashes, err := generateCase(spec, byName, hashesByCase, tempDir)
		if err != nil {
			return fmt.Errorf("case %s: %w", spec.name, err)
		}
		hashesByCase[spec.name] = chunkHashes
		result.Cases = append(result.Cases, entry)
	}

	jsonBytes, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	jsonBytes = append(jsonBytes, '\n')
	secondJSON, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	if !bytes.Equal(jsonBytes[:len(jsonBytes)-1], secondJSON) {
		return fmt.Errorf("manifest JSON encoding is not deterministic")
	}
	if err := os.WriteFile(filepath.Join(absOut, "manifest.json"), jsonBytes, 0o644); err != nil {
		return err
	}
	cborBytes, err := cbor.Marshal(result)
	if err != nil {
		return err
	}
	secondCBOR, err := cbor.Marshal(result)
	if err != nil {
		return err
	}
	if !bytes.Equal(cborBytes, secondCBOR) {
		return fmt.Errorf("manifest CBOR encoding is not deterministic")
	}
	if err := os.WriteFile(filepath.Join(absOut, "manifest.cbor"), cborBytes, 0o644); err != nil {
		return err
	}

	fmt.Printf("wrote %d cases to %s\n", len(result.Cases), absOut)
	return nil
}

func generateCase(spec caseSpec, byName map[string]caseSpec, hashesByCase map[string]map[string]bool, tempDir string) (vectorCase, map[string]bool, error) {
	data, err := materialize(spec, byName)
	if err != nil {
		return vectorCase{}, nil, err
	}

	chunks := dag.CutChunks(data)
	if len(data) > 0 && len(chunks) == 0 {
		return vectorCase{}, nil, fmt.Errorf("non-empty input produced no chunks")
	}

	entry := vectorCase{
		Name:        spec.name,
		Kind:        spec.kind,
		Seed:        spec.seed,
		Length:      len(data),
		Base:        spec.base,
		Op:          spec.op,
		Offset:      spec.offset,
		EditLength:  spec.editLength,
		PayloadSeed: spec.payloadSeed,
		Boundaries:  make([]int, 0, len(chunks)),
		ChunkSHA256: make([]string, 0, len(chunks)),
	}

	chunkHashes := make(map[string]bool, len(chunks))
	end := 0
	for index, chunk := range chunks {
		if len(chunk) > dag.FastCDCMaxSize {
			return vectorCase{}, nil, fmt.Errorf("chunk %d is %d bytes, above the fastcdc max", index, len(chunk))
		}
		if index < len(chunks)-1 && len(chunk) <= dag.FastCDCMinSize {
			return vectorCase{}, nil, fmt.Errorf("interior chunk %d is %d bytes, at or below the fastcdc min", index, len(chunk))
		}
		end += len(chunk)
		entry.Boundaries = append(entry.Boundaries, end)
		digest := sha256.Sum256(chunk)
		encoded := hex.EncodeToString(digest[:])
		entry.ChunkSHA256 = append(entry.ChunkSHA256, encoded)
		chunkHashes[encoded] = true
	}
	if end != len(data) {
		return vectorCase{}, nil, fmt.Errorf("chunks cover %d of %d bytes", end, len(data))
	}

	if spec.kind == "edit" {
		baseHashes, ok := hashesByCase[spec.base]
		if !ok {
			return vectorCase{}, nil, fmt.Errorf("edit case generated before its base %q", spec.base)
		}
		fresh := 0
		for _, encoded := range entry.ChunkSHA256 {
			reused := baseHashes[encoded]
			entry.Reused = append(entry.Reused, reused)
			if !reused {
				fresh++
			}
		}
		if fresh == len(entry.ChunkSHA256) {
			return vectorCase{}, nil, fmt.Errorf("edit case reused no chunk content; the delta property is broken")
		}
		if fresh > 4 {
			return vectorCase{}, nil, fmt.Errorf("edit case produced %d unseen chunks of %d; content-defined chunking should confine an edit to ~1-2 chunks plus resettling", fresh, len(entry.ChunkSHA256))
		}
	}

	// Build the single-file DAG so the corpus also pins the root tag, chunk
	// naming, and stats — and cross-check that the streaming builder cut the
	// same chunks as the slice cutter above.
	inputPath := filepath.Join(tempDir, spec.name+".bin")
	if err := os.WriteFile(inputPath, data, 0o644); err != nil {
		return vectorCase{}, nil, err
	}
	built, err := dag.CreateDag(inputPath, false)
	if err != nil {
		return vectorCase{}, nil, err
	}
	if err := built.Verify(); err != nil {
		return vectorCase{}, nil, fmt.Errorf("generated DAG does not verify: %w", err)
	}
	rootLeaf := built.Leafs[built.Root]
	if rootLeaf.AdditionalData[dag.ChunkingTagKey] != dag.ChunkingFastCDCV1 {
		return vectorCase{}, nil, fmt.Errorf("root is missing the fastcdc-v1 chunking tag")
	}
	entry.RootHash = built.Root
	entry.LeafCount = len(built.Leafs)
	builderChunkHashes := make(map[string]int)
	for _, leaf := range built.Leafs {
		if leaf.Type == dag.ChunkLeafType {
			entry.ChunkLeaves++
			builderChunkHashes[hex.EncodeToString(leaf.ContentHash)]++
		}
	}
	if len(chunks) > 1 {
		if entry.ChunkLeaves != len(chunks) {
			return vectorCase{}, nil, fmt.Errorf("builder produced %d chunk leaves for %d chunks", entry.ChunkLeaves, len(chunks))
		}
		for _, encoded := range entry.ChunkSHA256 {
			if builderChunkHashes[encoded] == 0 {
				return vectorCase{}, nil, fmt.Errorf("builder chunk leaves do not contain slice-cut chunk %s; streaming and slice cutting disagree", encoded)
			}
			builderChunkHashes[encoded]--
		}
	} else if entry.ChunkLeaves != 0 {
		return vectorCase{}, nil, fmt.Errorf("single-chunk file must store data on the file leaf, found %d chunk leaves", entry.ChunkLeaves)
	}

	return entry, chunkHashes, nil
}
