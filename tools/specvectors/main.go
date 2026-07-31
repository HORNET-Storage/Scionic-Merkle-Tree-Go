// Command specvectors generates the cross-language spec-vector corpus.
//
// The corpus is the shared parity fixture for every port: Go-produced DAGs,
// partials, transmission packets, batched packets and deliberately broken DAGs,
// plus the input trees they were built from, described by one manifest.
//
// It is written into a repository and COMMITTED there. That is the whole design:
// the Swift port originally resolved this corpus from a sibling Go checkout that
// might not exist, so its seven spec tests skipped silently on every machine that
// did not have one -- for four releases nobody noticed, because a skip is not a
// failure. A committed corpus cannot rot that way. Run this tool once per repo:
//
//	go run ./tools/specvectors -out spec/vectors
//	go run ./tools/specvectors -out ../Scionic-MerkleTree-Swift/spec/vectors
//	go run ./tools/specvectors -out ../Scionic-MerkleTree-Rust/spec/vectors
//
// # Why every artifact is a raw file
//
// An earlier draft inlined packets as base64 inside JSON. That quietly demanded a
// base64 decoder and a JSON parser from every port -- and the Rust port has
// neither, because it deliberately ships with one dependency (sha2) and hand-
// rolls its CBOR. Making a parity fixture require a port to grow a parser, or to
// hand-write one inside its own test file, means the fixture is partly testing
// the test harness. So: every DAG and every packet is a raw .cbor file, and the
// manifest is emitted twice from the same struct -- manifest.json for Go and
// Swift, manifest.cbor for Rust. Each port reads the corpus with a decoder it
// already ships and already tests.
//
// Determinism matters more than variety. The chunk size is pinned, root
// timestamps are off, and every list is sorted, so re-running the tool against an
// unchanged library reproduces byte-identical output and a diff means a real
// behaviour change.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/HORNET-Storage/Scionic-Merkle-Tree/v2/dag"
	"github.com/HORNET-Storage/Scionic-Merkle-Tree/v2/testutil"
	"github.com/fxamacker/cbor/v2"
)

// chunkSize is pinned rather than defaulted. Chunk boundaries are hash-visible,
// so a corpus generated at a different size describes a different set of CIDs and
// every port has to agree on which one this is.
const chunkSize = 4096

// batchSize is pinned well below the 4 MB default so the batched fixtures
// actually contain more than one batch. A single-batch corpus would exercise the
// batching path without ever exercising the part that splits.
const batchSize = 8 * 1024

type negativeVector struct {
	Path        string `json:"path" cbor:"path"`
	Kind        string `json:"kind" cbor:"kind"`
	Description string `json:"description" cbor:"description"`
}

type vectorCase struct {
	Name                string           `json:"name" cbor:"name"`
	RootKind            string           `json:"root_kind" cbor:"root_kind"`
	RootInputPath       string           `json:"root_input_path" cbor:"root_input_path"`
	RootHash            string           `json:"root_hash" cbor:"root_hash"`
	LeafCount           int              `json:"leaf_count" cbor:"leaf_count"`
	FileLeaves          int              `json:"file_leaves" cbor:"file_leaves"`
	DirectoryLeaves     int              `json:"directory_leaves" cbor:"directory_leaves"`
	ChunkLeaves         int              `json:"chunk_leaves" cbor:"chunk_leaves"`
	FullDag             string           `json:"full_dag" cbor:"full_dag"`
	PartialDags         []string         `json:"partial_dags" cbor:"partial_dags"`
	TransmissionPackets []string         `json:"transmission_packets" cbor:"transmission_packets"`
	BatchedPackets      []string         `json:"batched_packets" cbor:"batched_packets"`
	NegativeVectors     []negativeVector `json:"negative_vectors" cbor:"negative_vectors"`
}

type manifest struct {
	ChunkSize int          `json:"chunk_size" cbor:"chunk_size"`
	BatchSize int          `json:"batch_size" cbor:"batch_size"`
	Cases     []vectorCase `json:"cases" cbor:"cases"`
}

func main() {
	out := flag.String("out", "spec/vectors", "directory to write the corpus into")
	flag.Parse()

	if err := run(*out); err != nil {
		fmt.Fprintf(os.Stderr, "specvectors: %v\n", err)
		os.Exit(1)
	}
}

func run(out string) error {
	absOut, err := filepath.Abs(out)
	if err != nil {
		return err
	}

	// Wipe first. Regenerating into a stale tree leaves orphaned vectors that no
	// manifest entry references, and those are exactly the files nobody notices
	// have stopped being checked.
	if err := os.RemoveAll(absOut); err != nil {
		return fmt.Errorf("failed to clear %s: %w", absOut, err)
	}
	if err := os.MkdirAll(absOut, 0o755); err != nil {
		return err
	}

	dag.SetChunkSize(chunkSize)
	defer dag.SetDefaultChunkSize()
	dag.SetBatchSize(batchSize)
	defer dag.SetDefaultBatchSize()

	fixtures := testutil.GetAllFixtures()
	sort.Slice(fixtures, func(i, j int) bool { return fixtures[i].Name < fixtures[j].Name })

	result := manifest{ChunkSize: chunkSize, BatchSize: batchSize}
	for _, fixture := range fixtures {
		entry, err := generateCase(absOut, fixture)
		if err != nil {
			return fmt.Errorf("case %s: %w", fixture.Name, err)
		}
		result.Cases = append(result.Cases, entry)
	}

	if err := writeJSON(filepath.Join(absOut, "manifest.json"), result); err != nil {
		return err
	}
	encoded, err := cbor.Marshal(result)
	if err != nil {
		return fmt.Errorf("manifest CBOR: %w", err)
	}
	if err := os.WriteFile(filepath.Join(absOut, "manifest.cbor"), encoded, 0o644); err != nil {
		return err
	}

	fmt.Printf("wrote %d cases to %s (chunk size %d, batch size %d)\n",
		len(result.Cases), absOut, chunkSize, batchSize)
	return nil
}

func generateCase(out string, fixture testutil.TestFixture) (vectorCase, error) {
	caseDir := filepath.Join(out, "cases", fixture.Name)
	if err := os.MkdirAll(caseDir, 0o755); err != nil {
		return vectorCase{}, err
	}

	// The input tree is part of the corpus, not a temp directory: a port has to be
	// able to rebuild the DAG from the same bytes and land on the same root. That
	// is the one assertion here that tests DAG construction rather than decoding.
	inputPath, err := testutil.CreateFixture(caseDir, fixture)
	if err != nil {
		return vectorCase{}, err
	}

	d, err := dag.CreateDag(inputPath, false)
	if err != nil {
		return vectorCase{}, err
	}
	if err := d.Verify(); err != nil {
		return vectorCase{}, fmt.Errorf("generated DAG does not verify: %w", err)
	}

	relCase := filepath.ToSlash(filepath.Join("cases", fixture.Name))
	entry := vectorCase{
		Name:                fixture.Name,
		RootKind:            string(d.Leafs[d.Root].Type),
		RootInputPath:       fixture.Name,
		RootHash:            d.Root,
		LeafCount:           len(d.Leafs),
		FullDag:             relCase + "/full/dag.cbor",
		PartialDags:         []string{},
		TransmissionPackets: []string{},
		BatchedPackets:      []string{},
		NegativeVectors:     []negativeVector{},
	}
	for _, leaf := range d.Leafs {
		switch leaf.Type {
		case dag.FileLeafType:
			entry.FileLeaves++
		case dag.DirectoryLeafType:
			entry.DirectoryLeaves++
		case dag.ChunkLeafType:
			entry.ChunkLeaves++
		}
	}

	if err := writeDagCBOR(filepath.Join(out, entry.FullDag), d); err != nil {
		return vectorCase{}, err
	}

	if entry.PartialDags, err = writePartials(out, relCase, d); err != nil {
		return vectorCase{}, err
	}
	if entry.TransmissionPackets, err = writeTransmission(out, relCase, d); err != nil {
		return vectorCase{}, err
	}
	if entry.BatchedPackets, err = writeBatched(out, relCase, d); err != nil {
		return vectorCase{}, err
	}
	if entry.NegativeVectors, err = writeNegatives(out, relCase, d); err != nil {
		return vectorCase{}, err
	}

	return entry, nil
}

// sortedFileLeaves returns file-leaf hashes in sorted order, so partial
// selection does not depend on Go's randomized map iteration.
func sortedFileLeaves(d *dag.Dag) []string {
	var hashes []string
	for hash, leaf := range d.Leafs {
		if leaf.Type == dag.FileLeafType {
			hashes = append(hashes, hash)
		}
	}
	sort.Strings(hashes)
	return hashes
}

func writePartials(out, relCase string, d *dag.Dag) ([]string, error) {
	fileHashes := sortedFileLeaves(d)
	if len(fileHashes) == 0 {
		return []string{}, nil
	}

	// One partial holding the first file, and -- when the fixture has enough
	// files -- one holding a spread of them, which is the case that forces two
	// separate proof branches to reconcile against one root.
	selections := [][]string{{fileHashes[0]}}
	if len(fileHashes) >= 3 {
		selections = append(selections, []string{fileHashes[0], fileHashes[len(fileHashes)-1]})
	}

	paths := make([]string, 0, len(selections))
	for index, selection := range selections {
		partial, err := d.GetPartial(selection, true)
		if err != nil {
			return nil, fmt.Errorf("partial %d: %w", index, err)
		}
		if err := partial.Verify(); err != nil {
			return nil, fmt.Errorf("partial %d does not verify: %w", index, err)
		}
		relPath := fmt.Sprintf("%s/partial/%d/dag.cbor", relCase, index)
		if err := writeDagCBOR(filepath.Join(out, relPath), partial); err != nil {
			return nil, err
		}
		paths = append(paths, relPath)
	}
	return paths, nil
}

func writeTransmission(out, relCase string, d *dag.Dag) ([]string, error) {
	sequence := d.GetLeafSequence()
	if len(sequence) == 0 {
		return nil, fmt.Errorf("empty transmission sequence")
	}
	paths := make([]string, 0, len(sequence))
	for index, packet := range sequence {
		encoded, err := packet.ToCBOR()
		if err != nil {
			return nil, fmt.Errorf("packet %d: %w", index, err)
		}
		relPath := fmt.Sprintf("%s/transmission/packet-%03d.cbor", relCase, index)
		if err := writeFile(filepath.Join(out, relPath), encoded); err != nil {
			return nil, err
		}
		paths = append(paths, relPath)
	}
	return paths, nil
}

func writeBatched(out, relCase string, d *dag.Dag) ([]string, error) {
	sequence := d.GetBatchedLeafSequence()
	if len(sequence) == 0 {
		return nil, fmt.Errorf("empty batched sequence")
	}
	paths := make([]string, 0, len(sequence))
	for index, batch := range sequence {
		encoded, err := batch.ToCBOR()
		if err != nil {
			return nil, fmt.Errorf("batch %d: %w", index, err)
		}
		relPath := fmt.Sprintf("%s/batched/batch-%03d.cbor", relCase, index)
		if err := writeFile(filepath.Join(out, relPath), encoded); err != nil {
			return nil, err
		}
		paths = append(paths, relPath)
	}
	return paths, nil
}

// writeNegatives emits DAGs that MUST be rejected.
//
// A parity suite that only proves the ports accept the same valid input is half a
// suite: a port that accepted everything would pass it. These pin the other half.
//
// The manifest deliberately does NOT record an expected error string. Each port
// has its own typed error enum with its own wording, and demanding a shared
// substring would be asserting that three independent error vocabularies agree --
// which is not a real requirement, and would be "fixed" by rewording an error
// rather than by fixing anything. What every port must agree on is the outcome:
// a positive vector decodes AND verifies, a negative vector fails at one of those
// two steps. That is checkable without a shared vocabulary and cannot be
// satisfied by accident.
func writeNegatives(out, relCase string, d *dag.Dag) ([]negativeVector, error) {
	var vectors []negativeVector

	mutations := []struct {
		kind        string
		description string
		apply       func(*dag.Dag) (*dag.Dag, bool)
	}{
		// Content, name, and edge are three different fields of the same hash
		// preimage. A port that dropped any one of them from its CID computation
		// would still reject the other two, so all three are kept.
		{
			kind:        "tampered_content",
			description: "one leaf's content byte flipped; its CID no longer matches the content",
			apply:       tamperedContentDag,
		},
		{
			kind:        "tampered_item_name",
			description: "one leaf's ItemName altered while its content and stored CID are left alone",
			apply:       tamperedItemNameDag,
		},
		{
			kind:        "tampered_link",
			description: "one link retargeted at the root CID; every leaf is still present and individually well formed, only the relationship is wrong",
			apply:       tamperedLinkDag,
		},
	}

	for _, mutation := range mutations {
		broken, ok := mutation.apply(d)
		if !ok {
			continue
		}
		// A "negative" vector that actually verifies is worse than no vector: it
		// would make every port's rejection test fail for the wrong reason, or
		// pass by accident if the assertion were ever loosened.
		if err := broken.Verify(); err == nil {
			return nil, fmt.Errorf("negative vector %s still verifies", mutation.kind)
		}
		relPath := fmt.Sprintf("%s/negative/%s/dag.cbor", relCase, mutation.kind)
		if err := writeDagCBOR(filepath.Join(out, relPath), broken); err != nil {
			return nil, err
		}
		vectors = append(vectors, negativeVector{
			Path:        relPath,
			Kind:        mutation.kind,
			Description: mutation.description,
		})
	}

	if len(vectors) == 0 {
		return nil, fmt.Errorf("produced no negative vectors; the positive vectors alone cannot show a port rejects anything")
	}
	return vectors, nil
}

// There is deliberately no "missing child" negative vector.
//
// The first draft of this tool had one, and the self-check above rejected it: a
// full DAG with a child removed still verifies, in Go and in every port. That is
// correct behaviour, not a hole. Pruning is what a partial DAG IS -- you hold a
// subset of leaves plus the proofs binding them to the root -- so absence cannot
// be evidence of corruption without making every partial unverifiable. Verify()
// answers "is everything here authentic and bound to this root", never "is this
// complete". Completeness is a separate question, answered by comparing the leaf
// count against the root's declared total.
//
// The note stays because the assumption is an easy one to re-make.

func tamperedContentDag(d *dag.Dag) (*dag.Dag, bool) {
	var target string
	for hash, leaf := range d.Leafs {
		if hash == d.Root || len(leaf.Content) == 0 {
			continue
		}
		if target == "" || hash < target {
			target = hash
		}
	}
	if target == "" {
		return nil, false
	}

	clone := cloneDag(d)
	leaf := clone.Leafs[target]
	content := append([]byte(nil), leaf.Content...)
	content[0] ^= 0xff
	leaf.Content = content
	return clone, true
}

func tamperedItemNameDag(d *dag.Dag) (*dag.Dag, bool) {
	var target string
	for hash := range d.Leafs {
		if hash == d.Root {
			continue
		}
		if target == "" || hash < target {
			target = hash
		}
	}
	if target == "" {
		return nil, false
	}

	clone := cloneDag(d)
	clone.Leafs[target].ItemName += "-tampered"
	return clone, true
}

func tamperedLinkDag(d *dag.Dag) (*dag.Dag, bool) {
	var target string
	for hash, leaf := range d.Leafs {
		if len(leaf.Links) == 0 {
			continue
		}
		if target == "" || hash < target {
			target = hash
		}
	}
	if target == "" {
		return nil, false
	}

	// Links is an ordered slice, so index 0 is deterministic without sorting.
	// Retargeting at the root keeps the CID well formed and present in the DAG:
	// the only thing wrong with this vector is which leaf points at which.
	clone := cloneDag(d)
	clone.Leafs[target].Links[0] = clone.Root
	return clone, true
}

func cloneDag(d *dag.Dag) *dag.Dag {
	leaves := make(map[string]*dag.DagLeaf, len(d.Leafs))
	for hash, leaf := range d.Leafs {
		leaves[hash] = leaf.Clone()
	}
	labels := make(map[string]string, len(d.Labels))
	for key, value := range d.Labels {
		labels[key] = value
	}
	return &dag.Dag{Root: d.Root, Leafs: leaves, Labels: labels}
}

func writeDagCBOR(path string, d *dag.Dag) error {
	encoded, err := d.ToCBOR()
	if err != nil {
		return err
	}
	return writeFile(path, encoded)
}

func writeFile(path string, content []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, content, 0o644)
}

func writeJSON(path string, value any) error {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return writeFile(path, append(encoded, '\n'))
}
