package dag

import (
	"io"
	"os"
)

// fastcdc-v1 — content-defined chunking (FastCDC, Xia et al. 2016), the
// DEFAULT chunking mode for all new trees. Normative spec: docs/fastcdc-v1.md.
//
// Fixed-size chunking (SetChunkSize / DisableChunking) remains available as
// the legacy mode; the committed spec-vector corpus and older callers pin it
// explicitly. Verification is chunking-agnostic — no verifier re-chunks — so
// trees cut by either mode verify identically everywhere.
//
// Every constant in this file is NORMATIVE and frozen as fastcdc-v1. Any
// change — a size, a mask, a gear entry, an off-by-one in the boundary loop —
// is a NEW chunking version tag, never a mutation: producers only dedup
// against each other when every SDK cuts bit-identical boundaries, and a
// divergent implementation produces valid-looking trees that never dedup,
// detectable only by the conformance vectors.

const (
	// FastCDCMinSize is the cut-point skipping floor: no boundary test runs
	// inside the first FastCDCMinSize bytes of a chunk, and those bytes are
	// not hashed at all. Interior chunks are therefore at least
	// FastCDCMinSize+1 bytes; only a final tail chunk may be smaller.
	FastCDCMinSize = 512 * 1024

	// FastCDCTargetSize is the normalization switch: the strict mask judges
	// positions before it, the loose mask after it, squeezing the chunk-size
	// distribution toward the target. It matches the legacy fixed default
	// (DefaultChunkSize), so leaf counts and DagStats stay in the same
	// ballpark across the mode change.
	FastCDCTargetSize = 2048 * 1024

	// FastCDCMaxSize is the forced-cut ceiling. It exists to bound worst-case
	// chunk size (record framing, transport batching), not as a size anyone
	// chooses: with normalized chunking a forced cut is rare, degenerate-
	// content territory.
	FastCDCMaxSize = 8192 * 1024
)

const (
	// FastCDCStrictMask selects the top 23 bits of the rolling hash
	// (boundary ⇔ h < 2^41). Used for positions before FastCDCTargetSize.
	FastCDCStrictMask uint64 = 0xFFFFFE0000000000

	// FastCDCLooseMask selects the top 19 bits (boundary ⇔ h < 2^45). Used
	// for positions at or after FastCDCTargetSize. LooseMask ⊂ StrictMask.
	FastCDCLooseMask uint64 = 0xFFFFE00000000000
)

// FastCDCGearSeedPrefix is the frozen derivation seed for the gear table in
// fastcdc_gear.go:
//
//	G[i] = u64be(SHA-256(FastCDCGearSeedPrefix ++ byte(i))[0:8])
//
// where byte(i) is the single raw byte with value i. Regenerate the table
// with `go run ./tools/geargen`; the regeneration test re-derives every entry
// and fails on drift.
const FastCDCGearSeedPrefix = "scionic-fastcdc-v1:gear:"

// Root-tag vocabulary: the chunking tag lives in the root leaf's
// AdditionalData and informs producers and delta tooling only. Verification
// MUST NOT re-chunk; verifiers ignore the tag entirely.
const (
	// ChunkingTagKey is the AdditionalData key carrying the chunking tag.
	ChunkingTagKey = "chunking"
	// ChunkingFastCDCV1 tags roots cut with fastcdc-v1.
	ChunkingFastCDCV1 = "fastcdc-v1"
	// ChunkingFixed2M is the implied value when the tag is absent: every
	// pre-fastcdc v2 tree was cut fixed-size. Producers never stamp it.
	ChunkingFixed2M = "fixed-2m"
)

// chunkingFastCDC selects the active producer chunking mode. Like ChunkSize
// and BatchSize it is a process-global producer setting: configure it before
// CreateDag, not concurrently with one. SetChunkSize switches to the legacy
// fixed mode; SetDefaultChunkSize restores this default.
var chunkingFastCDC = true

// FastCDCEnabled reports whether new DAGs are cut with fastcdc-v1.
func FastCDCEnabled() bool {
	return chunkingFastCDC
}

// ActiveChunkingTag returns the root-tag value for the active mode:
// ChunkingFastCDCV1 under fastcdc-v1, or "" under the legacy fixed modes
// (absent tag ⇒ fixed-2m per the spec).
func ActiveChunkingTag() string {
	if chunkingFastCDC {
		return ChunkingFastCDCV1
	}
	return ""
}

// withChunkingTag returns additionalData plus the active chunking tag,
// copying the map so a caller's map is never mutated. The library owns this
// key: a caller-supplied "chunking" value is overwritten, because a tag that
// does not reflect how the tree was actually cut breaks delta tooling.
func withChunkingTag(additionalData map[string]string) map[string]string {
	tag := ActiveChunkingTag()
	if tag == "" {
		return additionalData
	}
	merged := make(map[string]string, len(additionalData)+1)
	for key, value := range additionalData {
		merged[key] = value
	}
	merged[ChunkingTagKey] = tag
	return merged
}

// fastCDCBoundary returns the length of the next chunk cut from data. The
// caller guarantees data is either at least FastCDCMaxSize bytes long or ends
// at EOF — under that contract the decision is final: a boundary can never
// depend on bytes past the forced maximum.
//
// This loop IS the normative fastcdc-v1 boundary definition (docs/
// fastcdc-v1.md). The rolling hash starts at zero for every chunk, bytes
// [0, FastCDCMinSize) are skipped without hashing, arithmetic is wrapping
// uint64, and a match on byte index i cuts AFTER that byte (length i+1).
func fastCDCBoundary(data []byte) int {
	n := len(data)
	if n <= FastCDCMinSize {
		return n
	}
	limit := n
	if limit > FastCDCMaxSize {
		limit = FastCDCMaxSize
	}
	normal := FastCDCTargetSize
	if normal > limit {
		normal = limit
	}
	var h uint64
	for i := FastCDCMinSize; i < normal; i++ {
		h = (h << 1) + fastCDCGear[data[i]]
		if h&FastCDCStrictMask == 0 {
			return i + 1
		}
	}
	for i := normal; i < limit; i++ {
		h = (h << 1) + fastCDCGear[data[i]]
		if h&FastCDCLooseMask == 0 {
			return i + 1
		}
	}
	return limit
}

// CutChunks splits data into chunks under the ACTIVE chunking mode: fastcdc-v1
// by default, or fixed-size slicing after SetChunkSize/DisableChunking. The
// returned chunks are subslices of data (no copies). Empty input returns nil.
//
// This is the public cutter for producers that hold content in memory (for
// example nosis-cli's git-archive builder): cutting through the library is
// what keeps every upload context producing identical chunks — per-workload
// chunking would silently break cross-context dedup.
func CutChunks(data []byte) [][]byte {
	if len(data) == 0 {
		return nil
	}
	if !chunkingFastCDC {
		if ChunkSize <= 0 || len(data) <= ChunkSize {
			return [][]byte{data}
		}
		chunks := make([][]byte, 0, (len(data)+ChunkSize-1)/ChunkSize)
		for offset := 0; offset < len(data); offset += ChunkSize {
			end := offset + ChunkSize
			if end > len(data) {
				end = len(data)
			}
			chunks = append(chunks, data[offset:end])
		}
		return chunks
	}
	chunks := make([][]byte, 0, len(data)/FastCDCTargetSize+1)
	offset := 0
	for offset < len(data) {
		cut := fastCDCBoundary(data[offset:])
		chunks = append(chunks, data[offset:offset+cut])
		offset += cut
	}
	return chunks
}

// streamChunksFromFile streams a file's chunks under the active chunking
// mode. It is the single dispatch point the DAG builders cut through.
func streamChunksFromFile(fullPath string, callback func(chunk []byte, index int) error) error {
	if chunkingFastCDC {
		return streamFastCDCFile(fullPath, callback)
	}
	return streamFileChunks(fullPath, ChunkSize, callback)
}

func streamFastCDCFile(fullPath string, callback func(chunk []byte, index int) error) error {
	file, err := os.Open(fullPath)
	if err != nil {
		return err
	}
	defer file.Close()
	return streamFastCDCChunks(file, callback)
}

// streamFastCDCChunks reads reader and emits fastcdc-v1 chunks in order. Each
// emitted chunk is an exact-size allocation owned by the callback — leaves
// retain chunk content, so chunks must never alias the reusable window.
// Transient memory is one FastCDCMaxSize window per concurrent call (parallel
// creation: one per active worker file).
//
// Windowing rule (normative): a boundary decision is final if and only if the
// window holds FastCDCMaxSize bytes or the input is exhausted — which is what
// makes streaming equal whole-buffer cutting, byte for byte.
func streamFastCDCChunks(reader io.Reader, callback func(chunk []byte, index int) error) error {
	window := make([]byte, FastCDCMaxSize)
	filled := 0
	index := 0
	eof := false
	for {
		for filled < len(window) && !eof {
			n, err := reader.Read(window[filled:])
			filled += n
			if err == io.EOF {
				eof = true
			} else if err != nil {
				return err
			}
		}
		if filled == 0 {
			return nil
		}
		for filled == len(window) || (eof && filled > 0) {
			cut := fastCDCBoundary(window[:filled])
			chunk := make([]byte, cut)
			copy(chunk, window[:cut])
			if err := callback(chunk, index); err != nil {
				return err
			}
			index++
			copy(window, window[cut:filled])
			filled -= cut
			if !eof {
				break // refill the window before judging the next boundary
			}
		}
		if eof && filled == 0 {
			return nil
		}
	}
}
