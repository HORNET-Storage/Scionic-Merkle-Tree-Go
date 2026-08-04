package dag

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"math/bits"
	"os"
	"path/filepath"
	"testing"
)

// corpusBytes is the deterministic corpus generator shared with the fastcdc
// vector corpus (docs/fastcdc-v1.md): block k of the stream is
// SHA-256(seed ++ u64be(k)); blocks are concatenated and truncated to length.
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

// TestFastCDCGearTableMatchesSeedDerivation re-derives the frozen gear table
// from the documented seed procedure. One wrong constant produces
// valid-looking trees that never dedup, detectable only by tests like this.
func TestFastCDCGearTableMatchesSeedDerivation(t *testing.T) {
	for i := 0; i < 256; i++ {
		message := append([]byte(FastCDCGearSeedPrefix), byte(i))
		digest := sha256.Sum256(message)
		expected := binary.BigEndian.Uint64(digest[:8])
		if fastCDCGear[i] != expected {
			t.Fatalf("fastCDCGear[%d] = %#016x, want %#016x: the checked-in table drifted from the fastcdc-v1 seed derivation", i, fastCDCGear[i], expected)
		}
	}
}

func TestFastCDCConstantsAreFrozen(t *testing.T) {
	if FastCDCMinSize != 512*1024 || FastCDCTargetSize != 2048*1024 || FastCDCMaxSize != 8192*1024 {
		t.Fatalf("fastcdc-v1 sizes changed: min=%d target=%d max=%d", FastCDCMinSize, FastCDCTargetSize, FastCDCMaxSize)
	}
	allOnes := ^uint64(0)
	if FastCDCStrictMask != allOnes<<41 {
		t.Fatalf("strict mask = %#016x, want the top 23 bits (%#016x)", FastCDCStrictMask, allOnes<<41)
	}
	if FastCDCLooseMask != allOnes<<45 {
		t.Fatalf("loose mask = %#016x, want the top 19 bits (%#016x)", FastCDCLooseMask, allOnes<<45)
	}
	if bits.OnesCount64(FastCDCStrictMask) != 23 || bits.OnesCount64(FastCDCLooseMask) != 19 {
		t.Fatalf("mask popcounts = %d/%d, want 23/19", bits.OnesCount64(FastCDCStrictMask), bits.OnesCount64(FastCDCLooseMask))
	}
	if FastCDCStrictMask&FastCDCLooseMask != FastCDCLooseMask {
		t.Fatal("loose mask must be a subset of the strict mask")
	}
}

func TestFastCDCCutBoundsAndDeterminism(t *testing.T) {
	data := corpusBytes("scionic-fastcdc-v1:test:bounds", 40<<20)
	first := CutChunks(data)
	second := CutChunks(data)
	if len(first) == 0 || len(first) != len(second) {
		t.Fatalf("cut counts differ between runs: %d vs %d", len(first), len(second))
	}
	total := 0
	for i, chunk := range first {
		if !bytes.Equal(chunk, second[i]) {
			t.Fatalf("chunk %d differs between two cuts of identical data", i)
		}
		if i < len(first)-1 && len(chunk) <= FastCDCMinSize {
			t.Errorf("interior chunk %d is %d bytes; interior chunks must exceed the %d-byte min", i, len(chunk), FastCDCMinSize)
		}
		if len(chunk) > FastCDCMaxSize {
			t.Errorf("chunk %d is %d bytes, above the %d-byte max", i, len(chunk), FastCDCMaxSize)
		}
		total += len(chunk)
	}
	if total != len(data) {
		t.Fatalf("chunks cover %d of %d bytes", total, len(data))
	}
	mean := total / len(first)
	if mean < 1<<20 || mean > 4<<20 {
		t.Errorf("mean chunk size %d is outside the [1MiB, 4MiB] sanity band around the 2MiB target", mean)
	}
}

// stutterReader returns data in awkward partial reads, including a short
// final read and (n>0, io.EOF) on the last call, to exercise every refill
// path of the streaming cutter.
type stutterReader struct {
	data   []byte
	offset int
	step   int
}

func (r *stutterReader) Read(p []byte) (int, error) {
	if r.offset >= len(r.data) {
		return 0, io.EOF
	}
	n := r.step
	if n > len(p) {
		n = len(p)
	}
	if r.offset+n >= len(r.data) {
		n = len(r.data) - r.offset
		copy(p, r.data[r.offset:])
		r.offset = len(r.data)
		return n, io.EOF
	}
	copy(p, r.data[r.offset:r.offset+n])
	r.offset += n
	return n, nil
}

func TestFastCDCStreamingMatchesSliceCutting(t *testing.T) {
	lengths := []int{0, 100, FastCDCMinSize, FastCDCMinSize + 1, FastCDCTargetSize, FastCDCMaxSize, FastCDCMaxSize + 1, 3 << 20, 20 << 20}
	for _, length := range lengths {
		data := corpusBytes("scionic-fastcdc-v1:test:stream", length)
		expected := CutChunks(data)
		var streamed [][]byte
		err := streamFastCDCChunks(&stutterReader{data: data, step: 64*1024 + 17}, func(chunk []byte, index int) error {
			if index != len(streamed) {
				t.Fatalf("length %d: chunk index %d arrived out of order", length, index)
			}
			streamed = append(streamed, chunk)
			return nil
		})
		if err != nil {
			t.Fatalf("length %d: streaming failed: %v", length, err)
		}
		if len(streamed) != len(expected) {
			t.Fatalf("length %d: streamed %d chunks, slice cutting produced %d", length, len(streamed), len(expected))
		}
		for i := range expected {
			if !bytes.Equal(streamed[i], expected[i]) {
				t.Fatalf("length %d: streamed chunk %d differs from slice-cut chunk", length, i)
			}
		}
	}
}

func TestFastCDCSmallInputsAreSingleChunks(t *testing.T) {
	for _, length := range []int{1, 4096, FastCDCMinSize - 1, FastCDCMinSize} {
		data := corpusBytes("scionic-fastcdc-v1:test:small", length)
		chunks := CutChunks(data)
		if len(chunks) != 1 || !bytes.Equal(chunks[0], data) {
			t.Fatalf("length %d: want exactly one chunk equal to the input, got %d chunks", length, len(chunks))
		}
	}
	if CutChunks(nil) != nil {
		t.Fatal("empty input must produce no chunks")
	}
}

// TestFastCDCConstantBytesStayBounded pins the degenerate-content contract:
// constant bytes make the rolling hash constant after 64 positions, so the
// cutter legally collapses to all-min or all-max runs — but it must stay
// deterministic, bounded, and covering.
func TestFastCDCConstantBytesStayBounded(t *testing.T) {
	for name, fill := range map[string]byte{"zeros": 0x00, "letter_a": 'a'} {
		data := bytes.Repeat([]byte{fill}, 20<<20)
		first := CutChunks(data)
		second := CutChunks(data)
		if len(first) != len(second) {
			t.Fatalf("%s: cut counts differ between runs", name)
		}
		total := 0
		for i, chunk := range first {
			if len(chunk) > FastCDCMaxSize {
				t.Errorf("%s: chunk %d is %d bytes, above max", name, i, len(chunk))
			}
			if i < len(first)-1 && len(chunk) <= FastCDCMinSize {
				t.Errorf("%s: interior chunk %d is %d bytes, at or below min", name, i, len(chunk))
			}
			total += len(chunk)
		}
		if total != len(data) {
			t.Fatalf("%s: chunks cover %d of %d bytes", name, total, len(data))
		}
	}
}

func chunkHashSet(chunks [][]byte) map[[sha256.Size]byte]bool {
	set := make(map[[sha256.Size]byte]bool, len(chunks))
	for _, chunk := range chunks {
		set[sha256.Sum256(chunk)] = true
	}
	return set
}

// TestFastCDCInsertReusesMostChunkContent is the delta property at unit-test
// strength: an insertion must confine damage to the edited chunk plus
// boundary resettling. The vector corpus pins the exact reuse sets; this
// asserts the property itself.
func TestFastCDCInsertReusesMostChunkContent(t *testing.T) {
	base := corpusBytes("scionic-fastcdc-v1:test:delta", 32<<20)
	insert := corpusBytes("scionic-fastcdc-v1:test:delta-insert", 4096)
	edited := make([]byte, 0, len(base)+len(insert))
	edited = append(edited, base[:16<<20]...)
	edited = append(edited, insert...)
	edited = append(edited, base[16<<20:]...)

	baseHashes := chunkHashSet(CutChunks(base))
	editedChunks := CutChunks(edited)
	reused, fresh := 0, 0
	for _, chunk := range editedChunks {
		if baseHashes[sha256.Sum256(chunk)] {
			reused++
		} else {
			fresh++
		}
	}
	if reused == 0 {
		t.Fatal("no chunk content reused after a 4KiB insertion into 32MiB")
	}
	if fresh > 3 {
		t.Errorf("insertion produced %d unseen chunks of %d; content-defined boundaries should confine an edit to ~1-2 chunks plus resettling", fresh, len(editedChunks))
	}
}

func TestChunkingModeSwitches(t *testing.T) {
	if !FastCDCEnabled() {
		t.Fatal("fastcdc-v1 must be the default chunking mode")
	}
	if ActiveChunkingTag() != ChunkingFastCDCV1 {
		t.Fatalf("default tag = %q, want %q", ActiveChunkingTag(), ChunkingFastCDCV1)
	}
	SetChunkSize(4096)
	if FastCDCEnabled() || ActiveChunkingTag() != "" {
		t.Fatal("SetChunkSize must switch to legacy fixed chunking with no tag")
	}
	DisableChunking()
	if FastCDCEnabled() {
		t.Fatal("DisableChunking must stay in legacy mode")
	}
	SetDefaultChunkSize()
	if !FastCDCEnabled() || ChunkSize != DefaultChunkSize {
		t.Fatal("SetDefaultChunkSize must restore the fastcdc-v1 default and reset ChunkSize")
	}
}

func TestCutChunksLegacyFixedMode(t *testing.T) {
	SetChunkSize(4096)
	defer SetDefaultChunkSize()
	data := corpusBytes("scionic-fastcdc-v1:test:fixed", 10000)
	chunks := CutChunks(data)
	if len(chunks) != 3 || len(chunks[0]) != 4096 || len(chunks[1]) != 4096 || len(chunks[2]) != 10000-8192 {
		t.Fatalf("fixed 4096 cutting of 10000 bytes produced %d chunks", len(chunks))
	}
	DisableChunking()
	whole := CutChunks(data)
	if len(whole) != 1 || !bytes.Equal(whole[0], data) {
		t.Fatalf("disabled chunking must return the whole input as one chunk")
	}
}

// TestChunkingRootTag pins the producer tag contract: fastcdc-v1 roots carry
// AdditionalData["chunking"] = "fastcdc-v1", the library owns the key, the
// caller's map is never mutated, and legacy fixed modes stamp nothing
// (absent ⇒ fixed-2m).
func TestChunkingRootTag(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tagged.bin")
	if err := os.WriteFile(path, corpusBytes("scionic-fastcdc-v1:test:tag", 4096), 0o644); err != nil {
		t.Fatal(err)
	}

	built, err := CreateDag(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := built.Leafs[built.Root].AdditionalData[ChunkingTagKey]; got != ChunkingFastCDCV1 {
		t.Fatalf("fastcdc root tag = %q, want %q", got, ChunkingFastCDCV1)
	}
	if err := built.Verify(); err != nil {
		t.Fatalf("tagged DAG does not verify: %v", err)
	}

	callerMetadata := map[string]string{ChunkingTagKey: "fixed-2m", "keep": "me"}
	stamped, err := CreateDagAdvanced(path, callerMetadata)
	if err != nil {
		t.Fatal(err)
	}
	root := stamped.Leafs[stamped.Root]
	if root.AdditionalData[ChunkingTagKey] != ChunkingFastCDCV1 {
		t.Errorf("caller-supplied chunking tag must be overwritten, got %q", root.AdditionalData[ChunkingTagKey])
	}
	if root.AdditionalData["keep"] != "me" {
		t.Error("caller metadata beside the tag was lost")
	}
	if callerMetadata[ChunkingTagKey] != "fixed-2m" {
		t.Error("the caller's own map was mutated")
	}

	SetChunkSize(4096)
	defer SetDefaultChunkSize()
	legacy, err := CreateDag(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, present := legacy.Leafs[legacy.Root].AdditionalData[ChunkingTagKey]; present {
		t.Error("legacy fixed mode must not stamp a chunking tag")
	}
}
