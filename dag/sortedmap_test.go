package dag

import (
	"encoding/hex"
	"testing"
)

// expectedWireMapOrdering pins the wire map comparator across all three ports.
//
// Every map key the spec-vector corpus exercises is a CID of uniform length,
// where length-first and plain-lexicographic ordering coincide -- so the corpus
// cannot tell the two apart. AdditionalData is the one wire map with arbitrary,
// mixed-length keys, and it is empty in every corpus case.
//
// This vector is the only thing standing between the three ports and a silent
// divergence on that axis. The identical bytes are asserted in Rust
// (src/encoding.rs) and Swift (WireMapOrderingTests.swift).
//
// Keys sort length-first, then bytewise: mm, zz, aaaaaa -- carrying values 2, 1,
// 3 respectively. Plain lexicographic -- what sort.Strings and
// SortMapForVerification use, and what the two other ports used before
// unification -- would give aaaaaa, mm, zz, a different byte string entirely.
const expectedWireMapOrdering = "a3626d6d6132627a7a6131666161616161616133"

func TestWireMapsSortLengthFirstThenBytewise(t *testing.T) {
	encoded, err := sortedMap[string]{
		"zz":     "1",
		"mm":     "2",
		"aaaaaa": "3",
	}.MarshalCBOR()
	if err != nil {
		t.Fatalf("MarshalCBOR: %v", err)
	}

	if got := hex.EncodeToString(encoded); got != expectedWireMapOrdering {
		t.Fatalf("wire map ordering drifted from the bytes Rust and Swift pin:\n got  %s\n want %s", got, expectedWireMapOrdering)
	}
}

// TestWireMapOrderingSurvivesMapIterationRandomness re-encodes the same map many
// times. Go randomizes map iteration per range statement, so a single agreeing
// encode would prove nothing.
func TestWireMapOrderingSurvivesMapIterationRandomness(t *testing.T) {
	source := sortedMap[string]{"zz": "1", "mm": "2", "aaaaaa": "3"}
	for i := 0; i < 500; i++ {
		encoded, err := source.MarshalCBOR()
		if err != nil {
			t.Fatalf("MarshalCBOR on iteration %d: %v", i, err)
		}
		if got := hex.EncodeToString(encoded); got != expectedWireMapOrdering {
			t.Fatalf("iteration %d produced %s, want %s", i, got, expectedWireMapOrdering)
		}
	}
}

// TestNilWireMapEncodesAsNull guards the nil-vs-empty distinction. fxamacker's
// default NilContainerAsNull emits null for a nil map and an empty map header for
// an empty one; collapsing the two would change the bytes of every absent map.
func TestNilWireMapEncodesAsNull(t *testing.T) {
	var nilMap sortedMap[string]
	encoded, err := nilMap.MarshalCBOR()
	if err != nil {
		t.Fatalf("MarshalCBOR on nil map: %v", err)
	}
	if got := hex.EncodeToString(encoded); got != "f6" {
		t.Fatalf("nil map encoded as %s, want f6 (null)", got)
	}

	empty, err := sortedMap[string]{}.MarshalCBOR()
	if err != nil {
		t.Fatalf("MarshalCBOR on empty map: %v", err)
	}
	if got := hex.EncodeToString(empty); got != "a0" {
		t.Fatalf("empty map encoded as %s, want a0 (empty map)", got)
	}
}
