package dag

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// The deployed Go v2.2.6 wire shape.
//
// This file is the guard whose ABSENCE let a wire-format regression ship. A
// sorted EncMode was introduced to make encoding reproducible; fxamacker applies
// Sort to struct fields as well as map keys, so it silently reordered every field
// on the wire. The Go suite passed 118/118 through all of it. The only thing that
// caught it was the Swift port's CrossCompatWireTests, which pins these names
// against golden bytes captured from a real deployed build.
//
// Swift should not be carrying that guard alone for three ports, so the same
// contract is asserted here, at the reference.
var deployedLeafKeyOrder = []string{
	"Hash", "ItemName", "Type", "ContentHash", "Content", "ClassicMerkleRoot",
	"CurrentLinkCount", "LeafCount", "ContentSize", "DagSize", "Links", "AdditionalData",
}

var deployedBatchKeyOrder = []string{"Leaves", "Relationships", "PacketIndex", "TotalPackets"}

var deployedDagKeyOrder = []string{"Root", "Leafs"}

// cborTextKey renders a map key exactly as CBOR encodes it, so searching for it
// in the raw bytes cannot collide with a value or with a longer key sharing the
// same prefix ("Content" vs "ContentHash").
func cborTextKey(s string) []byte {
	if len(s) < 24 {
		return append([]byte{byte(0x60 | len(s))}, s...)
	}
	return append([]byte{0x78, byte(len(s))}, s...)
}

// assertDeclarationOrder requires the first occurrence of each key to appear in
// the given order. Every leaf carries all twelve keys, so the first occurrence of
// each one lands in the first-encoded leaf, and monotonically increasing offsets
// mean that leaf emitted them in declaration order.
func assertDeclarationOrder(t *testing.T, label string, encoded []byte, keys []string) {
	t.Helper()
	prevOffset := -1
	prevKey := "(start)"
	for _, key := range keys {
		at := bytes.Index(encoded, cborTextKey(key))
		if at < 0 {
			t.Fatalf("%s: key %q is not on the wire at all", label, key)
		}
		if at <= prevOffset {
			t.Fatalf("%s: %q at offset %d is not after %q at offset %d -- fields are NOT in declaration order",
				label, key, at, prevKey, prevOffset)
		}
		prevOffset = at
		prevKey = key
	}
}

func buildWireShapeFixture(t *testing.T) *Dag {
	t.Helper()
	repo := filepath.Join(t.TempDir(), "golden-repo")
	if err := os.MkdirAll(filepath.Join(repo, "docs"), 0o755); err != nil {
		t.Fatalf("could not create fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repo, "readme.md"), []byte("hello golden repos"), 0o644); err != nil {
		t.Fatalf("could not write fixture file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repo, "docs", "guide.md"), []byte("swift parity guide"), 0o644); err != nil {
		t.Fatalf("could not write fixture file: %v", err)
	}

	d, err := CreateDag(repo, false)
	if err != nil {
		t.Fatalf("could not build fixture DAG: %v", err)
	}
	return d
}

func TestWireStructFieldsRideInDeclarationOrder(t *testing.T) {
	d := buildWireShapeFixture(t)

	encoded, err := d.ToCBOR()
	if err != nil {
		t.Fatalf("could not encode DAG: %v", err)
	}
	assertDeclarationOrder(t, "dag envelope", encoded, deployedDagKeyOrder)
	assertDeclarationOrder(t, "dag leaf", encoded, deployedLeafKeyOrder)

	batches := d.GetBatchedLeafSequence()
	if len(batches) == 0 {
		t.Fatal("fixture produced no batched packets")
	}
	batchEncoded, err := batches[0].ToCBOR()
	if err != nil {
		t.Fatalf("could not encode batched packet: %v", err)
	}
	assertDeclarationOrder(t, "batched packet", batchEncoded, deployedBatchKeyOrder)
	assertDeclarationOrder(t, "packet leaf", batchEncoded, deployedLeafKeyOrder)
}

// TestWireEncodingIsReproducible re-encodes many times rather than twice. Go
// randomizes map iteration per range statement, so a single agreeing pair of
// encodes is weak evidence.
func TestWireEncodingIsReproducible(t *testing.T) {
	d := buildWireShapeFixture(t)

	first, err := d.ToCBOR()
	if err != nil {
		t.Fatalf("could not encode DAG: %v", err)
	}
	for i := 1; i <= 200; i++ {
		next, err := d.ToCBOR()
		if err != nil {
			t.Fatalf("could not re-encode DAG on iteration %d: %v", i, err)
		}
		if !bytes.Equal(first, next) {
			t.Fatalf("encode #%d differs from encode #0", i)
		}
	}
}

// TestOmitEmptyStillDropsEmptyProofMaps guards the second regression that shipped.
//
// Declaring the map fields as sortedMap made them cbor.Marshaler implementations,
// and fxamacker returns alwaysNotEmpty for those (getEncodeFuncInternal), so
// `omitempty` stopped firing -- in BOTH OmitEmpty modes, since the isEmpty func is
// chosen from the type rather than the mode. Every leaf in a full DAG began
// carrying an empty stored_proofs it had never carried: 11 leaves, 11 stray keys,
// 8182 bytes where the ports had agreed on 8017.
//
// The corpus catches this only indirectly and only after regeneration, so it is
// asserted directly here.
func TestOmitEmptyStillDropsEmptyProofMaps(t *testing.T) {
	d := buildWireShapeFixture(t)

	encoded, err := d.ToCBOR()
	if err != nil {
		t.Fatalf("could not encode DAG: %v", err)
	}
	if bytes.Contains(encoded, cborTextKey("stored_proofs")) {
		t.Error("a full DAG carries stored_proofs, but no leaf in it has proofs")
	}

	// ...and it must not over-fire. The transmission path is where proofs are
	// actually attached, so the key has to survive there.
	for _, packet := range d.GetLeafSequence() {
		encodedPacket, err := packet.ToCBOR()
		if err != nil {
			t.Fatalf("could not encode transmission packet: %v", err)
		}
		if bytes.Contains(encodedPacket, cborTextKey("proofs")) {
			return
		}
	}
	t.Error("no packet carried a proofs key, so omitempty is over-firing (or the fixture is too shallow to prove it)")
}
