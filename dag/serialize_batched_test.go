package dag

import (
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func TestBatchedTransmissionPacketCBORPreservesCounters(t *testing.T) {
	packet := &BatchedTransmissionPacket{
		Leaves:        []*DagLeaf{{Hash: "root"}},
		Relationships: map[string]string{"root": ""},
		PacketIndex:   3,
		TotalPackets:  9,
	}
	encoded, err := packet.ToCBOR()
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := cbor.Unmarshal(encoded, &wire); err != nil {
		t.Fatal(err)
	}
	if _, ok := wire["PacketIndex"]; !ok {
		t.Fatal("PacketIndex is missing from CBOR")
	}
	if _, ok := wire["TotalPackets"]; !ok {
		t.Fatal("TotalPackets is missing from CBOR")
	}
	decoded, err := BatchedTransmissionPacketFromCBOR(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.PacketIndex != 3 || decoded.TotalPackets != 9 {
		t.Fatalf("counter round trip mismatch: index=%d total=%d", decoded.PacketIndex, decoded.TotalPackets)
	}
}

func TestBatchedTransmissionPacketCBORToleratesLegacyPackets(t *testing.T) {
	legacy := struct {
		Leaves        []*SerializableDagLeaf
		Relationships map[string]string
	}{
		Leaves:        []*SerializableDagLeaf{{Hash: "root"}},
		Relationships: map[string]string{"root": ""},
	}
	encoded, err := cbor.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := BatchedTransmissionPacketFromCBOR(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.PacketIndex != 0 || decoded.TotalPackets != 0 {
		t.Fatalf("legacy counters must default to zero: index=%d total=%d", decoded.PacketIndex, decoded.TotalPackets)
	}
}
