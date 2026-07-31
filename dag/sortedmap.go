package dag

import (
	"bytes"
	"encoding/binary"
	"sort"

	cbor "github.com/fxamacker/cbor/v2"
)

// sortedMap is a map[string]T whose CBOR encoding always emits its keys in a
// fixed order, WITHOUT imposing any ordering on struct fields.
//
// Why this exists instead of a sorted cbor.EncMode:
//
// fxamacker's Sort option applies to struct fields as well as map keys. Turning
// it on to fix map nondeterminism also reorders every struct field on the wire.
// That silently changes the serialized shape deployed peers produce -- Go
// v2.2.6, the version pinned by HORNETS-Nostr-Relay and hdk-nostr-go -- and the
// Swift port's CrossCompatWireTests pins that shape against golden bytes
// captured from a real deployed build. It caught exactly that regression:
//
//	expected [Leaves Relationships PacketIndex TotalPackets]  (declaration order)
//	got      [Leaves PacketIndex TotalPackets Relationships]  (sorted)
//
// Struct fields were never the problem. fxamacker emits them in declaration
// order deterministically; only Go's randomized map iteration is unstable. So
// the ordering is scoped to maps alone: every map field on the wire is declared
// as a sortedMap, and the envelope is still marshaled with the default mode,
// which leaves struct fields where they have always been.
//
// Ordering is length-first, then bytewise. That is the RFC 8949 core-
// deterministic rule for text keys, because a text string's encoded head grows
// monotonically with its length (0x60+len below 24, 0x78 through 255, 0x79
// through 65535), so comparing encoded bytes compares length first. Sorting the
// decoded strings instead -- plain sort.Strings -- would NOT be RFC 8949 for
// mixed-length keys, which is why AdditionalData cannot simply reuse
// SortMapForVerification's comparator here. (That one is fine where it lives:
// it emits a CBOR *array* of KeyValue structs, so map-key rules never apply to
// it, and its order is frozen into every CID ever minted.)
//
// Deployed peers emitted these maps in randomized order, so there is no
// historical ordering to preserve -- any deterministic choice is compatible,
// and RFC 8949 is the one the Rust and Swift ports also implement.
type sortedMap[T any] map[string]T

// MarshalCBOR encodes the map with sorted keys. Values are marshaled with the
// default mode, so nested structs keep declaration order and nested sortedMaps
// recurse through this same method.
func (m sortedMap[T]) MarshalCBOR() ([]byte, error) {
	// A nil map is null on the wire, not an empty map. fxamacker's default
	// NilContainerAsNull already does this, and changing it would alter bytes
	// for every absent map.
	if m == nil {
		return cbor.Marshal(nil)
	}

	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if len(keys[i]) != len(keys[j]) {
			return len(keys[i]) < len(keys[j])
		}
		return keys[i] < keys[j]
	})

	var buf bytes.Buffer
	writeCBORMapHeader(&buf, len(keys))
	for _, key := range keys {
		encodedKey, err := cbor.Marshal(key)
		if err != nil {
			return nil, err
		}
		buf.Write(encodedKey)

		encodedValue, err := cbor.Marshal(m[key])
		if err != nil {
			return nil, err
		}
		buf.Write(encodedValue)
	}
	return buf.Bytes(), nil
}

// writeCBORMapHeader writes a CBOR major type 5 (map) head for n pairs in the
// shortest form, which is the minimal-length encoding fxamacker itself emits.
func writeCBORMapHeader(buf *bytes.Buffer, n int) {
	const majorTypeMap = 0xa0

	switch {
	case n < 24:
		buf.WriteByte(byte(majorTypeMap | n))
	case n <= 0xff:
		buf.WriteByte(majorTypeMap | 24)
		buf.WriteByte(byte(n))
	case n <= 0xffff:
		var b [2]byte
		binary.BigEndian.PutUint16(b[:], uint16(n))
		buf.WriteByte(majorTypeMap | 25)
		buf.Write(b[:])
	case n <= 0xffffffff:
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], uint32(n))
		buf.WriteByte(majorTypeMap | 26)
		buf.Write(b[:])
	default:
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], uint64(n))
		buf.WriteByte(majorTypeMap | 27)
		buf.Write(b[:])
	}
}

// cborPair is one key/value of a hand-encoded struct map.
type cborPair struct {
	key   string
	value any
}

// encodeCBORStruct writes pairs as a CBOR map in exactly the order given.
//
// The two wire structs that carry an `omitempty` map field cannot be left to
// fxamacker, because the two requirements are mutually exclusive there:
//
//   - Map keys must be ordered, which needs the sortedMap type above.
//   - `omitempty` must still drop an empty stored_proofs/proofs, because deployed
//     peers and both other ports omit it.
//
// fxamacker's own source rules that combination out. getEncodeFuncInternal
// returns `encodeMarshalerType, alwaysNotEmpty` for any type implementing
// cbor.Marshaler (encode.go), so declaring a map field as sortedMap silently
// disables `omitempty` on it -- in BOTH OmitEmpty modes, since the isEmpty
// function is chosen from the type, not the mode. And the obvious escape, a
// sorted EncMode, is ruled out too: encodingStructType.getFields switches struct
// field order on the same em.sort knob that orders map keys (cache.go), so there
// is no setting that sorts maps while leaving struct fields in declaration order.
//
// So the owning struct encodes itself: declaration order is whatever this list
// says, `omitempty` is an explicit append, and each value still goes through
// cbor.Marshal, which keeps every scalar, slice and nil-vs-empty detail identical
// to what fxamacker would have written for that field.
func encodeCBORStruct(pairs []cborPair) ([]byte, error) {
	var buf bytes.Buffer
	writeCBORMapHeader(&buf, len(pairs))
	for _, pair := range pairs {
		encodedKey, err := cbor.Marshal(pair.key)
		if err != nil {
			return nil, err
		}
		buf.Write(encodedKey)

		encodedValue, err := cbor.Marshal(pair.value)
		if err != nil {
			return nil, err
		}
		buf.Write(encodedValue)
	}
	return buf.Bytes(), nil
}
