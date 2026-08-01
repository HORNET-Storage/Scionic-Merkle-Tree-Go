package dag

import (
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
// as a sortedMap, and every struct that encodes itself below lists its fields in
// declaration order -- exactly where they have always been. Nothing here sorts a
// struct field.
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

// cborAppender is implemented by the wire types that encode themselves.
//
// This interface is the entire performance story of this file. cbor.Marshaler's
// signature -- MarshalCBOR() ([]byte, error) -- forces every nesting level to
// allocate its own buffer and hand the finished bytes upward to be copied into
// its parent's buffer. Encoding an 18 MiB DAG that way allocated 8.3x the output
// size and spent 69% of ToCBOR's profile inside the runtime: 38% in
// memclrNoHeapPointers zeroing buffers that doubling had just outgrown, 30% in
// memmove copying the same content bytes from one level up to the next.
//
// Appending into a buffer the caller already owns removes the intermediate
// buffer at every level. That is what the Rust and Swift ports have always
// done -- they build one value tree and encode it in a single pass -- so this
// makes Go's shape match theirs rather than diverge from it.
//
// Determinism was never the cost. sort.Slice over a few hundred short strings
// does not appear in the profile at all. The sorting below is unchanged, and so
// are the bytes it produces.
type cborAppender interface {
	appendCBOR(dst []byte) ([]byte, error)
}

// cborNull is what fxamacker's default NilContainerAsNull writes for a nil slice
// or map, and what it writes for a nil pointer. Reproducing it by hand is
// mandatory rather than cosmetic: an absent ContentHash has to stay 0xf6 and must
// not quietly become an empty byte string, which is a different value to every
// decoder.
const cborNull = 0xf6

const (
	majorTypeByteString = 0x40
	majorTypeTextString = 0x60
	majorTypeMap        = 0xa0
)

// appendCBOR encodes the map with sorted keys, appending into dst. Values that
// cannot encode themselves still go through cbor.Marshal, so nested structs keep
// declaration order and every scalar detail stays byte-identical.
func (m sortedMap[T]) appendCBOR(dst []byte) ([]byte, error) {
	// A nil map is null on the wire, not an empty map. fxamacker's default
	// NilContainerAsNull already does this, and changing it would alter bytes
	// for every absent map.
	if m == nil {
		return append(dst, cborNull), nil
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

	dst = appendCBORHead(dst, majorTypeMap, uint64(len(keys)))
	var err error
	for _, key := range keys {
		dst = appendCBORTextString(dst, key)
		if dst, err = appendCBORValue(dst, m[key]); err != nil {
			return nil, err
		}
	}
	return dst, nil
}

// MarshalCBOR satisfies cbor.Marshaler for the paths that still route through
// fxamacker. It is a wrapper on purpose: there is exactly one encoder, so the two
// entry points cannot drift apart.
func (m sortedMap[T]) MarshalCBOR() ([]byte, error) {
	return m.appendCBOR(nil)
}

// appendCBORHead appends a major type and its argument in the shortest form,
// which is the minimal-length encoding fxamacker itself emits.
func appendCBORHead(dst []byte, majorType byte, argument uint64) []byte {
	switch {
	case argument < 24:
		return append(dst, majorType|byte(argument))
	case argument <= 0xff:
		return append(dst, majorType|24, byte(argument))
	case argument <= 0xffff:
		return append(dst, majorType|25, byte(argument>>8), byte(argument))
	case argument <= 0xffffffff:
		return append(dst, majorType|26,
			byte(argument>>24), byte(argument>>16), byte(argument>>8), byte(argument))
	default:
		return append(dst, majorType|27,
			byte(argument>>56), byte(argument>>48), byte(argument>>40), byte(argument>>32),
			byte(argument>>24), byte(argument>>16), byte(argument>>8), byte(argument))
	}
}

// appendCBORTextString appends a definite-length text string.
func appendCBORTextString(dst []byte, value string) []byte {
	dst = appendCBORHead(dst, majorTypeTextString, uint64(len(value)))
	return append(dst, value...)
}

// appendCBORValue appends one value, writing directly for the shapes that
// dominate the wire and delegating everything else to fxamacker.
//
// Exactly three cases are handled here, and each earns its place by removing a
// full copy of something that matters: map keys and CID strings (roughly two
// thousand per DAG, each previously its own allocation), byte slices (leaf
// content, megabytes, previously allocated by cbor.Marshal and then copied a
// second time into the parent buffer), and nested values that can append
// themselves.
//
// Everything else -- integers, LeafType, []string, *ClassicTreeBranch -- still
// goes through cbor.Marshal. Those are small, and routing them through fxamacker
// is what keeps every scalar, slice and nil-vs-empty detail exactly as it has
// always been on the wire.
func appendCBORValue(dst []byte, value any) ([]byte, error) {
	switch typed := value.(type) {
	case string:
		return appendCBORTextString(dst, typed), nil
	case []byte:
		// nil and empty are different values here; see cborNull.
		if typed == nil {
			return append(dst, cborNull), nil
		}
		dst = appendCBORHead(dst, majorTypeByteString, uint64(len(typed)))
		return append(dst, typed...), nil
	case cborAppender:
		return typed.appendCBOR(dst)
	default:
		encoded, err := cbor.Marshal(value)
		if err != nil {
			return nil, err
		}
		return append(dst, encoded...), nil
	}
}

// cborPair is one key/value of a hand-encoded struct map.
type cborPair struct {
	key   string
	value any
}

// appendCBORStruct appends pairs as a CBOR map in exactly the order given.
//
// The wire structs that carry an `omitempty` map field cannot be left to
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
// says, `omitempty` is an explicit append, and every value this file does not
// write directly still goes through cbor.Marshal, which keeps each scalar, slice
// and nil-vs-empty detail identical to what fxamacker would have written.
func appendCBORStruct(dst []byte, pairs []cborPair) ([]byte, error) {
	dst = appendCBORHead(dst, majorTypeMap, uint64(len(pairs)))
	var err error
	for _, pair := range pairs {
		dst = appendCBORTextString(dst, pair.key)
		if dst, err = appendCBORValue(dst, pair.value); err != nil {
			return nil, err
		}
	}
	return dst, nil
}
