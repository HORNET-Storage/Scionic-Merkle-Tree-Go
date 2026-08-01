package dag

import (
	"encoding/json"

	merkle_tree "github.com/HORNET-Storage/Scionic-Merkle-Tree/v2/tree"
	cbor "github.com/fxamacker/cbor/v2"
)

// strictCBORDecMode bounds decoding of untrusted CBOR (from peers/relays) to
// guard against resource exhaustion from deeply nested or absurdly large
// inputs, and rejects duplicate map keys. Limits stay generous enough for very
// large repositories.
var strictCBORDecMode cbor.DecMode

// Wire encoding uses fxamacker's DEFAULT mode -- plain cbor.Marshal, Sort:
// SortNone -- so struct fields ride the wire in declaration order, the exact
// shape deployed Go v2.2.6 peers produce, the version pinned by
// HORNETS-Nostr-Relay and hdk-nostr-go.
//
// Determinism comes from the map fields alone. Every type below carries at least
// one map -- Leafs, AdditionalData, StoredProofs, Proofs, Relationships -- and
// Go's map iteration is deliberately randomized, so encoding the same DAG twice
// in one process used to produce different bytes. That was not theoretical:
// generating the spec-vector corpus three times produced three different
// dag.cbor files for identical input.
//
// It never corrupted anything, because a CID is computed from leaf fields rather
// than from this envelope, and CBOR maps are unordered to any decoder. But it
// makes the serialized form unusable as an identity: you cannot digest it, cache
// by it, dedupe on it, diff it, or compare two ports' output byte for byte. The
// last of those is what the spec-vector corpus needs.
//
// The first fix here was a sorted EncMode. It did make encoding reproducible,
// but fxamacker's Sort applies to struct fields too, so it also reordered every
// field on the wire -- and the Swift port's CrossCompatWireTests caught that
// against golden bytes captured from a real deployed build. The ordering is now
// scoped to maps alone through the sortedMap type in sortedmap.go, which every
// map field below is declared as.
//
// `omitempty` is the second half of that scoping, and it could not be delegated
// either. fxamacker returns `encodeMarshalerType, alwaysNotEmpty` for any type
// implementing cbor.Marshaler, so simply declaring the map fields as sortedMap
// silently disabled `omitempty` on them -- in BOTH OmitEmpty modes, because the
// isEmpty function is chosen from the type rather than the mode. Every leaf in a
// full DAG began carrying an empty stored_proofs it had never carried before:
// 11 leaves, 11 stray keys, 8182 bytes where the ports had agreed on 8017.
//
// So the structs that cannot be left to fxamacker encode themselves, via
// appendCBORStruct in sortedmap.go. SerializableDagLeaf and
// SerializableTransmissionPacket own an `omitempty` map and have no choice, for
// the reason above. SerializableDag joins them for a different reason -- speed:
// leaving the envelope to reflection made fxamacker copy the entire encoded
// Leafs map one extra time, which on an 18 MiB DAG is a measurable cost by
// itself. It emits the identical two-key map either way.
// SerializableBatchedTransmissionPacket owns no `omitempty` map and is still
// left to fxamacker.
//
// The struct tags below stay as they are: encoding/json still reads them, and
// they document the wire contract the marshalers implement.

func init() {
	mode, err := cbor.DecOptions{
		MaxNestedLevels:  256,
		MaxArrayElements: 100_000_000,
		MaxMapPairs:      100_000_000,
		DupMapKey:        cbor.DupMapKeyEnforcedAPF,
	}.DecMode()
	if err != nil {
		panic(err)
	}
	strictCBORDecMode = mode
}

type SerializableDag struct {
	Root  string
	Leafs sortedMap[*SerializableDagLeaf]
}

type SerializableDagLeaf struct {
	Hash              string
	ItemName          string
	Type              LeafType
	ContentHash       []byte
	Content           []byte
	ClassicMerkleRoot []byte
	CurrentLinkCount  int
	LeafCount         int
	ContentSize       int64
	DagSize           int64
	Links             []string
	AdditionalData    sortedMap[string]
	StoredProofs      sortedMap[*ClassicTreeBranch] `json:"stored_proofs,omitempty" cbor:"stored_proofs,omitempty"`
}

// appendCBOR writes the leaf in declaration order, sorting its map fields and
// applying stored_proofs' `omitempty` by hand. See appendCBORStruct for why this
// cannot be left to fxamacker.
func (leaf *SerializableDagLeaf) appendCBOR(dst []byte) ([]byte, error) {
	// A nil leaf is null, matching what fxamacker writes for a nil pointer.
	if leaf == nil {
		return append(dst, cborNull), nil
	}

	pairs := []cborPair{
		{"Hash", leaf.Hash},
		{"ItemName", leaf.ItemName},
		{"Type", leaf.Type},
		{"ContentHash", leaf.ContentHash},
		{"Content", leaf.Content},
		{"ClassicMerkleRoot", leaf.ClassicMerkleRoot},
		{"CurrentLinkCount", leaf.CurrentLinkCount},
		{"LeafCount", leaf.LeafCount},
		{"ContentSize", leaf.ContentSize},
		{"DagSize", leaf.DagSize},
		{"Links", leaf.Links},
		{"AdditionalData", leaf.AdditionalData},
	}
	if len(leaf.StoredProofs) > 0 {
		pairs = append(pairs, cborPair{"stored_proofs", leaf.StoredProofs})
	}
	return appendCBORStruct(dst, pairs)
}

// MarshalCBOR satisfies cbor.Marshaler for the paths that still route through
// fxamacker; appendCBOR is the single implementation.
func (leaf *SerializableDagLeaf) MarshalCBOR() ([]byte, error) {
	return leaf.appendCBOR(make([]byte, 0, leaf.encodedSizeHint()))
}

// encodedSizeHint approximates this leaf's encoded size so a buffer can be
// allocated once at roughly the right size instead of grown into.
//
// This is a buffer hint and nothing else. It is deliberately NOT
// DagLeaf.EstimateSize, which sizes transmission BATCHES: that one is
// protocol-visible, because changing it changes how leaves are grouped across
// packets, so it stays exactly as it is. Being wrong here costs one extra
// reallocation and nothing else. Keeping the two apart means a harmless buffer
// tweak can never silently repartition every batched transmission.
func (leaf *SerializableDagLeaf) encodedSizeHint() int {
	if leaf == nil {
		return 1
	}

	// Content is the only field that varies by megabytes. Everything else is
	// bounded by a few hundred bytes, so the fixed 256 covers the twelve key
	// names, the four integers and the map head.
	size := len(leaf.Hash) + len(leaf.ItemName) + len(string(leaf.Type)) +
		len(leaf.ContentHash) + len(leaf.Content) + len(leaf.ClassicMerkleRoot) + 256
	for _, link := range leaf.Links {
		size += len(link) + 9
	}
	for key, value := range leaf.AdditionalData {
		size += len(key) + len(value) + 18
	}
	// A stored proof is a short path of 32-byte siblings; overshoot cheaply.
	size += len(leaf.StoredProofs) * 512
	return size
}

type SerializableTransmissionPacket struct {
	Leaf       *SerializableDagLeaf
	ParentHash string
	Proofs     sortedMap[*ClassicTreeBranch] `json:"proofs,omitempty" cbor:"proofs,omitempty"`
}

// appendCBOR writes the packet in declaration order, sorting Proofs and applying
// its `omitempty` by hand. See appendCBORStruct for why.
func (packet *SerializableTransmissionPacket) appendCBOR(dst []byte) ([]byte, error) {
	if packet == nil {
		return append(dst, cborNull), nil
	}

	pairs := []cborPair{
		{"Leaf", packet.Leaf},
		{"ParentHash", packet.ParentHash},
	}
	if len(packet.Proofs) > 0 {
		pairs = append(pairs, cborPair{"proofs", packet.Proofs})
	}
	return appendCBORStruct(dst, pairs)
}

// MarshalCBOR satisfies cbor.Marshaler; appendCBOR is the single implementation.
func (packet *SerializableTransmissionPacket) MarshalCBOR() ([]byte, error) {
	return packet.appendCBOR(make([]byte, 0, packet.Leaf.encodedSizeHint()+256))
}

type SerializableBatchedTransmissionPacket struct {
	Leaves        []*SerializableDagLeaf
	Relationships sortedMap[string]
	PacketIndex   int
	TotalPackets  int
}

func (dag *Dag) ToSerializable() *SerializableDag {
	serializable := &SerializableDag{
		Root:  dag.Root,
		Leafs: make(map[string]*SerializableDagLeaf),
	}

	for hash, leaf := range dag.Leafs {
		serializable.Leafs[hash] = leaf.ToSerializable()
	}

	return serializable
}

func FromSerializable(s *SerializableDag) *Dag {
	dag := &Dag{
		Root:  s.Root,
		Leafs: make(map[string]*DagLeaf),
	}

	// First pass: create all leaves
	for hash, sLeaf := range s.Leafs {
		dag.Leafs[hash] = &DagLeaf{
			Hash:              sLeaf.Hash,
			ItemName:          sLeaf.ItemName,
			Type:              sLeaf.Type,
			ContentHash:       sLeaf.ContentHash,
			Content:           sLeaf.Content,
			ClassicMerkleRoot: sLeaf.ClassicMerkleRoot,
			CurrentLinkCount:  sLeaf.CurrentLinkCount,
			Links:             make([]string, 0),
			AdditionalData:    make(map[string]string),
			Proofs:            make(map[string]*ClassicTreeBranch),
		}

		// Copy links preserving order (CRITICAL: order matters for chunked files!)
		// Links array order determines chunk reassembly sequence
		dag.Leafs[hash].Links = make([]string, len(sLeaf.Links))
		copy(dag.Leafs[hash].Links, sLeaf.Links)

		// Copy and sort additional data
		dag.Leafs[hash].AdditionalData = SortMapByKeys(sLeaf.AdditionalData)

		// Copy stored proofs
		if sLeaf.StoredProofs != nil {
			for k, v := range sLeaf.StoredProofs {
				dag.Leafs[hash].Proofs[k] = v
			}
		}

		// Set root-specific fields
		if hash == s.Root {
			dag.Leafs[hash].LeafCount = sLeaf.LeafCount
			dag.Leafs[hash].ContentSize = sLeaf.ContentSize
			dag.Leafs[hash].DagSize = sLeaf.DagSize
		}
	}

	// Check if this is a partial DAG
	isPartial := false
	for _, leaf := range dag.Leafs {
		if len(leaf.Links) < leaf.CurrentLinkCount {
			isPartial = true
			break
		}
	}

	// For full DAGs, rebuild Merkle trees
	// For partial DAGs, preserve the existing Merkle roots
	if !isPartial {
		// Second pass: rebuild Merkle trees for full DAGs
		for _, leaf := range dag.Leafs {
			// Rebuild Merkle tree if leaf has multiple links
			if len(leaf.Links) > 1 {
				builder := merkle_tree.CreateTree()
				for _, link := range leaf.Links {
					builder.AddLeaf(link, link)
				}

				merkleTree, leafMap, err := builder.Build()
				if err == nil {
					leaf.MerkleTree = merkleTree
					leaf.LeafMap = leafMap
					leaf.ClassicMerkleRoot = merkleTree.Root
				}
			}
		}
	}

	// Third pass: reconstruct parent hashes via a single child->parent index.
	// buildParentIndex already resolves a content-identical leaf's several
	// parents to the lowest parent hash; the local copy this replaced kept
	// whichever parent map iteration yielded first, so a shared chunk's
	// ParentHash changed from one deserialization of the same bytes to the next.
	parentOf := dag.buildParentIndex()
	for hash, leaf := range dag.Leafs {
		if parentHash, ok := parentOf[hash]; ok {
			leaf.ParentHash = parentHash
		}
	}

	return dag
}

// ToSerializable converts a DagLeaf to its serializable form
func (leaf *DagLeaf) ToSerializable() *SerializableDagLeaf {
	serializable := &SerializableDagLeaf{
		Hash:              leaf.Hash,
		ItemName:          leaf.ItemName,
		Type:              leaf.Type,
		ContentHash:       leaf.ContentHash,
		Content:           leaf.Content,
		ClassicMerkleRoot: leaf.ClassicMerkleRoot,
		CurrentLinkCount:  leaf.CurrentLinkCount,
		LeafCount:         leaf.LeafCount,
		ContentSize:       leaf.ContentSize,
		DagSize:           leaf.DagSize,
		Links:             make([]string, 0),
		AdditionalData:    make(map[string]string),
		StoredProofs:      make(map[string]*ClassicTreeBranch),
	}

	// Copy links preserving order (CRITICAL: order matters for chunked files!)
	// Links array order determines chunk reassembly sequence
	serializable.Links = make([]string, len(leaf.Links))
	copy(serializable.Links, leaf.Links)

	// Copy and sort additional data
	serializable.AdditionalData = SortMapByKeys(leaf.AdditionalData)

	// Copy stored proofs
	if leaf.Proofs != nil {
		for k, v := range leaf.Proofs {
			serializable.StoredProofs[k] = v
		}
	}

	return serializable
}

// appendCBOR writes the envelope: a two-key map, Root then Leafs, which is
// exactly the shape fxamacker produced for this struct when it was left to
// reflection.
func (serializable *SerializableDag) appendCBOR(dst []byte) ([]byte, error) {
	if serializable == nil {
		return append(dst, cborNull), nil
	}
	return appendCBORStruct(dst, []cborPair{
		{"Root", serializable.Root},
		{"Leafs", serializable.Leafs},
	})
}

// MarshalCBOR encodes the whole DAG in a single pass into one correctly sized
// buffer.
//
// The buffer is the point. Before this, every nesting level allocated its own
// bytes.Buffer, grew it by repeated doubling, and handed the result upward to be
// copied again -- 8.3x the output size in allocation, and 69% of the profile
// inside runtime.memclr and runtime.memmove. Sorting, the thing that made this
// encoding deterministic in the first place, never appeared in the profile at
// all.
func (serializable *SerializableDag) MarshalCBOR() ([]byte, error) {
	return serializable.appendCBOR(make([]byte, 0, serializable.encodedSizeHint()))
}

// encodedSizeHint approximates the encoded size of the whole DAG. See
// SerializableDagLeaf.encodedSizeHint for why this is kept apart from
// DagLeaf.EstimateSize.
func (serializable *SerializableDag) encodedSizeHint() int {
	if serializable == nil {
		return 1
	}

	size := len(serializable.Root) + 32
	for hash, leaf := range serializable.Leafs {
		size += len(hash) + 9 + leaf.encodedSizeHint()
	}
	return size
}

func (dag *Dag) ToCBOR() ([]byte, error) {
	return dag.ToSerializable().MarshalCBOR()
}

// AppendCBOR encodes the DAG onto dst and returns the extended slice, exactly as
// Go's own append-style encoders do.
//
// The bytes are identical to ToCBOR's; the only difference is who owns the
// buffer, and that turns out to be about half the cost. Encoding now runs at the
// floor set by allocating the output and copying into it, so a caller that
// encodes repeatedly -- a relay serving DAGs, a store rewriting them -- spends
// much of its time allocating a fresh multi-megabyte buffer and faulting it in.
// Passing a retained slice back in, dst[:0], pays that once instead of per call:
// on the 18.25 MiB benchmark corpus that is 1.8ms against 3.4ms, and 154 KB
// allocated per encode against 19.3 MB.
//
// The Rust port exposes the same escape hatch as Dag::to_cbor_into, for the same
// measured reason -- though Rust gains more from it (2.4x to Go's 1.9x), because
// Go's runtime already recycles large spans in its own heap instead of returning
// the pages to the OS on every free.
func (dag *Dag) AppendCBOR(dst []byte) ([]byte, error) {
	serializable := dag.ToSerializable()
	if cap(dst)-len(dst) < serializable.encodedSizeHint() {
		// One correctly sized growth rather than the doubling cascade; append
		// would otherwise reallocate and copy repeatedly on the way up.
		grown := make([]byte, len(dst), len(dst)+serializable.encodedSizeHint())
		copy(grown, dst)
		dst = grown
	}
	return serializable.appendCBOR(dst)
}

func (dag *Dag) ToJSON() ([]byte, error) {
	serializable := dag.ToSerializable()
	return json.MarshalIndent(serializable, "", "  ")
}

func FromCBOR(data []byte) (*Dag, error) {
	var serializable SerializableDag
	if err := strictCBORDecMode.Unmarshal(data, &serializable); err != nil {
		return nil, err
	}
	return FromSerializable(&serializable), nil
}

func FromJSON(data []byte) (*Dag, error) {
	var serializable SerializableDag
	if err := json.Unmarshal(data, &serializable); err != nil {
		return nil, err
	}
	return FromSerializable(&serializable), nil
}

// ToSerializable converts a TransmissionPacket to its serializable form
func (packet *TransmissionPacket) ToSerializable() *SerializableTransmissionPacket {
	serializable := &SerializableTransmissionPacket{
		Leaf:       packet.Leaf.ToSerializable(),
		ParentHash: packet.ParentHash,
		Proofs:     make(map[string]*ClassicTreeBranch),
	}

	// Copy proofs
	if packet.Proofs != nil {
		for k, v := range packet.Proofs {
			serializable.Proofs[k] = v
		}
	}

	return serializable
}

// TransmissionPacketFromSerializable reconstructs a TransmissionPacket from its serializable form
func TransmissionPacketFromSerializable(s *SerializableTransmissionPacket) *TransmissionPacket {
	// Create a DagLeaf from the serializable leaf
	leaf := &DagLeaf{
		Hash:              s.Leaf.Hash,
		ItemName:          s.Leaf.ItemName,
		Type:              s.Leaf.Type,
		ContentHash:       s.Leaf.ContentHash,
		Content:           s.Leaf.Content,
		ClassicMerkleRoot: s.Leaf.ClassicMerkleRoot,
		CurrentLinkCount:  s.Leaf.CurrentLinkCount,
		LeafCount:         s.Leaf.LeafCount,
		ContentSize:       s.Leaf.ContentSize,
		DagSize:           s.Leaf.DagSize,
		Links:             make([]string, 0),
		AdditionalData:    make(map[string]string),
		Proofs:            make(map[string]*ClassicTreeBranch),
	}

	// Copy links preserving order (order matters for chunked files)
	leaf.Links = make([]string, len(s.Leaf.Links))
	copy(leaf.Links, s.Leaf.Links)

	// Copy and sort additional data
	leaf.AdditionalData = SortMapByKeys(s.Leaf.AdditionalData)

	// Copy stored proofs
	if s.Leaf.StoredProofs != nil {
		for k, v := range s.Leaf.StoredProofs {
			leaf.Proofs[k] = v
		}
	}

	packet := &TransmissionPacket{
		Leaf:       leaf,
		ParentHash: s.ParentHash,
		Proofs:     make(map[string]*ClassicTreeBranch),
	}

	// Copy proofs
	if s.Proofs != nil {
		for k, v := range s.Proofs {
			packet.Proofs[k] = v
		}
	}

	return packet
}

// ToCBOR serializes a TransmissionPacket to CBOR format
func (packet *TransmissionPacket) ToCBOR() ([]byte, error) {
	serializable := packet.ToSerializable()
	return cbor.Marshal(serializable)
}

// ToJSON serializes a TransmissionPacket to JSON format
func (packet *TransmissionPacket) ToJSON() ([]byte, error) {
	serializable := packet.ToSerializable()
	return json.MarshalIndent(serializable, "", "  ")
}

// TransmissionPacketFromCBOR deserializes a TransmissionPacket from CBOR format
func TransmissionPacketFromCBOR(data []byte) (*TransmissionPacket, error) {
	var serializable SerializableTransmissionPacket
	if err := strictCBORDecMode.Unmarshal(data, &serializable); err != nil {
		return nil, err
	}
	return TransmissionPacketFromSerializable(&serializable), nil
}

// TransmissionPacketFromJSON deserializes a TransmissionPacket from JSON format
func TransmissionPacketFromJSON(data []byte) (*TransmissionPacket, error) {
	var serializable SerializableTransmissionPacket
	if err := json.Unmarshal(data, &serializable); err != nil {
		return nil, err
	}
	return TransmissionPacketFromSerializable(&serializable), nil
}

// ToSerializable converts a BatchedTransmissionPacket to its serializable form
func (packet *BatchedTransmissionPacket) ToSerializable() *SerializableBatchedTransmissionPacket {
	serializable := &SerializableBatchedTransmissionPacket{
		Leaves:        make([]*SerializableDagLeaf, len(packet.Leaves)),
		Relationships: make(map[string]string),
		PacketIndex:   packet.PacketIndex,
		TotalPackets:  packet.TotalPackets,
	}

	for i, leaf := range packet.Leaves {
		serializable.Leaves[i] = leaf.ToSerializable()
	}

	// Copy relationships
	if packet.Relationships != nil {
		for k, v := range packet.Relationships {
			serializable.Relationships[k] = v
		}
	}

	return serializable
}

// BatchedTransmissionPacketFromSerializable reconstructs a BatchedTransmissionPacket from its serializable form
func BatchedTransmissionPacketFromSerializable(s *SerializableBatchedTransmissionPacket) *BatchedTransmissionPacket {
	leaves := make([]*DagLeaf, len(s.Leaves))
	for i, serializableLeaf := range s.Leaves {
		leaves[i] = &DagLeaf{
			Hash:              serializableLeaf.Hash,
			ItemName:          serializableLeaf.ItemName,
			Type:              serializableLeaf.Type,
			ContentHash:       serializableLeaf.ContentHash,
			Content:           serializableLeaf.Content,
			ClassicMerkleRoot: serializableLeaf.ClassicMerkleRoot,
			CurrentLinkCount:  serializableLeaf.CurrentLinkCount,
			LeafCount:         serializableLeaf.LeafCount,
			ContentSize:       serializableLeaf.ContentSize,
			DagSize:           serializableLeaf.DagSize,
			Links:             make([]string, 0),
			AdditionalData:    make(map[string]string),
			Proofs:            make(map[string]*ClassicTreeBranch),
		}

		// Copy links preserving order (order matters for chunked files)
		leaves[i].Links = make([]string, len(serializableLeaf.Links))
		copy(leaves[i].Links, serializableLeaf.Links)

		// Copy and sort additional data
		leaves[i].AdditionalData = SortMapByKeys(serializableLeaf.AdditionalData)

		// Copy stored proofs
		if serializableLeaf.StoredProofs != nil {
			for k, v := range serializableLeaf.StoredProofs {
				leaves[i].Proofs[k] = v
			}
		}
	}

	packet := &BatchedTransmissionPacket{
		Leaves:        leaves,
		Relationships: make(map[string]string),
		PacketIndex:   s.PacketIndex,
		TotalPackets:  s.TotalPackets,
	}

	// Copy relationships
	if s.Relationships != nil {
		for k, v := range s.Relationships {
			packet.Relationships[k] = v
		}
	}

	return packet
}

// ToCBOR serializes a BatchedTransmissionPacket to CBOR format
func (packet *BatchedTransmissionPacket) ToCBOR() ([]byte, error) {
	serializable := packet.ToSerializable()
	return cbor.Marshal(serializable)
}

// ToJSON serializes a BatchedTransmissionPacket to JSON format
func (packet *BatchedTransmissionPacket) ToJSON() ([]byte, error) {
	serializable := packet.ToSerializable()
	return json.MarshalIndent(serializable, "", "  ")
}

// BatchedTransmissionPacketFromCBOR deserializes a BatchedTransmissionPacket from CBOR format
func BatchedTransmissionPacketFromCBOR(data []byte) (*BatchedTransmissionPacket, error) {
	var serializable SerializableBatchedTransmissionPacket
	if err := strictCBORDecMode.Unmarshal(data, &serializable); err != nil {
		return nil, err
	}
	return BatchedTransmissionPacketFromSerializable(&serializable), nil
}

// BatchedTransmissionPacketFromJSON deserializes a BatchedTransmissionPacket from JSON format
func BatchedTransmissionPacketFromJSON(data []byte) (*BatchedTransmissionPacket, error) {
	var serializable SerializableBatchedTransmissionPacket
	if err := json.Unmarshal(data, &serializable); err != nil {
		return nil, err
	}
	return BatchedTransmissionPacketFromSerializable(&serializable), nil
}
