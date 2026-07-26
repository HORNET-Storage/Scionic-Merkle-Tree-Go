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
	Leafs map[string]*SerializableDagLeaf
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
	AdditionalData    map[string]string
	StoredProofs      map[string]*ClassicTreeBranch `json:"stored_proofs,omitempty" cbor:"stored_proofs,omitempty"`
}

type SerializableTransmissionPacket struct {
	Leaf       *SerializableDagLeaf
	ParentHash string
	Proofs     map[string]*ClassicTreeBranch `json:"proofs,omitempty" cbor:"proofs,omitempty"`
}

type SerializableBatchedTransmissionPacket struct {
	Leaves        []*SerializableDagLeaf
	Relationships map[string]string
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

	// Third pass: reconstruct parent hashes via a single child->parent index
	parentOf := make(map[string]string, len(dag.Leafs))
	for _, potential := range dag.Leafs {
		for _, childHash := range potential.Links {
			if _, ok := parentOf[childHash]; !ok {
				parentOf[childHash] = potential.Hash
			}
		}
	}
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

func (dag *Dag) ToCBOR() ([]byte, error) {
	serializable := dag.ToSerializable()
	return cbor.Marshal(serializable)
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
