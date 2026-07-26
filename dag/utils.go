package dag

import (
	"fmt"
	"sort"

	cbor "github.com/fxamacker/cbor/v2"
)

type KeyValue struct {
	Key   string
	Value string
}

func SortMapForVerification(inputMap map[string]string) []KeyValue {
	if inputMap == nil {
		return nil
	}

	keys := make([]string, 0, len(inputMap))
	for key := range inputMap {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	sortedPairs := make([]KeyValue, 0, len(keys))
	for _, key := range keys {
		sortedPairs = append(sortedPairs, KeyValue{Key: key, Value: inputMap[key]})
	}

	return sortedPairs
}

func SortMapByKeys(inputMap map[string]string) map[string]string {
	if inputMap == nil {
		return map[string]string{}
	}

	if len(inputMap) <= 0 {
		return map[string]string{}
	}

	keys := make([]string, 0, len(inputMap))

	for key := range inputMap {
		keys = append(keys, key)
	}

	sort.Strings(keys)

	sortedMap := make(map[string]string)
	for _, key := range keys {
		sortedMap[key] = inputMap[key]
	}

	return sortedMap
}

func CalculateTotalContentSize(dag *Dag) int64 {
	var totalSize int64
	for _, leaf := range dag.Leafs {
		if leaf.Content != nil {
			totalSize += int64(len(leaf.Content))
		}
	}
	return totalSize
}

// SerializedLeafSize returns the exact number of bytes used by the canonical
// non-root leaf representation counted in a root leaf's DagSize.
func SerializedLeafSize(leaf *DagLeaf) (int64, error) {
	if leaf == nil {
		return 0, fmt.Errorf("cannot calculate size of nil leaf")
	}

	var linkHashes []string
	if len(leaf.Links) > 0 {
		linkHashes = append([]string(nil), leaf.Links...)
		sort.Strings(linkHashes)
	}

	data := struct {
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
	}{
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
		Links:             linkHashes,
		AdditionalData:    SortMapByKeys(leaf.AdditionalData),
	}

	serialized, err := cbor.Marshal(data)
	if err != nil {
		return 0, fmt.Errorf("failed to serialize leaf %s: %w", leaf.Hash, err)
	}
	return int64(len(serialized)), nil
}

func CalculateTotalDagSize(dag *Dag) (int64, error) {
	var totalSize int64
	for _, leaf := range dag.Leafs {
		size, err := SerializedLeafSize(leaf)
		if err != nil {
			return 0, err
		}
		totalSize += size
	}
	return totalSize, nil
}
