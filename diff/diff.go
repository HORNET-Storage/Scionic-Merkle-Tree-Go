package diff

import (
	"fmt"

	"github.com/HORNET-Storage/Scionic-Merkle-Tree/v2/dag"
)

type DiffType string

const (
	DiffTypeAdded   DiffType = "added"
	DiffTypeRemoved DiffType = "removed"
)

type LeafDiff struct {
	Type DiffType     `json:"type"`
	Hash string       `json:"hash"`
	Leaf *dag.DagLeaf `json:"leaf"`
}

type DagDiff struct {
	Diffs   map[string]*LeafDiff `json:"diffs"`
	Summary DiffSummary          `json:"summary"`
}

type DiffSummary struct {
	Added   int `json:"added"`
	Removed int `json:"removed"`
	Total   int `json:"total"`
}

// GetAddedLeaves returns a map of all added leaves from the diff.
func (diff *DagDiff) GetAddedLeaves() map[string]*dag.DagLeaf {
	addedLeaves := make(map[string]*dag.DagLeaf)

	for hash, leafDiff := range diff.Diffs {
		if leafDiff.Type == DiffTypeAdded {
			addedLeaves[hash] = leafDiff.Leaf
		}
	}

	return addedLeaves
}

// GetRemovedLeaves returns a map of all removed leaves from the diff.
func (diff *DagDiff) GetRemovedLeaves() map[string]*dag.DagLeaf {
	removedLeaves := make(map[string]*dag.DagLeaf)

	for hash, leafDiff := range diff.Diffs {
		if leafDiff.Type == DiffTypeRemoved {
			removedLeaves[hash] = leafDiff.Leaf
		}
	}

	return removedLeaves
}

// ApplyToDAG applies the diff to a DAG, creating a new DAG with the changes.
// This works by:
// 1. Creating a pool of all available leaves (old leaves + new leaves from diff)
// 2. Finding the new root (which will be one of the added leaves)
// 3. Traversing from the new root to collect only referenced leaves
//
// Leaves from the old DAG that aren't referenced by the new root are naturally excluded.
func (diff *DagDiff) ApplyToDAG(oldDag *dag.Dag) (*dag.Dag, error) {
	if oldDag == nil {
		return nil, fmt.Errorf("cannot apply diff: old DAG is nil")
	}
	if diff == nil {
		return nil, fmt.Errorf("cannot apply diff: diff is nil")
	}

	// If no additions, the DAG structure hasn't changed
	if diff.Summary.Added == 0 {
		// Return a copy of the old DAG
		newDag := &dag.Dag{
			Root:  oldDag.Root,
			Leafs: make(map[string]*dag.DagLeaf),
		}
		for hash, leaf := range oldDag.Leafs {
			newDag.Leafs[hash] = leaf
		}
		return newDag, nil
	}

	// Build a complete pool of available leaves using hashes as keys
	leafPool := make(map[string]*dag.DagLeaf)

	// Add all leaves from old DAG
	for hash, leaf := range oldDag.Leafs {
		leafPool[hash] = leaf
	}

	// Add all new leaves from diff (these will override if same hash exists)
	for hash, leafDiff := range diff.Diffs {
		if leafDiff.Type == DiffTypeAdded {
			leafPool[hash] = leafDiff.Leaf
		}
	}

	// Find the new root - it must be one of the added leaves
	// The root is the leaf that's not referenced by any other leaf
	addedLeaves := diff.GetAddedLeaves()

	// Build a set of all child hashes referenced by ALL leaves in the pool
	childHashes := make(map[string]bool)
	for _, leaf := range leafPool {
		for _, childHash := range leaf.Links {
			childHashes[childHash] = true
		}
	}

	// Find the new root among added leaves (not referenced by any leaf)
	var newRootHash string
	for hash, leaf := range addedLeaves {
		if !childHashes[hash] {
			// Only the root has a LeafCount value and will always be 1 or more
			if leaf.LeafCount > 0 {
				newRootHash = hash
				break
			}
		}
	}

	if newRootHash == "" {
		return nil, fmt.Errorf("cannot find new root among added leaves")
	}

	// Now traverse from the new root to collect all referenced leaves
	newDagLeaves := make(map[string]*dag.DagLeaf)
	visited := make(map[string]bool)

	var traverse func(hash string) error
	traverse = func(hash string) error {
		if visited[hash] {
			return nil
		}
		visited[hash] = true

		leaf, exists := leafPool[hash]
		if !exists {
			return fmt.Errorf("missing leaf in pool: %s", hash)
		}

		// Add this leaf to the new DAG
		newDagLeaves[hash] = leaf

		// Traverse all children
		for _, childHash := range leaf.Links {
			if err := traverse(childHash); err != nil {
				return err
			}
		}

		return nil
	}

	// Start traversal from new root
	if err := traverse(newRootHash); err != nil {
		return nil, fmt.Errorf("failed to traverse from new root: %w", err)
	}

	// Create the new DAG
	newDag := &dag.Dag{
		Root:  newRootHash,
		Leafs: newDagLeaves,
	}

	return newDag, nil
}

// CreatePartialDag creates a DAG containing all leaves needed for the new structure.
func (diff *DagDiff) CreatePartialDag(fullNewDag *dag.Dag) (*dag.Dag, error) {
	if diff == nil {
		return nil, fmt.Errorf("cannot create partial DAG: diff is nil")
	}
	if fullNewDag == nil {
		return nil, fmt.Errorf("cannot create partial DAG: full new DAG is required")
	}

	addedLeaves := diff.GetAddedLeaves()
	if len(addedLeaves) == 0 {
		return nil, fmt.Errorf("no added leaves to create partial DAG")
	}

	// Collect all added leaf hashes
	var addedHashes []string
	for hash := range addedLeaves {
		addedHashes = append(addedHashes, hash)
	}

	// Use GetPartial with pruneLinks=false to keep all link information
	// This allows the receiver to know which old leaves are still referenced
	partialDag, err := fullNewDag.GetPartial(addedHashes, false)
	if err != nil {
		return nil, fmt.Errorf("failed to create partial DAG: %w", err)
	}

	return partialDag, nil
}

func Diff(firstDag *dag.Dag, secondDag *dag.Dag) (*DagDiff, error) {
	if firstDag == nil {
		return nil, fmt.Errorf("cannot diff: source DAG is nil")
	}
	if secondDag == nil {
		return nil, fmt.Errorf("cannot diff: target DAG is nil")
	}

	diff := &DagDiff{
		Diffs: make(map[string]*LeafDiff),
		Summary: DiffSummary{
			Added:   0,
			Removed: 0,
			Total:   0,
		},
	}

	// Create maps of hash -> leaf for both DAGs
	oldLeafs := make(map[string]*dag.DagLeaf)
	for hash, leaf := range firstDag.Leafs {
		oldLeafs[hash] = leaf
	}

	newLeafs := make(map[string]*dag.DagLeaf)
	for hash, leaf := range secondDag.Leafs {
		newLeafs[hash] = leaf
	}

	// Find added leaves
	for hash, newLeaf := range newLeafs {
		if _, existsInOld := oldLeafs[hash]; !existsInOld {
			// Leaf was added
			diff.Diffs[hash] = &LeafDiff{
				Type: DiffTypeAdded,
				Hash: hash,
				Leaf: newLeaf,
			}
			diff.Summary.Added++
			diff.Summary.Total++
		}
	}

	// Find removed leaves
	for hash, oldLeaf := range oldLeafs {
		if _, existsInNew := newLeafs[hash]; !existsInNew {
			// Leaf was removed
			diff.Diffs[hash] = &LeafDiff{
				Type: DiffTypeRemoved,
				Hash: hash,
				Leaf: oldLeaf,
			}
			diff.Summary.Removed++
			diff.Summary.Total++
		}
	}

	return diff, nil
}

// DiffFromNewLeaves compares old DAG with new leaves (e.g., from partial DAG)
// Identifies added leaves and removed leaves no longer referenced by new structure
func DiffFromNewLeaves(originalDag *dag.Dag, newLeaves map[string]*dag.DagLeaf) (*DagDiff, error) {
	if originalDag == nil {
		return nil, fmt.Errorf("cannot diff: source DAG is nil")
	}
	if newLeaves == nil {
		return nil, fmt.Errorf("cannot diff: new leaves map is nil")
	}

	diff := &DagDiff{
		Diffs: make(map[string]*LeafDiff),
		Summary: DiffSummary{
			Added:   0,
			Removed: 0,
			Total:   0,
		},
	}

	// Create map of hash -> leaf for old DAG
	oldLeafs := make(map[string]*dag.DagLeaf)
	for hash, leaf := range originalDag.Leafs {
		oldLeafs[hash] = leaf
	}

	// Create map of hash -> leaf for new leaves
	newLeafsMap := make(map[string]*dag.DagLeaf)
	var newRoot *dag.DagLeaf
	var newRootHash string
	for hash, leaf := range newLeaves {
		newLeafsMap[hash] = leaf

		// Only the root leaf has a LeafCount (>= 1). Pick deterministically (by
		// highest LeafCount, then smallest hash) so malformed input can't yield a
		// nondeterministic root from map iteration order.
		if leaf.LeafCount > 0 {
			if newRoot == nil || leaf.LeafCount > newRoot.LeafCount ||
				(leaf.LeafCount == newRoot.LeafCount && hash < newRootHash) {
				newRoot = leaf
				newRootHash = hash
			}
		}
	}

	// Find added leaves (in new but not in old)
	for hash, newLeaf := range newLeafsMap {
		if _, existsInOld := oldLeafs[hash]; !existsInOld {
			diff.Diffs[hash] = &LeafDiff{
				Type: DiffTypeAdded,
				Hash: hash,
				Leaf: newLeaf,
			}
			diff.Summary.Added++
			diff.Summary.Total++
		}
	}

	// Find removed leaves - these are old leaves that are NOT reachable from the new root
	// Build the set of all hashes reachable from new root
	reachableFromNew := make(map[string]bool)
	if newRoot != nil {
		var traverse func(hash string)
		traverse = func(hash string) {
			if reachableFromNew[hash] {
				return
			}
			reachableFromNew[hash] = true

			// Look for this leaf in both old and new
			var leaf *dag.DagLeaf
			if l, exists := newLeafsMap[hash]; exists {
				leaf = l
			} else if l, exists := oldLeafs[hash]; exists {
				leaf = l
			}

			if leaf != nil {
				for _, childHash := range leaf.Links {
					traverse(childHash)
				}
			}
		}
		traverse(newRootHash)
	}

	// Any old leaf not reachable from new root is removed
	for hash, oldLeaf := range oldLeafs {
		if !reachableFromNew[hash] {
			diff.Diffs[hash] = &LeafDiff{
				Type: DiffTypeRemoved,
				Hash: hash,
				Leaf: oldLeaf,
			}
			diff.Summary.Removed++
			diff.Summary.Total++
		}
	}

	return diff, nil
}
