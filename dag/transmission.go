package dag

import (
	"fmt"
	"sort"

	merkle_tree "github.com/HORNET-Storage/Scionic-Merkle-Tree/v2/tree"
)

// getPartialLeafSequence packages partial DAG leaves for transmission in BFS order
// Proofs are already embedded from GetPartial, just preserve structure
func (d *Dag) getPartialLeafSequence() []*TransmissionPacket {
	var sequence []*TransmissionPacket

	// Get the root leaf
	rootLeaf := d.Leafs[d.Root]
	if rootLeaf == nil {
		return sequence
	}

	visited := make(map[string]bool)

	// Create root packet - preserve all links and proofs
	rootPacket := &TransmissionPacket{
		Leaf:       rootLeaf.Clone(), // Clone preserves links and proofs
		ParentHash: "",               // Root has no parent
		Proofs:     make(map[string]*ClassicTreeBranch),
	}
	sequence = append(sequence, rootPacket)
	visited[d.Root] = true

	// BFS traversal to ensure parent comes before children
	queue := []string{d.Root}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		currentLeaf := d.Leafs[current]

		// Sort links for deterministic order
		var sortedLinks []string
		sortedLinks = append(sortedLinks, currentLeaf.Links...)
		sort.Strings(sortedLinks)

		// Process each child that exists in this partial DAG
		for _, childHash := range sortedLinks {
			if !visited[childHash] {
				childLeaf := d.Leafs[childHash]
				if childLeaf == nil {
					// Child not in partial - that's fine, link preserved for receiver
					continue
				}

				// Clone the leaf - preserves links and embedded proofs
				leafClone := childLeaf.Clone()

				// Extract the proof for this child from parent's proofs
				var childProof *ClassicTreeBranch
				if currentLeaf.Proofs != nil {
					if proof, exists := currentLeaf.Proofs[childHash]; exists {
						childProof = proof
					}
				}

				// Validate proof exists if parent has multiple children
				if len(currentLeaf.Links) > 1 && childProof == nil {
					// This is a validation error - partial was created incorrectly
					fmt.Printf("Warning: Missing proof for child %s of parent %s with %d children\n",
						childHash[:12], current[:12], len(currentLeaf.Links))
				}

				packet := &TransmissionPacket{
					Leaf:       leafClone,
					ParentHash: current,
					Proofs:     make(map[string]*ClassicTreeBranch),
				}

				// Add the proof to the packet if it exists
				if childProof != nil {
					packet.Proofs[childHash] = childProof
				}

				sequence = append(sequence, packet)
				visited[childHash] = true
				queue = append(queue, childHash)
			}
		}
	}

	return sequence
}

// GetLeafSequence returns leaves in transmission order (BFS) with parent refs and proofs
func (d *Dag) GetLeafSequence() []*TransmissionPacket {
	// Check if this is a partial DAG
	if d.IsPartial() {
		// Use specialized method for partial DAGs
		return d.getPartialLeafSequence()
	}

	// For full DAGs, we need to:
	// 1. Build Merkle proofs for each child
	// 2. Preserve all links (needed for reconstruction)
	// 3. Ensure root-first BFS ordering so receiver has parent before children

	var sequence []*TransmissionPacket
	visited := make(map[string]bool)

	rootLeaf := d.Leafs[d.Root]
	if rootLeaf == nil {
		return sequence
	}

	// Create root packet - preserve links
	rootPacket := &TransmissionPacket{
		Leaf:       rootLeaf.Clone(), // Clone preserves links
		ParentHash: "",
		Proofs:     make(map[string]*ClassicTreeBranch),
	}
	sequence = append(sequence, rootPacket)
	visited[d.Root] = true

	// BFS traversal to ensure parent comes before children
	queue := []string{d.Root}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		currentLeaf := d.Leafs[current]

		// Sort links for deterministic order
		var sortedLinks []string
		sortedLinks = append(sortedLinks, currentLeaf.Links...)
		sort.Strings(sortedLinks)

		// Process each child
		for _, childHash := range sortedLinks {
			if !visited[childHash] {
				childLeaf := d.Leafs[childHash]
				if childLeaf == nil {
					continue
				}

				// Build Merkle proof for this child
				branch, err := d.buildVerificationBranch(childLeaf)
				if err != nil {
					// If we can't build proof, skip this leaf
					continue
				}

				// Clone the leaf - preserves links
				leafClone := childLeaf.Clone()

				packet := &TransmissionPacket{
					Leaf:       leafClone,
					ParentHash: current,
					Proofs:     make(map[string]*ClassicTreeBranch),
				}

				// Extract proofs from the verification branch
				// The branch contains proofs at each level from leaf to root
				for _, pathNode := range branch.Path {
					if pathNode.Proofs != nil {
						for k, v := range pathNode.Proofs {
							packet.Proofs[k] = v
						}
					}
				}

				sequence = append(sequence, packet)
				visited[childHash] = true
				queue = append(queue, childHash)
			}
		}
	}

	return sequence
}

func (d *Dag) VerifyTransmissionPacket(packet *TransmissionPacket) error {
	if packet.ParentHash == "" {
		if err := packet.Leaf.VerifyRootLeaf(nil); err != nil {
			return fmt.Errorf("transmission packet root leaf verification failed: %w", err)
		}
	} else {
		if err := packet.Leaf.VerifyLeaf(); err != nil {
			return fmt.Errorf("transmission packet leaf verification failed: %w", err)
		}

		if parent, exists := d.Leafs[packet.ParentHash]; exists && len(parent.Links) > 1 {
			proof, hasProof := packet.Proofs[packet.Leaf.Hash]
			if !hasProof {
				return fmt.Errorf("missing merkle proof for leaf %s in transmission packet", packet.Leaf.Hash)
			}

			if err := parent.VerifyBranch(proof); err != nil {
				return fmt.Errorf("invalid merkle proof for leaf %s: %w", packet.Leaf.Hash, err)
			}
		}
	}

	return nil
}

func (d *Dag) ApplyTransmissionPacket(packet *TransmissionPacket) {
	// Add the leaf to the DAG with all its links preserved
	d.Leafs[packet.Leaf.Hash] = packet.Leaf

	// Establish parent-child relationship
	// Note: For partial DAGs, the parent already has the link in its Links array
	// For full DAGs, we ensure the link exists
	if packet.ParentHash != "" {
		if parent, exists := d.Leafs[packet.ParentHash]; exists {
			if !parent.HasLink(packet.Leaf.Hash) {
				parent.AddLink(packet.Leaf.Hash)
			}
		}
	}

	// Apply proofs from the packet to parent leaves
	// This is important for partial DAGs where proofs come in the packet
	// For full DAGs, proofs are also provided in packets for verification
	for leafHash, proof := range packet.Proofs {
		// Find the parent leaf that has this child
		for _, leaf := range d.Leafs {
			if leaf.HasLink(leafHash) {
				if leaf.Proofs == nil {
					leaf.Proofs = make(map[string]*ClassicTreeBranch)
				}
				leaf.Proofs[leafHash] = proof
				break
			}
		}
	}
}

func (d *Dag) ApplyAndVerifyTransmissionPacket(packet *TransmissionPacket) error {
	if err := d.VerifyTransmissionPacket(packet); err != nil {
		return err
	}

	d.ApplyTransmissionPacket(packet)
	return nil
}

func (d *Dag) RemoveAllContent() {
	for _, leaf := range d.Leafs {
		leaf.Content = nil
	}
}

// GetBatchedLeafSequence groups leaves into batches up to BatchSize for efficient transmission
func (d *Dag) GetBatchedLeafSequence() []*BatchedTransmissionPacket {
	// If batch size is disabled, fall back to individual packets (one leaf per packet)
	if BatchSize <= 0 {
		individualPackets := d.GetLeafSequence()
		var batchedPackets []*BatchedTransmissionPacket
		for i, packet := range individualPackets {
			batchedPackets = append(batchedPackets, &BatchedTransmissionPacket{
				Leaves:        []*DagLeaf{packet.Leaf},
				Relationships: map[string]string{packet.Leaf.Hash: packet.ParentHash},
				PacketIndex:   i,
				TotalPackets:  len(individualPackets),
			})
		}
		return batchedPackets
	}

	// Batched transmission works for both partial and full DAGs
	// Goal: Pack as many leaves as possible per packet while maintaining BFS order
	// BFS guarantees parent always comes before or with children

	var batches []*BatchedTransmissionPacket
	visited := make(map[string]bool)

	rootLeaf := d.Leafs[d.Root]
	if rootLeaf == nil {
		return batches
	}

	// Start first batch with root
	currentBatch := d.createNewBatch()
	currentBatchSize := 0

	// Add root to first batch
	rootClone := rootLeaf.Clone()
	currentBatch.Leaves = append(currentBatch.Leaves, rootClone)
	currentBatch.Relationships[rootClone.Hash] = "" // Root has no parent
	currentBatchSize += rootClone.EstimateSize()
	visited[d.Root] = true

	// Track which parent hashes are in the current batch for proof optimization
	parentsInBatch := make(map[string]bool)
	parentsInBatch[d.Root] = true

	// BFS traversal
	queue := []string{d.Root}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		currentLeaf := d.Leafs[current]
		if currentLeaf == nil {
			continue
		}

		// Sort children for deterministic order
		var sortedChildren []string
		sortedChildren = append(sortedChildren, currentLeaf.Links...)
		sort.Strings(sortedChildren)

		// Process each child
		for _, childHash := range sortedChildren {
			if visited[childHash] {
				continue
			}

			childLeaf := d.Leafs[childHash]
			if childLeaf == nil {
				// Child not in this DAG (normal for partials with pruneLinks=false)
				continue
			}

			childClone := childLeaf.Clone()
			childSize := childClone.EstimateSize()

			// Check if adding this child would exceed batch size
			if currentBatchSize+childSize > BatchSize && len(currentBatch.Leaves) > 0 {
				// Finalize current batch and start new one
				d.finalizeBatch(currentBatch, parentsInBatch)
				batches = append(batches, currentBatch)

				currentBatch = d.createNewBatch()
				currentBatchSize = 0
				parentsInBatch = make(map[string]bool)
			}

			// Add child to current batch
			currentBatch.Leaves = append(currentBatch.Leaves, childClone)
			currentBatch.Relationships[childClone.Hash] = current
			currentBatchSize += childSize
			visited[childHash] = true
			parentsInBatch[childHash] = true
			queue = append(queue, childHash)
		}
	}

	// Finalize last batch
	if len(currentBatch.Leaves) > 0 {
		d.finalizeBatch(currentBatch, parentsInBatch)
		batches = append(batches, currentBatch)
	}

	// Set packet indices and total count
	for i := range batches {
		batches[i].PacketIndex = i
		batches[i].TotalPackets = len(batches)
	}

	return batches
}

func (d *Dag) createNewBatch() *BatchedTransmissionPacket {
	return &BatchedTransmissionPacket{
		Leaves:        make([]*DagLeaf, 0),
		Relationships: make(map[string]string),
	}
}

// finalizeBatch ensures parent leaves have proofs for ALL children (or clears if all present)
func (d *Dag) finalizeBatch(batch *BatchedTransmissionPacket, parentsInBatch map[string]bool) {
	// Build map of parent -> children IN THIS BATCH
	parentChildrenInBatch := make(map[string][]string)
	for childHash, parentHash := range batch.Relationships {
		if parentHash == "" {
			continue // Skip root
		}
		parentChildrenInBatch[parentHash] = append(parentChildrenInBatch[parentHash], childHash)
	}

	// Check if this is a partial DAG
	isPartial := d.IsPartial()

	// For each parent IN THIS BATCH, ensure it has proofs for ALL its children
	// BFS guarantees parent comes before children, so we set proofs when we see the parent
	for parentHash := range parentsInBatch {
		// Find the parent leaf IN THE BATCH (it's a clone, so we need to find it)
		var parentLeafInBatch *DagLeaf
		for _, leaf := range batch.Leaves {
			if leaf.Hash == parentHash {
				parentLeafInBatch = leaf
				break
			}
		}
		if parentLeafInBatch == nil {
			continue
		}

		// Get the original parent from the DAG to access its links
		originalParent := d.Leafs[parentHash]
		if originalParent == nil {
			continue
		}

		// Count total children of this parent using CurrentLinkCount
		// (Links may be pruned in partial DAGs, but CurrentLinkCount preserves original count)
		totalChildren := originalParent.CurrentLinkCount

		// Skip if parent has no children or only one child (no proofs needed)
		if totalChildren <= 1 {
			continue
		}

		// Check if ALL children are in this batch with the parent
		childrenInThisBatch := parentChildrenInBatch[parentHash]
		allChildrenPresent := len(childrenInThisBatch) == totalChildren

		if allChildrenPresent {
			// All children in this batch - receiver can do full Merkle verification by
			// rebuilding the tree from all children and comparing to ClassicMerkleRoot
			// Clear any proofs from the parent for efficiency
			parentLeafInBatch.Proofs = nil
			continue
		}

		// Not all children in this batch
		// Parent must have proofs for ALL children so they can be verified when they arrive

		if isPartial {
			// Partial DAG: proofs should already be in original parent leaf
			if len(originalParent.Proofs) == 0 {
				fmt.Printf("Warning: Partial DAG parent %s missing proofs for children\n", parentHash[:12])
				continue
			}

			// Copy ALL proofs from original parent to the parent in the batch
			if parentLeafInBatch.Proofs == nil {
				parentLeafInBatch.Proofs = make(map[string]*ClassicTreeBranch)
			}
			for childHash, proof := range originalParent.Proofs {
				parentLeafInBatch.Proofs[childHash] = proof
			}
		} else {
			// Full DAG: compute Merkle tree to generate proofs for ALL children
			builder := merkle_tree.CreateTree()

			// Add all children of this parent to the tree (in sorted order)
			sortedLinks := make([]string, len(originalParent.Links))
			copy(sortedLinks, originalParent.Links)
			sort.Strings(sortedLinks)

			for _, linkHash := range sortedLinks {
				builder.AddLeaf(linkHash, linkHash)
			}

			// Build the tree
			merkleTree, _, err := builder.Build()
			if err != nil {
				fmt.Printf("Warning: Failed to build Merkle tree for parent %s: %v\n", parentHash[:12], err)
				continue
			}

			// Generate proofs for ALL children and store in parent leaf in batch
			if parentLeafInBatch.Proofs == nil {
				parentLeafInBatch.Proofs = make(map[string]*ClassicTreeBranch)
			}
			for _, linkHash := range sortedLinks {
				// Find the index of this child in the tree
				index, exists := merkleTree.GetIndexForKey(linkHash)
				if exists && index < len(merkleTree.Proofs) {
					parentLeafInBatch.Proofs[linkHash] = &ClassicTreeBranch{
						Leaf:  linkHash,
						Proof: merkleTree.Proofs[index],
					}
				}
			}
		}
	}
}

func (d *Dag) VerifyBatchedTransmissionPacket(packet *BatchedTransmissionPacket) error {
	// Build a map of leaves in this batch for quick lookup
	batchLeaves := make(map[string]*DagLeaf)
	for _, leaf := range packet.Leaves {
		batchLeaves[leaf.Hash] = leaf
	}

	// Track parents whose full child set we've already checked, to verify each
	// complete parent's Merkle root exactly once.
	verifiedParents := make(map[string]bool)

	// Verify each leaf in the batch
	for _, childLeaf := range packet.Leaves {
		childHash := childLeaf.Hash
		parentHash, exists := packet.Relationships[childHash]
		if !exists {
			return fmt.Errorf("missing relationship for leaf %s", childHash)
		}

		if parentHash == "" {
			// Root leaf
			tempDag := &Dag{
				Root:  childLeaf.Hash,
				Leafs: make(map[string]*DagLeaf),
			}
			tempDag.Leafs[childLeaf.Hash] = childLeaf

			if err := childLeaf.VerifyRootLeaf(tempDag); err != nil {
				return fmt.Errorf("batched transmission packet root leaf %s verification failed: %w", childHash, err)
			}
		} else {
			// Non-root leaf - verify its internal structure
			if err := childLeaf.VerifyLeaf(); err != nil {
				return fmt.Errorf("batched transmission packet leaf %s verification failed: %w", childHash, err)
			}

			// Find the parent - either from this batch or from DAG (previous batch)
			var parentLeaf *DagLeaf
			var parentFromBatch bool

			if batchParent, exists := batchLeaves[parentHash]; exists {
				// Parent is in this batch
				parentLeaf = batchParent
				parentFromBatch = true
			} else if dagParent, exists := d.Leafs[parentHash]; exists {
				// Parent is in DAG (from previous batch)
				parentLeaf = dagParent
				parentFromBatch = false
			} else {
				return fmt.Errorf("parent %s not found in DAG or batch for leaf %s", parentHash, childHash)
			}

			// Verify merkle proof if parent has multiple children
			if len(parentLeaf.Links) > 1 {
				// Check if parent has proofs (if not, all children are in this batch)
				if len(parentLeaf.Proofs) == 0 {
					// No proofs means all children are in this batch with the
					// parent. Verify the parent's Merkle root against its full child
					// set now (once per parent) so a forged child is rejected here,
					// not only by a later Dag.Verify().
					if !verifiedParents[parentHash] {
						if err := parentLeaf.VerifyChildrenAgainstMerkleRoot(d); err != nil {
							return fmt.Errorf("parent %s merkle root verification failed: %w", parentHash, err)
						}
						verifiedParents[parentHash] = true
					}
					continue
				}

				// Get proof from parent's Proofs map
				proof, hasProof := parentLeaf.Proofs[childHash]
				if !hasProof {
					// If parent is from batch and has some proofs but not for this child,
					// it means this child is in the batch with all its siblings (no proof needed)
					if parentFromBatch {
						continue
					}
					return fmt.Errorf("missing merkle proof for child %s in parent %s", childHash, parentHash[:12])
				}

				if err := parentLeaf.VerifyBranch(proof); err != nil {
					return fmt.Errorf("invalid merkle proof for leaf %s: %w", childHash, err)
				}
			}
		}
	}

	return nil
}

func (d *Dag) ApplyBatchedTransmissionPacket(packet *BatchedTransmissionPacket) {
	parentsToUpdate := make(map[string]bool)

	for _, leaf := range packet.Leaves {
		// Check if leaf already exists
		if existingLeaf, exists := d.Leafs[leaf.Hash]; exists {
			// Merge links from the new leaf into the existing one
			if existingLeaf.Links == nil {
				existingLeaf.Links = make([]string, 0)
			}
			// Add any links that don't already exist
			for _, v := range leaf.Links {
				if !existingLeaf.HasLink(v) {
					existingLeaf.AddLink(v)
				}
			}
			// Merge proofs from the new leaf into the existing one
			if existingLeaf.Proofs == nil {
				existingLeaf.Proofs = make(map[string]*ClassicTreeBranch)
			}
			for k, v := range leaf.Proofs {
				existingLeaf.Proofs[k] = v
			}
			// Update other fields if needed (Merkle tree, etc.)
			if leaf.MerkleTree != nil {
				existingLeaf.MerkleTree = leaf.MerkleTree
				existingLeaf.LeafMap = leaf.LeafMap
				existingLeaf.ClassicMerkleRoot = leaf.ClassicMerkleRoot
			}
			// Don't overwrite the existing leaf, just update it
		} else {
			// Leaf doesn't exist, add it
			d.Leafs[leaf.Hash] = leaf
		}

		// Update parent links
		if parentHash, exists := packet.Relationships[leaf.Hash]; exists && parentHash != "" {
			if parent, parentExists := d.Leafs[parentHash]; parentExists {
				if !parent.HasLink(leaf.Hash) {
					parent.AddLink(leaf.Hash)
					parentsToUpdate[parentHash] = true
				}
			}
		}
	}

	// Note: Proofs are already embedded in parent leaves from finalizeBatch
	// No need to apply them separately - they come with the parent leaf
}

func (d *Dag) ApplyAndVerifyBatchedTransmissionPacket(packet *BatchedTransmissionPacket) error {
	if err := d.VerifyBatchedTransmissionPacket(packet); err != nil {
		return err
	}

	d.ApplyBatchedTransmissionPacket(packet)
	return nil
}

// GetRootLeaf returns the root leaf from the batch.
// The root leaf is the one with an empty parent in the Relationships map.
func (packet *BatchedTransmissionPacket) GetRootLeaf() *DagLeaf {
	if packet == nil || len(packet.Leaves) == 0 {
		return nil
	}

	// The root is the leaf whose parent hash is empty string
	for _, leaf := range packet.Leaves {
		if parentHash, exists := packet.Relationships[leaf.Hash]; exists && parentHash == "" {
			return leaf
		}
	}

	// Fallback to first leaf (shouldn't happen in properly formed packets)
	return packet.Leaves[0]
}
