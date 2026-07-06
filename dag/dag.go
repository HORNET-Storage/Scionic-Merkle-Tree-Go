package dag

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	merkle_tree "github.com/HORNET-Storage/Scionic-Merkle-Tree/v2/tree"
)

type fileInfoDirEntry struct {
	fileInfo os.FileInfo
}

func (e fileInfoDirEntry) Name() string {
	return e.fileInfo.Name()
}

func (e fileInfoDirEntry) IsDir() bool {
	return e.fileInfo.IsDir()
}

func (e fileInfoDirEntry) Type() fs.FileMode {
	return e.fileInfo.Mode().Type()
}

func (e fileInfoDirEntry) Info() (fs.FileInfo, error) {
	return e.fileInfo, nil
}

func newDirEntry(path string) (fs.DirEntry, error) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	return fileInfoDirEntry{fileInfo: fileInfo}, nil
}

func CreateDag(path string, timestampRoot bool) (*Dag, error) {
	var additionalData map[string]string = nil

	if timestampRoot {
		currentTime := time.Now().UTC()
		timeString := currentTime.Format(time.RFC3339)
		additionalData = map[string]string{
			"timestamp": timeString,
		}
	}

	dag, err := createDag(path, additionalData, nil)
	if err != nil {
		return nil, err
	}

	return dag, nil
}

func CreateDagAdvanced(path string, additionalData map[string]string) (*Dag, error) {
	dag, err := createDag(path, additionalData, nil)
	if err != nil {
		return nil, err
	}

	return dag, nil
}

func CreateDagCustom(path string, rootAdditionalData map[string]string, processor LeafProcessor) (*Dag, error) {
	dag, err := createDag(path, rootAdditionalData, processor)
	if err != nil {
		return nil, err
	}

	return dag, nil
}

func CreateDagWithConfig(path string, config *DagBuilderConfig) (*Dag, error) {
	if config == nil {
		config = DefaultConfig()
	}

	var additionalData map[string]string = config.AdditionalData
	if config.TimestampRoot {
		currentTime := time.Now().UTC()
		timeString := currentTime.Format(time.RFC3339)
		additionalData = map[string]string{
			"timestamp": timeString,
		}
	}

	if config.EnableParallel {
		return createDagParallel(path, additionalData, config.Processor, config)
	}

	dag, err := createDag(path, additionalData, config.Processor)
	if err != nil {
		return nil, err
	}

	return dag, nil
}

func createDag(path string, additionalData map[string]string, processor LeafProcessor) (*Dag, error) {
	dag := CreateDagBuilder()

	fileInfo, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	dirEntry, err := newDirEntry(path)
	if err != nil {
		return nil, err
	}

	parentPath := filepath.Dir(path)

	var leaf *DagLeaf

	if fileInfo.IsDir() {
		leaf, err = processDirectory(dirEntry, path, &parentPath, dag, true, additionalData, processor)
	} else {
		leaf, err = processFile(dirEntry, path, &parentPath, dag, true, additionalData, processor)
	}

	if err != nil {
		return nil, err
	}

	rootBuilder := CreateDagLeafBuilder(leaf.ItemName)
	rootBuilder.SetType(leaf.Type)

	for _, linkHash := range leaf.Links {
		rootBuilder.AddLink(linkHash)
	}

	if leaf.Content != nil {
		rootBuilder.SetData(leaf.Content)
	}

	rootLeaf, err := rootBuilder.BuildRootLeaf(dag, additionalData)
	if err != nil {
		return nil, err
	}

	// Add the root leaf to the builder
	dag.Leafs[rootLeaf.Hash] = rootLeaf

	return dag.BuildDag(rootLeaf.Hash), nil
}

// createDagParallel creates a DAG using parallel processing
func createDagParallel(path string, additionalData map[string]string, processor LeafProcessor, config *DagBuilderConfig) (*Dag, error) {
	dag := CreateDagBuilder()

	fileInfo, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	dirEntry, err := newDirEntry(path)
	if err != nil {
		return nil, err
	}

	parentPath := filepath.Dir(path)

	var leaf *DagLeaf

	if fileInfo.IsDir() {
		leaf, err = processDirectoryParallel(dirEntry, path, &parentPath, dag, true, additionalData, processor, config)
	} else {
		leaf, err = processFileParallel(dirEntry, path, &parentPath, dag, true, additionalData, processor, config)
	}

	if err != nil {
		return nil, err
	}

	rootBuilder := CreateDagLeafBuilder(leaf.ItemName)
	rootBuilder.SetType(leaf.Type)

	for _, linkHash := range leaf.Links {
		rootBuilder.AddLink(linkHash)
	}

	if leaf.Content != nil {
		rootBuilder.SetData(leaf.Content)
	}

	rootLeaf, err := rootBuilder.BuildRootLeaf(dag, additionalData)
	if err != nil {
		return nil, err
	}

	// Add the root leaf to the builder
	dag.mu.Lock()
	dag.Leafs[rootLeaf.Hash] = rootLeaf
	dag.mu.Unlock()

	return dag.BuildDag(rootLeaf.Hash), nil
}

func processEntry(entry fs.DirEntry, fullPath string, path *string, dag *DagBuilder, processor LeafProcessor) (*DagLeaf, error) {
	var result *DagLeaf
	var err error

	if entry.IsDir() {
		result, err = processDirectory(entry, fullPath, path, dag, false, nil, processor)
	} else {
		result, err = processFile(entry, fullPath, path, dag, false, nil, processor)
	}

	if err != nil {
		return nil, err
	}

	return result, nil
}

func processDirectory(entry fs.DirEntry, fullPath string, path *string, dag *DagBuilder, isRoot bool, additionalData map[string]string, processor LeafProcessor) (*DagLeaf, error) {
	relPath, err := filepath.Rel(*path, fullPath)
	if err != nil {
		return nil, err
	}

	// Apply processor if provided and not root (root uses additionalData directly)
	if processor != nil && !isRoot {
		customData := processor(fullPath, relPath, entry, isRoot, DirectoryLeafType)
		if customData != nil {
			// Create additionalData if it's nil
			if additionalData == nil {
				additionalData = make(map[string]string)
			}

			// Merge custom data
			for k, v := range customData {
				additionalData[k] = v
			}
		}
	}

	builder := CreateDagLeafBuilder(relPath)
	builder.SetType(DirectoryLeafType)

	entries, err := os.ReadDir(fullPath)
	if err != nil {
		return nil, err
	}

	var result *DagLeaf

	for _, childEntry := range entries {
		leaf, err := processEntry(childEntry, filepath.Join(fullPath, childEntry.Name()), &fullPath, dag, processor)
		if err != nil {
			return nil, err
		}

		builder.AddLink(leaf.Hash)
		dag.AddLeaf(leaf, nil)
	}

	result, err = builder.BuildLeaf(additionalData)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func processFile(entry fs.DirEntry, fullPath string, path *string, dag *DagBuilder, isRoot bool, additionalData map[string]string, processor LeafProcessor) (*DagLeaf, error) {
	relPath, err := filepath.Rel(*path, fullPath)
	if err != nil {
		return nil, err
	}

	// Apply processor if provided and not root (root uses additionalData directly)
	if processor != nil && !isRoot {
		customData := processor(fullPath, relPath, entry, isRoot, FileLeafType)
		if customData != nil {
			// Create additionalData if it's nil
			if additionalData == nil {
				additionalData = make(map[string]string)
			}

			// Merge custom data
			for k, v := range customData {
				additionalData[k] = v
			}
		}
	}

	var result *DagLeaf
	builder := CreateDagLeafBuilder(relPath)
	builder.SetType(FileLeafType)

	// Use streaming I/O to avoid loading entire file into memory
	// We process chunks incrementally, only keeping one chunk in memory at a time
	var singleChunk []byte
	chunkCount := 0

	streamErr := streamFileChunks(fullPath, ChunkSize, func(chunk []byte, index int) error {
		chunkCount++
		if chunkCount == 1 {
			// Store first chunk - might be the only one
			singleChunk = chunk
			return nil
		}

		// We have multiple chunks - need to process them as child leaves
		if chunkCount == 2 && singleChunk != nil {
			// Process the first chunk we stored earlier
			chunkEntryPath := filepath.Join(relPath, "0")
			chunkBuilder := CreateDagLeafBuilder(chunkEntryPath)
			chunkBuilder.SetType(ChunkLeafType)
			chunkBuilder.SetData(singleChunk)

			chunkLeaf, err := chunkBuilder.BuildLeaf(nil)
			if err != nil {
				return err
			}

			builder.AddLink(chunkLeaf.Hash)
			dag.AddLeaf(chunkLeaf, nil)
			singleChunk = nil // Release memory
		}

		// Process current chunk
		chunkEntryPath := filepath.Join(relPath, strconv.Itoa(index))
		chunkBuilder := CreateDagLeafBuilder(chunkEntryPath)
		chunkBuilder.SetType(ChunkLeafType)
		chunkBuilder.SetData(chunk)

		chunkLeaf, err := chunkBuilder.BuildLeaf(nil)
		if err != nil {
			return err
		}

		builder.AddLink(chunkLeaf.Hash)
		dag.AddLeaf(chunkLeaf, nil)
		return nil
	})
	if streamErr != nil {
		return nil, streamErr
	}

	// If only one chunk, set it as data directly
	if chunkCount == 1 && singleChunk != nil {
		builder.SetData(singleChunk)
	}

	result, err = builder.BuildLeaf(additionalData)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// streamFileChunks reads a file in chunks using streaming I/O, calling the callback for each chunk.
// This is more memory efficient than reading the entire file into memory first.
// If chunkSize <= 0, reads the entire file as a single chunk.
func streamFileChunks(fullPath string, chunkSize int, callback func(chunk []byte, index int) error) error {
	file, err := os.Open(fullPath)
	if err != nil {
		return err
	}
	defer file.Close()

	// If no chunk size specified, read entire file (fallback behavior)
	if chunkSize <= 0 {
		data, err := io.ReadAll(file)
		if err != nil {
			return err
		}
		return callback(data, 0)
	}

	// Stream file in chunks
	buffer := make([]byte, chunkSize)
	index := 0

	for {
		n, err := io.ReadFull(file, buffer)
		if err == io.EOF {
			break
		}
		if err == io.ErrUnexpectedEOF {
			// Partial read - this is the last chunk
			chunk := make([]byte, n)
			copy(chunk, buffer[:n])
			if err := callback(chunk, index); err != nil {
				return err
			}
			break
		}
		if err != nil {
			return err
		}

		// Full chunk read - make a copy since we reuse the buffer
		chunk := make([]byte, n)
		copy(chunk, buffer[:n])
		if err := callback(chunk, index); err != nil {
			return err
		}
		index++
	}

	return nil
}

// processEntryResult holds the result of processing a single entry in parallel
type processEntryResult struct {
	leaf  *DagLeaf
	err   error
	index int
}

// processDirectoryParallel processes a directory using parallel workers
func processDirectoryParallel(entry fs.DirEntry, fullPath string, path *string, dag *DagBuilder, isRoot bool, additionalData map[string]string, processor LeafProcessor, config *DagBuilderConfig) (*DagLeaf, error) {
	relPath, err := filepath.Rel(*path, fullPath)
	if err != nil {
		return nil, err
	}

	// Apply processor if provided
	if processor != nil && !isRoot {
		customData := processor(fullPath, relPath, entry, isRoot, DirectoryLeafType)
		if customData != nil {
			if additionalData == nil {
				additionalData = make(map[string]string)
			}
			for k, v := range customData {
				additionalData[k] = v
			}
		}
	}

	builder := CreateDagLeafBuilder(relPath)
	builder.SetType(DirectoryLeafType)

	entries, err := os.ReadDir(fullPath)
	if err != nil {
		return nil, err
	}

	// Sort entries by name
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})

	// Determine worker count
	maxWorkers := config.MaxWorkers
	if maxWorkers == 0 {
		maxWorkers = runtime.NumCPU()
	} else if maxWorkers < 0 {
		maxWorkers = len(entries)
	}

	// Limit workers to number of entries
	if maxWorkers > len(entries) {
		maxWorkers = len(entries)
	}

	// If only one entry, process sequentially
	if len(entries) <= 1 {
		for _, childEntry := range entries {
			leaf, err := processEntryParallel(childEntry, filepath.Join(fullPath, childEntry.Name()), &fullPath, dag, processor, config)
			if err != nil {
				return nil, err
			}

			builder.AddLink(leaf.Hash)
			dag.AddLeafSafe(leaf, nil)
		}

		var result *DagLeaf
		if isRoot {
			result, err = builder.BuildRootLeaf(dag, additionalData)
		} else {
			result, err = builder.BuildLeaf(additionalData)
		}

		return result, err
	}

	// Process entries in parallel
	jobs := make(chan struct {
		entry fs.DirEntry
		index int
	}, len(entries))
	results := make(chan processEntryResult, len(entries))

	// Start worker pool
	var wg sync.WaitGroup
	for w := 0; w < maxWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				leaf, err := processEntryParallel(job.entry, filepath.Join(fullPath, job.entry.Name()), &fullPath, dag, processor, config)
				results <- processEntryResult{
					leaf:  leaf,
					err:   err,
					index: job.index,
				}
			}
		}()
	}

	// Send jobs (already sorted)
	for i, e := range entries {
		jobs <- struct {
			entry fs.DirEntry
			index int
		}{entry: e, index: i}
	}
	close(jobs)

	// Wait for all workers to finish
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results and sort by original index to maintain determinism
	resultSlice := make([]processEntryResult, 0, len(entries))
	for result := range results {
		resultSlice = append(resultSlice, result)
	}

	// Sort results by original index
	sort.Slice(resultSlice, func(i, j int) bool {
		return resultSlice[i].index < resultSlice[j].index
	})

	// Apply results in sorted order
	for _, result := range resultSlice {
		if result.err != nil {
			return nil, result.err
		}

		builder.AddLink(result.leaf.Hash)
		dag.AddLeafSafe(result.leaf, nil)
	}

	finalResult, err := builder.BuildLeaf(additionalData)
	if err != nil {
		return nil, err
	}

	return finalResult, nil
}

// processEntryParallel is the parallel version of processEntry
func processEntryParallel(entry fs.DirEntry, fullPath string, path *string, dag *DagBuilder, processor LeafProcessor, config *DagBuilderConfig) (*DagLeaf, error) {
	var result *DagLeaf
	var err error

	if entry.IsDir() {
		result, err = processDirectoryParallel(entry, fullPath, path, dag, false, nil, processor, config)
	} else {
		result, err = processFileParallel(entry, fullPath, path, dag, false, nil, processor, config)
	}

	if err != nil {
		return nil, err
	}

	return result, nil
}

// processFileParallel processes a file (parallel mode)
func processFileParallel(entry fs.DirEntry, fullPath string, path *string, dag *DagBuilder, isRoot bool, additionalData map[string]string, processor LeafProcessor, config *DagBuilderConfig) (*DagLeaf, error) {
	relPath, err := filepath.Rel(*path, fullPath)
	if err != nil {
		return nil, err
	}

	// Apply processor if provided and not root
	if processor != nil && !isRoot {
		customData := processor(fullPath, relPath, entry, isRoot, FileLeafType)
		if customData != nil {
			if additionalData == nil {
				additionalData = make(map[string]string)
			}
			for k, v := range customData {
				additionalData[k] = v
			}
		}
	}

	var result *DagLeaf
	builder := CreateDagLeafBuilder(relPath)
	builder.SetType(FileLeafType)

	// Use streaming I/O to avoid loading entire file into memory
	// We process chunks incrementally, only keeping one chunk in memory at a time
	var singleChunk []byte
	chunkCount := 0

	streamErr := streamFileChunks(fullPath, ChunkSize, func(chunk []byte, index int) error {
		chunkCount++
		if chunkCount == 1 {
			// Store first chunk - might be the only one
			singleChunk = chunk
			return nil
		}

		// We have multiple chunks - need to process them as child leaves
		if chunkCount == 2 && singleChunk != nil {
			// Process the first chunk we stored earlier
			// Use simple numeric string as ItemName for chunks
			chunkBuilder := CreateDagLeafBuilder("0")
			chunkBuilder.SetType(ChunkLeafType)
			chunkBuilder.SetData(singleChunk)

			chunkLeaf, err := chunkBuilder.BuildLeaf(nil)
			if err != nil {
				return err
			}

			builder.AddLink(chunkLeaf.Hash)
			dag.AddLeafSafe(chunkLeaf, nil)
			singleChunk = nil // Release memory
		}

		// Process current chunk
		chunkItemName := strconv.Itoa(index)
		chunkBuilder := CreateDagLeafBuilder(chunkItemName)
		chunkBuilder.SetType(ChunkLeafType)
		chunkBuilder.SetData(chunk)

		chunkLeaf, err := chunkBuilder.BuildLeaf(nil)
		if err != nil {
			return err
		}

		builder.AddLink(chunkLeaf.Hash)
		dag.AddLeafSafe(chunkLeaf, nil)
		return nil
	})
	if streamErr != nil {
		return nil, streamErr
	}

	// If only one chunk, set it as data directly
	if chunkCount == 1 && singleChunk != nil {
		builder.SetData(singleChunk)
	}

	result, err = builder.BuildLeaf(additionalData)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func CreateDagBuilder() *DagBuilder {
	return &DagBuilder{
		Leafs: map[string]*DagLeaf{},
	}
}

// AddLeafSafe is a thread-safe version of AddLeaf for parallel processing
func (b *DagBuilder) AddLeafSafe(leaf *DagLeaf, parentLeaf *DagLeaf) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.addLeafUnsafe(leaf, parentLeaf)
}

// addLeafUnsafe is the internal implementation without locking
func (b *DagBuilder) addLeafUnsafe(leaf *DagLeaf, parentLeaf *DagLeaf) error {
	if parentLeaf != nil {
		// Check if link already exists
		if !parentLeaf.HasLink(leaf.Hash) {
			parentLeaf.AddLink(leaf.Hash)
		}

		// If parent has more than one link, rebuild its merkle tree
		if len(parentLeaf.Links) > 1 {
			builder := merkle_tree.CreateTree()
			for _, link := range parentLeaf.Links {
				builder.AddLeaf(link, link)
			}

			merkleTree, leafMap, err := builder.Build()
			if err == nil {
				parentLeaf.MerkleTree = merkleTree
				parentLeaf.LeafMap = leafMap
				parentLeaf.ClassicMerkleRoot = merkleTree.Root
			}
		}
	}

	b.Leafs[leaf.Hash] = leaf
	return nil
}

func (b *DagBuilder) AddLeaf(leaf *DagLeaf, parentLeaf *DagLeaf) error {
	return b.addLeafUnsafe(leaf, parentLeaf)
}

func (b *DagBuilder) BuildDag(root string) *Dag {
	return &Dag{
		Leafs: b.Leafs,
		Root:  root,
	}
}

// verifyFullDag verifies a complete DAG by checking parent-child relationships
func (d *Dag) verifyFullDag() error {
	return d.IterateDag(func(leaf *DagLeaf, parent *DagLeaf) error {
		if leaf.Hash == d.Root {
			err := leaf.VerifyRootLeaf(d)
			if err != nil {
				return err
			}
			// Verify root's children against merkle root if we have all children
			if len(leaf.Links) == leaf.CurrentLinkCount && leaf.CurrentLinkCount > 0 {
				if err := leaf.VerifyChildrenAgainstMerkleRoot(d); err != nil {
					return fmt.Errorf("root leaf merkle root verification failed: %w", err)
				}
			}
		} else {
			err := leaf.VerifyLeaf()
			if err != nil {
				return err
			}

			if !parent.HasLink(leaf.Hash) {
				return fmt.Errorf("parent %s does not contain link to child %s", parent.Hash, leaf.Hash)
			}
		}

		// For non-root leaves, verify parent's merkle root if we have all of parent's children
		if parent != nil && len(parent.Links) == parent.CurrentLinkCount && parent.CurrentLinkCount > 0 {
			if err := parent.VerifyChildrenAgainstMerkleRoot(d); err != nil {
				return fmt.Errorf("parent %s merkle root verification failed: %w", parent.Hash, err)
			}
		}

		return nil
	})
}

// verifyWithProofs verifies a partial DAG using stored Merkle proofs
func (d *Dag) verifyWithProofs() error {
	// First verify the root leaf
	rootLeaf := d.Leafs[d.Root]
	if err := rootLeaf.VerifyRootLeaf(d); err != nil {
		return fmt.Errorf("root leaf failed to verify: %w", err)
	}

	// If root has all children in the DAG, verify merkle root
	if len(rootLeaf.Links) == rootLeaf.CurrentLinkCount && rootLeaf.CurrentLinkCount > 0 {
		// Count how many children actually exist in the DAG
		childrenInDag := 0
		for _, childHash := range rootLeaf.Links {
			if _, exists := d.Leafs[childHash]; exists {
				childrenInDag++
			}
		}
		// Check if we have all children
		if childrenInDag == rootLeaf.CurrentLinkCount {
			// All children present, verify merkle root
			if err := rootLeaf.VerifyChildrenAgainstMerkleRoot(d); err != nil {
				return fmt.Errorf("root leaf merkle root verification failed: %w", err)
			}
		} else if rootLeaf.CurrentLinkCount == 1 {
			// Single child case: can't use merkle proofs with only one child
			// The ClassicMerkleRoot should be set to the child's hash directly
			// If child exists, verify it matches; if not, it will be verified when child arrives
			if childrenInDag > 0 {
				// Child exists, verify ClassicMerkleRoot matches child hash
				childHash := rootLeaf.Links[0]
				childLeaf := d.Leafs[childHash]
				if childLeaf != nil {
					// Verify that ClassicMerkleRoot equals the child's hash
					if string(rootLeaf.ClassicMerkleRoot) != childHash {
						return fmt.Errorf("single child verification failed: ClassicMerkleRoot doesn't match child hash")
					}
				}
			}
			// If child doesn't exist yet, verification will happen when it's added
		} else if len(rootLeaf.Proofs) == 0 {
			// Multiple children missing and no proofs - this is a broken DAG
			return fmt.Errorf("broken DAG: root has %d links but only %d children exist in DAG (no proofs available)", rootLeaf.CurrentLinkCount, childrenInDag)
		}
		// Else: children missing but we have proofs - will be verified in loop below
	}

	// Verify each non-root leaf
	for _, leaf := range d.Leafs {
		if leaf.Hash == d.Root {
			continue
		}

		// First verify the leaf itself
		if err := leaf.VerifyLeaf(); err != nil {
			return fmt.Errorf("leaf %s failed to verify: %w", leaf.Hash, err)
		}

		// Then verify the path to root
		current := leaf
		for current.Hash != d.Root {
			// Find parent in this partial DAG
			var parent *DagLeaf
			for _, potential := range d.Leafs {
				if potential.HasLink(current.Hash) {
					parent = potential
					break
				}
			}
			if parent == nil {
				return fmt.Errorf("broken path to root for leaf %s", leaf.Hash)
			}

			// Verify parent leaf
			if parent.Hash != d.Root {
				if err := parent.VerifyLeaf(); err != nil {
					return fmt.Errorf("parent leaf %s failed to verify: %w", parent.Hash, err)
				}
			}

			// Check if we have all of parent's children
			hasAllChildren := len(parent.Links) == parent.CurrentLinkCount

			if hasAllChildren && parent.CurrentLinkCount > 0 {
				// Count how many children actually exist in the DAG
				childrenInDag := 0
				for _, childHash := range parent.Links {
					if _, exists := d.Leafs[childHash]; exists {
						childrenInDag++
					}
				}
				// Check if we have all children
				if childrenInDag == parent.CurrentLinkCount {
					// All children present, verify merkle root
					if err := parent.VerifyChildrenAgainstMerkleRoot(d); err != nil {
						return fmt.Errorf("parent %s merkle root verification failed: %w", parent.Hash, err)
					}
				} else {
					// Some children missing - check if we have a proof for the current child
					if _, hasProof := parent.Proofs[current.Hash]; !hasProof {
						// No proof for current child - this is a broken DAG
						return fmt.Errorf("broken DAG: parent %s has %d links but only %d children exist in DAG (no proof for child %s)", parent.Hash, parent.CurrentLinkCount, childrenInDag, current.Hash)
					}
					// Have proof for current child, verify it
					err := parent.VerifyBranch(parent.Proofs[current.Hash])
					if err != nil {
						return fmt.Errorf("invalid merkle proof for node %s: %w", current.Hash, err)
					}
				}
			} else if parent.CurrentLinkCount > 1 {
				// If we don't have all children, we must use stored proofs
				proof, hasProof := parent.Proofs[current.Hash]

				if !hasProof {
					return fmt.Errorf("missing merkle proof for node %s in partial DAG", current.Hash)
				}

				err := parent.VerifyBranch(proof)
				if err != nil {
					return fmt.Errorf("invalid merkle proof for node %s: %w", current.Hash, err)
				}
			}

			current = parent
		}
	}

	return nil
}

// Verify checks the integrity of the DAG, automatically choosing between full and partial verification
func (d *Dag) Verify() error {
	if d.IsPartial() {
		// Use more thorough verification with proofs for partial DAGs
		return d.verifyWithProofs()
	}
	// Use simpler verification for full DAGs
	return d.verifyFullDag()
}

func (dag *Dag) CreateDirectory(path string) error {
	rootHash := dag.Root
	rootLeaf := dag.Leafs[rootHash]

	err := rootLeaf.CreateDirectoryLeaf(path, dag)
	if err != nil {
		return err
	}

	return nil
}

func ReadDag(path string) (*Dag, error) {
	fileData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("could not read file: %w", err)
	}

	// Use FromCBOR to properly deserialize through SerializableDag
	dag, err := FromCBOR(fileData)
	if err != nil {
		return nil, fmt.Errorf("could not decode Dag: %w", err)
	}

	return dag, nil
}

func (dag *Dag) GetContentFromLeaf(leaf *DagLeaf) ([]byte, error) {
	var content []byte

	if len(leaf.Links) > 0 {
		// For chunked files, sort chunks by ItemName (which is just "0", "1", "2", ...)
		// Create a sortable slice of link info
		type linkInfo struct {
			hash     string
			leaf     *DagLeaf
			itemName string
		}

		links := make([]linkInfo, 0, len(leaf.Links))
		for _, link := range leaf.Links {
			childLeaf := dag.Leafs[link]
			if childLeaf == nil {
				return nil, fmt.Errorf("invalid link: %s", link)
			}

			links = append(links, linkInfo{
				hash:     link,
				leaf:     childLeaf,
				itemName: childLeaf.ItemName,
			})
		}

		// Sort by ItemName (extract numeric part from path-based names like "bundle/0", "bundle/1")
		sort.Slice(links, func(i, j int) bool {
			// Extract the basename (last component) from the path
			baseI := filepath.Base(links[i].itemName)
			baseJ := filepath.Base(links[j].itemName)

			// Convert to int for proper numeric sorting
			numI, errI := strconv.Atoi(baseI)
			numJ, errJ := strconv.Atoi(baseJ)
			if errI != nil || errJ != nil {
				// Fallback to string comparison if conversion fails
				return links[i].itemName < links[j].itemName
			}
			return numI < numJ
		})

		// Concatenate content in sorted order
		for _, linkInfo := range links {
			content = append(content, linkInfo.leaf.Content...)
		}
	} else if len(leaf.Content) > 0 {
		// For single-chunk files, return content directly
		content = leaf.Content
	}

	return content, nil
}

func (d *Dag) IterateDag(processLeaf func(leaf *DagLeaf, parent *DagLeaf) error) error {
	var iterate func(leafHash string, parentHash *string) error
	iterate = func(leafHash string, parentHash *string) error {
		var leaf *DagLeaf
		for hash, l := range d.Leafs {
			if hash == leafHash {
				leaf = l
				break
			}
		}
		if leaf == nil {
			return fmt.Errorf("child is missing when iterating dag (hash: %s)", leafHash)
		}

		var parent *DagLeaf
		if parentHash != nil {
			for hash, l := range d.Leafs {
				if hash == *parentHash {
					parent = l
					break
				}
			}
		}

		err := processLeaf(leaf, parent)
		if err != nil {
			return err
		}

		childHashes := []string{}
		childHashes = append(childHashes, leaf.Links...)

		sort.Slice(childHashes, func(i, j int) bool {
			numI, _ := strconv.Atoi(strings.Split(childHashes[i], ":")[0])
			numJ, _ := strconv.Atoi(strings.Split(childHashes[j], ":")[0])
			return numI < numJ
		})

		for _, childHash := range childHashes {
			err := iterate(childHash, &leaf.Hash)
			if err != nil {
				return err
			}
		}

		return nil
	}

	return iterate(d.Root, nil)
}

// IsPartial returns true if this DAG is a partial DAG (has fewer leaves than the total count)
func (d *Dag) IsPartial() bool {
	// Get the root leaf
	rootLeaf := d.Leafs[d.Root]
	if rootLeaf == nil {
		return true // If root leaf is missing, it's definitely partial
	}

	// Check if the number of leaves in the DAG matches the total leaf count
	return len(d.Leafs) < rootLeaf.LeafCount
}

// pruneIrrelevantLinks removes links that aren't needed for partial verification
func (d *Dag) pruneIrrelevantLinks(relevantHashes map[string]bool) {
	for _, leaf := range d.Leafs {
		// Create new array for relevant links
		prunedLinks := make([]string, 0, len(leaf.Links))

		// Only keep links that are relevant
		for _, hash := range leaf.Links {
			if relevantHashes[hash] {
				prunedLinks = append(prunedLinks, hash)
			}
		}

		// Only modify the Links array, keep everything else as is
		// since they're part of the leaf's identity
		leaf.Links = prunedLinks
	}
}

// compareChunkItemNames orders chunk leaves by the numeric suffix of their
// ItemName (e.g. "file/0", "file/1", ...), falling back to lexical order.
func compareChunkItemNames(a, b string) bool {
	numA, errA := strconv.Atoi(filepath.Base(a))
	numB, errB := strconv.Atoi(filepath.Base(b))
	if errA != nil || errB != nil {
		return a < b
	}
	return numA < numB
}

// safeJoin joins base with a single-component child name, rejecting names that
// contain path separators, are "."/"..", or are absolute. This prevents a
// malicious DAG's ItemName (e.g. "../../etc/passwd") from escaping the target
// directory when a downloaded DAG is reconstructed to disk.
func safeJoin(base, name string) (string, error) {
	if name == "" || name == "." || name == ".." ||
		strings.ContainsAny(name, `/\`) || filepath.IsAbs(name) {
		return "", fmt.Errorf("unsafe item name %q for path reconstruction", name)
	}
	child := filepath.Join(base, name)
	rel, err := filepath.Rel(base, child)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("item name %q escapes the target directory", name)
	}
	return child, nil
}

// buildParentIndex returns a child-hash -> parent-hash map for O(1) parent
// lookups (avoids scanning every leaf for each path step).
func (d *Dag) buildParentIndex() map[string]string {
	parentOf := make(map[string]string, len(d.Leafs))
	for _, leaf := range d.Leafs {
		for _, childHash := range leaf.Links {
			if _, ok := parentOf[childHash]; !ok {
				parentOf[childHash] = leaf.Hash
			}
		}
	}
	return parentOf
}

// buildVerificationBranch creates a branch containing the leaf and its verification path
func (d *Dag) buildVerificationBranch(leaf *DagLeaf) (*DagBranch, error) {
	// Clone the root leaf first to ensure it has all fields
	rootLeaf := d.Leafs[d.Root].Clone()
	parentOf := d.buildParentIndex()

	branch := &DagBranch{
		Leaf: leaf.Clone(),
		Path: make([]*DagLeaf, 0),
	}

	// Always add root leaf to path
	branch.Path = append(branch.Path, rootLeaf)

	// Find path to root through parent nodes
	current := leaf
	for current.Hash != d.Root {
		// Find parent in this partial DAG, not the original
		parentHash, ok := parentOf[current.Hash]
		if !ok {
			return nil, fmt.Errorf("failed to find parent for leaf %s", current.Hash)
		}
		parent := d.Leafs[parentHash]
		if parent == nil {
			return nil, fmt.Errorf("failed to find parent for leaf %s", current.Hash)
		}

		// Clone parent before any modifications
		parentClone := parent.Clone()

		// If parent has multiple children according to CurrentLinkCount,
		// we must generate and store a proof since this is our only chance
		if parent.CurrentLinkCount > 1 {
			// Find the hash for current in parent's links
			var childHash string
			for _, h := range parent.Links {
				if h == current.Hash {
					childHash = h
					break
				}
			}
			if childHash == "" {
				return nil, fmt.Errorf("unable to find child hash for key")
			}

			// Build merkle tree with all current links
			builder := merkle_tree.CreateTree()
			for _, h := range parent.Links {
				builder.AddLeaf(h, h)
			}
			merkleTree, _, err := builder.Build()
			if err != nil {
				return nil, err
			}

			// Get proof for the current leaf
			index, exists := merkleTree.GetIndexForKey(childHash)
			if !exists {
				return nil, fmt.Errorf("unable to find index for key %s", childHash)
			}

			// Store proof in parent clone
			if parentClone.Proofs == nil {
				parentClone.Proofs = make(map[string]*ClassicTreeBranch)
			}

			proof := &ClassicTreeBranch{
				Leaf:  current.Hash,
				Proof: merkleTree.Proofs[index],
			}

			parentClone.Proofs[current.Hash] = proof
		}

		// Always add parent to path so its proofs get merged
		branch.Path = append(branch.Path, parentClone)

		current = parent
	}

	return branch, nil
}

// addBranchToPartial adds a branch to the partial DAG
func (d *Dag) addBranchToPartial(branch *DagBranch, partial *Dag) error {
	// Add leaf if not present
	if _, exists := partial.Leafs[branch.Leaf.Hash]; !exists {
		partial.Leafs[branch.Leaf.Hash] = branch.Leaf
	}

	// Add all path nodes (including root) and merge their proofs
	for i := 0; i < len(branch.Path); i++ {
		pathNode := branch.Path[i]
		if existingNode, exists := partial.Leafs[pathNode.Hash]; exists {
			// Create a new node with merged proofs
			mergedNode := existingNode.Clone()
			if mergedNode.Proofs == nil {
				mergedNode.Proofs = make(map[string]*ClassicTreeBranch)
			}
			if pathNode.Proofs != nil {
				for k, v := range pathNode.Proofs {
					mergedNode.Proofs[k] = v
				}
			}

			// Update the node in the map
			partial.Leafs[pathNode.Hash] = mergedNode

		} else {
			partial.Leafs[pathNode.Hash] = pathNode

		}
	}

	// Now establish the parent-child links along the verification path
	// The path structure is: [root, ..., parent_of_parent, direct_parent]
	// We need to:
	//   1. Link the last path node (direct parent) to the target leaf
	//   2. Link each path node to the next path node (walking from root down)

	// Link the direct parent (last in path) to the target leaf
	if len(branch.Path) > 0 {
		directParentIdx := len(branch.Path) - 1
		directParent := branch.Path[directParentIdx]

		// Check if this parent should link to the leaf
		if directParent.HasLink(branch.Leaf.Hash) {
			if partialNode, exists := partial.Leafs[directParent.Hash]; exists {
				// Ensure the link exists in the partial node
				if !partialNode.HasLink(branch.Leaf.Hash) {
					partialNode.AddLink(branch.Leaf.Hash)
				}
			}
		}
	}

	// Now link each path node to the next one down the path
	// Path is [root, intermediate..., direct_parent]
	// So we walk forward and check if path[i] should link to path[i+1]
	for i := 0; i < len(branch.Path)-1; i++ {
		current := branch.Path[i]
		next := branch.Path[i+1]

		// Check if current should link to next
		if current.HasLink(next.Hash) {
			if partialNode, exists := partial.Leafs[current.Hash]; exists {
				// Ensure the link exists in the partial node
				if !partialNode.HasLink(next.Hash) {
					partialNode.AddLink(next.Hash)
				}
			}
		}
	}

	return nil
}

// GetPartial creates a partial DAG with specified leaves and their verification paths
// pruneLinks: true = remove unreferenced links (verification), false = keep all links (reconstruction)
func (d *Dag) GetPartial(leafHashes []string, pruneLinks bool) (*Dag, error) {
	if len(leafHashes) == 0 {
		return nil, fmt.Errorf("no leaf hashes provided")
	}

	partialDag := &Dag{
		Leafs: make(map[string]*DagLeaf),
		Root:  d.Root,
	}

	// Track hashes that are relevant for verification
	relevantHashes := make(map[string]bool)
	relevantHashes[d.Root] = true

	// Process each requested leaf hash
	for _, requestedHash := range leafHashes {
		// Find the leaf with this hash
		targetLeaf := d.Leafs[requestedHash]

		if targetLeaf == nil {
			return nil, fmt.Errorf("leaf not found: %s", requestedHash)
		}

		// Add target leaf hash to relevant hashes
		relevantHashes[requestedHash] = true

		// Build verification path
		branch, err := d.buildVerificationBranch(targetLeaf)
		if err != nil {
			return nil, err
		}

		// Track hashes from verification path
		for _, pathNode := range branch.Path {
			relevantHashes[pathNode.Hash] = true
		}

		// Track hashes from Merkle proofs
		for _, proof := range branch.MerkleProofs {
			// Add the leaf hash
			relevantHashes[proof.Leaf] = true
			// Add all sibling hashes from the proof
			for _, sibling := range proof.Proof.Siblings {
				relevantHashes[string(sibling)] = true
			}
		}

		// Add branch to partial DAG
		err = d.addBranchToPartial(branch, partialDag)
		if err != nil {
			return nil, err
		}
	}

	// Optionally prune irrelevant links from the partial DAG
	if pruneLinks {
		partialDag.pruneIrrelevantLinks(relevantHashes)
	}

	return partialDag, nil
}

// CalculateLabels populates the Labels map with deterministic label assignments.
// Each leaf hash (excluding the root) is assigned a numeric label as a string.
// The root is always label "0" and is not included in the map.
// This function is deterministic - calling it multiple times on the same DAG
// will always produce the same label assignments based on DAG traversal order.
func (d *Dag) CalculateLabels() error {
	if d.Labels == nil {
		d.Labels = make(map[string]string)
	} else {
		// Clear existing labels
		for k := range d.Labels {
			delete(d.Labels, k)
		}
	}

	// Use a counter to track label assignment
	labelCounter := 1

	// Iterate through the DAG and assign labels in traversal order
	err := d.IterateDag(func(leaf *DagLeaf, parent *DagLeaf) error {
		// Skip the root (it's implicitly label "0")
		if leaf.Hash == d.Root {
			return nil
		}

		// Assign label to this leaf
		label := strconv.Itoa(labelCounter)
		d.Labels[label] = leaf.Hash
		labelCounter++

		return nil
	})

	return err
}

// ClearLabels removes all label assignments from the DAG.
func (d *Dag) ClearLabels() {
	if d.Labels != nil {
		for k := range d.Labels {
			delete(d.Labels, k)
		}
	}
}

// GetHashesByLabelRange returns an array of leaf hashes for the specified label range (inclusive).
// startLabel and endLabel are string representations of numeric labels.
// For example, GetHashesByLabelRange("20", "48") returns hashes for labels 20, 21, 22, ..., 48.
// Returns an error if labels are invalid, out of range, or if labels haven't been calculated.
func (d *Dag) GetHashesByLabelRange(startLabel, endLabel string) ([]string, error) {
	if len(d.Labels) == 0 {
		return nil, fmt.Errorf("labels not calculated, call CalculateLabels() first")
	}

	// Parse label strings to integers
	start, err := strconv.Atoi(startLabel)
	if err != nil {
		return nil, fmt.Errorf("invalid start label %q: %w", startLabel, err)
	}

	end, err := strconv.Atoi(endLabel)
	if err != nil {
		return nil, fmt.Errorf("invalid end label %q: %w", endLabel, err)
	}

	// Validate range
	if start < 1 {
		return nil, fmt.Errorf("start label must be >= 1 (root is label 0 and not included)")
	}

	if end < start {
		return nil, fmt.Errorf("end label (%d) must be >= start label (%d)", end, start)
	}

	if end > len(d.Labels) {
		return nil, fmt.Errorf("end label (%d) exceeds available labels (%d)", end, len(d.Labels))
	}

	// Collect hashes in the specified range
	var hashes []string
	for i := start; i <= end; i++ {
		label := strconv.Itoa(i)
		hash, exists := d.Labels[label]
		if !exists {
			return nil, fmt.Errorf("label %q not found in labels map", label)
		}
		hashes = append(hashes, hash)
	}

	return hashes, nil
}

// GetLabel returns the label for a given leaf hash.
// Returns "0" if the hash is the root, or the numeric label as a string for other leaves.
// Returns an error if labels haven't been calculated or if the hash is not found.
func (d *Dag) GetLabel(hash string) (string, error) {
	// Check if it's the root
	if hash == d.Root {
		return "0", nil
	}

	// Check if labels have been calculated
	if len(d.Labels) == 0 {
		return "", fmt.Errorf("labels not calculated, call CalculateLabels() first")
	}

	// Search for the hash in the labels map
	for label, labelHash := range d.Labels {
		if labelHash == hash {
			return label, nil
		}
	}

	// Hash not found
	return "", fmt.Errorf("hash %q not found in labels", hash)
}
