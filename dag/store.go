package dag

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"

	merkle_tree "github.com/HORNET-Storage/Scionic-Merkle-Tree/v2/tree"
)

// LeafStore defines the interface for storing and retrieving DAG leaves.
//
// Ownership contract, and it runs both directions:
//
//   - StoreLeaf must not retain the caller's *DagLeaf. Store a Clone.
//   - RetrieveLeaf must not hand back a pointer the caller can mutate into
//     stored state. Return a Clone.
//
// Both halves are required, and one without the other is worth almost nothing:
// DagStore.RetrieveLeaf re-attaches separately stored content by assigning
// leaf.Content, and UpdateParentHashesStreaming assigns leaf.ParentHash. Against
// a store that returns its own pointer, those writes land inside the store --
// silently re-inlining every payload into the metadata store that exists
// precisely to stay small.
//
// Content is the one documented exception, and it is the same exception Clone()
// already makes: the payload is shared rather than copied, because a leaf's CID
// commits to sha256(Content), so those bytes are immutable by construction.
// Replace Content wholesale; never write through it. The Rust port enforces this
// structurally -- its content lives behind an Arc that hands out no &mut -- and
// passes the same suite, which is the evidence that nothing in this library
// needs to write through a payload.
type LeafStore interface {
	StoreLeaf(leaf *DagLeaf) error
	RetrieveLeaf(hash string) (*DagLeaf, error)
	HasLeaf(hash string) (bool, error)
	DeleteLeaf(hash string) error
}

// ContentStore defines the interface for storing leaf content separately from metadata.
type ContentStore interface {
	StoreContent(hash string, content []byte) error
	RetrieveContent(hash string) ([]byte, error)
	HasContent(hash string) (bool, error)
	DeleteContent(hash string) error
}

// BatchLeafStore is an optional interface for stores that support batch operations.
type BatchLeafStore interface {
	LeafStore
	StoreLeaves(leaves []*DagLeaf) error
	RetrieveLeaves(hashes []string) (map[string]*DagLeaf, error)
}

// BatchContentStore is an optional interface for content stores that support batch operations.
type BatchContentStore interface {
	ContentStore
	StoreContents(contents map[string][]byte) error
	RetrieveContents(hashes []string) (map[string][]byte, error)
}

// LeafCounter is an optional interface for efficient leaf counting.
type LeafCounter interface {
	Count() int
}

// LeafEnumerator is an optional interface for enumerating all stored leaf hashes.
type LeafEnumerator interface {
	GetAllLeafHashes() []string
}

// RelationshipCache is an optional interface for stores that cache parent-child relationships.
// This enables fast index rebuilding without traversing the entire DAG structure.
type RelationshipCache interface {
	// GetCachedRelationships returns a map of childHash -> parentHash.
	// Returns nil if relationships are not cached (caller should fall back to traversal).
	GetCachedRelationships() map[string]string
}

// MemoryLeafStore is an in-memory implementation of LeafStore.
type MemoryLeafStore struct {
	leaves map[string]*DagLeaf
	mu     sync.RWMutex
}

func NewMemoryLeafStore() *MemoryLeafStore {
	return &MemoryLeafStore{
		leaves: make(map[string]*DagLeaf),
	}
}

func (s *MemoryLeafStore) StoreLeaf(leaf *DagLeaf) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Clone on the way in: the caller keeps its own leaf and is free to keep
	// mutating it. See the LeafStore ownership contract.
	s.leaves[leaf.Hash] = leaf.Clone()
	return nil
}

func (s *MemoryLeafStore) RetrieveLeaf(hash string) (*DagLeaf, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	leaf, exists := s.leaves[hash]
	if !exists {
		return nil, nil
	}
	// Clone on the way out for the mirror-image reason: DagStore.RetrieveLeaf
	// assigns Content onto whatever comes back from here.
	return leaf.Clone(), nil
}

func (s *MemoryLeafStore) HasLeaf(hash string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, exists := s.leaves[hash]
	return exists, nil
}

func (s *MemoryLeafStore) DeleteLeaf(hash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.leaves, hash)
	return nil
}

func (s *MemoryLeafStore) StoreLeaves(leaves []*DagLeaf) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, leaf := range leaves {
		s.leaves[leaf.Hash] = leaf.Clone()
	}
	return nil
}

func (s *MemoryLeafStore) RetrieveLeaves(hashes []string) (map[string]*DagLeaf, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make(map[string]*DagLeaf)
	for _, hash := range hashes {
		if leaf, exists := s.leaves[hash]; exists {
			result[hash] = leaf.Clone()
		}
	}
	return result, nil
}

func (s *MemoryLeafStore) GetAllLeaves() map[string]*DagLeaf {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make(map[string]*DagLeaf, len(s.leaves))
	for k, v := range s.leaves {
		result[k] = v.Clone()
	}
	return result
}

func (s *MemoryLeafStore) GetAllLeafHashes() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	hashes := make([]string, 0, len(s.leaves))
	for hash := range s.leaves {
		hashes = append(hashes, hash)
	}
	return hashes
}

func (s *MemoryLeafStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.leaves)
}

type MemoryContentStore struct {
	contents map[string][]byte
	mu       sync.RWMutex
}

func NewMemoryContentStore() *MemoryContentStore {
	return &MemoryContentStore{
		contents: make(map[string][]byte),
	}
}

func (s *MemoryContentStore) StoreContent(hash string, content []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.contents[hash] = content
	return nil
}

func (s *MemoryContentStore) RetrieveContent(hash string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	content, exists := s.contents[hash]
	if !exists {
		return nil, nil
	}
	return content, nil
}

func (s *MemoryContentStore) HasContent(hash string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, exists := s.contents[hash]
	return exists, nil
}

func (s *MemoryContentStore) DeleteContent(hash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.contents, hash)
	return nil
}

func (s *MemoryContentStore) StoreContents(contents map[string][]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for hash, content := range contents {
		s.contents[hash] = content
	}
	return nil
}

func (s *MemoryContentStore) RetrieveContents(hashes []string) (map[string][]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make(map[string][]byte)
	for _, hash := range hashes {
		if content, exists := s.contents[hash]; exists {
			result[hash] = content
		}
	}
	return result, nil
}

// DagStore provides storage-backed operations for DAGs.
type DagStore struct {
	Root            string
	Labels          map[string]string
	LeafCount       int
	leafStore       LeafStore
	contentStore    ContentStore
	separateContent bool

	// In-memory index for efficient traversal without loading leaves
	index      *DagIndex
	indexBuilt bool

	mu sync.RWMutex
}

// DagIndex holds lightweight metadata for efficient DAG traversal.
// Only stores hashes and relationships - actual leaf data stays in the database.
type DagIndex struct {
	LeafHashes []string            // All leaf hashes in traversal order
	Children   map[string][]string // parentHash -> []childHash
	Parents    map[string]string   // childHash -> parentHash (empty for root)
}

// NewDagIndex creates an empty index.
func NewDagIndex() *DagIndex {
	return &DagIndex{
		LeafHashes: make([]string, 0),
		Children:   make(map[string][]string),
		Parents:    make(map[string]string),
	}
}

type DagStoreOption func(*DagStore)

func WithLeafStore(store LeafStore) DagStoreOption {
	return func(ds *DagStore) {
		ds.leafStore = store
	}
}

func WithContentStore(store ContentStore) DagStoreOption {
	return func(ds *DagStore) {
		ds.contentStore = store
	}
}

func WithSeparateContent(separate bool) DagStoreOption {
	return func(ds *DagStore) {
		ds.separateContent = separate
	}
}

// NewDagStore creates a new DagStore from an existing Dag using in-memory stores.
func NewDagStore(d *Dag) *DagStore {
	store := &DagStore{
		Root:            d.Root,
		Labels:          d.Labels,
		leafStore:       NewMemoryLeafStore(),
		contentStore:    nil,
		separateContent: false,
	}

	// Import all leaves from the Dag
	if d.Leafs != nil {
		for _, leaf := range d.Leafs {
			store.leafStore.StoreLeaf(leaf)
		}
	}

	// Set leaf count from root
	if rootLeaf, _ := store.leafStore.RetrieveLeaf(d.Root); rootLeaf != nil {
		store.LeafCount = rootLeaf.LeafCount
	}

	return store
}

// NewDagStoreWithStorage creates a new DagStore with custom storage backends.
func NewDagStoreWithStorage(d *Dag, leafStore LeafStore, contentStore ContentStore) *DagStore {
	store := &DagStore{
		Root:            d.Root,
		Labels:          d.Labels,
		leafStore:       leafStore,
		contentStore:    contentStore,
		separateContent: contentStore != nil,
	}

	// Import all leaves from the Dag
	if d.Leafs != nil {
		for _, leaf := range d.Leafs {
			store.StoreLeaf(leaf)
		}
	}

	// Set leaf count from root
	if rootLeaf, _ := store.RetrieveLeaf(d.Root); rootLeaf != nil {
		store.LeafCount = rootLeaf.LeafCount
	}

	return store
}

func NewDagStoreWithOptions(d *Dag, opts ...DagStoreOption) *DagStore {
	store := &DagStore{
		Root:            d.Root,
		Labels:          d.Labels,
		leafStore:       NewMemoryLeafStore(),
		contentStore:    nil,
		separateContent: false,
	}

	// Apply options
	for _, opt := range opts {
		opt(store)
	}

	// Import all leaves from the Dag
	if d.Leafs != nil {
		for _, leaf := range d.Leafs {
			store.StoreLeaf(leaf)
		}
	}

	// Set leaf count from root
	if rootLeaf, _ := store.RetrieveLeaf(d.Root); rootLeaf != nil {
		store.LeafCount = rootLeaf.LeafCount
	}

	return store
}

// NewEmptyDagStore creates an empty DagStore for incremental building.
func NewEmptyDagStore(leafStore LeafStore, contentStore ContentStore) *DagStore {
	if leafStore == nil {
		leafStore = NewMemoryLeafStore()
	}
	return &DagStore{
		Root:            "",
		Labels:          make(map[string]string),
		leafStore:       leafStore,
		contentStore:    contentStore,
		separateContent: contentStore != nil,
	}
}

func NewEmptyDagStoreWithOptions(opts ...DagStoreOption) *DagStore {
	store := &DagStore{
		Root:            "",
		Labels:          make(map[string]string),
		leafStore:       NewMemoryLeafStore(),
		contentStore:    nil,
		separateContent: false,
	}

	for _, opt := range opts {
		opt(store)
	}

	return store
}

// StoreLeaf stores a leaf, optionally separating content.
func (ds *DagStore) StoreLeaf(leaf *DagLeaf) error {
	if ds.separateContent && ds.contentStore != nil && len(leaf.Content) > 0 {
		// Store content separately
		if err := ds.contentStore.StoreContent(leaf.Hash, leaf.Content); err != nil {
			return fmt.Errorf("failed to store content for leaf %s: %w", leaf.Hash, err)
		}

		// Create a copy without content for storage
		leafCopy := leaf.Clone()
		leafCopy.Content = nil

		return ds.leafStore.StoreLeaf(leafCopy)
	}

	return ds.leafStore.StoreLeaf(leaf)
}

// RetrieveLeaf retrieves a leaf, re-attaching content if stored separately.
func (ds *DagStore) RetrieveLeaf(hash string) (*DagLeaf, error) {
	leaf, err := ds.leafStore.RetrieveLeaf(hash)
	if err != nil {
		return nil, err
	}
	if leaf == nil {
		return nil, nil
	}

	// Re-attach content if stored separately and leaf has a content hash
	if ds.separateContent && ds.contentStore != nil && len(leaf.ContentHash) > 0 && len(leaf.Content) == 0 {
		content, err := ds.contentStore.RetrieveContent(hash)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve content for leaf %s: %w", hash, err)
		}
		if content != nil {
			leaf.Content = content
		}
	}

	return leaf, nil
}

// RetrieveLeafWithoutContent retrieves a leaf without loading its content.
func (ds *DagStore) RetrieveLeafWithoutContent(hash string) (*DagLeaf, error) {
	return ds.leafStore.RetrieveLeaf(hash)
}

func (ds *DagStore) HasLeaf(hash string) (bool, error) {
	return ds.leafStore.HasLeaf(hash)
}

func (ds *DagStore) DeleteLeaf(hash string) error {
	if ds.contentStore != nil {
		if err := ds.contentStore.DeleteContent(hash); err != nil {
			return fmt.Errorf("failed to delete content for leaf %s: %w", hash, err)
		}
	}
	return ds.leafStore.DeleteLeaf(hash)
}

func (ds *DagStore) SetRoot(rootHash string) error {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	ds.Root = rootHash

	rootLeaf, err := ds.RetrieveLeaf(rootHash)
	if err != nil {
		return err
	}
	if rootLeaf != nil {
		ds.LeafCount = rootLeaf.LeafCount
	}

	return nil
}

// BuildIndex builds the in-memory index by traversing the DAG structure once.
// This loads each leaf temporarily to extract hashes and relationships,
// then discards the leaf data. Only string hashes are kept in memory.
// If the LeafStore implements RelationshipCache and has cached relationships,
// the index is built from the cache without traversing leaves.
func (ds *DagStore) BuildIndex() error {
	if ds.Root == "" {
		return fmt.Errorf("no root set")
	}

	ds.mu.Lock()
	defer ds.mu.Unlock()

	// Check if we have cached relationships - much faster than traversal
	if cache, ok := ds.leafStore.(RelationshipCache); ok {
		if relationships := cache.GetCachedRelationships(); relationships != nil {
			return ds.buildIndexFromCache(relationships)
		}
	}

	// Fall back to BFS traversal
	return ds.buildIndexByTraversal()
}

// buildIndexFromCache builds the index from cached parent-child relationships.
// This is much faster than traversal since it doesn't need to load any leaves.
// Uses BFS order to ensure parent leaves come before children (required for transmission).
func (ds *DagStore) buildIndexFromCache(relationships map[string]string) error {
	index := NewDagIndex()

	// First pass: rebuild the parent -> children direction from the cache.
	for childHash, parentHash := range relationships {
		if parentHash != "" {
			index.Children[parentHash] = append(index.Children[parentHash], childHash)
		}
	}

	// A RelationshipCache stores one parent per child, so a shared chunk's other
	// parent edges are already discarded before we get here and this direction
	// cannot be re-derived from them. Route it through the same single rule as
	// every other path anyway, so a cache that does supply canonical parents stays
	// canonical. The contract that follows from that: GetCachedRelationships must
	// report the LOWEST parent hash for a child with several parents, or return
	// nil so the caller falls back to full traversal.
	index.Parents = minimumParentIndex(index.Children)
	index.Parents[ds.Root] = ""

	// Second pass: BFS traversal to build LeafHashes in correct order
	// This ensures parent leaves come before children, required for transmission
	visited := make(map[string]bool)
	queue := []string{ds.Root}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		if visited[current] {
			continue
		}
		visited[current] = true

		// Add to LeafHashes in BFS order
		index.LeafHashes = append(index.LeafHashes, current)

		// Queue children for processing (sorted copy, for determinism -- sorting
		// index.Children in place would reorder the index's own stored edges)
		children := append([]string(nil), index.Children[current]...)
		sort.Strings(children)
		for _, childHash := range children {
			if !visited[childHash] {
				queue = append(queue, childHash)
			}
		}
	}

	// Get leaf count from root leaf (we still need this one leaf)
	rootLeaf, err := ds.leafStore.RetrieveLeaf(ds.Root)
	if err == nil && rootLeaf != nil {
		ds.LeafCount = rootLeaf.LeafCount
	}

	ds.index = index
	ds.indexBuilt = true

	return nil
}

// buildIndexByTraversal builds the index by traversing all leaves via BFS.
// This is the fallback when no cached relationships are available.
func (ds *DagStore) buildIndexByTraversal() error {
	index := NewDagIndex()
	visited := make(map[string]bool)

	// BFS traversal to build index - processes one leaf at a time
	queue := []string{ds.Root}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		if visited[current] {
			continue
		}
		visited[current] = true

		// Load leaf temporarily - only need hash and links
		leaf, err := ds.leafStore.RetrieveLeaf(current)
		if err != nil {
			return fmt.Errorf("failed to retrieve leaf %s: %w", current, err)
		}
		if leaf == nil {
			// Leaf not found - skip (might be partial DAG)
			continue
		}

		// Store in index
		index.LeafHashes = append(index.LeafHashes, current)

		// Copy children hashes before discarding leaf
		if len(leaf.Links) > 0 {
			children := make([]string, len(leaf.Links))
			copy(children, leaf.Links)
			index.Children[current] = children

			// Queue children for processing
			for _, childHash := range children {
				if !visited[childHash] {
					queue = append(queue, childHash)
				}
			}
		}

		// Update leaf count from root
		if current == ds.Root {
			ds.LeafCount = leaf.LeafCount
		}
	}

	// The walk above fixes LeafHashes order (parents before children, which
	// transmission requires) and collects every parent -> children edge. The
	// child -> parent direction is resolved only now, because a shared chunk's
	// FIRST-SEEN parent depends on traversal order while its ParentHash must not:
	// FromSerializable pins ParentHash to the lowest parent hash, so a store load
	// has to agree with a deserialization of the same DAG. Recording the traversal
	// parent here is exactly what made those two disagree.
	index.Parents = minimumParentIndex(index.Children)
	index.Parents[ds.Root] = ""

	ds.index = index
	ds.indexBuilt = true

	return nil
}

// HasIndex returns whether the index has been built.
func (ds *DagStore) HasIndex() bool {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	return ds.indexBuilt
}

// GetIndex returns the current index (may be nil if not built).
func (ds *DagStore) GetIndex() *DagIndex {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	return ds.index
}

// ClearIndex clears the in-memory index to free memory.
func (ds *DagStore) ClearIndex() {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	ds.index = nil
	ds.indexBuilt = false
}

// AddToIndex adds a leaf to the index during streaming upload.
// This is used when building a DAG incrementally.
func (ds *DagStore) AddToIndex(leafHash string, parentHash string, children []string) {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	if ds.index == nil {
		ds.index = NewDagIndex()
	}

	// Check if already indexed
	for _, h := range ds.index.LeafHashes {
		if h == leafHash {
			return // Already indexed
		}
	}

	ds.index.LeafHashes = append(ds.index.LeafHashes, leafHash)
	ds.index.Parents[leafHash] = parentHash
	if len(children) > 0 {
		ds.index.Children[leafHash] = children
	}
}

// MarkIndexBuilt marks the index as complete after streaming upload.
func (ds *DagStore) MarkIndexBuilt() {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	ds.indexBuilt = true
}

// ToDag converts the DagStore back to a regular Dag by loading all leaves into memory.
func (ds *DagStore) ToDag() (*Dag, error) {
	d := &Dag{
		Root:   ds.Root,
		Leafs:  make(map[string]*DagLeaf),
		Labels: ds.Labels,
	}

	// If the leaf store is a MemoryLeafStore, we can get all leaves efficiently
	if memStore, ok := ds.leafStore.(*MemoryLeafStore); ok {
		allLeaves := memStore.GetAllLeaves()
		for hash, leaf := range allLeaves {
			// Re-attach content if stored separately
			if ds.separateContent && ds.contentStore != nil && len(leaf.ContentHash) > 0 && len(leaf.Content) == 0 {
				content, err := ds.contentStore.RetrieveContent(hash)
				if err != nil {
					return nil, fmt.Errorf("failed to retrieve content for leaf %s: %w", hash, err)
				}
				if content != nil {
					leafCopy := leaf.Clone()
					leafCopy.Content = content
					d.Leafs[hash] = leafCopy
					continue
				}
			}
			d.Leafs[hash] = leaf
		}
		return d, nil
	}

	// For other store types, we need to iterate through the DAG structure
	// Start from root and traverse all children
	if ds.Root == "" {
		return d, nil
	}

	visited := make(map[string]bool)
	queue := []string{ds.Root}

	for len(queue) > 0 {
		hash := queue[0]
		queue = queue[1:]

		if visited[hash] {
			continue
		}
		visited[hash] = true

		leaf, err := ds.RetrieveLeaf(hash)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve leaf %s: %w", hash, err)
		}
		if leaf == nil {
			continue
		}

		d.Leafs[hash] = leaf

		// Queue children
		for _, childHash := range leaf.Links {
			if !visited[childHash] {
				queue = append(queue, childHash)
			}
		}
	}

	return d, nil
}

// Verify checks the integrity of the DAG.
func (ds *DagStore) Verify() error {
	// Convert to Dag and use existing verification
	// For very large DAGs, we could implement streaming verification
	// but for now this provides correct behavior
	d, err := ds.ToDag()
	if err != nil {
		return fmt.Errorf("failed to load DAG for verification: %w", err)
	}
	return d.Verify()
}

func (ds *DagStore) VerifyLeaf(hash string) error {
	leaf, err := ds.RetrieveLeafWithoutContent(hash)
	if err != nil {
		return err
	}
	if leaf == nil {
		return fmt.Errorf("leaf not found: %s", hash)
	}

	if hash == ds.Root {
		// For root verification, we need more context
		d, err := ds.ToDag()
		if err != nil {
			return err
		}
		return leaf.VerifyRootLeaf(d)
	}

	return leaf.VerifyLeaf()
}

// GetContentFromLeaf retrieves the full content for a file leaf.
func (ds *DagStore) GetContentFromLeaf(hash string) ([]byte, error) {
	leaf, err := ds.RetrieveLeaf(hash)
	if err != nil {
		return nil, err
	}
	if leaf == nil {
		return nil, fmt.Errorf("leaf not found: %s", hash)
	}

	// If leaf has no links, return its direct content
	if len(leaf.Links) == 0 {
		return leaf.Content, nil
	}

	// For chunked files, we need to load and concatenate all chunks
	// Convert to Dag to reuse existing logic
	d, err := ds.ToDag()
	if err != nil {
		return nil, err
	}

	return d.GetContentFromLeaf(leaf)
}

// IterateDag iterates through the DAG structure, loading leaves on-demand.
func (ds *DagStore) IterateDag(processLeaf func(leaf *DagLeaf, parent *DagLeaf) error) error {
	// Content-identical chunk leaves are stored once and may be linked by more
	// than one parent, so each unique leaf is visited exactly once — the same
	// guard IterateDagStreaming already applies.
	visited := make(map[string]bool)

	var iterate func(leafHash string, parentHash *string) error
	iterate = func(leafHash string, parentHash *string) error {
		if visited[leafHash] {
			return nil
		}
		visited[leafHash] = true

		leaf, err := ds.RetrieveLeaf(leafHash)
		if err != nil {
			return err
		}
		if leaf == nil {
			return fmt.Errorf("leaf not found: %s", leafHash)
		}

		var parent *DagLeaf
		if parentHash != nil {
			parent, err = ds.RetrieveLeaf(*parentHash)
			if err != nil {
				return err
			}
		}

		if err := processLeaf(leaf, parent); err != nil {
			return err
		}

		// Iterate children
		for _, childHash := range leaf.Links {
			if err := iterate(childHash, &leaf.Hash); err != nil {
				return err
			}
		}

		return nil
	}

	return iterate(ds.Root, nil)
}

func (ds *DagStore) CreateDirectory(path string) error {
	d, err := ds.ToDag()
	if err != nil {
		return err
	}
	return d.CreateDirectory(path)
}

func (ds *DagStore) IsPartial() bool {
	// Count leaves in store
	if memStore, ok := ds.leafStore.(*MemoryLeafStore); ok {
		return memStore.Count() < ds.LeafCount
	}

	// For other stores, we'd need to count by iterating
	// This is a simplification - in practice you'd track this
	return false
}

func (ds *DagStore) CalculateLabels() error {
	d, err := ds.ToDag()
	if err != nil {
		return err
	}

	if err := d.CalculateLabels(); err != nil {
		return err
	}

	ds.mu.Lock()
	ds.Labels = d.Labels
	ds.mu.Unlock()

	return nil
}

func (ds *DagStore) GetHashesByLabelRange(startLabel, endLabel string) ([]string, error) {
	ds.mu.RLock()
	defer ds.mu.RUnlock()

	if len(ds.Labels) == 0 {
		return nil, fmt.Errorf("labels not calculated, call CalculateLabels() first")
	}

	// Reuse Dag implementation by creating a temporary Dag with just labels
	tempDag := &Dag{
		Root:   ds.Root,
		Labels: ds.Labels,
		Leafs:  make(map[string]*DagLeaf),
	}

	return tempDag.GetHashesByLabelRange(startLabel, endLabel)
}

// AddTransmissionPacket adds a leaf from a transmission packet to the store.
func (ds *DagStore) AddTransmissionPacket(packet *TransmissionPacket) error {
	// If this is the root packet
	if packet.ParentHash == "" {
		if err := packet.Leaf.VerifyRootLeaf(nil); err != nil {
			return fmt.Errorf("root leaf verification failed: %w", err)
		}

		if err := ds.StoreLeaf(packet.Leaf); err != nil {
			return err
		}

		ds.mu.Lock()
		ds.Root = packet.Leaf.Hash
		ds.LeafCount = packet.Leaf.LeafCount
		ds.mu.Unlock()

		return nil
	}

	// Verify the leaf itself
	if err := packet.Leaf.VerifyLeaf(); err != nil {
		return fmt.Errorf("leaf verification failed: %w", err)
	}

	// Verify against parent if parent exists
	parent, err := ds.RetrieveLeafWithoutContent(packet.ParentHash)
	if err != nil {
		return err
	}

	if parent != nil {
		// Verify parent has link to this leaf
		if !parent.HasLink(packet.Leaf.Hash) {
			return fmt.Errorf("parent %s does not contain link to child %s", parent.Hash, packet.Leaf.Hash)
		}

		// Verify Merkle proof if parent has multiple children
		if parent.CurrentLinkCount > 1 {
			proof, hasProof := packet.Proofs[packet.Leaf.Hash]
			if !hasProof {
				return fmt.Errorf("missing merkle proof for leaf %s", packet.Leaf.Hash)
			}

			if err := parent.VerifyBranch(proof); err != nil {
				return fmt.Errorf("invalid merkle proof for leaf %s: %w", packet.Leaf.Hash, err)
			}
		}
	}

	// Store the leaf
	return ds.StoreLeaf(packet.Leaf)
}

// AddBatchedTransmissionPacket adds multiple leaves from a batched packet.
func (ds *DagStore) AddBatchedTransmissionPacket(packet *BatchedTransmissionPacket) error {
	if packet == nil || len(packet.Leaves) == 0 {
		return nil
	}

	// Collect verified leaves for batch storage
	var verifiedLeaves []*DagLeaf

	// Process each leaf in the batch
	for _, leaf := range packet.Leaves {
		// Get parent hash from relationships
		parentHash := ""
		if packet.Relationships != nil {
			parentHash = packet.Relationships[leaf.Hash]
		}

		// If this is the root leaf (no parent)
		if parentHash == "" && ds.Root == "" {
			if err := leaf.VerifyRootLeaf(nil); err != nil {
				return fmt.Errorf("root leaf verification failed: %w", err)
			}

			verifiedLeaves = append(verifiedLeaves, leaf)

			ds.mu.Lock()
			ds.Root = leaf.Hash
			ds.LeafCount = leaf.LeafCount
			ds.mu.Unlock()

			continue
		}

		// Verify the leaf itself
		if err := leaf.VerifyLeaf(); err != nil {
			return fmt.Errorf("leaf verification failed: %w", err)
		}

		// Verify against parent if we have one
		if parentHash != "" {
			parent, err := ds.RetrieveLeafWithoutContent(parentHash)
			if err != nil {
				return err
			}

			if parent != nil {
				// Verify parent has link to this leaf
				if !parent.HasLink(leaf.Hash) {
					return fmt.Errorf("parent %s does not contain link to child %s", parent.Hash, leaf.Hash)
				}
			}
		}

		verifiedLeaves = append(verifiedLeaves, leaf)
	}

	// Store all verified leaves - use batch if available
	if len(verifiedLeaves) > 0 {
		if batchStore, ok := ds.leafStore.(BatchLeafStore); ok {
			if err := batchStore.StoreLeaves(verifiedLeaves); err != nil {
				return err
			}
		} else {
			// Fallback to individual stores
			for _, leaf := range verifiedLeaves {
				if err := ds.StoreLeaf(leaf); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// StoreLeavesInBatches stores multiple leaves using batch storage if available.
func (ds *DagStore) StoreLeavesInBatches(leaves []*DagLeaf) error {
	if len(leaves) == 0 {
		return nil
	}

	if batchStore, ok := ds.leafStore.(BatchLeafStore); ok {
		return batchStore.StoreLeaves(leaves)
	}

	// Fallback to individual stores
	for _, leaf := range leaves {
		if err := ds.StoreLeaf(leaf); err != nil {
			return err
		}
	}
	return nil
}

// UpdateParentHashesStreaming updates parent hashes for all leaves using streaming.
// Processes leaves in small batches to avoid loading all leaves into memory.
func (ds *DagStore) UpdateParentHashesStreaming(batchSize int) error {
	if ds.Root == "" {
		return fmt.Errorf("no root set")
	}

	// Build index if not already built
	if !ds.indexBuilt || ds.index == nil {
		if err := ds.BuildIndex(); err != nil {
			return fmt.Errorf("failed to build index: %w", err)
		}
	}

	if batchSize <= 0 {
		batchSize = 10
	}

	var batch []*DagLeaf

	// Iterate using index - we know parent hashes from the index
	for _, leafHash := range ds.index.LeafHashes {
		parentHash := ds.index.Parents[leafHash]

		// Load leaf without content
		leaf, err := ds.RetrieveLeafWithoutContent(leafHash)
		if err != nil {
			return fmt.Errorf("failed to retrieve leaf %s: %w", leafHash, err)
		}
		if leaf == nil {
			continue
		}

		// Update parent hash
		leaf.ParentHash = parentHash
		batch = append(batch, leaf)

		// Store batch when full
		if len(batch) >= batchSize {
			if err := ds.StoreLeavesInBatches(batch); err != nil {
				return fmt.Errorf("failed to store batch: %w", err)
			}
			batch = batch[:0] // Clear batch, reuse backing array
		}
	}

	// Store any remaining leaves
	if len(batch) > 0 {
		if err := ds.StoreLeavesInBatches(batch); err != nil {
			return fmt.Errorf("failed to store final batch: %w", err)
		}
	}

	return nil
}

// GetLeafSequence returns leaves in transmission order.
func (ds *DagStore) GetLeafSequence() ([]*TransmissionPacket, error) {
	d, err := ds.ToDag()
	if err != nil {
		return nil, err
	}
	return d.GetLeafSequence(), nil
}

func (ds *DagStore) GetPartial(leafHashes []string, pruneLinks bool) (*Dag, error) {
	d, err := ds.ToDag()
	if err != nil {
		return nil, err
	}
	return d.GetPartial(leafHashes, pruneLinks)
}

func (ds *DagStore) ToCBOR() ([]byte, error) {
	d, err := ds.ToDag()
	if err != nil {
		return nil, err
	}
	return d.ToCBOR()
}

func (ds *DagStore) ToJSON() ([]byte, error) {
	d, err := ds.ToDag()
	if err != nil {
		return nil, err
	}
	return d.ToJSON()
}

func FromCBORToStore(data []byte, leafStore LeafStore, contentStore ContentStore) (*DagStore, error) {
	d, err := FromCBOR(data)
	if err != nil {
		return nil, err
	}

	if leafStore == nil {
		leafStore = NewMemoryLeafStore()
	}

	return NewDagStoreWithStorage(d, leafStore, contentStore), nil
}

func FromJSONToStore(data []byte, leafStore LeafStore, contentStore ContentStore) (*DagStore, error) {
	d, err := FromJSON(data)
	if err != nil {
		return nil, err
	}

	if leafStore == nil {
		leafStore = NewMemoryLeafStore()
	}

	return NewDagStoreWithStorage(d, leafStore, contentStore), nil
}

// VerifyStreaming verifies the DAG integrity without loading all leaves into memory.
func (ds *DagStore) VerifyStreaming() error {
	if ds.Root == "" {
		return fmt.Errorf("no root set")
	}

	// Check if this is a partial DAG
	isPartial, err := ds.isPartialStreaming()
	if err != nil {
		return fmt.Errorf("failed to check if DAG is partial: %w", err)
	}

	if isPartial {
		return ds.verifyWithProofsStreaming()
	}

	return ds.verifyFullDagStreaming()
}

func (ds *DagStore) isPartialStreaming() (bool, error) {
	rootLeaf, err := ds.RetrieveLeafWithoutContent(ds.Root)
	if err != nil {
		return false, err
	}
	if rootLeaf == nil {
		return true, nil // Missing root = definitely partial
	}

	// If the leaf store implements LeafCounter, use it for efficient counting
	if counter, ok := ds.leafStore.(LeafCounter); ok {
		actualCount := counter.Count()
		return actualCount < rootLeaf.LeafCount, nil
	}

	// Fallback: count every existing leaf reachable from the root and compare to
	// the root's LeafCount. Fewer existing leaves than expected means partial.
	hashes, err := ds.collectExistingLeafHashesFromRoot()
	if err != nil {
		return false, err
	}
	return len(hashes) < rootLeaf.LeafCount, nil
}

func (ds *DagStore) verifyFullDagStreaming() error {
	rootLeaf, err := ds.RetrieveLeafWithoutContent(ds.Root)
	if err != nil {
		return fmt.Errorf("failed to retrieve root leaf: %w", err)
	}
	if rootLeaf == nil {
		return fmt.Errorf("root leaf not found: %s", ds.Root)
	}

	// Verify root leaf hash (pass nil since we're doing streaming verification)
	if err := rootLeaf.VerifyRootLeaf(nil); err != nil {
		return fmt.Errorf("root leaf verification failed: %w", err)
	}

	// Verify root's children against merkle root if it has children
	if len(rootLeaf.Links) == rootLeaf.CurrentLinkCount && rootLeaf.CurrentLinkCount > 0 {
		if err := ds.verifyChildrenAgainstMerkleRootStreaming(rootLeaf); err != nil {
			return fmt.Errorf("root leaf merkle root verification failed: %w", err)
		}
	}

	// Track visited nodes
	visited := make(map[string]bool)
	visited[ds.Root] = true

	// Verify all children recursively
	return ds.verifyChildrenFullDagStreaming(rootLeaf, visited)
}

func (ds *DagStore) verifyChildrenFullDagStreaming(parent *DagLeaf, visited map[string]bool) error {
	for _, childHash := range parent.Links {
		if visited[childHash] {
			continue
		}
		visited[childHash] = true

		childLeaf, err := ds.RetrieveLeafWithoutContent(childHash)
		if err != nil {
			return fmt.Errorf("failed to retrieve child leaf %s: %w", childHash, err)
		}
		if childLeaf == nil {
			return fmt.Errorf("child leaf not found: %s (parent: %s)", childHash, parent.Hash)
		}

		// Verify the child leaf's hash
		if err := childLeaf.VerifyLeaf(); err != nil {
			return fmt.Errorf("child leaf %s verification failed: %w", childHash, err)
		}

		// Verify parent contains link to this child
		if !parent.HasLink(childHash) {
			return fmt.Errorf("parent %s does not contain link to child %s", parent.Hash, childHash)
		}

		// Verify this parent's merkle root if it has multiple children
		if parent.CurrentLinkCount > 0 && len(parent.Links) == parent.CurrentLinkCount {
			if err := ds.verifyChildrenAgainstMerkleRootStreaming(parent); err != nil {
				return fmt.Errorf("parent %s merkle root verification failed: %w", parent.Hash, err)
			}
		}

		// Recursively verify this child's children
		if err := ds.verifyChildrenFullDagStreaming(childLeaf, visited); err != nil {
			return err
		}
	}

	return nil
}

func (ds *DagStore) verifyWithProofsStreaming() error {
	// First verify the root leaf
	rootLeaf, err := ds.RetrieveLeafWithoutContent(ds.Root)
	if err != nil {
		return fmt.Errorf("failed to retrieve root leaf: %w", err)
	}
	if rootLeaf == nil {
		return fmt.Errorf("root leaf not found: %s", ds.Root)
	}

	if err := rootLeaf.VerifyRootLeaf(nil); err != nil {
		return fmt.Errorf("root leaf failed to verify: %w", err)
	}

	// Handle root's children verification
	if rootLeaf.CurrentLinkCount > 0 {
		childrenInDag := 0
		for _, childHash := range rootLeaf.Links {
			exists, err := ds.HasLeaf(childHash)
			if err != nil {
				return err
			}
			if exists {
				childrenInDag++
			}
		}

		if childrenInDag == rootLeaf.CurrentLinkCount && len(rootLeaf.Links) == rootLeaf.CurrentLinkCount {
			// All children present, verify merkle root
			if err := ds.verifyChildrenAgainstMerkleRootStreaming(rootLeaf); err != nil {
				return fmt.Errorf("root leaf merkle root verification failed: %w", err)
			}
		} else if rootLeaf.CurrentLinkCount == 1 {
			// Single child case
			if childrenInDag > 0 && len(rootLeaf.Links) > 0 {
				childHash := rootLeaf.Links[0]
				if string(rootLeaf.ClassicMerkleRoot) != childHash {
					return fmt.Errorf("single child verification failed: ClassicMerkleRoot doesn't match child hash")
				}
			}
		} else if len(rootLeaf.Proofs) == 0 && childrenInDag < rootLeaf.CurrentLinkCount {
			// Multiple children missing and no proofs
			return fmt.Errorf("broken DAG: root has %d links but only %d children exist in DAG (no proofs available)",
				rootLeaf.CurrentLinkCount, childrenInDag)
		}
	}

	// Collect all leaf hashes we need to verify (using partial-DAG aware method)
	leafHashes, err := ds.collectAllLeafHashesForPartialDag()
	if err != nil {
		return err
	}

	// Build a child->parent index once so each path-to-root check is O(1) instead
	// of scanning every leaf per step.
	parentOf := make(map[string]string, len(leafHashes))
	for _, hash := range leafHashes {
		l, err := ds.RetrieveLeafWithoutContent(hash)
		if err != nil {
			return err
		}
		if l == nil {
			continue
		}
		for _, childHash := range l.Links {
			// Lowest parent hash wins, so a leaf linked by several parents resolves
			// identically on every run no matter what order
			// collectAllLeafHashesForPartialDag returned.
			if existing, ok := parentOf[childHash]; !ok || hash < existing {
				parentOf[childHash] = hash
			}
		}
	}

	// Verify each non-root leaf and its path to root
	for _, leafHash := range leafHashes {
		if leafHash == ds.Root {
			continue
		}

		leaf, err := ds.RetrieveLeafWithoutContent(leafHash)
		if err != nil {
			return err
		}
		if leaf == nil {
			continue // Skip missing leaves (they're not in our partial DAG)
		}

		// Verify the leaf itself
		if err := leaf.VerifyLeaf(); err != nil {
			return fmt.Errorf("leaf %s failed to verify: %w", leafHash, err)
		}

		// Verify path to root
		if err := ds.verifyPathToRootStreaming(leaf, parentOf); err != nil {
			return err
		}
	}

	return nil
}

func (ds *DagStore) verifyPathToRootStreaming(leaf *DagLeaf, parentOf map[string]string) error {
	current := leaf

	for current.Hash != ds.Root {
		// Find parent via the precomputed index
		parentHash, ok := parentOf[current.Hash]
		if !ok {
			return fmt.Errorf("broken path to root for leaf %s", leaf.Hash)
		}
		parent, err := ds.RetrieveLeafWithoutContent(parentHash)
		if err != nil {
			return err
		}
		if parent == nil {
			return fmt.Errorf("broken path to root for leaf %s", leaf.Hash)
		}

		// Verify parent leaf (if not root)
		if parent.Hash != ds.Root {
			if err := parent.VerifyLeaf(); err != nil {
				return fmt.Errorf("parent leaf %s failed to verify: %w", parent.Hash, err)
			}
		}

		// Check if we have all of parent's children
		hasAllChildren := len(parent.Links) == parent.CurrentLinkCount

		if hasAllChildren && parent.CurrentLinkCount > 0 {
			// Count how many children actually exist
			childrenInDag := 0
			for _, childHash := range parent.Links {
				exists, err := ds.HasLeaf(childHash)
				if err != nil {
					return err
				}
				if exists {
					childrenInDag++
				}
			}

			if childrenInDag == parent.CurrentLinkCount {
				// All children present, verify merkle root
				if err := ds.verifyChildrenAgainstMerkleRootStreaming(parent); err != nil {
					return fmt.Errorf("parent %s merkle root verification failed: %w", parent.Hash, err)
				}
			} else {
				// Some children missing - need proof for current child
				if err := ds.verifyWithProofStreaming(parent, current.Hash); err != nil {
					return err
				}
			}
		} else if parent.CurrentLinkCount > 1 {
			// Don't have all children info, must use proofs
			if err := ds.verifyWithProofStreaming(parent, current.Hash); err != nil {
				return err
			}
		}

		current = parent
	}

	return nil
}

func (ds *DagStore) verifyWithProofStreaming(parent *DagLeaf, childHash string) error {
	proof, hasProof := parent.Proofs[childHash]
	if !hasProof {
		return fmt.Errorf("missing merkle proof for node %s in partial DAG", childHash)
	}

	if err := parent.VerifyBranch(proof); err != nil {
		return fmt.Errorf("invalid merkle proof for node %s: %w", childHash, err)
	}

	return nil
}

func (ds *DagStore) collectAllLeafHashesForPartialDag() ([]string, error) {
	// If the store implements LeafEnumerator, use it directly
	if enumerator, ok := ds.leafStore.(LeafEnumerator); ok {
		return enumerator.GetAllLeafHashes(), nil
	}

	// Fallback: traverse only existing children from root
	return ds.collectExistingLeafHashesFromRoot()
}

func (ds *DagStore) collectExistingLeafHashesFromRoot() ([]string, error) {
	if ds.Root == "" {
		return nil, fmt.Errorf("no root set")
	}

	visited := make(map[string]bool)
	var hashes []string

	var collect func(hash string) error
	collect = func(hash string) error {
		if visited[hash] {
			return nil
		}

		// Check if leaf exists
		exists, err := ds.leafStore.HasLeaf(hash)
		if err != nil {
			return err
		}
		if !exists {
			return nil // Skip missing leaves
		}

		visited[hash] = true
		hashes = append(hashes, hash)

		// Load leaf to get children
		leaf, err := ds.RetrieveLeafWithoutContent(hash)
		if err != nil {
			return err
		}
		if leaf == nil {
			return nil
		}

		// Recursively collect existing children
		for _, childHash := range leaf.Links {
			if err := collect(childHash); err != nil {
				return err
			}
		}

		return nil
	}

	if err := collect(ds.Root); err != nil {
		return nil, err
	}

	return hashes, nil
}

func (ds *DagStore) verifyChildrenAgainstMerkleRootStreaming(parent *DagLeaf) error {
	if parent.CurrentLinkCount == 0 {
		return nil
	}

	if parent.CurrentLinkCount == 1 {
		// Single child - ClassicMerkleRoot should be the child's hash
		if len(parent.Links) > 0 {
			expectedRoot := []byte(parent.Links[0])
			if string(parent.ClassicMerkleRoot) != string(expectedRoot) {
				return fmt.Errorf("single child merkle root mismatch")
			}
		}
		return nil
	}

	// Multiple children - rebuild merkle tree and compare
	builder := merkle_tree.CreateTree()
	for _, linkHash := range parent.Links {
		builder.AddLeaf(linkHash, linkHash)
	}

	merkleTree, _, err := builder.Build()
	if err != nil {
		return fmt.Errorf("failed to rebuild merkle tree: %w", err)
	}

	if string(merkleTree.Root) != string(parent.ClassicMerkleRoot) {
		return fmt.Errorf("merkle root mismatch: expected %x, got %x",
			parent.ClassicMerkleRoot, merkleTree.Root)
	}

	return nil
}

// verifyLeafContentHash checks that a leaf's content matches its committed
// ContentHash. Streaming verification loads leaves without content, so the
// content-hash binding must be re-checked here whenever content is loaded.
func verifyLeafContentHash(leaf *DagLeaf) error {
	if leaf == nil || leaf.Content == nil {
		return nil
	}
	if leaf.ContentHash == nil {
		return fmt.Errorf("leaf %s has content but no content hash to verify against", leaf.Hash)
	}
	h := sha256.Sum256(leaf.Content)
	if !bytes.Equal(h[:], leaf.ContentHash) {
		return fmt.Errorf("leaf %s content does not match its content hash", leaf.Hash)
	}
	return nil
}

// GetContentFromLeafStreaming retrieves content for a file leaf using streaming.
func (ds *DagStore) GetContentFromLeafStreaming(hash string) ([]byte, error) {
	leaf, err := ds.RetrieveLeafWithoutContent(hash)
	if err != nil {
		return nil, err
	}
	if leaf == nil {
		return nil, fmt.Errorf("leaf not found: %s", hash)
	}

	// If leaf has no links, it's a single chunk - get content directly
	if len(leaf.Links) == 0 {
		fullLeaf, err := ds.RetrieveLeaf(hash)
		if err != nil {
			return nil, err
		}
		if err := verifyLeafContentHash(fullLeaf); err != nil {
			return nil, err
		}
		return fullLeaf.Content, nil
	}

	// For chunked files, load every chunk (verifying each against its content
	// hash), order them by numeric ItemName since link order is not part of the
	// CID, then concatenate.
	chunkHashes := make([]string, len(leaf.Links))
	copy(chunkHashes, leaf.Links)

	chunkLeaves := make(map[string]*DagLeaf, len(chunkHashes))
	for _, chunkHash := range chunkHashes {
		chunkLeaf, err := ds.RetrieveLeaf(chunkHash)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve chunk %s: %w", chunkHash, err)
		}
		if chunkLeaf == nil {
			return nil, fmt.Errorf("chunk not found: %s", chunkHash)
		}
		if err := verifyLeafContentHash(chunkLeaf); err != nil {
			return nil, err
		}
		chunkLeaves[chunkHash] = chunkLeaf
	}

	sort.SliceStable(chunkHashes, func(i, j int) bool {
		return compareChunkItemNames(chunkLeaves[chunkHashes[i]].ItemName, chunkLeaves[chunkHashes[j]].ItemName)
	})

	var content []byte
	for _, chunkHash := range chunkHashes {
		content = append(content, chunkLeaves[chunkHash].Content...)
	}

	return content, nil
}

// CreateDirectoryStreaming recreates the directory structure using streaming.
func (ds *DagStore) CreateDirectoryStreaming(path string) error {
	rootLeaf, err := ds.RetrieveLeafWithoutContent(ds.Root)
	if err != nil {
		return fmt.Errorf("failed to retrieve root leaf: %w", err)
	}
	if rootLeaf == nil {
		return fmt.Errorf("root leaf not found")
	}

	return ds.createDirectoryLeafStreaming(rootLeaf, path)
}

func (ds *DagStore) createDirectoryLeafStreaming(leaf *DagLeaf, path string) error {
	switch leaf.Type {
	case DirectoryLeafType:
		// Create the directory
		if err := createDir(path); err != nil {
			return err
		}

		// Process each child
		for _, childHash := range leaf.Links {
			childLeaf, err := ds.RetrieveLeafWithoutContent(childHash)
			if err != nil {
				return fmt.Errorf("failed to retrieve child %s: %w", childHash, err)
			}
			if childLeaf == nil {
				return fmt.Errorf("child leaf not found: %s", childHash)
			}

			childPath, err := safeJoin(path, childLeaf.ItemName)
			if err != nil {
				return err
			}
			if err := ds.createDirectoryLeafStreaming(childLeaf, childPath); err != nil {
				return err
			}
			// childLeaf can be garbage collected
		}

	case FileLeafType:
		// Get content using streaming method
		content, err := ds.GetContentFromLeafStreaming(leaf.Hash)
		if err != nil {
			return fmt.Errorf("failed to get content for %s: %w", leaf.ItemName, err)
		}

		// Write the file
		if err := writeFile(path, content); err != nil {
			return err
		}

	case ChunkLeafType:
		// Chunks are handled by their parent file leaf
		// This shouldn't be called directly
		return fmt.Errorf("unexpected chunk leaf at path: %s", path)
	}

	return nil
}

// IterateDagStreaming iterates through the DAG without keeping all leaves in memory.
func (ds *DagStore) IterateDagStreaming(processLeaf func(leaf *DagLeaf, parent *DagLeaf) error) error {
	if ds.Root == "" {
		return fmt.Errorf("no root set")
	}

	visited := make(map[string]bool)

	var iterate func(leafHash string, parentHash *string) error
	iterate = func(leafHash string, parentHash *string) error {
		if visited[leafHash] {
			return nil
		}
		visited[leafHash] = true

		// Load leaf without content for efficiency
		leaf, err := ds.RetrieveLeafWithoutContent(leafHash)
		if err != nil {
			return err
		}
		if leaf == nil {
			return fmt.Errorf("leaf not found: %s", leafHash)
		}

		// Load parent if needed
		var parent *DagLeaf
		if parentHash != nil {
			parent, err = ds.RetrieveLeafWithoutContent(*parentHash)
			if err != nil {
				return err
			}
		}

		// Process this leaf
		if err := processLeaf(leaf, parent); err != nil {
			return err
		}

		// Get children before we lose reference to leaf
		children := make([]string, len(leaf.Links))
		copy(children, leaf.Links)
		currentHash := leaf.Hash

		// leaf and parent can now be garbage collected

		// Process children
		for _, childHash := range children {
			if err := iterate(childHash, &currentHash); err != nil {
				return err
			}
		}

		return nil
	}

	return iterate(ds.Root, nil)
}

// IterateDagWithIndex iterates through the DAG using the pre-built index.
// This is much faster than IterateDagStreaming as it avoids DB lookups for traversal.
// The callback receives leafHash and parentHash - load leaf content only when needed.
// If the index is not built, it falls back to building it first.
func (ds *DagStore) IterateDagWithIndex(processLeaf func(leafHash string, parentHash string) error) error {
	if ds.Root == "" {
		return fmt.Errorf("no root set")
	}

	// Build index if not already built
	if !ds.indexBuilt || ds.index == nil {
		if err := ds.BuildIndex(); err != nil {
			return fmt.Errorf("failed to build index: %w", err)
		}
	}

	// Iterate through all leaves in order
	for _, leafHash := range ds.index.LeafHashes {
		parentHash := ds.index.Parents[leafHash]
		if err := processLeaf(leafHash, parentHash); err != nil {
			return err
		}
	}

	return nil
}

func (ds *DagStore) CountLeavesStreaming() (int, error) {
	// If index is built, just return length of leafHashes
	if ds.indexBuilt && ds.index != nil && len(ds.index.LeafHashes) > 0 {
		return len(ds.index.LeafHashes), nil
	}

	// Try to get the count from the DagStore's LeafCount field
	if ds.LeafCount > 0 {
		return ds.LeafCount, nil
	}

	// If LeafCount not set on DagStore, try to get it from the root leaf
	rootLeaf, err := ds.RetrieveLeafWithoutContent(ds.Root)
	if err != nil {
		return 0, err
	}
	if rootLeaf != nil && rootLeaf.LeafCount > 0 {
		return rootLeaf.LeafCount, nil
	}

	// Fallback to full iteration (slow)
	count := 0
	err = ds.IterateDagStreaming(func(leaf *DagLeaf, parent *DagLeaf) error {
		count++
		return nil
	})
	return count, err
}

// VerifyLeafWithParent verifies a single leaf against its parent.
func (ds *DagStore) VerifyLeafWithParent(leafHash string, parentHash string, proof *ClassicTreeBranch) error {
	// Get the leaf
	leaf, err := ds.RetrieveLeafWithoutContent(leafHash)
	if err != nil {
		return err
	}
	if leaf == nil {
		return fmt.Errorf("leaf not found: %s", leafHash)
	}

	// Verify the leaf's own hash
	if err := leaf.VerifyLeaf(); err != nil {
		return fmt.Errorf("leaf hash verification failed: %w", err)
	}

	// Get the parent
	parent, err := ds.RetrieveLeafWithoutContent(parentHash)
	if err != nil {
		return err
	}
	if parent == nil {
		return fmt.Errorf("parent not found: %s", parentHash)
	}

	// Verify parent has link to this leaf
	if !parent.HasLink(leafHash) {
		return fmt.Errorf("parent %s does not contain link to child %s", parentHash, leafHash)
	}

	// Verify merkle proof if parent has multiple children
	if parent.CurrentLinkCount > 1 {
		if proof == nil {
			return fmt.Errorf("merkle proof required for leaf %s (parent has %d children)", leafHash, parent.CurrentLinkCount)
		}
		if err := parent.VerifyBranch(proof); err != nil {
			return fmt.Errorf("merkle proof verification failed: %w", err)
		}
	}

	return nil
}

func createDir(path string) error {
	return os.MkdirAll(path, 0o755)
}

func joinPath(base, name string) string {
	return filepath.Join(base, name)
}

func writeFile(path string, content []byte) error {
	return os.WriteFile(path, content, 0o644)
}
