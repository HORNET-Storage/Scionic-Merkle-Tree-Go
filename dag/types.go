package dag

import (
	"io/fs"
	"sync"

	"github.com/HORNET-Storage/Scionic-Merkle-Tree/v2/merkletree"
)

const DefaultChunkSize = 2048 * 1024 // 2MB

var ChunkSize = DefaultChunkSize

type LeafType string

const (
	FileLeafType      LeafType = "file"
	ChunkLeafType     LeafType = "chunk"
	DirectoryLeafType LeafType = "directory"
)

// LeafProcessor generates custom metadata for a leaf during DAG creation
type LeafProcessor func(path string, relPath string, entry fs.DirEntry, isRoot bool, leafType LeafType) map[string]string

type Dag struct {
	Root   string
	Leafs  map[string]*DagLeaf
	Labels map[string]string // label -> leaf hash (excludes root which is always "0")
}

// DagStats contains the exact aggregate values committed into a root leaf.
// The values describe unique non-root leaves, matching the Dag.Leafs map semantics.
type DagStats struct {
	LeafCount   int
	ContentSize int64
	DagSize     int64
}

type DagBuilder struct {
	Leafs map[string]*DagLeaf
	stats DagStats
	mu    sync.Mutex
}

type DagLeaf struct {
	Hash              string                          `json:"hash"`
	ItemName          string                          `json:"item_name"`
	Type              LeafType                        `json:"type"`
	ContentHash       []byte                          `json:"content_hash,omitempty"`
	Content           []byte                          `json:"content,omitempty"`
	ClassicMerkleRoot []byte                          `json:"classic_merkle_root,omitempty"`
	CurrentLinkCount  int                             `json:"current_link_count"`
	LeafCount         int                             `json:"leaf_count,omitempty"`
	ContentSize       int64                           `json:"content_size,omitempty"`
	DagSize           int64                           `json:"dag_size,omitempty"`
	Links             []string                        `json:"links,omitempty"`
	ParentHash        string                          `json:"parent_hash,omitempty"`
	AdditionalData    map[string]string               `json:"additional_data,omitempty"`
	MerkleTree        *merkletree.MerkleTree          `json:"-"`
	LeafMap           map[string]merkletree.DataBlock `json:"-"`
	Proofs            map[string]*ClassicTreeBranch   `json:"proofs,omitempty"`
}

type DagLeafBuilder struct {
	ItemName string
	Label    int64
	LeafType LeafType
	Data     []byte
	Links    []string
}

type ClassicTreeBranch struct {
	Leaf  string
	Proof *merkletree.Proof
}

type DagBranch struct {
	Leaf         *DagLeaf
	Path         []*DagLeaf
	MerkleProofs map[string]*ClassicTreeBranch
}

type TransmissionPacket struct {
	Leaf       *DagLeaf
	ParentHash string
	Proofs     map[string]*ClassicTreeBranch
}

type BatchedTransmissionPacket struct {
	Leaves        []*DagLeaf
	Relationships map[string]string // childHash -> parentHash
	PacketIndex   int
	TotalPackets  int
}

const DefaultBatchSize = 4 * 1024 * 1024 // 4MB

var BatchSize = DefaultBatchSize

func SetBatchSize(size int) {
	BatchSize = size
}

func DisableBatching() {
	SetBatchSize(-1)
}

func SetDefaultBatchSize() {
	SetBatchSize(DefaultBatchSize)
}

func SetChunkSize(size int) {
	ChunkSize = size
}

func DisableChunking() {
	SetChunkSize(-1)
}

func SetDefaultChunkSize() {
	SetChunkSize(DefaultChunkSize)
}

// DagBuilderConfig controls DAG building behavior
type DagBuilderConfig struct {
	// EnableParallel enables parallel processing of files and directories
	// Default: false (sequential processing for backward compatibility)
	EnableParallel bool

	// MaxWorkers controls the maximum number of concurrent goroutines when parallel processing
	// 0 = use runtime.NumCPU() (auto-detect based on available cores)
	// -1 = unlimited workers (not recommended, may overwhelm system)
	// >0 = use exactly this many workers
	MaxWorkers     int  // Parallel only, 0=auto-detect
	TimestampRoot  bool // Add timestamp to root
	AdditionalData map[string]string
	Processor      LeafProcessor
}

func DefaultConfig() *DagBuilderConfig {
	return &DagBuilderConfig{
		EnableParallel: false,
		MaxWorkers:     0,
		TimestampRoot:  false,
		AdditionalData: map[string]string{},
		Processor:      nil,
	}
}

func ParallelConfig() *DagBuilderConfig {
	return &DagBuilderConfig{
		EnableParallel: true,
		MaxWorkers:     0,
		TimestampRoot:  false,
		AdditionalData: map[string]string{},
		Processor:      nil,
	}
}

func ParallelConfigWithWorkers(workers int) *DagBuilderConfig {
	return &DagBuilderConfig{
		EnableParallel: true,
		MaxWorkers:     workers,
		TimestampRoot:  false,
		AdditionalData: map[string]string{},
		Processor:      nil,
	}
}
