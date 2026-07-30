![nostr Badge](https://img.shields.io/badge/nostr-8e30eb?style=flat) ![Go Badge](https://img.shields.io/badge/Go-00ADD8?logo=go&logoColor=white) <img src="https://static.wixstatic.com/media/e9326a_3823e7e6a7e14488954bb312d11636da~mv2.png" height="20"> ![example workflow](https://github.com/HORNET-Storage/Scionic-Merkle-Tree/actions/workflows/go.yml/badge.svg)
[![codecov](https://codecov.io/gh/HORNET-Storage/Scionic-Merkle-Tree/graph/badge.svg?token=1UBLJ1YYFI)](https://codecov.io/gh/HORNET-Storage/Scionic-Merkle-Tree)


# Scionic Merkle Trees

## Combining Merkle Trees and Merkle DAGs

We've designed a [new type of Merkle DAG/Merkle Tree hybrid](https://www.hornet.storage/) known as the Scionic Merkle Tree. Scionic Merkle Trees contain small branches like Classic Merkle Trees, the folder storage support of Merkle DAGs, and numbered Merkle leaves so anyone can sync by requesting a range of missing leaf numbers that correspond to missing file chunks. LeafSync is the name of the simple protocol used to request a range of leaf numbers in order to retrieve a batch of missing file chunks corresponding to the leaf numbers.

![Tree Comparison Diagram](https://static.wixstatic.com/media/e9326a_ee5ee567806d439b93eaf3ce49afe072~mv2.png)

Scionic Merkle Trees maintain the advantages of IPFS Merkle DAGs with the slim Merkle Branches of Classic Merkle Trees, while providing LeafSync as a new feature that complements any set reconciliation system (IBLTs, negentropy, et al.). In plant grafting, the "Scion" is the upper part of the plant, chosen for its desirable fruits or flowers; it's grafted onto another plant's base to grow together. In a similar vein, the Scionic Merkle Tree was born from grafting together Merkle Trees and Merkle DAGs. This process emphasizes why we use the term "Scion" for the Scionic Merkle Trees: it symbolizes the digital grafting of these two similar data structures, combining their strengths into one piece of software.

## Scionic Merkle Trees: The Best of Both Worlds

### ***Classic Merkle Trees***

 Merkle Trees are cryptographic structures used to manage and securely verify large amounts of data. However, there's a significant drawback: they cannot store folders of files.

The number of hashes required for a Merkle proof in a Classic Merkle Tree grows logarithmically with the number of file chunks, meaning the growth rate slows as the input (tree) size increases. This pattern makes them very efficient for large datasets because the growth of the Merkle branch size becomes exponentially less as the number of chunks rise.

### ***Scionic Merkle Trees v.s IPFS Merkle DAGs***

Merkle DAGs were developed as a solution to incorporate folders of files, addressing a key limitation of Classic Merkle Trees. However, this structure has its own challenge: to securely download a single file chunk, you must download the hash of every other file chunk inside the folder its stored in. This means that each parent leaf can continue to grow if the number of file chunks in the folder grow, even though the size of each Merkle chunk should always remain the same! This flaw of parent leaves in IPFS Merkle DAGs is resolved by Scionic Merkle Trees because each Scionic parent leaf is chunked using a Classic Merkle Tree, ensuring every part of the Scionic Merkle Tree is uniformly chunked. In the most extreme cases of P2P decentralization, a user could retrieve each Merkle branch from a different source without needing to download the entire parent leaf first.

### ***Folders and Subfolders of Files:***

Like Merkle DAGs, Scionic Merkle Trees can accommodate storing folders of files. This means an entire directory of files and subfolders can be converted into a Scionic Merkle Tree.

### ***Chunked Parent Leaves:***

Within each parent leaf (folder), its list of hashes (chunks/children) are organized as a Classic Merkle Tree rather than a potentially large plaintext list of hashes. Large files or folders lead to many chunks, which can eventually lead to an extremely large lists of hashes. By ensuring the parent leaf is chunked with a Classic Merkle Tree, this scaling problem emerging from large amounts of data can be avoided.

### ***File Chunk Downloading with Chunked Parent Leaves:***

If a user wants to download a specific file chunk within a Scionic Merkle Tree, they no longer need to download every file chunk hash in its folder. Instead, they will download a Classic Merkle branch linked to the folder (parent leaf) they're downloading the file chunk from. This process allows the user to verify that the file is part of the tree without needing to download every hash of all other file chunks in the folder.

### ***Scionic Merkle Tree:***
![Scionic Merkle Tree Diagram](https://i.ibb.co/XJjbwmP/Scionic-Merkle-Tree.jpg)

### ***Scionic Merkle Branch:***
![Scionic Merkle Branch Diagram](https://i.ibb.co/nLcNLw1/Merkle-Branch.png)

## Scionic Merkle Branch Statistics

*Comparing the size of a Scionic Merkle Branch to bloated Merkle DAG Branches:*

* For a folder containing 10 files, a Scionic branch needs just 5 leaves, while a Merkle DAG branch requires all 10. This makes the Scionic branch about **2x smaller**.
* When the folder contains 1000 files, a Scionic branch uses only 11 leaves, compared to the full 1000 required by a Merkle DAG branch. This results in the Scionic branch being approximately **90x smaller**.
* In the case of a folder with 10,000 files, a Scionic branch requires 15 leaves, while a Merkle DAG branch needs all 10,000. This means the Scionic branch is roughly **710x smaller**.
* If the folder contains 1,000,000 files, a Scionic branch for any file in that folder would require around 21 leaves. This Scionic branch would be **50,000x smaller**.

These statistics underline the substantial efficiency improvements made by Scionic Merkle Trees.

## Understanding Growth Patterns: Logarithmic vs Linear

Scionic Merkle Trees, which incorporate Classic Merkle Trees within their structure, exhibit Merkle branches that grow logarithmically; this means that as the size of the input (the number of file chunks in a folder) increases, the growth rate of its Classic Merkle Tree branches decrease. This makes Scionic Merkle Trees an efficient structure for tranmissing large files ***because the growth of the Scionic Merkle branch becomes exponentially less*** as the number of file chunks increase, thanks to the Classic Merkle Trees nested within them.

In stark contrast, the number of hashes required to validate a single file chunk in an IPFS Merkle DAG exhibits linear growth. The hash of each file chunk in the folder must be downloaded in order to retrieve any individual file chunk from the folder. If the number of file chunks grow, then the parent leaf in the Merkle branch grows linearly in size as well; this requirement can lead to overly large Merkle branches that make IPFS Merkle DAGs less efficient for large datasets when compared to Scionic Merkle Trees.

## Syncing Scionic Merkle Trees by Requesting a Range of Leaf Numbers

To further enhance the functionality of Scionic Merkle Trees and support efficient data retrieval, each leaf in the tree is labeled with a sequenced number. The total number of leaves are listed within the Merkle root of the tree, meaning it must be downloaded first before the leaves can be retrieved. This method facilitates [LeafSync Messages, which are requests for a range of Merkle leaves](https://www.hornet.storage/negentropy-leafsync) that correspond to file chunks the requestor is missing.

# Documentation

## Install
```
go get github.com/HORNET-Storage/Scionic-Merkle-Tree/v2/dag
```

## Example Usage
There are good examples inside the `tests/` package (start with `tests/dag_test.go`), but below is a basic example to get you started. This library is intended to be very simple while still allowing for powerful usage...

Turn a folder and its files into a Scionic Merkle DAG-Tree, verify, then convert the Scionic Merkle tree back to the original files in a new directory:
```go
input := filepath.Join(tmpDir, "input")
output := filepath.Join(tmpDir, "output")

// Set chunk size for file processing (optional - defaults to 2 MB)
SetChunkSize(4096)

// Create DAG from directory with timestamp in root
dag, err := CreateDag(input, true)
if err != nil {
  fmt.Fatalf("Error: %s", err)
}

// Verify the entire DAG structure
err = dag.Verify()
if err != nil {
  fmt.Fatalf("Error: %s", err)
}

fmt.Println("Dag verified successfully")

// Recreate the directory structure from the DAG
err = dag.CreateDirectory(output)
if err != nil {
  fmt.Fatalf("Error: %s", err)
}
```

### Advanced Example with Additional Data
```go
// Create DAG with custom additional data
additionalData := map[string]string{
  "author": "example",
  "version": "1.0.0",
}

dag, err := CreateDagAdvanced("./my-directory", additionalData)
if err != nil {
  fmt.Fatalf("Error: %s", err)
}

// Serialize to JSON or CBOR
jsonData, err := dag.ToJSON()
if err != nil {
  fmt.Fatalf("Error: %s", err)
}

// Deserialize from JSON
restoredDag, err := FromJSON(jsonData)
if err != nil {
  fmt.Fatalf("Error: %s", err)
}
```

### Chunking Configuration
```go
// Set custom chunk size
SetChunkSize(1024 * 1024) // 1MB chunks

// Disable chunking entirely (files processed as single chunks)
DisableChunking()

// Reset to default chunk size (2 MB)
SetDefaultChunkSize()
```

## Types

The dag builder and dag leaf builder types are used to temporarily store data during the dag creation process as the dag is created from the root down but then built from the bottom back up to the root.
It is not required to understand how this works but if you plan to build the trees yourself without the built in creation process (for example you may wish to create trees from data already in memory) then these will be useful.

### Dag Leaf
```go
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
```

Every leaf in the tree consists of the DagLeaf data type and these are what they are used for:

### Hash: string
The hash field is a cid, encoded as a string, of the following fields serialized in cbor with sha256 hasing:
- ItemName
- Type
- ContentHash
- ClassicMerkleRoot
- CurrentLinkCount
- AdditionalData

Only the root leaf has these fields included in the hash
- LeafCount
- ContentSize
- DagSize

### ItemName: string
This can be anything but our usage is the file name including the type so that we can accurately re-create a directory / file with all the files and types intact

### Type: LeafType
This is a string but we use a custom type to enforce specific usage, there are currently only 3 types that a leaf can be:
```go
type LeafType string

const (
	FileLeafType      LeafType = "file"
	ChunkLeafType     LeafType = "chunk"
	DirectoryLeafType LeafType = "directory"
)
```

file is a file
chunk are the chunks that make up a file incase the file was larger than the max chunk size
directory is a directory

New types can be added without breaking existing data if needed

### ContentHash: []byte
### content: []byte
ContentHash and Content are important together as you can't have one without the other.
The content hash is a sha256 hash of the content, currently the content is from a file on disk but it could be anything as long as it's serialized in a byte array.
We have no need to encode any of this data as we are using cbor for serializing the leaf data which can safely handle byte arrays directly as it's not a plain text format like json.
The content hash is included in the leaf hash which means it's cryptographically verifiable, which also means the content can be verified as well to ensure there isn't tampering.
This is important because it means we can send and recieve the leaves with or without the content, while still being able to verify the content, which is important for de-duplicating data transmission over the network.

### ClassicMerkleRoot: []byte
We use classic merkle trees inside of our dag by creating a tree of the links inside of a leaf, if the leaf has more than 1 link. This allows us to verify the leaves without having all of the children present making our branches a lot smaller.
This also means we do not need to include the links in the leaf hash because this merkle root is included in their place, potentially removing a lot of data when sending individual leaves if there are a lot of child leaves present.

### CurrentLinkCount: int
This is the count of how many links a leaf has and it's included in the leaf hash to ensure that we always know and can verify how many links a leaf should have which prevents any lying about the number of children when verifying branches or partial trees.

### ContentSize: int64
The total size of all content held by the dag's leaves, counted once per unique leaf. Because the store is content addressed, a chunk shared by two files is one leaf and is therefore counted once. Stored and hashed only in the root leaf.

### DagSize: int64
The total serialized size of the dag. Stored and hashed only in the root leaf.

### Labelling
Labelling is per dag rather than per leaf, and lives on the `Dag` itself as `Labels map[string]string` (label -> leaf hash, excluding the root which is always "0"). Call `CalculateLabels()` to populate it; it is deterministic because it assigns in `IterateDag` traversal order. There is no `LatestLabel` field on a leaf.

### LeafCount: int
The overall number of leaves that the entire dag contains which is why this is only stored and hashed in the root leaf, it ensures you can always know if you have all of the children or not.

### Links: []string
The hashes of a leaf's children, in order. Links are **not** part of the leaf hash — the ClassicMerkleRoot stands in for them — so link order is not cryptographically pinned and must never be trusted for correctness.

Because of that, chunk reassembly does not read link order at all. Every path that rebuilds file content (`Dag.GetContentFromLeaf`, `DagLeaf.CreateDirectoryLeaf`, and the streaming `DagStore` equivalents) re-sorts the children by the chunk's **numeric `ItemName` index** using `compareChunkItemNames`. That comparator also strips a legacy path prefix (`"file/0"` on Unix, `"file\0"` on Windows) before parsing the index, so a dag authored on one platform and read on another still orders chunk 2 before chunk 10 rather than falling back to lexical order.

Link order *is* still preserved verbatim through serialization, and links must be held in an ordered sequence rather than a set or map — but the authoritative ordering key is the ItemName index, not the link position.

One asymmetry worth knowing when building leaves by hand: `BuildLeaf` sorts links lexicographically **only** for `DirectoryLeafType`. File leaves keep their insertion order.

### ParentHash: string
The hash of the leaf's parent, added to make upward traversal possible. This is purely for speed and the parent it points to should still be verified, as we can't include the parent hash inside of the leaf hash.
This is because the parent hash doesn't exist yet, the leaf hashes are created from bottom to top, despite dag creation starting at the top.

Note that a content-identical chunk can be linked by **several** parents, so "the" parent is a choice. It is resolved deterministically to the **lowest parent hash** (`buildParentIndex`); resolving it by Go's randomized map order made proofs and reconstructed parent hashes differ from run to run.

### AdditionalData: map[string]string
This map is included in the leaf hash allowing for developers to add additional data to the dag leaves if and when needed.
AdditionalData does get included in the leaf hash so any content stored here is cryptographically verifiable, the map is sorted by keys alphanumerically before it gets serialized and hashed to ensure consistency no matter what order they get added.
Currently we only use this to store the timestamp in the root leaf which is an optional parameter when creating a dag from a directory or file but advanced users that build the trees themselves can utilize this feature to store anything they want.

## Functions

### DAG Creation and Management
```go
func CreateDag(path string, timestampRoot bool) (*Dag, error)
func CreateDagAdvanced(path string, additionalData map[string]string) (*Dag, error)
func CreateDagCustom(path string, rootAdditionalData map[string]string, processor LeafProcessor) (*Dag, error)

func CreateDagBuilder() *DagBuilder
func (b *DagBuilder) AddLeaf(leaf *DagLeaf, parentLeaf *DagLeaf) error
func (b *DagBuilder) BuildDag(root string) *Dag
func (b *DagBuilder) Stats() DagStats
```

### DAG Operations
```go
func (dag *Dag) Verify() error
func (dag *Dag) CreateDirectory(path string) error
func (dag *Dag) GetContentFromLeaf(leaf *DagLeaf) ([]byte, error)
func (dag *Dag) IterateDag(processLeaf func(leaf *DagLeaf, parent *DagLeaf) error) error
func (d *Dag) GetPartial(leafHashes []string, pruneLinks bool) (*Dag, error)
func ReadDag(path string) (*Dag, error)
```

### Transmission and Synchronization
```go
func (d *Dag) GetLeafSequence() []*TransmissionPacket
func (d *Dag) VerifyTransmissionPacket(packet *TransmissionPacket) error
func (d *Dag) ApplyTransmissionPacket(packet *TransmissionPacket)
func (d *Dag) ApplyAndVerifyTransmissionPacket(packet *TransmissionPacket) error
```

### Serialization
```go
func (dag *Dag) ToCBOR() ([]byte, error)
func (dag *Dag) ToJSON() ([]byte, error)
func FromCBOR(data []byte) (*Dag, error)
func FromJSON(data []byte) (*Dag, error)

func (packet *TransmissionPacket) ToCBOR() ([]byte, error)
func (packet *TransmissionPacket) ToJSON() ([]byte, error)
func TransmissionPacketFromCBOR(data []byte) (*TransmissionPacket, error)
func TransmissionPacketFromJSON(data []byte) (*TransmissionPacket, error)
```

### Chunk Size Configuration
```go
func SetChunkSize(size int)
func DisableChunking()
func SetDefaultChunkSize()
```

### Leaf Builder
```go
func CreateDagLeafBuilder(name string) *DagLeafBuilder
func (b *DagLeafBuilder) SetType(leafType LeafType)
func (b *DagLeafBuilder) SetData(data []byte)
func (b *DagLeafBuilder) AddLink(hash string)
func (b *DagLeafBuilder) BuildLeaf(additionalData map[string]string) (*DagLeaf, error)
func (b *DagLeafBuilder) BuildRootLeaf(dag *DagBuilder, additionalData map[string]string) (*DagLeaf, error)
```

### Leaf Operations
```go
func (leaf *DagLeaf) GetBranch(key string) (*ClassicTreeBranch, error)
func (leaf *DagLeaf) VerifyBranch(branch *ClassicTreeBranch) error
func (leaf *DagLeaf) VerifyLeaf() error
func (leaf *DagLeaf) VerifyRootLeaf(dag *Dag) error
func (leaf *DagLeaf) CreateDirectoryLeaf(path string, dag *Dag) error
func (leaf *DagLeaf) HasLink(hash string) bool
func (leaf *DagLeaf) AddLink(hash string)
func (leaf *DagLeaf) Clone() *DagLeaf
```

### Labels
```go
func (d *Dag) CalculateLabels() error
func (d *Dag) ClearLabels()
```

### Batching (LeafSync transmission)
```go
const DefaultBatchSize = 4 * 1024 * 1024 // 4 MB

func SetBatchSize(size int)
func DisableBatching()
func SetDefaultBatchSize()
func (d *Dag) GetBatchedLeafSequence() []*BatchedTransmissionPacket
```

## Advanced Features

### Transmission Packets and LeafSync Protocol

Scionic Merkle Trees support efficient synchronization through transmission packets. Each packet contains a leaf and its verification proofs, allowing for individual leaf verification without requiring the entire DAG:

```go
// Get all leaves as transmission packets
packets := dag.GetLeafSequence()

// Create a new DAG to receive transmitted leaves
receiverDag := &Dag{
  Leafs: make(map[string]*DagLeaf),
  // ... other initialization
}

// Process each packet individually
for _, packet := range packets {
  // Verify the packet independently
  err := receiverDag.VerifyTransmissionPacket(packet)
  if err != nil {
    fmt.Printf("Packet verification failed: %v\n", err)
    continue
  }

  // Apply the verified packet to the receiver DAG
  receiverDag.ApplyTransmissionPacket(packet)

  // Or combine verification and application in one step
  err = receiverDag.ApplyAndVerifyTransmissionPacket(packet)
  if err != nil {
    fmt.Printf("Failed to apply packet: %v\n", err)
  }
}
```

### Chunking Configuration

The library provides flexible file chunking options:

#### Default Chunking
Files are automatically split into chunks of 2,097,152 bytes (2 MB) by default:
```go
// Uses default chunk size
dag, err := CreateDag("./directory", true)
```

#### Custom Chunk Size
Set a specific chunk size for your use case:
```go
// Set 1MB chunk size
SetChunkSize(1024 * 1024)
dag, err := CreateDag("./directory", true)

// Set 4KB chunk size for smaller files
SetChunkSize(4096)
dag, err := CreateDag("./directory", true)
```

#### Disable Chunking
When chunking is disabled, entire files are processed as single chunks regardless of size:
```go
// Disable chunking - files stored as single chunks
DisableChunking()
dag, err := CreateDag("./directory", true)

// This is equivalent to:
SetChunkSize(-1)
```

**Use DisableChunking() when:**
- Working with many small files where chunking overhead isn't beneficial
- You want simpler DAG structures with fewer total leaves
- Network transmission of individual files is more important than partial file access
- You're building custom chunking logic at a higher level

**Note:** Disabling chunking can result in very large leaves for big files, which may impact memory usage and network transmission efficiency for partial file access.

#### Reset to Default
```go
// Reset back to default 2 MB chunks
SetDefaultChunkSize()
```

The trees are now in beta and the data structure of the trees will no longer change.
#
