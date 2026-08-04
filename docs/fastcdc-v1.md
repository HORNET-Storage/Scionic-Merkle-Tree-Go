# fastcdc-v1 — Normative Chunking Specification

**Status: NORMATIVE and FROZEN.** This document defines `fastcdc-v1`, the default content-defined chunking mode for Scionic Merkle Trees (FastCDC, Xia et al. 2016, with fixed parameters). Chunking runs client-side — the client builds and signs the DAG — so **every SDK must produce bit-identical boundaries**: the content plane dedups across upload contexts only if every path cuts identical chunks. A divergent implementation — one wrong gear constant, one off-by-one — produces valid-looking trees that never dedup, and is detectable **only** by the conformance vectors. Nothing in this document may change; any change is a new tag (`fastcdc-v2`), never a mutation.

Verification is chunking-agnostic and **MUST NOT re-chunk**. Verifiers are unchanged by this spec; v2 trees (fixed-size, tagless) remain valid and verifiable forever.

## Constants

| Constant | Value | Meaning |
| --- | --- | --- |
| `min` | 524288 (512 KiB) | Cut-point skipping: bytes `[0, min)` of each chunk are skipped entirely — not tested **and not hashed**. Interior chunks are therefore ≥ `min`+1 bytes; only a final tail chunk may be ≤ `min`. |
| `target` | 2097152 (2 MiB) | Normalization switch: strict mask before, loose mask after. Matches the legacy fixed default, preserving leaf counts. |
| `max` | 8388608 (8 MiB) | Forced cut. Bounds worst-case chunk size for record framing and transport; rarely reached on real content. |
| `strictMask` | `0xFFFFFE0000000000` | Top 23 bits of the rolling hash. Boundary ⇔ `h & strictMask == 0` ⇔ `h < 2^41`. |
| `looseMask` | `0xFFFFE00000000000` | Top 19 bits. Boundary ⇔ `h < 2^45`. `looseMask ⊂ strictMask`. |

## Gear table

The 256-entry table of `uint64` constants is derived once and checked into the reference repository at `dag/fastcdc_gear.go` (regenerate: `go run ./tools/geargen`). Derivation, frozen:

```text
G[i] = u64be( SHA-256( ASCII "scionic-fastcdc-v1:gear:" ++ byte(i) )[0:8] )
```

`byte(i)` is the single raw byte with value `i` (0..255) appended to the ASCII prefix; `u64be` reads the first 8 digest bytes big-endian. Eyeball anchors: `G[0] = 0x947e4e1b8bedab5d`, `G[1] = 0xd7d7f340329c706e`, `G[255]` is the table's final entry in `fastcdc_gear.go`. Ports may copy the constants or re-derive them; either way their CI must include a derivation test (the Go reference runs `TestFastCDCGearTableMatchesSeedDerivation`).

## The boundary function (normative)

The Go reference loop **is** the definition. `data` is the unchunked remainder; the caller guarantees `len(data) ≥ max` or `data` ends at EOF — under that contract the decision is final, because a boundary can never depend on bytes past the forced maximum.

```go
func fastCDCBoundary(data []byte) int {
	n := len(data)
	if n <= min {
		return n // tail rule: the whole remainder is one chunk
	}
	limit := n
	if limit > max {
		limit = max
	}
	normal := target
	if normal > limit {
		normal = limit
	}
	var h uint64
	for i := min; i < normal; i++ {
		h = (h << 1) + G[data[i]] // wrapping uint64 arithmetic
		if h&strictMask == 0 {
			return i + 1 // cut AFTER the matching byte
		}
	}
	for i := normal; i < limit; i++ {
		h = (h << 1) + G[data[i]]
		if h&looseMask == 0 {
			return i + 1
		}
	}
	return limit // forced cut at max, or EOF tail
}
```

Rules a port must not miss:

1. **Wrapping arithmetic.** `h = (h << 1) + G[b]` is modulo 2^64. Languages without native wrapping integers must emulate it exactly.
2. **`h` starts at 0 for every chunk**, and the skipped bytes `[0, min)` are never hashed — the hash window effectively begins at offset `min`.
3. **Cut position is `i + 1`**: the boundary test runs after including byte `i`, and a match ends the chunk after that byte.
4. **The hash carries across the mask switch**: the loose loop continues with the `h` accumulated in the strict loop.
5. **Tail rule**: a remainder ≤ `min` is one chunk, untested. Consequently interior chunks are ≥ `min`+1 bytes; a final chunk may be any size ≥ 1.
6. **Streaming windowing rule**: implementations may stream with a single `max`-sized window; a boundary decision is final iff the window holds `max` bytes or the input is exhausted. Streamed output must equal whole-buffer cutting byte for byte (pinned by `TestFastCDCStreamingMatchesSliceCutting`).

## Tree shape rules (unchanged from v2)

- **Empty file** ⇒ a file leaf with no content and no chunks (`ContentSize` 0).
- **Exactly one chunk** (input ≤ `min`, or no cut before EOF) ⇒ the bytes are stored directly on the file leaf; **no chunk leaves exist**. Identical to the fixed-mode single-chunk shape.
- **Multiple chunks** ⇒ one chunk leaf per chunk, `ItemName` = bare decimal cut index (`"0"`, `"1"`, `"2"`, …), file-leaf links in cut order. No path separators in chunk names.
- Files in `(min, 2 MiB]` may now split where `fixed-2m` kept them whole — expected and correct.

## Root tag

Producers stamp `AdditionalData["chunking"] = "fastcdc-v1"` on the root leaf of every tree cut under this mode. The library owns the key (a caller-supplied value is overwritten — a tag that misstates how the tree was cut breaks delta tooling). Legacy fixed modes stamp nothing; **absent ⇒ `fixed-2m`** (all pre-fastcdc v2 trees). The tag informs producers and delta tooling only — verifiers ignore it and never re-chunk.

## Delta property (what “reuse” means)

Chunk reuse is **content-hash-level**: `sha256(chunk bytes)` — the content-plane key — is what survives an edit. Chunk **leaf CIDs** downstream of an insertion legitimately change even when their bytes are identical, because a chunk leaf's `ItemName` is its cut index and insertions renumber later chunks. That renumbering is skeleton-plane cost, which is per-DAG by design. Edit vectors therefore assert reused-vs-new **chunk hash sets**, never leaf CIDs.

## Conformance corpus (`spec/fastcdc-vectors/`)

Generated by `go run ./tools/fastcdcvectors -out spec/fastcdc-vectors` and committed. Corpus **inputs are regenerated, never committed**; every port implements the deterministic generator:

```text
corpus(seed, length): block[k] = SHA-256( UTF-8(seed) ++ u64be(k) ), k = 0,1,2,…
                      stream   = block[0] ++ block[1] ++ … truncated to length
```

Zero-fill cases are literal runs of `0x00`. Each manifest case records the seed/fill, length, chunk **end offsets**, chunk SHA-256s (hex), and — for DAG cases — the root CID of the single-file tree built from the input under fastcdc-v1 (which also pins the root tag, chunk naming, and stats). Edit cases record the base case, the edit operation, and the expected reused/new chunk-hash partition. A port is conformant only when every case matches exactly; the vectors run in every SDK's CI (Go: `tests/fastcdc_vector_parity_test.go`).

## Port checklist

- [ ] uint64 wrapping on `(h << 1) + G[b]`
- [ ] `u64be` (big-endian) in gear derivation and corpus generator
- [ ] `h = 0` at every chunk start; bytes `[0, min)` skipped AND unhashed
- [ ] cut at `i + 1`, after the matching byte
- [ ] `h` carries across the strict→loose switch at `target`
- [ ] forced cut at `max`; tail ≤ `min` emitted untested
- [ ] streaming equals whole-buffer cutting
- [ ] single-chunk files store bytes on the file leaf (no chunk leaves)
- [ ] chunk leaves named by bare decimal index, no separators
- [ ] root tag `chunking=fastcdc-v1` stamped; absent under legacy fixed
- [ ] gear derivation test + full vector corpus wired into CI
