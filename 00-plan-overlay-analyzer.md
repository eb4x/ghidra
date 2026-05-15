# Plan 00: RTLink/Plus Overlay Analyzer

## Context

Ghidra's MzLoader ignores overlay data past the MZ image end, leaving ~72% of RTLink/Plus-based DOS binaries unanalyzed. This plan describes a standalone BYTE_ANALYZER that runs after MzLoader, detects RTLink/Plus overlay pages in the trailing file data, creates overlay memory blocks for each page, applies segment relocations, and wires cross-references from dispatch stubs to overlay functions. It's general-purpose — no hardcoded offsets.

## New Files (4 total)

All in `Ghidra/Features/Base/src/main/java/`:

| # | File | Purpose |
|---|------|---------|
| 1 | `ghidra/app/util/bin/format/mz/RTLinkPageHeader.java` | Parse 16-byte page header, validate, StructConverter |
| 2 | `ghidra/app/util/bin/format/mz/RTLinkRelocation.java` | Parse 4-byte relocation entry, StructConverter |
| 3 | `ghidra/app/util/bin/format/mz/RTLinkOverlayPage.java` | Container for one page (header + relocs + code region metadata) with static factory to parse all pages |
| 4 | `ghidra/app/plugin/core/analysis/RTLinkOverlayAnalyzer.java` | BYTE_ANALYZER: detection, block creation, relocations, xrefs |

No existing files are modified.

---

## File 1: `RTLinkPageHeader.java`

Parses the 16-byte struct from a `BinaryReader`:

```
uint16 totalParagraphs      — total record size in 16-byte paragraphs
uint16 overheadParagraphs   — header+relocs+padding; code starts after
uint32 frameSize            — overlay frame size (e.g. 0x2BC0)
uint32 relocCount           — number of 4-byte relocation entries
uint32 reserved             — always 0
```

Key methods:
- Constructor reads 2 shorts + 3 ints from reader (all unsigned)
- `getTotalSizeBytes()` → `totalParagraphs * 16`
- `getOverheadSizeBytes()` → `overheadParagraphs * 16`
- `getCodeSizeBytes()` → `getTotalSizeBytes() - getOverheadSizeBytes()`
- `isValid()` — validation checks (see below)
- `toDataType()` — StructureDataType under category `/DOS/RTLink`

Validation in `isValid()`:
1. `totalParagraphs > 0`
2. `overheadParagraphs > 0 && overheadParagraphs <= totalParagraphs`
3. `frameSize > 0 && frameSize <= 0x10000`
4. `reserved == 0`
5. `HEADER_SIZE + relocCount * 4 <= overheadParagraphs * 16` (relocs fit in overhead)

## File 2: `RTLinkRelocation.java`

Parses a 4-byte relocation entry from `BinaryReader`. Follows `MzRelocation.java` pattern.

Fields: `int offset` (uint16), `int segIndex` (uint16).
- `toDataType()` — StructureDataType under `/DOS/RTLink`

## File 3: `RTLinkOverlayPage.java`

Container class — stores header, relocation list, page index, and file offset. Does NOT hold code bytes (those come from FileBytes when creating memory blocks).

Key methods:
- Constructor: reads header at fileOffset, then reads `relocCount` relocation entries
- `getCodeFileOffset()` → `fileOffset + header.getOverheadSizeBytes()`
- `getCodeSize()` → `header.getCodeSizeBytes()`
- Static `parseAllPages(BinaryReader reader, long overlayStart, long fileLength)`:
  - Walks pages contiguously from `overlayStart`
  - Stops when header validation fails or file end reached
  - Returns `List<RTLinkOverlayPage>`
  - The first entry (the global overlay table) is parsed as a page too — the analyzer handles it specially

## File 4: `RTLinkOverlayAnalyzer.java`

### Registration
- Extends `AbstractAnalyzer`
- Type: `AnalyzerType.BYTE_ANALYZER`
- Priority: `AnalysisPriority.FORMAT_ANALYSIS.after()` — after MzLoader finishes, before disassembly
- Default enabled: `true`
- Class name ends in "Analyzer" → auto-discovered by ClassSearcher (Base module already lists "Analyzer" in `ExtensionPoint.manifest`)

### `canAnalyze(Program program)`
1. `program.getExecutableFormat()` must equal `"Old-style DOS Executable (MZ)"` (from `MzLoader.MZ_NAME`)
2. Default address space must be `SegmentedAddressSpace`

### `added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)`

Run-once guard: track `lastTxId` (same pattern as `GolangSymbolAnalyzer`). Also check a stored program property to skip across sessions.

Main flow:

**Step 1 — Get file bytes and build reader**
```java
FileBytes fileBytes = program.getMemory().getAllFileBytes().get(0);
ByteProvider provider = new FileBytesProvider(fileBytes);
BinaryReader reader = new BinaryReader(provider, true); // little-endian
```

**Step 2 — Compute MZ image end (overlay start)**

Parse `OldDOSHeader` from the reader. Compute image end:
```java
int pages = Short.toUnsignedInt(header.e_cp());
int lastPageBytes = Short.toUnsignedInt(header.e_cblp());
long imageEnd = (lastPageBytes == 0) ? (long) pages * 512 : ((long)(pages - 1)) * 512 + lastPageBytes;
```
If `imageEnd >= fileBytes.getSize()`, no overlay data — return false.

**Step 3 — Detect RTLink/Plus format**

Read a tentative `RTLinkPageHeader` at `imageEnd`. Validate with `isValid()`. For extra confidence, if a second page fits in the file, check that it has the same `frameSize`. If detection fails, return false silently.

**Step 4 — Parse all overlay pages**

Call `RTLinkOverlayPage.parseAllPages(reader, imageEnd, fileBytes.getSize())`. The first "page" is the global overlay table (function directory + resident stubs) — separate it from the actual code pages. Log the count.

**Step 5 — Create overlay memory blocks**

For each code page (pages after the global table):
```java
SegmentedAddressSpace space = (SegmentedAddressSpace) program.getAddressFactory().getDefaultAddressSpace();
Address overlayBase = space.getAddress(0x1000, 0); // same base as MzLoader's INITIAL_SEGMENT_VAL

MemoryBlock block = MemoryBlockUtils.createInitializedBlock(
    program, true,  // isOverlay=true → new overlay address space per block
    String.format("OVERLAY_%02d", pageIndex),
    overlayBase, fileBytes, page.getCodeFileOffset(), page.getCodeSize(),
    "RTLink/Plus overlay page " + pageIndex, "RTLink",
    true, false, true,  // r, w, x
    log);
```

Each block gets its own overlay space (no collision despite shared base address). Store the `(page, block)` pairs for later steps.

**Step 6 — Apply relocations**

Discover the data segment value from `ProgramContext`:
```java
Register ds = program.getProgramContext().getRegister("ds");
BigInteger dsValue = context.getValue(ds, entryAddress, false);
```
Fallback: scan entry point for `mov dx, imm16` (0xBA), then fall back to 0x1000.

For each relocation in each page:
- `segIndex == 0` → patch with data segment value
- `segIndex != 0` → patch with `(0x1000 + currentValue) & 0xffff` (standard MZ relocation adjustment)

Apply via `memory.setShort(blockStart.add(reloc.offset), (short) segmentValue)` and record in `program.getRelocationTable()`.

**Step 7 — Discover and process jump table stubs**

Two detection strategies, tried in order:

*Strategy A — JMPF with segment 0x0000:*
Scan non-overlay executable blocks for far jump instructions (opcode `EA`) where the target segment bytes are `00 00`. These are unrelocated overlay dispatch jumps. The offset is a virtual function index resolved through the function directory (see plan 01).

*Strategy B — INT 3Fh (fallback for older RTLink):*
Scan for `CD 3F` byte pattern. The two words following are overlay_id and target offset.

For each discovered stub, create a reference and labels.

**Step 8 — Markup headers (optional)**

For each page, create an overlay block in `OTHER_SPACE` containing the raw header+relocation data, then apply `RTLinkPageHeader.toDataType()` and `RTLinkRelocation.toDataType()` as data structures.

### Analyzer Options

Three booleans registered via `registerOptions()`:
- "Apply Relocations" (default: true)
- "Create Stub Cross-References" (default: true)
- "Markup Page Headers" (default: true)

---

## Key APIs Reused

| API | Source | Used for |
|-----|--------|----------|
| `MemoryBlockUtils.createInitializedBlock(program, isOverlay, ...)` | `MemoryBlockUtils.java` | Creating overlay memory blocks from FileBytes |
| `FileBytesProvider(fileBytes)` | `FileBytesProvider.java` | Wrapping FileBytes as ByteProvider for BinaryReader |
| `BinaryReader(provider, littleEndian)` | `BinaryReader.java` | Parsing overlay headers and relocations |
| `Memory.getAllFileBytes()` | `Memory.java` | Retrieving stored file bytes from program |
| `ReferenceManager.addMemoryReference(...)` | `ReferenceManager.java` | Creating xrefs from stubs to overlay functions |
| `ProgramContext.getValue(register, address, ...)` | `ProgramContext.java` | Reading DS register value set by MzLoader |
| `DataUtilities.createData(...)` | `DataUtilities.java` | Applying struct markup to headers |

## Verification

1. **Build**: `gradle buildGhidra` from repo root — confirms compilation
2. **Unit tests**: Add test class in `Ghidra/Features/Base/src/test/java/` that constructs synthetic RTLink page data, parses it, and verifies field values
3. **Integration test with VICEROY.EXE**:
   - Import VICEROY.EXE into Ghidra with MzLoader
   - Verify analyzer auto-detects 30 overlay pages
   - Verify OVERLAY_00 through OVERLAY_29 blocks appear in the memory map
   - Verify relocations are applied (data segment references patched)
   - Verify xrefs exist from main program stubs to overlay functions
   - Check overlay page 26 for `madspack_open` (spec test case)
   - Check decompilation produces meaningful output for overlay functions
