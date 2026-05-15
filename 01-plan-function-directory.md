# Plan 01: Function Directory Resolution

## Context

The RTLink/Plus overlay analyzer (plan 00) creates overlay memory blocks and scans for dispatch stubs, but `resolveStubTarget()` used a naive heuristic — it picked the first overlay page where the virtual offset fits within the code size. This is wrong: the JMPF stubs encode a virtual function index that maps through a **function directory** in the global overlay table. Without parsing that directory, stub→overlay xrefs are unreliable or missing.

The global overlay table (the first "page" in the overlay data) contains a function directory: an array of `uint32` entries that map virtual function IDs to `(page_number, offset_within_page)` pairs. The spec says VICEROY.EXE has 527 such entries across 30 overlay pages.

## Changes

### New file: `RTLinkFunctionDirectory.java`

**Location**: `Ghidra/Features/Base/src/main/java/ghidra/app/util/bin/format/mz/RTLinkFunctionDirectory.java`

Parses the function directory from the global overlay table's code region and provides resolution from virtual offset to (page, code_offset).

```java
public class RTLinkFunctionDirectory {

    // Each directory entry: uint32 in little-endian
    // Low 16 bits = offset within the overlay page code
    // High 16 bits = 1-based page number (1 = first code page)
    public record DirectoryEntry(int pageNumber, int offsetInPage) {}

    private final List<DirectoryEntry> entries;

    public RTLinkFunctionDirectory(BinaryReader reader, long directoryFileOffset,
            int maxEntries, int numCodePages, long frameSize) throws IOException { ... }

    public DirectoryEntry resolve(int virtualOffset) { ... }
    public int getEntryCount() { ... }
}
```

**Parsing logic**:
- Read uint32 values from `directoryFileOffset` in the file
- Interpret each as: `page = (value >> 16) & 0xFFFF`, `offset = value & 0xFFFF`
- Validate: `page` must be 1..numCodePages, `offset` must be < frameSize
- Stop reading when 3 consecutive entries fail validation (indicates end of directory / start of stub code)
- Trim trailing invalid entries
- If this encoding produces 0 valid entries, try alternate encoding: `page = value & 0xFFFF`, `offset = (value >> 16) & 0xFFFF` — whichever produces more valid entries wins
- Zero-valued entries (`0x00000000`) are kept as valid placeholders (unused function slots)

**Resolution logic** — `resolve(int virtualOffset)`:
- The JMPF's 16-bit offset field is used as the lookup key
- Default mode: direct index (`entries.get(virtualOffset)`) — JMPF offset = function index
- Fallback mode: byte-offset (`entries.get(virtualOffset / 4)`) — JMPF offset = byte offset into directory
- Auto-detected: byte-offset mode selected only when entry count exceeds 0x3FFF (which would make 16-bit direct indexing impossible)

### Modified file: `RTLinkOverlayAnalyzer.java`

**Changes**:

1. **Parse function directory after parsing pages** (in `added()`, between overlay block creation and stub discovery):
   ```java
   RTLinkFunctionDirectory directory = new RTLinkFunctionDirectory(
       reader, globalTable.getCodeFileOffset(),
       (int)(globalTable.getCodeSize() / 4),  // max possible entries
       codePages.size(),
       codePages.get(0).getFrameSize());
   ```

2. **Pass directory to stub discovery** — update `discoverAndProcessStubs()` signature:
   - Remove `RTLinkOverlayPage globalTable` and `BinaryReader reader` parameters
   - Add `RTLinkFunctionDirectory directory` parameter

3. **Update `scanForJmpfStubs()`**:
   - Add `RTLinkFunctionDirectory directory` parameter
   - Early-return 0 if directory is null or empty
   - Use `directory.resolve(virtualOffset)` to get `DirectoryEntry`
   - Use `entry.offsetInPage()` for target address (not raw JMPF offset)
   - Use `entry.pageNumber()` for labels (not derived from block index)

4. **Replace `resolveStubTarget()`** — from naive size-based heuristic to:
   ```java
   private OverlayBlockInfo resolveStubTarget(
           RTLinkFunctionDirectory.DirectoryEntry entry,
           List<OverlayBlockInfo> overlayBlocks) {
       int blockIndex = entry.pageNumber() - 1;  // directory pages are 1-based
       if (blockIndex < 0 || blockIndex >= overlayBlocks.size()) {
           return null;
       }
       return overlayBlocks.get(blockIndex);
   }
   ```

5. **`scanForInt3fStubs()`** — no change needed (already uses overlayId as direct page index, independent of the function directory)

### Summary of signature changes

| Method | Before | After |
|--------|--------|-------|
| `discoverAndProcessStubs()` | `(program, overlayBlocks, globalTable, reader, log, monitor)` | `(program, overlayBlocks, directory, log, monitor)` |
| `scanForJmpfStubs()` | `(program, overlayBlocks, log, monitor)` | `(program, overlayBlocks, directory, log, monitor)` |
| `resolveStubTarget()` | `(int virtualOffset, List<OverlayBlockInfo>)` | `(DirectoryEntry entry, List<OverlayBlockInfo>)` |

## Files

| File | Action |
|------|--------|
| `ghidra/app/util/bin/format/mz/RTLinkFunctionDirectory.java` | **New** |
| `ghidra/app/plugin/core/analysis/RTLinkOverlayAnalyzer.java` | **Modify** — parse directory, wire into stub resolution |

## Verification

1. `./gradlew :Base:compileJava` — clean build
2. For VICEROY.EXE: directory should parse 527 entries across 30 pages
3. JMPF stubs with segment 0x0000 should now resolve to the correct page AND correct offset within that page, not just "first page where offset fits"
4. xref labels should show accurate page numbers and offsets (e.g., `OVL26_xxxx` for functions in overlay page 26)
