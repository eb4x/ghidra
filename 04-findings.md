# 04: Findings and Incorrect Assumptions

## What Works

### Overlay detection and block creation (Plan 00) — WORKS
- The BYTE_ANALYZER correctly detects RTLink/Plus overlay data past the MZ image end
- Paragraph alignment fix: MZ image ends at 0x20665, overlay data starts at 0x20670 (16-byte aligned). Fix: `overlayStart = (imageEnd + 15) & ~15L`
- 31 overlay pages parsed successfully (page 0 = global table, pages 1-30 = code pages)
- 29 overlay memory blocks created in Ghidra with correct code bytes
- `RTLinkPageHeader`, `RTLinkRelocation`, `RTLinkOverlayPage` all parse correctly

### Page header fields — CONFIRMED
```
struct rtlink_page_header {
    uint16 total_paragraphs;     // total record size in 16-byte paragraphs
    uint16 overhead_paragraphs;  // header+relocs+padding; code starts after
    uint32 frame_size;           // 700 (0x2BC) for all pages — paragraphs, not bytes
    uint32 reloc_count;          // number of 4-byte relocation entries
    uint32 reserved;             // always 0
};
```
- `frame_size` = 700 paragraphs = 11200 bytes = 0x2BC0 for all pages. This is the runtime frame size, NOT the individual page code size. Pages have varying code sizes (0x0260 to 0x7350).

### Overlay page catalog — VERIFIED
- 31 pages total (0-30), packed contiguously from file offset 0x20670
- Page 0 is the "global overlay table" — contains resident stub code and relocations, not a function directory
- Pages 1-30 are code pages with sizes ranging from 608 to 29520 bytes

---

## Incorrect Assumptions

### 1. Global table contains a function directory (Plan 01) — WRONG

**Assumed**: The global overlay table (page 0) code region contains an array of uint32 entries encoding `(page_number, offset_in_page)` pairs — a function directory mapping virtual offsets to overlay targets. Plan 01 said "527 such entries across 30 overlay pages."

**Reality**: The 527 entries in the global table are real relocation entries (all have segIdx=0, offsets within code region 0x0009-0x3D0E). The code region (15632 bytes at file offset 0x20EE0) contains actual x86 resident stub code — PUSH/CALL FAR/RETF sequences, 72 RETF instructions, 484 CALL FAR instructions. This is executable code that stays resident, not a lookup table.

**Impact**: `RTLinkFunctionDirectory.java` parses 0 entries and is fundamentally wrong. The entire Plan 01 approach needs to be replaced.

### 2. JMPF offset is a direct function index or byte offset into a directory — WRONG

**Assumed** (Plan 01): The JMPF offset in dispatch stubs is either a direct index into the function directory or a byte offset into it.

**Reality**: The JMPF offset is a code offset within an overlay page, but the page number is determined by the overlay manager through a separate mechanism. With 555 unique JMPF offsets (range 0x0000-0x6D8E) across 658 stubs, most offsets are ambiguous — they fit within multiple pages' code regions.

### 3. There are only two dispatch entry points (0DAB and 0D91) — INCOMPLETE

**Previously documented**: Two CALLF targets at 110D:0DAB (658 stubs) and 110D:0D91 (3 stubs, later found to be 365).

**Actually found**: Four distinct CALLF targets in stubs:
| Target | Stubs | JMPF seg behavior |
|--------|-------|--------------------|
| 110D:0DAB | 658 | seg always 0x0000 |
| 110D:0D91 | 365 | seg varies (0x0000-0x1103), 78 distinct values |
| 110D:0727 | 1 | seg=0x0D1D (points to CRT) |
| 110D:1341 | 6 | seg=0x110D (points within overlay manager itself) |

### 4. JMPF segment is always 0x0000 — WRONG (only true for 0DAB stubs)

**Assumed**: JMPF target segment is always 0 (unrelocated overlay dispatch).

**Reality**: Only the 0DAB stubs have JMPF seg=0. The 0D91 stubs encode meaningful information in the JMPF segment — 78 distinct values ranging from 0x0000 to 0x1103. These are NOT page numbers (max page is 30), NOT cumulative paragraph offsets from overlay start, and NOT flat byte offsets. Their meaning is still unknown.

### 5. Prologue scanning can disambiguate page targets — UNRELIABLE

**Attempted**: Scan each overlay page for function prologues (PUSH BP, ENTER, etc.) at each JMPF offset to determine which page the offset belongs to.

**Result**: 223 unique matches, 259 ambiguous (multiple pages have prologues at that offset), 73 no-match (offset doesn't point to a prologue in any page). Not reliable enough for automated resolution.

---

## Key Discoveries

### The overlay manager is at segment 210D (~24KB)
- 61 functions already identified by Ghidra in the original VICEROY.EXE
- Contains the string "Smart vectoring failed" at 210d:28cd — this is RTLink/Plus terminology
- Both 0DAB and 0D91 dispatch paths call `FUN_210d_2fd2` for page resolution

### Dispatch mechanism (partially understood)
- `FUN_210d_0dab` (0DAB dispatch): sets a "mode" byte to 0x00, saves return address, calls `FUN_210d_2fd2`
- `FUN_210d_0d91` (0D91 dispatch): sets the same mode byte to 0x52 ('R'), otherwise identical logic
- The 'R' flag selects different code paths after resolution (different function pointers: 0x147c/0x149c vs 0x1216/0x1251)
- `FUN_210d_2fd2` is the core page resolution function — call chain: `2fd2` → `302e` → `3254`
- `FUN_210d_3254` examines instruction bytes at the call site (checks for opcodes 0x9A, 0xE8, MOV patterns)
- The resolution mechanism reads the JMPF instruction at the return address to extract dispatch parameters

### Stubs are interleaved, not grouped
- 0DAB and 0D91 stubs are interleaved by physical address (not in separate segments)
- Stubs span physical addresses 0x181F0-0x1B204 (file offsets 0x1A5F0-0x1D604)
- This corresponds to segments around 0x281F in Ghidra's address space

### DS register discovery is deferred
- At BYTE_ANALYZER priority, the entry point hasn't been analyzed yet, so DS register value falls back to 0x1000
- Not critical for block creation but affects relocation patching accuracy

---

## Tooling Lessons

### Eclipse MCP workflow
- All Java edits must go through Eclipse MCP tools (replaceString, applyPatch, insertIntoFile), NOT direct filesystem writes
- Eclipse's incremental compiler only sees changes made through its workspace — filesystem edits leave class files stale
- Hot code replace works when Ghidra is launched from Eclipse in debug mode

### Ghidra segment aliasing
- 16-bit real mode segment aliasing causes Ghidra to sometimes resolve addresses to unexpected functions
- Physical address 0x11E7B can be 110d:0dab or 112b:0790 — Ghidra may pick the "wrong" normalization
- Always verify decompilation targets by checking the function entry address, not just the address you requested

---

## Current State of Code

| File | Status |
|------|--------|
| `RTLinkPageHeader.java` | Working correctly |
| `RTLinkRelocation.java` | Working correctly |
| `RTLinkOverlayPage.java` | Working correctly |
| `RTLinkOverlayAnalyzer.java` | Partially working — block creation works, function directory resolution broken, diagnostic logging still present |
| `RTLinkFunctionDirectory.java` | Fundamentally broken — wrong assumption about data format, parses 0 entries |
| `RTLinkOverlayXrefAnalyzer.java` | Written but untested — depends on correct entry point seeding |
