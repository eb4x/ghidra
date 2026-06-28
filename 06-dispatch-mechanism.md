# 06: RTLink/Plus Overlay Dispatch Mechanism — Resolved

## Summary

The overlay manager page resolution does NOT use a function directory. The page number is **embedded directly in each dispatch stub**, stored as trailing data bytes after the JMPF instruction. The overlay manager reads these bytes at runtime via `[SI+5]` and `[SI+7]` (relative to the JMPF instruction address).

## Stub Layouts

### 0DAB Stubs (14 bytes) — "Load and Call" Dispatch

```
Byte   Content            Field
0-4    9A xx xx yy yy     CALLF seg:0DAB  (call dispatch handler)
5-9    EA oo oo 00 00     JMPF 0000:offset (target offset within overlay page)
10-11  pp pp              page_id: bits 0-13 = 1-based overlay page number
                                   bit 14 (0x4000) = "resident-capable" flag
12-13  ss ss              seg_delta: intra-frame segment offset (added to frame base
                                     to compute the final segment for the JMPF patch)
```

- **658 stubs** use this format
- JMPF segment is always 0x0000 (unpatched)
- At runtime, the overlay manager:
  1. Reads page_id from `[JMPF+5]`
  2. Uses `((page_id & 0x3FFF) - 1) * 2 + page_table_base` to index the page table
  3. Loads the overlay page into the overlay frame (if not already loaded)
  4. Patches the JMPF segment at `[JMPF+3]` with `frame_base + seg_delta`
  5. On subsequent calls, the patched JMPF goes directly to the loaded page

### 0D91 Stubs (10 bytes) — "Resident Call" Dispatch

```
Byte   Content            Field
0-4    9A xx xx yy yy     CALLF seg:0D91  (call resident dispatch handler)
5-9    EA oo oo ss ss     JMPF seg:offset (target in overlay frame, pre-patched)
```

- **365 stubs** use this format
- JMPF segment is NON-ZERO (e.g., 0x1000, 0x1009, 0x1BBB)
- The 'R' flag (0x52 = 'R') set by the 0D91 dispatcher means "Resident" mode
- These stubs point directly into the overlay frame where a page is (or will be) loaded
- The overlay manager handles page-swap bookkeeping but doesn't need to look up the page number from the stub — it derives it from the frame segment

## Page Table

The page table is an array of **2-byte entries** stored at a runtime-initialized base address (`CS:[0x399b]` in the overlay manager, zeroed in the static binary). Each entry corresponds to one overlay page (1-based indexing).

The page table entry at offset `(page_num - 1) * 2` from the base contains status flags:
- Bit 0 (0x0001): page is loaded in a frame
- Bit 14 (0x4000): page swap pending
- Bit 15 (0x8000): page loading in progress
- Bits for frame base address in `ES:[0x2]`

## Resolution Flow (FUN_210d_0ea1)

```
1. Load SI = far pointer to JMPF instruction (from CS:[0x397d])
2. Read AX = [SI+5] (page_id word)
3. If (AX & 0x4000):  → "R" mode path (resident overlay)
     - Set bit 1 of status flags
     - Compute page_table_entry = ((AX & 0x3FFF) - 1) * 2 + page_table_base
     - If page loaded: use existing frame
     - If not: load page, set up frame
4. Else:  → standard overlay loading path
     - Check if overlay already loaded (DAT_210d_2888)
     - If not loaded or different page needed:
       a. Compute page_table_entry (same formula)
       b. Call FUN_210d_1ebd to load page from disk
       c. Set up frame segment
5. Patch JMPF:
     - [SI+3] = frame_base_segment + [SI+7]  (write frame segment to JMPF)
     - [SI+1] = offset within page (already correct)
6. Return to stub → JMPF now executes into loaded overlay page
```

## Key Addresses in Overlay Manager (segment 210D)

| Address | Role |
|---------|------|
| 0DAB | Primary dispatch entry (0DAB stubs) — sets mode=0x00 |
| 0D91 | Resident dispatch entry (0D91 stubs) — sets mode=0x52 ('R') |
| 0EA1 | Core resolution function — page lookup, loading, JMPF patching |
| 1216/1251 | Non-R mode return handlers |
| 147C/149C | R mode return handlers |
| 1EBD | Page loader — reads page from disk, applies relocations |
| 2FD2 | Instruction decoder entry — analyzes call site for smart vectoring |
| 302E | Check for CALLF (0x9A) at [DI-5] |
| 3018 | Check for CALL near (0xE8) at [DI-3] |
| 3094 | Check for indirect CALL via register/memory |
| 3046 | Check for INT instructions (0xCC, 0xCE, 0xCD) |
| 3254 | Recursive instruction pattern decoder |

## Smart Vectoring (FUN_210d_2fd2)

The "smart vectoring" mechanism at 2FD2 is **not** the page resolution — it's an optimization for return path handling. After the overlay call returns, the overlay manager needs to know what instruction called the stub so it can properly restore state. The chain 2FD2→302E→3018→3094→3046→3367→3322 walks backward from the return address checking for:
- 0x9A: CALLF (direct far call to stub)
- 0xE8: CALL near (near call to stub)
- Various MOV/indirect call patterns

This determines how to restore the stack frame after the overlay function returns.

## Implications for the Analyzer

### What to implement:

1. **0DAB stub parsing**: Scan for `9A xx xx 0D 21` (CALLF to segment 210D, offset 0DAB). Read the 14-byte stub:
   - JMPF offset at bytes 6-7 = code offset within overlay page
   - Page ID at bytes 10-11 = `value & 0x3FFF` = 1-based page number
   - Seg delta at bytes 12-13 = intra-frame offset (informational)

2. **0D91 stub handling**: These are 10-byte stubs. The JMPF segment encodes the runtime frame segment. Without the page table (runtime-only), we cannot statically determine which overlay page they target. Options:
   - Skip 0D91 stubs entirely (they represent ~35% of stubs)
   - Use heuristic: match JMPF offset against overlay page code sizes

3. **Delete RTLinkFunctionDirectory.java**: It's based on wrong assumptions. The global table (page 0) contains resident stub code and its relocations, not a function directory.

4. **Simplify the analyzer**: No need for function directory parsing, prologue scanning, or page heuristics for 0DAB stubs. The page number is right there in the stub bytes.

## Verified Against VICEROY.EXE

| Stub Address | Type | JMPF offset | Page# | Seg Delta |
|-------------|------|-------------|-------|-----------|
| 281f:0000 | 0DAB | 0x025A | 25 | 0x00E7 |
| 281f:002c | 0DAB | 0x0118 | 31→exceeds 30 pages? | 0x004F |
| 281f:0048 | 0DAB | 0x000E | 31 | 0x004F |
| 281f:0ef4 | 0DAB | 0x1E66 | 1 | 0x0000 |
| 281f:0f00 | 0DAB | 0x1106 | 1 | 0x0000 |
| 2a1f:0000 | 0DAB | 0x06D2 | 6 | 0x0000 |
| 2a1f:087c | 0DAB | 0x0006 | 20 | 0x024A |
| 2a1f:088a | 0DAB | 0x0198 | 24 | ? |
| 281f:0013 | 0D91 | 0x0000 | (seg=0x1000) | — |
| 281f:001d | 0D91 | 0x002C | (seg=0x1000) | — |
| 2a1f:0868 | 0D91 | 0x0006 | (seg=0x1BBB) | — |

Note: page 31 in stubs like 281f:002c — the analyzer creates 30 code pages (pages 1-30), so page 31 may be an error or the global table (page 0) is counted differently. Need to verify against actual overlay page count.
