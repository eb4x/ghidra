# 05: Reverse-Engineer the RTLink/Plus Overlay Manager

## Goal

Understand how the overlay manager at segment 210D resolves dispatch stubs to overlay page functions. This is the missing piece — without it, we can't build the stub→overlay cross-reference mapping that makes the analyzer useful.

## Approach

Work in the **original /VICEROY.EXE** project (not test copies). The overlay manager has 61 functions already identified by Ghidra. The task is pure reverse engineering: decompile, rename, annotate, and trace the dispatch logic until the page resolution mechanism is understood.

## What We Know

### Entry points into the overlay manager

| Address | Role | Notes |
|---------|------|-------|
| `FUN_210d_0dab` | Primary dispatch (658 stubs) | Sets mode=0x00, calls 2fd2 |
| `FUN_210d_0d91` | Secondary dispatch (365 stubs) | Sets mode=0x52 ('R'), calls 2fd2 |
| `FUN_210d_0727` | Rare dispatch (1 stub) | Unknown role |
| `FUN_210d_1341` | Internal dispatch (6 stubs) | JMPF targets within 210D itself |

### Key internal functions (call chain from dispatch)

| Address | Role | Notes |
|---------|------|-------|
| `FUN_210d_2fd2` | Page resolution entry | Called by both 0DAB and 0D91 |
| `FUN_210d_302e` | Resolution helper | Checks if byte at [DI-5] == 0x9A (CALLF opcode) |
| `FUN_210d_3254` | Instruction decoder | Examines opcodes 0x9A, 0xE8, MOV patterns at call site |
| `FUN_210d_1695` | Error/fallback path | Called when stack check fails in 0DAB |
| `FUN_210d_37d9` | Re-entrant handler | Called when dispatch is busy |
| `FUN_210d_37ad` | Re-entrant handler | Called after 37d9 |

### Key data structures

| Address | Content | Notes |
|---------|---------|-------|
| `210d:28ad` | 4-byte field (DAT_210d_28ad) | Stores return CS:IP during dispatch |
| `210d:28b3` | Pointer (DAT_210d_28b3) | Points to caller's stack frame |
| `210d:28cd` | String "Smart vectoring failed" | RTLink error message; byte at +0x44 is busy flag, +0x54 is mode flag, +0x41 has status bits, +0x53 is another flag |

### The unanswered question

How does the overlay manager map a JMPF offset (0x0000-0x6D8E) to a specific overlay page number (1-30)?

Possibilities still open:
1. A lookup table somewhere in segment 210D's data area
2. The page number is computed from the stub's own address (its position in a known segment)
3. The JMPF offset encodes the page number implicitly (e.g., each page "owns" a range of offsets)
4. The resolution function at 2fd2→302e→3254 walks back from the return address and extracts page info from the CALLF instruction or surrounding context

## Task List

### Phase 1: Map the dispatch core

1. **Decompile and annotate `FUN_210d_2fd2`** — This is the page resolution function called by both dispatchers. Understand its inputs (what it reads from the stack/globals) and outputs (what it writes to DAT_210d_28ad). Rename variables and the function itself.

2. **Decompile and annotate `FUN_210d_302e`** — Called by 2fd2. Known to check `[DI-5] == 0x9A`. Understand what DI points to (likely the return address = the JMPF instruction in the stub) and what it does with the CALLF bytes before the JMPF.

3. **Decompile and annotate `FUN_210d_3254`** — The instruction decoder. Checks opcodes 0x9A, 0xE8, MOV patterns. This likely extracts the dispatch parameters from the stub instruction bytes. Understand what value it produces and how.

4. **Follow the complete data flow**: trace how the JMPF offset + whatever else is extracted flows through to a page number. The page number must end up somewhere that the page-loading code uses.

### Phase 2: Map the page loading mechanism

5. **Identify the page loading function** — After resolution determines the target page, something loads the page's code from disk/memory into the overlay frame. Find this function and understand:
   - Where the overlay frame is in memory (what segment)
   - How it reads the page data (from file or from a cached copy)
   - How it applies relocations at load time

6. **Find the page table** — The overlay manager must track which page is currently loaded (or which pages, if there are multiple frame slots). Find the data structure that records current page state.

### Phase 3: Understand the 0D91 "R" mode

7. **Trace the 0D91-specific code path** — The mode byte 0x52 ('R') selects different function pointers (0x147c/0x149c vs 0x1216/0x1251). Decompile the functions at these addresses to understand what's different about "R" mode resolution.

8. **Decode the 0D91 JMPF segment meaning** — The 78 distinct segment values (0x0000-0x1103) must encode page+offset or a table index. Once the 0D91 code path is understood, the segment encoding should become clear.

### Phase 4: Build the mapping

9. **Extract the complete stub→(page, offset) mapping** — Once the resolution mechanism is understood, either:
   - Parse the same table/algorithm the overlay manager uses to build the mapping statically
   - Or emulate the resolution for each stub to produce the mapping empirically

10. **Validate against known code** — Check that resolved targets point to valid function prologues in the overlay pages. Cross-reference with the known function at overlay page 26 (`madspack_open` at file offset 0x76E50).

## Notes for the Agent

- Use the Ghidra MCP tools to decompile, rename functions, rename variables, set comments, etc. on the **original /VICEROY.EXE** (not test copies)
- The original has 658 functions and 180KB of mapped memory — no overlay blocks, just the base MZ image
- Segment 210D in Ghidra = the overlay manager. 61 functions already exist there
- Beware of segment aliasing: address 210d:0dab might decompile as a different function if Ghidra normalizes to a different seg:off pair. Always check the function entry address matches what you expect
- The string at 210d:28cd ("Smart vectoring failed") is a useful landmark — data fields near it control the dispatch state machine
- When you find the page resolution mechanism, document it clearly — this is the critical piece needed to fix `RTLinkFunctionDirectory.java` (or replace it entirely)
