# Ghidra Enhancement Spec: RTLink/Plus Overlay Support

## Problem Statement

VICEROY.EXE uses the RTLink/Plus overlay manager to swap code pages in and
out of a fixed-size memory frame at runtime. 72% of the binary (~254KB across
30 overlay pages) is effectively invisible to Ghidra's static analysis. This
is not a niche format — RTLink/Plus was widely used in late-DOS commercial
software (Microprose, Sierra, etc.).

## Current Shortcomings in Ghidra

### 1. Overlay code is never disassembled

Overlay pages are stored at file offsets that don't correspond to their
runtime segment addresses. Ghidra's MZ loader maps segments based on the
relocation table in the MZ header, but overlay data lives past the end of
the "normal" executable image. Ghidra treats it as trailing data and ignores it.

**Impact:** ~636 functions are analyzed; hundreds more in overlay pages are not.

### 2. Cross-reference resolution fails through overlay dispatch

All calls to overlay-resident functions go through a jump table (segments
281f and 2a1f) containing CALLF+JMPF stub pairs. The JMPF targets use
virtual page:offset addressing that the overlay manager resolves at runtime.
Ghidra sees JMPF to segment 0x0000 with various offsets — these are
unrelocated and unresolvable statically without understanding the overlay
manager's page mapping.

**Impact:** `get_xrefs_to` returns nothing for data segment addresses
referenced from overlay code. Tracing callers/callees across the overlay
boundary is impossible. The call graph is incomplete.

### 3. Indirect jump tables cause mega-functions

When Ghidra encounters an indirect jump (`JMP word ptr CS:[BX + offset]`)
through a switch table, it sometimes cannot determine the valid target set.
In 16-bit real mode with overlapping segments, this causes the function body
to absorb code from unrelated segments through address aliasing. A 94-byte
switch dispatch at 112b:0002 grew into a 471-byte function spanning from
segment 1000 to segment 1caa.

**Impact:** Decompilation produces garbage. Multiple real functions get merged
into one. Other functions that happen to occupy aliased addresses lose their
boundaries.

### 4. Real-mode segment aliasing confuses function boundaries

In 16-bit real mode, physical address 0x112B2 can be expressed as 112b:0002,
1000:12B2, 1100:02B2, etc. When Ghidra's analysis follows code paths that
cross segment boundaries (even if they map to the same physical memory), it
can create function bodies that span enormous address ranges. This is a
fundamental issue with Ghidra's real-mode memory model.

### 5. No byte pattern wildcards in search

`search_byte_patterns` does not support wildcard bytes (e.g., `C8 ?? 00 00`
to find all ENTER prologues regardless of frame size). This forces multiple
searches with specific values or manual scanning of disassembly output.

## What Needs to Be Implemented

### Feature 1: RTLink/Plus Overlay Loader (highest priority)

A Ghidra loader module (or post-analysis script) that understands the
RTLink/Plus overlay format and maps overlay pages into the analysis.

**Input data (all known, documented in CLAUDE.md):**

```
Overlay data region: file offsets 0x20670 – 0x78D3E

Page header format (16 bytes):
  struct rtlink_page_header {
      uint16 total_paragraphs;     // total record size in 16-byte paragraphs
      uint16 overhead_paragraphs;  // header+relocs+padding; code starts after
      uint32 frame_size;           // always 700 (0x2BC0 = 11200 bytes)
      uint32 reloc_count;          // number of 4-byte relocation entries
      uint32 reserved;             // always 0
  };

Relocation entry format (4 bytes each):
  uint16 offset;    // offset within page code to patch
  uint16 segidx;    // always 0x0000 in observed data (target = data segment)

Global overlay table at file offset 0x20670:
  Same header format. Contains 527 uint32 function directory entries
  followed by ~15KB of resident stub code.

30 overlay pages packed contiguously from 0x24BF0 to EOF.
```

**Required behavior:**

1. Parse the overlay region starting at the known file offset
2. For each of the 30 pages:
   - Read the page header
   - Skip the relocation table and padding
   - Map the code bytes into a memory block in Ghidra
   - Apply relocations (patch in the data segment value at each offset)
   - Run auto-analysis (disassembly + function detection) on the mapped code
3. Parse the jump table stubs in segments 281f and 2a1f
4. Resolve the virtual offset → page mapping so that JMPF targets in the
   stubs can be linked to actual functions in overlay pages
5. Create cross-references from jump table stubs to overlay functions

**Memory mapping strategy:**

Each overlay page should be mapped to its own memory block at a unique
address range (e.g., `OVLY00:0000`, `OVLY01:0000`, etc.) since multiple
pages share the same runtime frame address and cannot coexist in a single
flat address space. Alternatively, use Ghidra's overlay address space feature.

### Feature 2: Overlay-Aware Cross-Reference Engine

Once overlay pages are mapped, extend the xref system to trace references
through the dispatch chain:

```
Caller → CALLF stub (281f/2a1f) → overlay dispatcher (210d:0dab)
  → page load → overlay function
```

When a user asks "what calls function X in overlay page 5?", the system
should be able to trace back through the stub to find all CALLF sites that
target that stub.

Similarly, overlay code contains far calls to CRT functions (segment 1d1d)
with unrelocated segment bytes (`0d 1d` instead of `1d 1d`). After
relocation is applied, these should generate proper xrefs to the CRT.

### Feature 3: Switch Table Recovery for Real-Mode Binaries

Improve handling of indirect jumps through CS-relative tables in real-mode
code. When the pattern is:

```asm
SHL AX, 1        ; multiply index by 2
XCHG AX, BX
JMP word ptr CS:[BX + table_offset]
```

Ghidra should:
1. Recognize this as a switch dispatch
2. Read the jump table entries as word offsets
3. Use the bounds check (CMP + JA before the shift) to determine table size
4. Restrict the function body to targets within the table, not follow
   aliased segment addresses into unrelated code

## Test Cases

A successful implementation would:

1. Discover and disassemble all functions in all 30 overlay pages
2. Show proper decompilation for overlay page 26's `madspack_open` function
   (currently only found via raw hex search at file offset 0x76E50)
3. Resolve xrefs from overlay code to data segment globals
4. Link jump table stubs to their target overlay functions
5. Decompile `get_sprite_id_for_type` (112b:0002) correctly as a simple
   10-case switch returning sprite ID constants

## Reference

- CLAUDE.md contains the complete overlay page catalog (file offsets, code
  sizes, relocation counts) and the page header format
- The RTLink/Plus overlay manager code is in segment 210d (~24KB)
- The dispatch entry point is 210d:0dab (overlay page load)
- FUN_210d_2fd2 is the key page resolution function
