# 07: Analyze RTLink/Plus Overlay Functions in VICEROY.EXE

## Goal

Reverse-engineer the overlay functions in VICEROY.EXE to understand what they do. VICEROY.EXE is a DOS game by Microprose that uses the RTLink/Plus overlay system. The overlay code has been loaded into Ghidra and analysis has run — 3,370 functions total, ~2,600 in overlay blocks, 4,737 cross-references between overlays and the main program.

## Setup

- Ghidra is running with the MCP plugin connected
- Project: "viceroy", program: VICEROY.EXE (path `/VICEROY.EXE`)
- **Two programs are open** — always pass `program` parameter explicitly as `VICEROY.EXE`
- 29 overlay blocks: OVERLAY_00 through OVERLAY_28 (1-based page numbering in labels: OVL01 = OVERLAY_00)
- Overlay addresses use the format `OVERLAY_xx::01yyyy`
- Main program code is in segments 1000-281f (default address space)
- Overlay manager is at segment 210D (~24KB, 61 functions) — don't analyze this, it's already understood

## What's Available

### Overlay function naming
- Stub functions in main program: `OVLSTUB_pp_oooo` (page pp, offset oooo)
- Overlay target functions: `OVLpp_oooo` (page pp, offset oooo)
- Auto-discovered functions in overlays have default names like `FUN_...`

### Key tools
- `decompile_function` — decompile by address (use `OVERLAY_xx::01yyyy` format)
- `search_strings` — find strings referenced from overlay code
- `list_strings` — list defined strings with filter
- `get_function_callees` / `get_function_callers` — trace call graphs
- `get_function_xrefs` — cross-references
- `search_functions` — find functions by name pattern
- `rename_function_by_address` — rename once you identify purpose
- `set_plate_comment` — add function documentation
- `batch_set_comments` — add multiple comments at once
- `batch_rename_function_components` — rename function + params + locals atomically

### What we know about the game
VICEROY.EXE is a Microprose strategy/simulation game. The overlay code likely contains:
- Game logic (turn processing, AI, economy simulation)
- UI/menu screens
- File I/O (save/load, resource loading)
- Graphics routines (VGA/EGA rendering)
- Sound/music drivers
- String handling and text display

### CRT and runtime
- Segment 1d1d contains the C runtime library (Borland C likely)
- Common CRT calls from overlay code: printf, malloc, fopen, fread, fwrite, sprintf, memcpy, strcpy, etc.
- Far calls from overlays to 1d1d:xxxx are CRT calls — identifying these helps understand overlay function purpose

## Approach

1. **Start with strings** — search for interesting strings in overlay blocks to find anchor points (file names, error messages, menu text, game terms)
2. **Identify CRT wrappers** — find commonly-called functions that are wrappers around CRT routines
3. **Work outward from anchors** — once you identify a function's purpose from strings or CRT calls, trace its callers/callees to understand the surrounding code
4. **Name and document** — rename functions and add plate comments as you identify them
5. **Group by overlay** — each overlay page likely has a thematic grouping (all graphics code, all save/load code, etc.)

## Notes
- The overlay manager at segment 210D has already been fully reverse-engineered — skip it
- 0D91 "resident" stubs (365 of them) were not resolved — their targets are unknown
- Some decompiler errors are expected (segmented address overflow) — ignore them
- When decompiling, watch for `switch` statements and string references as the best clues
