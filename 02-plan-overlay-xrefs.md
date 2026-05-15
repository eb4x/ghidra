# Plan 02: Overlay-Aware Cross-Reference Engine

## Context

The RTLink/Plus overlay analyzer (plans 00–01) creates overlay memory blocks and wires stubs to overlay functions, but three gaps prevent full cross-reference tracing:

1. **No overlay entry points** — overlay blocks have code bytes but no function entry points, so auto-analysis never disassembles them. Without disassembly, no instructions exist to produce xrefs.
2. **No thunk functions at stubs** — the dispatch stubs have xrefs to overlay functions, but they aren't marked as thunk functions, so Ghidra's call graph doesn't chain through them. "What calls overlay function X?" doesn't trace back to callers.
3. **No far call xrefs from overlay code** — overlay functions call main-program CRT routines via `CALL FAR seg:offset`, but `OperandReferenceAnalyzer` returns false for 16-bit address spaces (`canAnalyze` checks `bitSize > 16`), and `ConstantPropagationAnalyzer` disables parameter analysis for segmented spaces. Result: far calls in overlay code produce zero xrefs.

## Changes

### A. Seed overlay entry points (modified `RTLinkOverlayAnalyzer.java`)

New method `seedOverlayEntryPoints()`, called in `added()` after directory parsing and before stub discovery. Iterates all function directory entries, creates labels at each target address in overlay blocks, and calls `addExternalEntryPoint()` to trigger auto-analysis disassembly.

Directory parsing was moved out of the `createStubXrefs` conditional so entry points are always seeded. A new `getEntry(int index)` method was added to `RTLinkFunctionDirectory` for raw index iteration (vs. `resolve()` which applies JMPF offset translation).

### B. Thunk functions at dispatch stubs (modified `RTLinkOverlayAnalyzer.java`)

New helper `createThunkAtStub()` called from both `scanForJmpfStubs()` and `scanForInt3fStubs()` after creating xrefs and labels. Creates a function at the overlay target (if none exists), then creates a thunk function at the stub address pointing to it.

- JMPF stubs: 5-byte body (EA + 4 bytes)
- INT 3Fh stubs: 6-byte body (CD 3F + 4 bytes)
- Uses `FunctionManager.createThunkFunction()` for new stubs, or `setThunkedFunction()` if a function already exists at the stub address

### C. Overlay far call xref analyzer (new `RTLinkOverlayXrefAnalyzer.java`)

A separate `INSTRUCTION_ANALYZER` at `REFERENCE_ANALYSIS.after()` priority. Triggers when auto-analysis creates instructions in overlay blocks (after `seedOverlayEntryPoints` causes disassembly).

- `canAnalyze()`: checks MZ format + SegmentedAddressSpace
- `added()`: checks `RTLink Overlay Analyzed` flag, then iterates newly-created instructions
- For each instruction in an overlay block: checks raw bytes for opcode `9A` (CALL FAR) or `EA` (JMP FAR), extracts segment:offset target, resolves in main program's SegmentedAddressSpace, creates xref if target is in a physical (non-overlay) block

**Why a separate analyzer**: `RTLinkOverlayAnalyzer` is a `BYTE_ANALYZER` that runs before disassembly. This `INSTRUCTION_ANALYZER` runs after disassembly creates instructions, when far call targets can be accurately identified from instruction bytes.

## Files

| File | Action |
|------|--------|
| `ghidra/app/util/bin/format/mz/RTLinkFunctionDirectory.java` | **Modify** — add `getEntry(int)` for raw index access |
| `ghidra/app/plugin/core/analysis/RTLinkOverlayAnalyzer.java` | **Modify** — entry point seeding, thunk creation, restructured `added()` |
| `ghidra/app/plugin/core/analysis/RTLinkOverlayXrefAnalyzer.java` | **New** — INSTRUCTION_ANALYZER for overlay far call xrefs |

## Verification

1. `./gradlew :Base:compileJava` — clean build ✓
2. For VICEROY.EXE:
   - Overlay blocks should have disassembled code (not just raw bytes)
   - Function list should include overlay functions (OVL00_xxxx etc.)
   - Dispatch stubs should appear as thunk functions in the function list
   - "Show References To" on an overlay function should trace back through the thunk to callers in the main program
   - Far calls from overlay code to CRT (segment 0x1d1d) should have xrefs
   - Call graph should show transparent chains: main_func → [thunk] → overlay_func
