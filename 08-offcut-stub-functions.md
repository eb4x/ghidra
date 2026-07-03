# 08: The three offcut overlay stubs (accepted, will not fix)

## Summary / decision

Of the 604 RTLink dispatch stubs the analyzer resolves, **three** never end up as
clean thunked functions:

| Stub | Target | Overlay page | Runtime entry decodes cleanly? | Ghidra function state |
|------|--------|--------------|-------------------------------|------------------------|
| `281f:0000` (`OVLSTUB_24_025A`) | `OVERLAY_23::01025A` | 24 | **yes** (trampoline) | exists but body is an offcut-merged mega-blob |
| `281f:0574` (`OVLSTUB_04_14A8`) | `OVERLAY_03::0114A8` | 4  | **no** (mid-instruction) | 21-byte garbage function |
| `281f:05b6` (`OVLSTUB_25_0034`) | `OVERLAY_24::010034` | 25 | **yes** | deleted by body-repair pass |

**Decision: accept these three as-is and do not attempt to fix them.** They are a
manifestation of *overlapping / offcut 16-bit code*, which Ghidra fundamentally
cannot represent (one code unit per address per space — see the "why" section).
Every fix attempt either fails to change the outcome or actively corrupts a
routine (see commit history: the "bound stub bodies" attempt was reverted because
capping split a real instruction). Navigation still works: each stub keeps a
surviving `UNCONDITIONAL_CALL` reference to its target, so "go to target" from the
stub is intact.

Assembly and decompile for each are exported under
[`overlay-offcut-exports/`](overlay-offcut-exports/).

## Why Ghidra can't just show both alignments

Ghidra stores at most **one defined code unit per (address-space, offset)**, with
all instructions occupying mutually disjoint ranges
(`CodeManager.checkValidAddressRange` throws `CodeUnitInsertionException` on any
byte-range overlap). The only overlap feature is *length-override*, which merely
shrinks an instruction so a later one can start inside its parsed bytes — it
models "flow that converges after an offcut," not two independent decodings. The
only faithful way to hold both alignments is a **second overlay space over the
same file bytes**, but the decompiler collapses an overlay to its base and
handles only one overlay-per-base, so the alternate alignment would be listable
but not coherently decompilable across flow. Not worth it for three cosmetic
cases. (Full investigation is in the session notes; this file is the takeaway.)

## The shared mechanism

Each overlay page is disassembled starting from its stub targets, following
flow. When two entries into the same page imply **different instruction
alignments of the same bytes**, Ghidra's page-flow (fall-through) decode wins the
bytes, and the stub target that disagrees is left offcut. Downstream,
`ClearFlowAndRepairCmd` (run by the non-returning-functions / call-fixup passes)
treats an offcut entry as "not a valid subroutine start" and **removes** it;
removing a thunk's target then breaks the stub thunk. That is why these three
stay non-thunk.

---

## 1. `OVL24_025A` — menu / list-selection UI handler

- **Stub / target:** `281f:0000` → `OVERLAY_23::01025A`
- **Caller (live):** `FUN_1d1d_0150` (game startup/init sequence)
- **What it does:** `OVL24_025A` is a 2-instruction trampoline
  (`LES AX,[SI]; JMP 0x010246`) into `FUN_OVERLAY_23__010246`, a **keyboard-driven
  menu/list selector**: saves the screen region (`[0x83a0..0x83a4]`), draws each
  list item as a NUL-terminated string, reads keys and dispatches on scancodes
  (`0x20` space, `0x1b` ESC, `0x148`/`0x150` up/down arrows), highlights the
  current entry, and returns the chosen index.
- **The offcut:** page-flow decodes `010259: ADD SP,0x4` (`83 c4 04`) which spans
  `010259..01025b` and swallows `01025a`. The entry itself is a valid 2-byte
  `LES AX,[SI]`, so a function *does* get created — but its declared body
  `01025a-01119a` is an **offcut-merged mega-blob** that absorbed ~8 neighbouring
  routines (many stray `ENTER`/`RETF` pairs), and the decompile is partial
  ("bad instruction data").
- **Export:** [`OVL24_025A.asm`](overlay-offcut-exports/OVL24_025A.asm),
  [`OVL24_025A.decomp.c`](overlay-offcut-exports/OVL24_025A.decomp.c)

## 2. `OVL04_14A8` — offcut into a far-call argument push run (unrecoverable)

- **Stub / target:** `281f:0574` → `OVERLAY_03::0114A8`
- **Caller (live):** `FUN_130d_0290`
- **What it does:** *Undetermined from this entry.* The stub target `0114A8` is
  the **last byte of `PUSH word ptr [0x2dae]`** (`ff 36 ae 2d`, spanning
  `0114a5..0114a8`). The real surrounding code is a run of far-call argument
  pushes (`PUSH [0x2dac]; PUSH [0x2daa]; PUSH [0x2da8]; …` from `0114a9`), i.e. the
  intended routine's true entry is one byte past the stub target. Decoding from
  `0114A8` yields garbage; Ghidra's 21-byte function there
  (`… MOV AX,0x57; MOV DX,0x19; RETF`) is meaningless. This is the only one of the
  three whose stub-target alignment does not produce sensible code.
- **Export:** [`OVL04_14A8.asm`](overlay-offcut-exports/OVL04_14A8.asm),
  [`OVL04_14A8.decomp.c`](overlay-offcut-exports/OVL04_14A8.decomp.c)

## 3. `OVL25_0034` — far-call sequence into main code (clean entry, deleted)

- **Stub / target:** `281f:05b6` → `OVERLAY_24::010034`
- **Callers (live, 4x):** `FUN_130d_0290` (2 sites), `FUN_130d_0172`, `FUN_137f_0228`
- **What it does:** Decoded from the stub-target alignment it is a **clean
  routine that makes a sequence of far calls into the main code segment**:
  `CALLF 0x1000:0928` (test result via `OR DX,AX; JZ`), then `CALLF 0x1000:091c`,
  `CALLF 0x1000:031a` with argument pushes (`[0x08a8]`, `[0x0896]`), etc. — a
  wrapper that forwards to several `1000:xxxx` helpers. It is a real, frequently
  called routine.
- **The offcut:** page-flow decodes `010033: AND byte ptr [BP+SI+0x928],BL`
  (`20 9a 28 09`, spanning `010033..010036`) which swallows `010034`. Ghidra's
  repair pass therefore **deletes** the `010034` function, so there is no
  decompile — only the manual disassembly from the raw bytes.
- **Export:** [`OVL25_0034.asm`](overlay-offcut-exports/OVL25_0034.asm)
  (manual decode; no decompile — function was removed)

---

## If this ever needs revisiting

The only real fix is per-conflict **parallel overlay spaces** (map the offending
bytes a second time, disassemble the stub-target alignment there, thunk into it).
It's analyzer-only work (no Ghidra core change) but the decompiler's
one-overlay-per-base limitation caps its value, and it is disproportionate for
three routines that already navigate via their surviving stub references. Leave
them.
