# RESOLVED: the "unresolved 12-byte stubs at 281f" were overlay record 0's stubs

**Status:** closed 2026-07-13. Root cause found, analyzer fixed, verified on a scratch
re-import. The original investigation notes (below) were factually accurate but their
central interpretive table had an off-by-one that manufactured the mystery.

## The answer

There is no special 12-byte encoding. `page_id` is a 1-based descriptor index over the
overlay records: **page_id N targets record N−1, so page_id 1 targets record 0** — and
record 0 is a *real code page* (0x3D10 = 15,632 bytes of code, 0x20F relocations of its
own, header at file 0x20670, code at 0x20ee0). `RTLinkOverlayAnalyzer` assumed record 0
was a non-code "global overlay table" and dropped it at `subList(1, ...)`; every stub
with page word 1 then failed the `blockIndex < 0` bounds check in `scanForJmpfStubs`
and silently fell out of the candidate set. The 12-byte form itself was already
understood (module 0, JMPF offset = in-page offset) and is used by other pages too.

Verification of the decode against the raw file: stub targets land on textbook function
entries in record 0's code — `+0x1e66` = `C8 08 00 00` (ENTER 8,0), `+0x3b68` =
ENTER 6,0, `+0x0000` = `PUSH DS; PUSH imm; ...`.

## Corrections to the original notes

1. **The "naive decode fails" table was off by one.** It tested page-word-1 targets
   against `OVERLAY_00`, but `OVERLAY_00` (old naming) was record 1 = page word 2
   (proof: `OVLSTUB_01_0000` thunks `assess_colony_threat` at `OVERLAY_00::010000`;
   `OVLSTUB_06_10EE` thunks into `OVERLAY_05`). The naive theory was never actually
   refuted — correctly applied, it is the answer.
2. **47 stubs, not 46.** The exact pattern `9a ab 0d 0d 21 ea ?? ?? 00 00 01 00`
   matches the run of 46 (`281f:0ef4`–`1114`) **plus `281f:062c`**, which sits among
   the resolved stubs. Enumerate by byte pattern, not by run.
3. **No 14-byte entries in the run.** The irregular stride is 4 bytes of zero padding
   at `281f:0ffc`, which exists to align the tail group to `281f:1000`.
4. **Not dead table entries** (theory 3): 3 stubs have direct `CALLF` callers
   (`062c` ×2 resident, `0f3c` ×2 from `Title_OpeningMenu`, `0f6c` ×1 from
   `OVL06_10EE`). The other 44 run stubs are each targeted by one entry of a
   **44-entry `JMPF` jump table occupying the last 0xDC bytes of record 0 itself**
   (`OVERLAY_00::013c34`–end, stride 5) — visible as 5-byte thunk functions once
   record 0 is mapped. 44 table entries + `0f3c`/`0f6c` direct = all 46 run stubs
   accounted for.

## The fix (this commit)

- `RTLinkOverlayAnalyzer` now creates a block for every record with code, record 0
  included, and **blocks are numbered by record index**: record i → `OVERLAY_i`
  (00..30 in VICEROY). This aligns `OVLSTUB_NN` ↔ `OVERLAY_NN` ↔ `RTLINK_HDR_NN`;
  the old scheme's extra −1 (block = record−1) was a side effect of the same wrong
  global-table assumption, and its stub↔block skew is what tripped the original
  investigation.
- Stub scans look blocks up by record index (`blocksByRecord`), not list position,
  so a code-less record can no longer shift later pages onto wrong blocks.
- One Shot (`repairStubThunks`) detects legacy-named programs (no block for the last
  code-bearing record) and keeps pairing each record with the block holding its code,
  so it still repairs old DBs — record-0 stubs stay unresolved there; resolving them
  needs a re-import.

**Scratch verification (2026-07-13):** fresh import + analyze produced 31 overlay
blocks (`OVERLAY_00` = record 0, 010000–013d0f), "Resolved **658** dispatch stub(s)"
(611 + 47) with trampolines unchanged at 370, all 47 `OVLSTUB_00_*` wired as thunks
(e.g. `OVLSTUB_00_0000` → `OVL00_0000` at `OVERLAY_00::010000`), zero husk functions
in `OVERLAY_00`, and the ERROR bookmark channel down to the single genuine
`275d:0778` — `281f:0f71` is gone. One quirk: the stub at `281f:0ff0` (followed by
the 4 zero padding bytes) classifies as 14-byte with module_word 0, which decodes to
the identical target — harmless. Scratch program deleted after verification.

**Live-DB note:** `/VICEROY.EXE` keeps the old `OVERLAY_00..29` naming (= records
1..30) until manually renamed; docs in `../../viceroy/docs/` referencing `OVERLAY_NN`
mean the old numbering unless stated otherwise. The live DB also still carries ~541
stale ERROR "Bad Instruction" fossils on stub JMPFs (e.g. `281f:0005`) — a One Shot
RTLink/Plus Overlay pass clears the ones whose stubs it can resolve.

---

# Original investigation notes (2026-07-13, kept for the record)

**Provenance:** surfaced after `RTLinkOverlayAnalyzer` stopped leaving 538 stale
"Bad Instruction" bookmarks (`a533fb648d`). The ERROR channel went from 540 marks (all
false) to 2 — `275d:0778` (repeated-byte run, separate issue) and `281f:0f71`, the JMPF
of the one record-0 stub that a caller happened to reach and disassemble into unmapped
`0000:001e`.

Evidence that held up byte-for-byte: the two stub forms (`281f:0000` 14-byte resolved,
`281f:0ef4` 12-byte unresolved, same `210d:0dab` dispatcher), the run boundaries, page
word `0x0001` on every unresolved stub, the absence of `OVLSTUB_00_*`, the analyzer's
total silence about them, and the ground rules section — all verified 2026-07-13.

The "What I do NOT know" section listed three theories: (1) different target encoding,
(2) not overlay stubs at all, (3) dead table entries. All three were wrong; the naive
theory it believed refuted was right, once the page→block mapping error (see
correction 1) is removed.
