# Handoff: the XLAT problem (Sleigh bug + the state machines we never bounded)

**Status: RESOLVED (2026-07-13).** Everything below is kept as the record of the
investigation; the current documentation is `docs/rtlink-format.md` ("The XLAT state
machine, and the Sleigh bug behind it") and the upstream draft is
`docs/upstream-xlat-issue.md`. What was done, in the order item 2/3 below prescribed:

1. **The FSM is bounded by its own data** (`recoverFormatterFsmTable` in
   `RTLinkSwitchTableAnalyzer`, + `RTLinkFsmSwitchTableTest`). The table is MSC's
   dual-purpose `__lookuptable` — class in the low nibble of `table[c-' ']`, next state
   in the high nibble of `table[class*8+state]`, the regions deliberately overlapping —
   and a fixpoint over reachable (class, state) pairs gives the exact count: **8 states
   in all four binaries**, cross-checked against each jump table (which ends exactly at
   the FSM function's entry point). Phase A (recognizer alone, bug still in place):
   switch overrides 39/83/124/59 (each baseline+1), ERROR bookmarks unchanged 1/5/5/4,
   all four FSMs decompile as manually-overridden 8-case switches.
2. **The Sleigh fix was re-taken** (`ia.sinc:4989` → `segment(seg16,BX+zext(AL))`).
   Phase B (recognizer + fix, fresh imports): `ram:0000:*` warnings gone, ERROR
   bookmarks still 1/5/5/4, overrides still 39/83/124/59, FSMs read their real DGROUP
   tables, and the `XLAT SS:BX` overlay sites decompile as stack-table translate loops.
3. **The runtime `XLAT CS:` sites were reversed** (item 4): they are the VM nucleus's
   modrm reg-field → saved-register-frame-offset decoder (fault operand recovery),
   ground truth the compiled `vmnuc` module in `RTLUTILS.LIB` ($$VMNUC — no vendor .ASM
   exists; OVLMGR.ASM is the disk overlay manager). Not dispatches. They did expose an
   xref bug — the address-of pass gave their `MOV BX,imm` table pointers DGROUP refs —
   fixed via `RTLinkXrefAnalyzer.xlatOverrideSegment` (retarget to CS / withdraw for
   SS:/ES:).
4. **Upstream** (item 5): PR-quality draft with the patch, repro, the 32-bit FS/GS
   `segWide` gap, and the `JumpBasic::calcRange` nzmask gap (bounding would give 16, not
   8 — necessary context for why the override approach is the local answer) is in
   `docs/upstream-xlat-issue.md`. Not filed; file it manually.

The section below ("The claim you are here to demolish") was right to be suspicious: the
counter-examples were real, and the FSM bound was exactly where it predicted — in the
table data.

---

**Original handoff follows, unchanged.**

**Status:** open. Nothing here is fixed. One attempted fix was measured and reverted
(`94c6e08683`), and this document exists because the reasoning that led to that revert is
not good enough.

**Who this is for:** an agent picking this up cold. Dig into Ghidra core if you need to
(`DecompilerSwitchAnalyzer`, `JumpTable`, `jumptable.cc`, `EmulateFunction`), and fan out to
subagents freely. Budget is not the constraint; being right is.

---

## The claim you are here to demolish

`docs/rtlink-format.md` and `RTLinkSwitchTableAnalyzer` both say the `XLAT`-indexed dispatches
are declined **"because nothing in the instruction stream bounds the table."**

That is almost certainly false, and I never actually checked it. Two counter-examples were
found in ten minutes of looking, *after* the claim had been written twice:

- **VICEROY `210d:3147`** — `MOV AL,AH; PUSH AX; PUSH BX; PUSH SI; MOV BX,0x3171; AND AL,7;
  CS: XLAT`. The `AND AL,7` bounds the table to **8 entries**, in the instruction stream,
  three bytes before the `XLAT`. Byte-identical code exists at ROE2MAIN `208d:2703` and
  SPHERE `1967:2703`.
- **The formatter FSM** (below) bounds its *class* lookup with `CMP AL,0x58` and its *state*
  index with `SHR AL,4`. The jump table's entry count is not written in the instruction
  stream, but it is *derivable from the state table's own contents* — which is a bound, just
  one that requires reading data instead of instructions.

So treat "nothing bounds it" as a placeholder for "I did not investigate", which is what it
was. The real questions are below.

---

## Fact 1 — the Sleigh bug (confirmed, stock Ghidra, not RTLink)

`Ghidra/Processors/x86/data/languages/ia.sinc:4989`:

```
:XLAT seg16^BX  is vexMode=0 & addrsize=0 & seg16 & byte=0xd7; BX  { tmp:$(SIZE)= 0; ptr2(tmp,BX+zext(AL)); AL = *tmp; }
```

`macro ptr2(r,x) { r = zext(x); }` — a **flat** address. `XLAT` is the only memory access in
the entire x86 spec that ignores its segment: `Mem16` (line ~1126), `moffs*`, and every string
op go through `segment(seg16, offset)`, which the real-mode pspec
(`x86-16-real.pspec`, `<segmentop space="ram" ... userop="segment">`) maps onto the segmented
address space. The `XLAT` constructor even *parses and prints* its segment operand — and then
discards it.

Consequences, both real:

1. **In real mode, the translate table is read from physical `0000:offset`** — the interrupt
   vector table. This is the source of the one benign-looking warning each binary leaves:
   `Unable to read bytes at ram:0000:4f36` (NEBULAR), `ram:0000:acdc` (ROE2MAIN),
   `ram:0000:5b92` (SPHERE), `ram:0000:2a56` (VICEROY).
2. **Segment overrides are silently dropped.** `XLAT CS:BX` and `XLAT SS:BX` both occur in
   this corpus, and the p-code for them is identical to `XLAT DS:BX`. Everywhere the listing
   says `CS:`, the decompiler is reading `DS:`.

That second point is the one that should worry you, because of *where* those sites are:
**the `XLAT CS:BX` sites are in the RTLink runtime itself** (VICEROY `210d`, ROE2MAIN `208d`,
SPHERE `1967` — the same segment as the VM dispatcher and the list-2 relocation code documented
in `docs/rtlink-format.md`). Any conclusion previously drawn about that code from the
decompiler is suspect. **This is probably the "other XLAT issue in VICEROY" that prompted this
handoff — go and confirm or refute that.**

## Fact 2 — the formatter FSM (the thing we decline)

One per binary, in the C library — the MSC `_output`/`printf` state machine. VICEROY
`FUN_1d1d_196e` (`1d1d:199c`), NEBULAR `FUN_1417_0d64` (`1417:0d92`), ROE2MAIN `FUN_122e_1026`,
SPHERE `FUN_160f_0c86`. All four are byte-identical modulo the table address:

```
1d1d:199c  bb 56 2a     MOV BX,0x2a56     ; table base — a DGROUP offset (VICEROY DGROUP=0x2B5A)
1d1d:199f  2c 20        SUB AL,0x20       ; c - ' '
1d1d:19a1  3c 58        CMP AL,0x58
1d1d:19a3  77 05        JA  +5            ; class 0 if out of range  -> bounds the CLASS table at 0x59
1d1d:19a5  d7           XLAT              ; AL = DS:[BX + AL]        -> class byte
1d1d:19a6  24 0f        AND AL,0x0f       ; low nibble = class
   ...
1d1d:19ac  b1 03        MOV CL,3
1d1d:19ae  d2 e0        SHL AL,CL         ; class * 8
1d1d:19b0  02 46 fb     ADD AL,[BP-0x5]   ; + current state
1d1d:19b3  d7           XLAT              ; SAME BX — second lookup into the same table
1d1d:19b4  fe c1        INC CL            ; CL = 4
1d1d:19b6  d2 e8        SHR AL,CL         ; high nibble = NEXT STATE
1d1d:19b8  88 46 fb     MOV [BP-0x5],AL   ; store it
1d1d:19bb  98           CBW
1d1d:19bc  8b d8        MOV BX,AX
1d1d:19be  d1 e3        SHL BX,1
1d1d:19c0  2e ff a7 ..  JMP word ptr CS:[BX + disp]   ; <-- the dispatch we decline
```

Note both `XLAT`s share one `BX`, so the class table and the transition table are **one table**
— work out its exact layout (the `class*8 + state` index must not collide with the `0..0x58`
class region; figure out how, that is a real question, not a rhetorical one).

**The bound you need is the number of states**, i.e. `max(high nibble over the transition
table) + 1`. That is computable statically from the table bytes. Whether *we* should compute
it, or make the decompiler compute it, is the open design question.

## Fact 3 — what happens if you "just fix" the Sleigh bug (measured, then reverted)

I changed the 16-bit form to `segment(seg16, BX+zext(AL))` (what `Mem16` does), ran
`./gradlew sleighCompile`, restarted, and re-imported all four **fresh**. Results:

- The `ram:0000:*` warnings disappear, and DS resolves **correctly** — the decompiler reads
  the real table (I verified `switchdataD_2000_56b6` = flat `0x256b6` = `2078:4f36` = NEBULAR's
  DGROUP table). So the fix itself is right.
- But the decompiler then goes on to resolve the FSM's `JMP word ptr CS:[BX+disp]` — the very
  dispatch we decline — **unbounded**. It invents cases (`0x88`, `0xc8`, …), emits
  `halt_baddata`, plants bad flows.
- ERROR bookmarks: **ROE2MAIN 4 → 6**, **SPHERE 5 → 6**. `FUN_1417_0d64` decompiles *worse*
  than with the bug. NEBULAR/VICEROY bookmark counts unchanged.

I reverted on that evidence. **That was the cautious call, not necessarily the right one** —
"the bug is load-bearing" is a bad place to leave a codebase. The correct sequence is almost
certainly: bound the FSM dispatch *first*, then take the Sleigh fix.

---

## What to actually investigate

1. **Reverse the FSM properly.** Dump the table (VICEROY `2b5a:2a56`, NEBULAR `2078:4f36`,
   ROE2MAIN DGROUP+`0xacdc`, SPHERE +`0x5b92`), establish its layout, count the states, and
   confirm the count against the CS-relative jump table's actual entries. Cross-check against
   MSC's published `_output` source if you can find it — this is a *known* library routine, not
   a one-off. Then: is the entry count a constant across all four binaries (same library), and
   is it derivable by a rule an analyzer can apply?
2. **Decide who bounds it.** Options, in the order I'd rank them cold — but rank them yourself:
   - `RTLinkSwitchTableAnalyzer` recognizes the FSM idiom, computes the state count from the
     table, and registers the computed refs *before* `DecompilerSwitchAnalyzer` (this is exactly
     how every other dispatch class in this codebase is handled; see `recoverTable()` and
     `recoverDataTable()`, and note the `hasComputedReference()` race we always win).
   - Teach the decompiler to bound it: read `Ghidra/Features/Decompiler/src/decompile/cpp/jumptable.cc`
     — `JumpBasic::foldInGuards`, the `GuardRecord` machinery, `findNormalForm`. Why does it
     *not* pick up the `CMP AL,0x58` / `SHR AL,4` guards? Is a `JumpTable` override the
     supported answer, or is there a genuine gap in the guard analysis for a table-driven
     (data-dependent) index? A defensible upstream patch here would be worth more than a local
     hack.
   - Something better that neither of us has thought of.
3. **Then re-take the Sleigh fix** and prove the whole set improves: warnings gone, ERROR
   bookmarks not worse (ROE2MAIN 4, SPHERE 5, NEBULAR 5, VICEROY 1), switch tables not worse
   (VICEROY 38, NEBULAR 82, SPHERE 123, ROE2MAIN 58), and the four library functions decompile
   as real state machines.
4. **The runtime `XLAT CS:BX` sites** (VICEROY `210d:3147`, `210d:3188`, `210d:33c4`,
   `210d:33d5`, and their twins in ROE2MAIN `208d:*` / SPHERE `1967:*`). These are bounded
   (`AND AL,7`) and they are in the overlay manager. What do they actually do? Does the dropped
   `CS:` override mean anything in `docs/rtlink-format.md` is wrong? The runtime is documented
   from RE plus the vendor `OVLMGR.ASM` at `~/dosbox/RTLINK` — use the vendor source as ground
   truth where it covers this.
5. **Report upstream.** The `XLAT` segment bug affects every real-mode x86 binary in Ghidra,
   not just ours. Worth an issue with a minimal repro regardless of what we do locally.

## Working constraints (from CLAUDE.md — do not skip)

- **Edit Java through the `eclipse-coder` MCP tools**, never raw writes: Ghidra runs from
  Eclipse's build. Same for `ia.sinc` (project `Processors x86`). Sleigh is *not* built by
  Eclipse — `./gradlew sleighCompile`, then restart Ghidra via `eclipse-runner`.
- Confirm a class actually compiled: `javap -c <class> | grep -c "Unresolved compilation"`
  must be 0. Eclipse will happily emit a class whose methods throw at runtime.
- **Measure on fresh scratch imports only** (`/scratch-*`), and delete them afterwards.
  Re-analyzing an existing program does **not** exercise switch recovery —
  `added()` skips any dispatch that already `hasComputedReference()`, and the garbage refs are
  already in those DBs. **Never** re-analyze the live `/VICEROY.EXE` (hand-added names/types)
  or `/VICEROY.OLD`.
- Ghidra is a **shared** instance; coordinate restarts. Don't poll it with `curl | grep | sleep`
  — use `get_program_info` and `read_log`.
- Local commits only; do not push.

## Where things are

| | |
|---|---|
| Sleigh bug | `Ghidra/Processors/x86/data/languages/ia.sinc:4989` (and `ptr2` at ~1929, `Mem16` at ~1126) |
| Our switch recovery | `.../plugin/core/analysis/RTLinkSwitchTableAnalyzer.java` — `recoverTable`, `recoverOverlayTable`, `recoverDataTable`, `tableEntryCount` |
| Decompiler overrides | `.../plugin/core/analysis/RTLinkSwitchOverrideAnalyzer.java` (shares `recoverTable()`) |
| Ghidra's own switch pass | `Ghidra/Features/Decompiler/.../DecompilerSwitchAnalyzer.java` (priority `CODE_ANALYSIS`), C++ side in `src/decompile/cpp/jumptable.cc` |
| Format/runtime doc | `docs/rtlink-format.md` — read "How our analyzers model this" and the new XLAT section |
| Vendor source | `~/dosbox/RTLINK` (`OVLMGR.ASM`, VMEX examples); harness `~/dosbox/RTLTEST` |
| Relevant commits | `94c6e08683` (this revert + doc), `f2e0fe01a4` (overlay table anchors), `1ae5855873` (DS-relative table) |
| Corpus (host paths) | `~/dosbox/GOG/COLONIZE/VICEROY.EXE`, `~/dosbox/GOG/NEBULAR/NEBULAR.EXE`, `~/dosbox/GOG/DRAGON/SPHERE.EXE`, `~/dosbox/AW/ROE2/ROE2MAIN.EXE` |

## XLAT site inventory (from the current DBs)

| Binary | FSM (formatter) | other DS: sites | runtime `CS:` sites |
|---|---|---|---|
| VICEROY | `1d1d:19a5`, `1d1d:19b3` | `1d1d:154b` | `210d:3151`, `210d:3188`, `210d:33c4`, `210d:33d5` |
| ROE2MAIN | `122e:105e`, `122e:106c` | `122e:0629`, `122e:32dd`, `122e:332d`, `122e:333a` | `208d:2703`, `208d:273a`, `208d:28e1`, `208d:28f2` |
| SPHERE | `160f:0cbd`, `160f:0ccb` | `160f:05eb`, `OVERLAY_011::02f02f`, `OVERLAY_023::02f097` (**`XLAT SS:BX`**) | `1967:2703`, `1967:273a`, `1967:28e1`, `1967:28f2` |
| NEBULAR | `1417:0d9b`, `1417:0da9` | `1417:05df`, `OVERLAY_64::02d02f`, `OVERLAY_75::02d097` (**`XLAT SS:BX`**) | `1731:258c`, `1731:25c3`, `1731:275e`, `1731:276f` |

Two things fall straight out of this table and are worth stating plainly:

- **Every binary has the same four `XLAT CS:BX` sites in its runtime segment**, at the same
  offsets (`+0x2703/+0x273a/+0x28e1/+0x28f2` in ROE2MAIN and SPHERE, shifted in VICEROY and
  NEBULAR). That is one routine, shipped in all four — almost certainly RTLink's own, given the
  segment. Reverse it once and you have it everywhere. `~/dosbox/RTLINK/OVLMGR.ASM` may just
  contain it in source.
- **NEBULAR `OVERLAY_75::02d097` and SPHERE `OVERLAY_023::02f097` are `XLAT SS:BX`** — the same
  routine again, in overlay code, translating through a table on the *stack*. Under the current
  spec that reads from `DS:` instead, which is not a warning, not a bookmark, and not visible
  anywhere: it is just silently wrong output. This is the strongest single argument for fixing
  the Sleigh bug properly rather than living with it.
