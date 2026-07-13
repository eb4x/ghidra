# Upstream draft: 16-bit XLAT ignores its segment (flat p-code address)

Draft issue/PR text for github.com/NationalSecurityAgency/ghidra. **Not filed yet** —
review and file manually. The patch below is already applied locally
(`7bcf5fd75d`, worktree `rtlink`); it is a strict subset of what upstream needs, so
the PR can be cherry-picked from that commit.

---

## Title

x86-16: XLAT ignores its segment — reads a flat address, drops CS:/SS:/ES: overrides

## Summary

The 16-bit `XLAT` constructor in `Ghidra/Processors/x86/data/languages/ia.sinc` is the
only memory access in the x86 spec whose p-code ignores its segment operand:

```
:XLAT seg16^BX  is vexMode=0 & addrsize=0 & seg16 & byte=0xd7; BX  { tmp:$(SIZE)= 0; ptr2(tmp,BX+zext(AL)); AL = *tmp; }
```

`macro ptr2(r,x) { r = zext(x); }` — a flat address. The constructor *parses and
prints* `seg16` (so the listing shows `XLAT DS:BX`, `XLAT CS:BX`, `XLAT SS:BX`
correctly) and then discards it. Every other 16-bit memory access — `Mem16`, the
`moffs` forms, the string ops — goes through `segment(seg16, offset)`, which the
16-bit pspecs (`x86-16-real.pspec`, `x86-16.pspec`) map onto the segmented address
space via their `<segmentop>`.

Two consequences, both observed on real DOS binaries:

1. **In real mode the translate table is always read from physical `0000:offset`** —
   the interrupt vector table. Any program calling MSC's `printf` machinery (whose
   `_output` state machine uses `XLAT` twice) makes the decompiler read the state
   table from the IVT and log `Unable to read bytes at ram:0000:xxxx` during
   jump-table recovery.
2. **Segment overrides are silently dropped.** `XLAT CS:BX` (translate table embedded
   in the code segment — used by, e.g., the RTLink/Plus overlay manager's register-
   field decoding) and `XLAT SS:BX` (table on the stack) produce p-code identical to
   `XLAT DS:BX`. The listing shows the override; the decompiler reads a different
   table. There is no warning, no bookmark — just wrong decompiler output.

## Reproduction

Any `x86:LE:16:Real Mode` program containing byte `D7` (optionally prefixed with
`2E`/`36`/`26`). Minimal: assemble

```asm
mov bx, 0x1234
xlat            ; listing: XLAT BX  — p-code reads *[ram]:2:zext(BX + zext(AL))
cs: xlat        ; listing: XLAT CS:BX — identical p-code, CS discarded
```

import as `x86:LE:16:Real Mode`, and inspect the p-code of either instruction: the
`LOAD` address is `zext(BX + zext(AL))` — flat, segmentless — where every comparable
instruction (e.g. `MOV AL,[BX+0x10]`) produces `segment(DS, ...)`.

## Fix

One line, mirroring `Mem16: seg16^addr16 { tmp:$(SIZE) = segment(seg16,addr16); ... }`:

```diff
-:XLAT seg16^BX      is vexMode=0 & addrsize=0 & seg16 & byte=0xd7; BX           { tmp:$(SIZE)= 0; ptr2(tmp,BX+zext(AL)); AL = *tmp; }
+:XLAT seg16^BX      is vexMode=0 & addrsize=0 & seg16 & byte=0xd7; BX           { tmp:$(SIZE) = segment(seg16,BX+zext(AL)); AL = *tmp; }
```

`seg16` already exports DS by default and the override register (`CS`/`SS`/`ES`/…)
when prefixed, so the one change fixes the default segment and every override at
once. In x86-32/64 the `addrsize=0` (`0x67`-prefixed) form also becomes *more*
consistent, not less: 16-bit `Mem16` accesses there already emit `segment(...)`, and
the 32-bit pspec's segmentop treats it as a plain offset.

Verified on four RTLink/Plus DOS executables (fresh imports, before/after): the
`ram:0000:*` warnings disappear, disassembler error bookmarks are unchanged, and the
MSC `_output` translate tables resolve to their real DGROUP addresses.

## Caveat for reviewers: unbounded XLAT-fed switches become reachable

One reason this bug can look load-bearing: with the flat read in place, the
decompiler cannot follow an `XLAT`-driven dispatch (like MSC `_output`'s
`JMP word ptr CS:[BX+disp]`) into a real table, so it gives up quietly. With the fix,
it follows the table read — and then resolves the dispatch **unbounded**, because
`JumpBasic::calcRange` (`Features/Decompiler/src/decompile/cpp/jumptable.cc`, the
`getMaxValue` path) only recognizes `INT_AND` masks. The `_output` index is bounded
by `SHR AL,4` (nzmask `0x0f` — already computed, never consulted), so recovery
fabricates cases for the whole byte range of the LOAD, and `sanityCheck` does not
trim in-segment loadable garbage. On two of our four test binaries this produced new
`halt_baddata` flows until we bounded that dispatch externally (a `JumpTable`
override). See "related" below; the XLAT fix itself is still correct — the switch
over-recovery is a pre-existing, separate gap that the bug was masking.

## Related (separate issues, mentioned for completeness)

- **32-bit form drops FS/GS bases:** `:XLAT segWide^EBX ... ptr4(tmp,EBX+zext(AL))`
  discards `segWide`, so `XLAT FS:EBX` loses `FS_OFFSET`. The `Mem` table handles
  this with a `highseg=1` variant (`tmp = segWide + zext(addr32)`); XLAT would need
  the same pair of constructors. Not included in the patch above (no real-mode
  impact; wants its own test).
- **`JumpBasic::calcRange` ignores the index varnode's nzmask** (`jumptable.cc`,
  comment `// Should we go ahead and use nzmask in all cases?`). Intersecting the
  computed range with `CircleRange::setNZMask(vn->getNZMask(), ...)` — the same
  narrow-only use the guard path already makes in `CircleRange::pullBack` — would
  bound `SHR`-masked, LOAD-fed switch indices (0..15 for the `_output` FSM) instead
  of the full byte range. Not sufficient on its own for exact recovery (the true
  bound there is 8, derivable only from the table data), but it would stop the
  fabricated-case blowup for every nibble-indexed dispatch.
