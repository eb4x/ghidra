# Work brief: switch tables whose base is fixed up by a branch on the index

Status: **not started.** Internal work item, not filed upstream. Written by
`ghidra-dailydriver` on 2026-09-19 so the next agent to pick this up doesn't have to
rediscover the ground. Read `Ghidra/Features/Decompiler/src/decompile/cpp/jumptable.cc`
alongside it.

## The symptom

A Keil C51 jump table on the GL3523 firmware does not recover, under stock Ghidra
**or** with our `bitflagguard` fix applied:

    Could not recover jumptable at CODE:bcbf. Too many branches

The three other switches in the same image do recover with `bitflagguard` — 11, 8 and 9
cases plus default at `CODE:89b6`, `CODE:a81c` and `CODE:bd6a`. `bcbf` is the one that
does not, and it fails differently: `bitflagguard` was about *seeing the guard* that
bounds the index, which now works; this is about the table **base** not being a
constant.

The error message is misleading. `JumpTable::recoverAddresses` (jumptable.cc:2643)
prints "Too many branches" whenever `recoverModel` leaves `jmodel` null — that is, when
*no* model matched, for any reason. Don't read it as a size or path-count limit.

## The code shape

Keil emits `JMP @A+DPTR`, with `A` the index and `DPTR` the table base. When the table
straddles a 256-byte page, it fixes up the high byte first:

    MOV  DPTR,#table
    ...
    JNC  $+2
    INC  DPH
    JMP  @A+DPTR

So the base is selected by a branch, and the branch condition is the carry out of the
index arithmetic. Low indices take one base, high indices the other. Base and index are
not independent: the carry *is* a predicate on the index.

## Why the models decline it

`JumpTable::recoverModel` (jumptable.cc:2272) tries, in order:

1. `JumpAssisted` — only when the BRANCHIND input is a `CPUI_CALLOTHER`. Not us.
2. `JumpBasic` — wants a switch variable with a recoverable range feeding a base that
   is constant. The base here is a `MULTIEQUAL`, so it fails.
3. `JumpBasic2` — this is the near miss, and worth understanding before designing
   anything.

`JumpBasic2` (class doc at jumptable.hh:429, implementation at jumptable.cc:1681) exists
for a switch reached by two paths, where **one path sets a default constant** and the
other is a straight-line calculation from the switch variable. Its recovery explicitly
requires:

- `extravn` traced back to a `CPUI_MULTIEQUAL` (line 1697);
- exactly two inputs (line 1699);
- one input written by a `CPUI_COPY` of a **constant** (lines 1702-1711);
- the *other* input to be the straight-line calculation from the switch variable.

The page-carry case satisfies the first three and fails the fourth. Both incoming values
are constants — `base_hi` and `base_hi + 1` — because both are just the high byte of a
base address. Neither path is a calculation from the index. `JumpBasic2` is looking for
a default-value join; what we have is a base-selection join.

When `JumpBasic2` returns false, `jmodel` is deleted and left null, and the caller
throws.

## What a fix has to do

The two branch paths correspond to **disjoint index ranges** — that is the whole point
of the carry fix-up. On each side of the `JNC`, the index range is known and the base is
a single constant. So the table is really two ordinary tables, and each is recoverable
by the existing machinery.

Two shapes worth evaluating, in rough order of appeal:

1. **Fold the dead branch per path.** Push the guard's range constraint into each side of
   the `MULTIEQUAL` before the model runs. On each side one base is unreachable, the
   join collapses to a constant, and `JumpBasic` succeeds unchanged — twice. Then union
   the two address tables. This is the approach the `bitflagguard` commit message
   pointed at, and it reuses the most existing code.
2. **A model that follows an index-dependent select.** A sibling of `JumpBasic2` that
   accepts a `MULTIEQUAL` of two constants and recovers the predicate relating them to
   the index, then emits one table per branch. More explicit, more new code, and it has
   to reason about the predicate rather than inheriting the range analysis.

Either way the output must be a single `JumpTable` whose address table covers both
halves, with case values that map back to the original index — not two separate tables,
since there is one BRANCHIND.

## Watch out for

- **`bitflagguard` is a prerequisite, not a competitor.** The carry here is 8051 `PSW[7,1]`,
  a bit-field flag, so the guard is only visible at all because of that fix. Don't start
  from a tree without it.
- **This is a general shape, not an 8051 quirk.** Any compiler that fixes up a table base
  with a conditional increment lands here. The fix belongs in the generic machinery, not
  behind a processor test.
- **Verify on a scratch import**, never on a live curated program, and delete it after.
  Re-check the three switches that already work (`89b6`, `a81c`, `bd6a`) as a regression
  guard — a change to guard handling can easily break the cases `bitflagguard` fixed.
- **Add datatests.** The decompiler's own suite is the only thing that will keep this
  from regressing; a firmware image is not a test fixture.

## The workaround today

`JumpBasicOverride` (jumptable.hh:455) takes an explicitly supplied address table rather
than recovering one, and repurposes `JumpBasic`'s analysis to find the switch variable.
It gets the control flow right. It does not give you case values, so the decompiled
switch has correct targets and unlabelled cases. That is the honest answer to "can I
read this function today" while this work item is unstarted.

## Upstream

Not filed. If it is ever submitted, it is an **issue** rather than a PR — a clean
reproducible report of a real limitation, which costs the maintainers nothing to
receive and commits us to nothing. Our standing policy is that upstream PRs are opened
sparingly and only when Erik decides.
