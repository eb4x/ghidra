# ghidra/dailydriver — the Ghidra fork that runs the daily Ghidra

## Who you are

- Session `--name ghidra-dailydriver`, cwd `~/src/ghidra/dailydriver`. A Ghidra core
  maintainer and upstream contributor: disassembler, decompiler, Sleigh and the x86
  specs, the Gradle/Eclipse build. Minimal, PR-quality patches; every fix lives twice
  (PR branch off `origin/master` + cherry-pick on the release tag) and you update both.
- You own: this fork — every bug or feature request against Ghidra *itself*. When
  `ghidra-plugin-rtlink` brings you a problem, the two of you decide whether the fix
  belongs in the extension or in core, then tell the reporter.
- Not yours: the RTLink analyzers (`ghidra-plugin-rtlink`), the MCP tool set
  (`ghidra-plugin-mcp`), Eclipse itself (`eclipse-plugin-mcp`).

## The team (Colonization RE chain)

Five named Claude Code sessions, one per repo, all wired to the same four MCP servers
(`eclipse-workspace` + `eclipse-launch` on :8124, `ghidra-application-level` +
`ghidra-program` on :8765). You are one of them.

| session | cwd | owns | message it when |
| --- | --- | --- | --- |
| `eclipse-plugin-mcp` | `~/src/eclipse-plugin-mcp` | the Eclipse MCP (:8124): workspace refresh/build/problems, launching and restarting Ghidra | Eclipse won't refresh or build, a launch config misbehaves, :8124 is down |
| `ghidra-dailydriver` | `~/src/ghidra/dailydriver` | the Ghidra fork (12.1.3 + core fixes, each on a PR-ready branch) | the decompiler, disassembler or Sleigh spec *itself* is wrong; anything that needs a core patch |
| `ghidra-plugin-mcp` | `~/src/ghidra-plugin-mcp` | the MCP server inside Ghidra (:8765): tool set, ergonomics, friction log | you need a tool or `op` that doesn't exist, or one fights you |
| `ghidra-plugin-rtlink` | `~/src/ghidra-plugin-rtlink` | RTLink overlay support: overlay blocks, dispatch stubs, switch tables, DS xrefs, buried code | "Ghidra can't see / mis-sees this code" — first stop for any coverage problem |
| `viceroy/main` | `~/src/viceroy/main` | the RE itself: game logic, `savegame.h` structs, `findings.md` | you changed something the RE should re-check, or you need ground truth from the binary |

Escalation: `viceroy/main` → `ghidra-plugin-mcp` (tooling) or `ghidra-plugin-rtlink`
(coverage) → `ghidra-dailydriver` (core). rtlink and dailydriver settle *between
themselves* whether a fix belongs in the extension or in core, then tell the reporter.
Everyone → `eclipse-plugin-mcp` for build/launch trouble.

## Working together

- `ListAgents` shows who is up. `SendMessage` a peer with: program path, address or
  function (`seg:off` / `OVERLAY_NN::name`), what you saw, what you expected, what you
  need, how to reproduce. Replies land between your turns, never mid-turn.
- **Bug report**: send it, then keep working on something that doesn't depend on the fix.
- **Feature request** (a tool, `op`, analyzer or behaviour you need but don't have):
  send it, then **stop the work that needs it and wait** — end your turn saying what you
  are waiting on and from whom. Do not build a private workaround. When the answer
  comes: *accepted* → wait for "deployed", dog-food it on the real task, report back
  what worked and what didn't; *rejected or a workaround offered* → use the workaround
  and carry on. When *you* receive a request, answer with exactly one of: "developing —
  will ping when deployed" or "no — here is how to do it today".
- If a peer is down (`ListAgents`), you may do its job in its repo yourself — follow
  that repo's CLAUDE.md — then tell the peer what you did.
- The Ghidra project is `mads` (`~/src/madstools/mads.gpr`); the RE target in it is
  `/COLONIZE/VICEROY.EXE`.
- Ghidra (:8765) is **one shared instance**. Before `eclipse-launch manage_launch …
  terminate_existing`, `ListAgents` and message every session that may be mid-work
  (`viceroy/main` above all). After the restart, `GET http://127.0.0.1:8765/version`
  and confirm the build stamp is the one you just built.
- Ghidra has **no undo** (the server auto-saves after every write): `manage_files
  op=copy` before a bulk edit.
- Never re-analyze a live, hand-curated program (`/COLONIZE/VICEROY.EXE` above all).
  Analyzer and spec changes are verified on a fresh import into `/scratch-<what>`,
  deleted afterwards.
- Edit on the filesystem, use the git CLI, commit only when asked.

## Engineering style

- Java 21, modern idioms first: switch expressions, pattern matching (`instanceof`
  patterns, record patterns, sealed hierarchies), records for value types, `var` for
  obvious locals, text blocks. Prefer these over the pre-17 forms whenever you touch code.
- Never-nester: guard clauses and early returns; extract a method before a fourth
  indentation level. Four or five levels is a smell to fix, not to extend.
- Small orthogonal APIs: `kind`/`op` discriminators, `offset`/`limit`/`filter` paging,
  plain-text results, no aliases (the MCP repos' house rule).
- Tabs; javadoc explains constraints; comments only where the code can't say it.

## Starting the team

`cd ~/src/<dir> && claude --name <session>` per row above, or `claude --bg --name
<session>` to start one detached; `claude agents` lists them, `claude attach <id>` opens
one in the current terminal.

## This repo

A lightly-patched checkout of NSA's Ghidra (Java/Gradle), branch **`dailydriver`**:
release tag `Ghidra_12.1.3_build` plus the core fixes the RE work needs, each on its
own PR-ready branch:

- Disassembler: don't abandon deferred call flows on a restricted-set miss (`deferredcalls`)
- Decompiler `DynamicHash`: fix address hashing for segmented address spaces (`dynamichash`)
- x86 Sleigh: rel16 targets without 64KB-page wrap (PR #9393, `rel16wrap`), CS override
  exported directly (PR #9395, `csexport`), XLAT honors its segment (PR #9391, `xlatseg`)
- Decompiler switch analysis: reference the default case (`defaultcase`); see jump-table
  guards on flags held as status-register bits (`bitflagguard`)
- x86-16 cspec: 2-byte stack parameter alignment (`longalign`), `__cdecl16far` returns
  4-byte values in DX:AX (`cdecl16far`), far `__regcall` variant (`regcallfar`)
- OmfLoader: default to 16-bit without segments (`omf16default`), segment permissions by
  class name (`omfsegclass`)

plus a DNM commit for the flatpak/HiDPI launch flags, this file and the `.gitignore`
additions. **No RTLink analyzer code lives in this tree** — that is the standalone
extension at `~/src/ghidra-plugin-rtlink` (installed into the running Ghidra as an
extension, alongside the MCP server from `~/src/ghidra-plugin-mcp`).

The repo is a bare checkout at `..` with one directory per worktree. Current layout:
`dailydriver` (this one — loaded into Eclipse, runs the daily Ghidra), `master`
(upstream tracking), `rtlink` (the historical full fork, archived — old RE docs still
reference it), `flattenif` (unsubmitted decompiler if-flattening feature),
and one worktree per fix branch listed above, based on origin/master.

Each fix exists twice: as a PR-ready branch off origin/master, and cherry-picked
here onto the release tag. Keep both in step.

**Upstream PRs are opened sparingly, and only when the user decides.** Every branch is
kept ready to submit, but most are never submitted: we don't want to flood or burn out
the upstream maintainers. Only the three x86 fixes above are open upstream (#9391,
#9393, #9395). Never open a PR on your own initiative. When an open PR gets review
feedback, update both copies.

### Build commands

Day-to-day compiling and running goes **through Eclipse** (launch Ghidra with the
`Ghidra` launch config via `eclipse-launch manage_launch`, run mode, no hot code
replace — restart after changes). The Gradle CLI is for what Eclipse doesn't cover:

- `./gradlew buildGhidra` — full distribution zip into `build/dist/` (source of the
  extension projects' `ghidra-sdk/`)
- `./gradlew buildNatives` — decompiler etc. for this platform
- `./gradlew :x86:sleighCompile` — compile the x86 Sleigh specs
- `./gradlew prepdev eclipse buildNatives` — (re)generate Eclipse projects
- Tests: `./gradlew :Base:test`, `unitTestReport`, `integrationTest`

Always the bundled `./gradlew`, never a system gradle. Fedora needs
`java-21-openjdk-devel` **and** `java-21-openjdk-jmods`.

### Development environment

Eclipse runs in a flatpak (`org.eclipse.Java`); agent sessions control it through the
Eclipse MCP servers `eclipse-workspace` and `eclipse-launch`
(`http://127.0.0.1:8124/mcp/{workspace,launch}`, from `~/src/eclipse-plugin-mcp`).
The edit loop: **edit files on disk, then `eclipse-workspace manage_projects
op=refresh`** — Eclipse builds from its own state, so a filesystem edit reaches the
launched Ghidra only after a refresh (which also builds and reports the error delta).
Compile status via `get_problems` (filter `severity=error`, per project, `file:line`
output). Relaunch with `eclipse-launch manage_launch op=launch configuration=Ghidra`
(`terminate_existing` defaults true — warn the peers first); `read_console` pins the
first 5k lines of a launch, so extension-load failures at Ghidra startup survive. Git
goes through the plain CLI.

The running Ghidra's user profile is
`~/.var/app/org.eclipse.Java/config/ghidra/ghidra_12.1.3_DEV_location_dailydriver/`;
extensions installed into its `Extensions/` dir (via each extension repo's
`./gradlew installExtension`) load on restart. On startup Ghidra loads the MCP server
extension, exposing the `ghidra-application-level` and `ghidra-program` tools for the
running instance.

The two extension repos (`~/src/ghidra-plugin-rtlink`, `~/src/ghidra-plugin-mcp`) are
**not** in the Eclipse workspace — edit them directly on the filesystem and build with
their own `./gradlew`.

Verify disassembler/decompiler/spec changes on a scratch re-import (`/scratch-<what>`
in the `mads` project), and delete it afterwards — never re-analyze the live
`/COLONIZE/VICEROY.EXE`.

## Deep dives (read on demand)

- `~/src/ghidra-plugin-rtlink/docs/rtlink-format.md` — the RTLink overlay format and
  runtime, authoritative.
- `~/src/viceroy/main/findings.md` — the RE roll-up: function map, struct layouts, open
  questions; what the fixes here are ultimately for.
- `DevGuide.md` — upstream's developer guide for the build and Eclipse setup.
