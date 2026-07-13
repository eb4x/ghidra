# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repository is

A fork of NSA's Ghidra (software reverse engineering framework, Java/Gradle) extending
it with **RTLink/Plus overlay support** for late-DOS MZ executables (target binary:
VICEROY.EXE). The repo is a bare checkout at `..` with one directory per worktree
(`master`, `claude`, `mcp`, `rtlink`); **this worktree is branch `rtlink`** — the one
loaded into the Eclipse workspace and used for all current RTLink work. The custom code
lives in `Ghidra/Features/Base`:

- `src/main/java/ghidra/app/util/bin/format/mz/RTLink{PageHeader,Relocation,OverlayPage}.java` —
  overlay file-format parsing
- five analyzers in `src/main/java/ghidra/app/plugin/core/analysis/`, each pinned to a
  different slot in the auto-analysis pipeline (an analyzer registers exactly one
  `AnalyzerType` + `AnalysisPriority`, which is why this is five classes and not one):
  - `RTLinkOverlayAnalyzer` — BYTE, `FORMAT_ANALYSIS.after()`. Detects overlay data past
    the MZ image end, parses pages, creates the overlay memory blocks, wires up the
    dispatch-stub thunks and assumes DS=DGROUP. Runs on raw bytes, before disassembly.
  - `RTLinkSwitchTableAnalyzer` — INSTRUCTION, `CODE_ANALYSIS.before()`. Recovers the
    CS-/module-relative switch tables and fixes their *references*. Must run before
    `DecompilerSwitchAnalyzer`, which skips any computed branch that already has
    computed refs — winning that race is what keeps bogus targets from being
    disassembled into other segments.
  - `RTLinkSwitchOverrideAnalyzer` — INSTRUCTION, `FUNCTION_ANALYSIS.after()`. Writes the
    decompiler jump-table overrides for those same tables (shares
    `RTLinkSwitchTableAnalyzer.recoverTable()`). Cannot be merged into the above: the
    override symbols need a defined `FunctionDB` to hang a namespace off, which does not
    exist that early.
  - `RTLinkXrefAnalyzer` — INSTRUCTION, `REFERENCE_ANALYSIS.after()`. Resolves the
    DS-relative data references that Ghidra's own reference pass declines to make on
    RTLink programs.
  - `RTLinkFlowRepairAnalyzer` — BYTE, `LOW_PRIORITY.after()` (dead last, once every
    other pass has planted its flows and the disassembler has stamped its conflict
    bookmarks). Recovers **buried code** — real, evidenced instructions left
    undisassembled under junk. Three detectors: a CALL whose fall-through lands on an
    MZ-relocated segment word cannot return there, so the word is sealed as data and the
    call marked `CALL_RETURN`; a "conflicting instruction" bookmark is arbitrated by
    evidence, and unreferenced junk loses to referenced code; and an undefined gap
    between routines that decodes exactly onto the code after it — a prologue, or a
    stranded epilogue — is disassembled. Everything unevidenced (padding, zero-run
    islands) is left strictly alone.

Analyzer housekeeping: all five set `setSupportsOneTimeAnalysis()` so they can be re-run
from Analysis → One Shot on an already-analyzed program. Report success counts with
`Msg.info`, never `log.appendMsg` — any content in the analysis `MessageLog` makes
`AutoAnalysisPlugin` pop a "warnings/errors issued during analysis" dialog, so the
`MessageLog` is for genuine failures only.

**`docs/rtlink-format.md` is the authoritative reference for the overlay format and
runtime** — the on-disk record/header/relocation layout, the VM dispatcher and stub forms,
the overlay-sections mechanism, and how the analyzers model all of it. Read it before
changing anything format-related; it supersedes
`../../viceroy/docs/archive/rtlink-overlay-format.md`. The vendor distribution it is
derived from (RTLink/Plus 6.10, incl. the overlay manager's assembly source and the VMEX
example programs) is at `~/dosbox/RTLINK`; the build-to-order harness at `~/dosbox/RTLTEST`.

Current work plans live in `docs/` in this worktree; RE-side documentation (workflow,
symbol map, findings) in `../../viceroy/docs/`. (Historical plan/finding files exist in
the `claude` worktree but are outdated — don't consult them unless digging into why a
past decision was made.)

## Build commands

> Day-to-day compiling, running, and testing goes **through Eclipse** (see
> "Development environment" below): Eclipse auto-builds on save and launches Ghidra.
> The Gradle CLI below is for what Eclipse doesn't cover (distribution builds,
> natives, headless test runs) — it compiles into `build/`, which the
> Eclipse-launched Ghidra does **not** run.

Always use the bundled wrapper `./gradlew`, never a system `gradle`.

One-time setup (fetches non-Maven dependencies into `dependencies/`, then Maven deps):

```
./gradlew -I gradle/support/fetchDependencies.gradle
./gradlew prepdev
```

Common tasks:

- `./gradlew buildGhidra` — full distribution zip into `build/dist/` (current platform only)
- `./gradlew assembleAll` — same but uncompressed
- `./gradlew buildNatives` — native components (decompiler, etc.) for the current platform
- `./gradlew sleighCompile` — compile Sleigh processor specs manually
- `./gradlew prepdev eclipse buildNatives` — set up for Eclipse development
- `./gradlew buildGhidra -x ip` — skip a failing task (e.g. `ip`, the license-header check
  that fails on new source files missing the standard Apache header; every `.java` file
  needs the `/* ### IP: GHIDRA ... */` header)

Fedora specifics: requires `java-21-openjdk-devel` **and**
`java-21-openjdk-jmods` (without jmods, Gradle reports the JDK "does not provide the
required capabilities: [JAVA_COMPILER]"). After installing JDK packages, restart the
daemon with `./gradlew --stop`.

## Tests

- `./gradlew unitTestReport` — all unit tests with report
- `./gradlew integrationTest` — integration tests
- `./gradlew combinedTestReport` — both, with a combined report

Gradle project names are the flat module directory names, not paths (`:Base`, not
`:Ghidra:Features:Base`). To run tests for one module or one class:

```
./gradlew :Base:test
./gradlew :Base:test --tests "ghidra.app.util.bin.format.mz.SomeTest"
```

Each Java module also has `integrationTest` (`src/test.slow/`) alongside `test`
(`src/test/`). Headless/CI test runs need an X display:
`Xvfb :99 -nolisten tcp & export DISPLAY=:99`.

## Architecture

Multi-project Gradle build; every module under `Ghidra/` is its own Gradle/Eclipse
project with `src/main/java`, `src/test`, optional `data/` and `ghidra_scripts/`, and a
`Module.manifest`. Major groupings:

- `Ghidra/Framework/` — layered libraries, bottom-up roughly:
  `Utility`/`Generic` → `DB` (custom database) → `SoftwareModeling` (program model,
  address/memory/listing APIs, p-code, Sleigh compiler) → `Project` →
  `Docking`/`Gui` (Swing windowing/component framework) → `Help`.
- `Ghidra/Features/` — application features as plugin collections. `Base` is the core:
  loaders (`ghidra.app.util.opinion`), file-format parsing (`ghidra.app.util.bin.format.*`,
  including `mz` for DOS executables), auto-analysis analyzers
  (`ghidra.app.plugin.core.analysis`). `Decompiler` wraps the **C++ decompiler**, whose
  source is at `Ghidra/Features/Decompiler/src/decompile/cpp` (a separate Gradle project
  named `decompile`; built by `buildNatives`).
- `Ghidra/Processors/` — one module per architecture holding Sleigh specs
  (`.slaspec`/`.sinc`/`.pspec`/`.cspec`/`.ldefs`). The `x86` module covers 16-bit real
  mode relevant to the overlay work.
- `Ghidra/Debug/` — debugger; back-ends are out-of-process Python connectors speaking
  the protobuf-based Trace RMI protocol (see DevGuide.md for details).
- `GPL/` — GPL-licensed code must live here as standalone, independently buildable
  modules; everything else is Apache 2.0.

Extension points relevant here: **Analyzers** implement `Analyzer` (usually via
`AbstractAnalyzer`) in a plugin package and are discovered by classpath scanning — no
registration file needed. Loaders and file-format parsers follow the same discovery
pattern in `Features/Base`.

## Development environment

**All Ghidra development is driven through Eclipse.** Eclipse runs in a flatpak
(`org.eclipse.Java`) and agent sessions control it through the Eclipse MCP servers
(`eclipse-ide`, `eclipse-coder`, `eclipse-git`, `eclipse-runner`).

- **Read from the filesystem, write through Eclipse.** Reading source in this
  worktree (and running `git` on it) is fine and preferred. But Eclipse does not
  register filesystem changes made while it is running, and building, compiling,
  running and testing all work off Eclipse's own state — so submit every source
  change through the `eclipse-coder` MCP tools (`replaceString`, `applyPatch`,
  `createFile`, …); the change then shows up on the filesystem, not the other way
  around.
- **Compile status** comes from `eclipse-ide getCompilationErrors` (Eclipse
  auto-builds on save); run tests with the `eclipse-ide` test tools.
- **Launch/restart Ghidra** with the `eclipse-runner` `Ghidra` launch configuration
  (run mode; configs live under modules' `.launch/` directories, e.g.
  `Ghidra/Features/Base/.launch/Ghidra.launch`). Run mode has no hot code replace —
  restart Ghidra after every change.

- **Verify analyzer changes on a scratch re-import, and delete it afterwards.**
  Analysis bakes references into the DB, so a program analyzed with the old build
  stays wrong after you fix the analyzer — only a fresh `import` into a
  `/scratch-<what>` folder measures the change, and each variant you compare needs
  its own. Never re-analyze the live `/VICEROY.EXE` (hand-added names/types) or the
  read-only `/VICEROY.OLD`. When you are done, remove every `/scratch-*` program you
  created (`manage_files` `op=delete`); a stale scratch DB records the behaviour of a
  build that no longer exists. Details in `../../viceroy/docs/ghidra-workflow.md`.

On startup Ghidra loads our MCP server plugin (source in `../../ebbex-ghidra-mcp`),
which exposes the `ghidra-application-level` and `ghidra-program` tools for
controlling the running instance — useful for inspecting the analyzed VICEROY.EXE
directly. That project is the **exception** to the Eclipse rule: it is not part of
the Eclipse workspace — edit it directly on the filesystem, run
`./gradlew installExtension` there (installs into the flatpak Ghidra's user
Extensions dir), and restart Ghidra via `eclipse-runner` to load the new build. Any
friction with the plugin's tools should be recorded in
`../../ebbex-ghidra-mcp/docs/mcp-feedback.md` — the log lives in the plugin's own
repo, where the fixes land — so the plugin can be improved.
