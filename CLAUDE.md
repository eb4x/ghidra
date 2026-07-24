# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repository is

A lightly-patched checkout of NSA's Ghidra (Java/Gradle), branch **`dailydriver`**:
release tag `Ghidra_12.1.2_build` plus the five core fixes required by the RTLink
extension, each tracked as an upstream PR:

- Disassembler: don't abandon deferred call flows on a restricted-set miss
- Decompiler `DynamicHash`: fix address hashing for segmented address spaces
- x86 Sleigh: rel16 targets without 64KB-page wrap (PR #9393), CS override exported
  directly (PR #9395), XLAT honors its segment (PR #9391)

plus a DNM commit for the flatpak/HiDPI launch flags and this file. **No RTLink
analyzer code lives in this tree** — that is now the standalone extension at
`~/src/ghidra-plugin-rtlink` (see its CLAUDE.md; installed into the running Ghidra as
an extension, alongside the MCP server from `~/src/ghidra-plugin-mcp`).

The repo is a bare checkout at `..` with one directory per worktree. Current layout:
`dailydriver` (this one — loaded into Eclipse, runs the daily Ghidra), `master`
(upstream tracking), `rtlink` (the historical full fork, archived — RE docs still
reference it), `flattenif` (unsubmitted decompiler if-flattening feature),
`deferredcalls`/`dynamichash`/`rel16wrap`/`csexport`/`xlatseg` (one worktree per
upstream PR, based on origin/master).

Each of the five fixes exists twice: as a PR branch off origin/master, and cherry-picked
here onto the release tag. **When a PR gets review feedback, update both.**

RE-side documentation (workflow, symbol map, findings) lives in `../../viceroy/docs/`;
the RTLink overlay format reference is `~/src/ghidra-plugin-rtlink/docs/rtlink-format.md`.

## Build commands

Day-to-day compiling and running goes **through Eclipse** (auto-builds on save; launch
Ghidra with the `eclipse-runner` `Ghidra` launch config, run mode, no hot code replace —
restart after changes). The Gradle CLI is for what Eclipse doesn't cover:

- `./gradlew buildGhidra` — full distribution zip into `build/dist/` (source of the
  extension projects' `ghidra-sdk/`)
- `./gradlew buildNatives` — decompiler etc. for this platform
- `./gradlew :x86:sleighCompile` — compile the x86 Sleigh specs
- `./gradlew prepdev eclipse buildNatives` — (re)generate Eclipse projects
- Tests: `./gradlew :Base:test`, `unitTestReport`, `integrationTest`

Always the bundled `./gradlew`, never a system gradle. Fedora needs
`java-21-openjdk-devel` **and** `java-21-openjdk-jmods`.

## Development environment

Eclipse runs in a flatpak (`org.eclipse.Java`); agent sessions control it through the
Eclipse MCP servers (`eclipse-ide`, `eclipse-coder`, `eclipse-git`, `eclipse-runner`).
**Read from the filesystem, write through Eclipse** (`eclipse-coder`) — Eclipse builds
from its own state, so filesystem-only edits never reach the launched Ghidra. Compile
status via `eclipse-ide getCompilationErrors`.

The running Ghidra's user profile is
`~/.var/app/org.eclipse.Java/config/ghidra/ghidra_12.1.2_DEV_location_dailydriver/`;
extensions installed into its `Extensions/` dir (via each extension repo's
`./gradlew installExtension`) load on restart. On startup Ghidra loads the MCP server
extension, exposing the `ghidra-application-level` and `ghidra-program` tools for the
running instance.

The two extension repos (`~/src/ghidra-plugin-rtlink`, `~/src/ghidra-plugin-mcp`) are
**not** in the Eclipse workspace — edit them directly on the filesystem and build with
their own `./gradlew`.

**Verify analyzer/spec changes on a scratch re-import, and delete it afterwards** —
never re-analyze the live `/VICEROY.EXE` or the read-only `/VICEROY.OLD`. Details in
`../../viceroy/docs/ghidra-workflow.md`.
