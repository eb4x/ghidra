# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Ghidra is the NSA's open-source software reverse engineering framework: disassembly, decompilation, emulation, debugging, and scripting across ~40 processor architectures. Primary language is Java (JDK 21). The decompiler is C++, processor specifications are written in Sleigh, and debugger back-ends are Python 3.

## Build Commands

Requires JDK 21 (64-bit) and Python 3.9–3.14 with pip. Always use the bundled wrapper `./gradlew`, not a system `gradle`.

```bash
# One-time setup: fetch non-Maven-Central dependencies into ./dependencies/
./gradlew -I gradle/support/fetchDependencies.gradle

# Prepare development environment (Maven deps, generated sources)
./gradlew prepdev

# Build native components (decompiler, demangler, etc.) — needs GCC/Clang + make
./gradlew buildNatives

# Full compressed distribution for this platform, output to build/dist/
./gradlew buildGhidra

# Uncompressed distribution
./gradlew assembleAll

# Compile Sleigh processor specs (otherwise done lazily at runtime)
./gradlew sleighCompile

# Generate Eclipse project files (Eclipse is the supported IDE)
./gradlew cleanEclipse eclipse

# Skip a failing task, e.g. IP header checks on new files
./gradlew buildGhidra -x ip

# Set up PyGhidra dev venv at build/venv/
./gradlew prepPyGhidra

# Re-assemble debugger/PyGhidra Python packages after editing src/main/py
./gradlew assemblePyPackage
```

Known issue: on non-English Linux locales, set `LC_MESSAGES=en_US.UTF-8` or Gradle may fail to find native toolchains.

## Testing

Gradle project names equal module directory names (e.g. `Ghidra/Features/Base` → `:Base`, `Ghidra/Framework/SoftwareModeling` → `:SoftwareModeling`).

```bash
# All unit tests (src/test/) with HTML report
./gradlew unitTestReport

# Integration tests (src/test.slow/), new JVM per test class
./gradlew integrationTest

# Both, with combined report
./gradlew combinedTestReport

# P-code processor tests (src/test.processors/)
./gradlew pcodeTestReport

# Single test class / single method
./gradlew :Base:test --tests 'ghidra.app.plugin.core.analysis.AnalysisManagerTest'
./gradlew :Base:test --tests 'ghidra.app.plugin.core.analysis.AnalysisManagerTest.testMethodName'

# Single integration test class
./gradlew :Base:integrationTest --tests 'fully.qualified.TestName'
```

Headless environments (CI, Docker) need a display for AWT:
```bash
Xvfb :99 -nolisten tcp &
export DISPLAY=:99
```

**Test placement rule:** tests that extend integration base classes (e.g. `AbstractGhidraHeadlessIntegrationTest`) must live in `src/test.slow/`, never `src/test/` — the unit-test source set shares JVM/application initialization that integration base classes break. Classes matching `*Suite*` are excluded from test discovery.

## Architecture

### Repository Layout

```
Ghidra/
  Framework/     - Core libraries: Utility, Generic, DB, Docking, Gui, Graph, Help,
                   FileSystem, Project, Pty, Emulation, SoftwareModeling
  Features/      - Analysis features: Base, Decompiler, BSim, PDB, FileFormats,
                   VersionTracking, FunctionID, PyGhidra, GhidraServer, ...
  Processors/    - One module per ISA (x86, ARM, AARCH64, MIPS, RISCV, ...)
  Debug/         - Debugger UI, Trace database, and per-debugger agents
  Extensions/    - Optional/example extensions
  Test/          - Test infrastructure
GPL/             - GPL-licensed code; must be standalone, independently buildable modules
GhidraBuild/     - Build tooling, LaunchSupport, Eclipse plugins (GhidraDev, SleighEditor)
gradle/          - Shared build logic (javaProject.gradle, javaTestProject.gradle, ...)
```

### Key Concepts

- **SoftwareModeling** (Framework) is the heart: the program model (addresses, code units, symbols, data types, references), the Sleigh compiler, and p-code (the architecture-neutral IR every processor lifts to). Nearly everything depends on it.
- **Base** (Features) is the main application layer: CodeBrowser, analyzers, importers/loaders, and most plugins.
- **Decompiler** is a native C++ program (`Ghidra/Features/Decompiler/src/decompile/cpp/`) that communicates with Java over process I/O — not JNI. It has its own gradle project (`:decompile`).
- **DB** (Framework) is a custom table-based database that backs both Programs and Traces, providing transactions, undo/redo, and versioned shared projects.
- **Docking/Gui** (Framework) is the Swing docking-window framework. Plugins contribute UI as `ComponentProvider`s and actions as `DockingAction`s.
- **Plugins** extend `Plugin`, carry a `@PluginInfo` annotation declaring provided/consumed services, and are composed into a `PluginTool` at runtime. Cross-plugin communication goes through services and plugin events, not direct references.

### Processor Modules (Sleigh)

Each `Ghidra/Processors/<name>/data/languages/` directory contains:
- `.slaspec` — top-level Sleigh spec (includes the `.sinc` files)
- `.sinc` — instruction definitions (bulk of the content)
- `.pspec` — processor spec: registers, memory map, context
- `.cspec` — compiler/ABI spec: calling conventions, stack, data organization
- `.ldefs` — language definitions: variants, endianness, spec wiring

Sleigh describes how machine instructions decode and translate to p-code; the same specs drive disassembly, decompilation, and emulation.

### Debugger (Trace RMI)

Back-ends ("agents") for GDB, LLDB, dbgeng/WinDbg, drgn, and x64dbg live in `Ghidra/Debug/Debugger-agent-*`, implemented in Python 3 under `src/main/py`. They connect to the Java front-end over a protobuf-based TCP protocol (Trace RMI) and populate a Trace database — machine state recorded over time, stored via the same DB framework as Programs. By design, no code touching a native debugger API runs inside the Ghidra JVM; crashes stay contained in the agent process. Per-agent architecture mappings live in each agent's `arch.py`; agent tests are split into Commands, Methods, and Hooks categories (see GDB's as the template).

## Contribution Conventions

- Apache 2.0 license; any GPL code must be a standalone module under `GPL/`. Every source file needs the IP header (checked by the `ip` task).
- Squash commits; the message starts with the GitHub issue number.
- No refactoring, repackaging, find-and-replace, or third-party dependency updates in PRs unless pre-approved by the Ghidra team.
- Keep patches minimal and isolated; no self-generated binaries.
