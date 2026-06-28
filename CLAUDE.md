# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Ghidra is an open-source software reverse engineering framework developed by the NSA. It provides binary analysis, disassembly, decompilation, and scripting capabilities for 40+ processor architectures. Primary language is Java (JDK 21), with C++ for the decompiler, Sleigh for processor specifications, and Python 3 for scripting/debugger integration.

## Build Commands

Requires JDK 21 (64-bit) and Gradle 8.5+.

```bash
# First-time setup: fetch non-Maven dependencies, then prepare dev environment
gradle -I gradle/support/fetchDependencies.gradle
gradle prepdev

# Build native components (decompiler, etc.) - requires GCC/Clang + make
gradle buildNatives

# Build full distribution (compressed, single-platform) to build/dist/
gradle buildGhidra

# Build uncompressed distribution
gradle assembleAll

# Compile Sleigh processor specs (also happens at runtime if needed)
gradle sleighCompile

# Generate Eclipse project files
gradle cleanEclipse eclipse

# Skip a failing task (e.g., IP header checks)
gradle buildGhidra -x ip
```

## Testing

```bash
# Unit tests (src/test/java)
gradle unitTestReport

# Integration tests (src/test.slow/java) - separate JVM per test
gradle integrationTest

# Both unit + integration with report
gradle combinedTestReport

# P-code processor tests (src/test.processors/java)
gradle pcodeTestReport

# Run a single test class from a specific module
gradle :Base:test --tests 'ghidra.app.plugin.core.analysis.AnalysisManagerTest'

# Run a single test method
gradle :Base:test --tests 'ghidra.app.plugin.core.analysis.AnalysisManagerTest.testMethodName'
```

For headless/CI environments:
```bash
Xvfb :99 -nolisten tcp &
export DISPLAY=:99
export JAVA_TOOL_OPTIONS="-DUSER_AGREEMENT=ACCEPT"
```

Test base class rule: tests extending `AbstractGhidraHeadlessIntegrationTest` must go in `src/test.slow/` (the integrationTest source set), not `src/test/`, because they require a shared JVM initialization.

## Architecture

### Module Organization

```
Ghidra/
  Framework/     - Core libraries (14 modules): DB, SoftwareModeling, Generic, Gui, Docking,
                   Emulation, FileSystem, Graph, Help, Project, Pty, Utility
  Features/      - Analysis features (36+ modules): Base, Decompiler, FileFormats, BSim, PDB,
                   VersionTracking, PyGhidra, FunctionID, debugger extensions
  Processors/    - ISA definitions (40 modules): x86, ARM, AARCH64, MIPS, PowerPC, RISCV, etc.
  Extensions/    - Extension examples and optional plugins
  Debug/         - Debugger UI, agents (GDB, LLDB, dbgeng), Trace RMI framework
  Test/          - Test infrastructure
GPL/             - GPL-licensed standalone modules (built independently)
GhidraBuild/     - Build tooling, Eclipse plugins (GhidraDev)
```

### Key Frameworks

- **SoftwareModeling** — The core: Sleigh compiler, P-code intermediate representation, program model (addresses, symbols, data types, references). Almost everything depends on this.
- **Base** (in Features/) — Main Ghidra UI: CodeBrowser, plugins, analyzers, importers, navigation. The central feature module.
- **Decompiler** — C++ native decompiler in `Ghidra/Features/Decompiler/src/decompile/cpp/`. Communicates with Java via process I/O, not JNI.
- **DB** — Custom object database underpinning Programs and Traces. Supports undo/redo and shared projects.
- **Docking/Gui** — Swing-based docking window framework. Plugins provide `ComponentProvider` panels and `DockingAction` menu/toolbar actions.

### Plugin System

Plugins use `@PluginInfo` annotation, extend `Plugin`, and are loaded into a `PluginTool`. They register/consume services and provide UI via `ComponentProvider`. Extensions are standalone modules with `extension.properties` and `Module.manifest`.

### Processor Modules (Sleigh)

Each processor in `Ghidra/Processors/{name}/data/languages/` contains:
- `.slaspec` — Main Sleigh specification (entry point, includes .sinc files)
- `.sinc` — Instruction definitions (the bulk of the work)
- `.cspec` — Compiler/ABI spec (calling conventions, stack behavior)
- `.pspec` — Processor spec (memory map, registers, context)
- `.ldefs` — Language definitions metadata (variants, endianness)

Sleigh files define how binary instructions map to P-code operations.

### Debugger Architecture

Uses Trace RMI protocol: Python 3 back-ends (GDB, LLDB, dbgeng) connect to Java front-end via protobuf TCP. Native API access is always out-of-process to contain crashes. Trace database records machine state over time using the same DB framework as Programs.

### Module Source Layout

```
Module/
  src/main/java/            # Production source
  src/main/resources/       # Resources
  src/main/help/            # Help HTML
  src/test/java/            # Unit tests
  src/test.slow/java/       # Integration tests
  src/test.processors/java/ # P-code tests (processor modules)
  data/                     # Module data files (languages, typeinfo, etc.)
  ghidra_scripts/           # Built-in Ghidra scripts
```

## Contribution Conventions

- License: Apache 2.0. Any GPL code must be a standalone module under `GPL/`.
- Squash commits with message starting with the issue number.
- Avoid refactoring, find-and-replace, or dependency update PRs unless pre-approved.
- Do not submit self-generated binaries.
- Known Gradle issue: set `LC_MESSAGES=en_US.UTF-8` on non-English Linux locales.
