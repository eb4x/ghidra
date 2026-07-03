# Building Ghidra on Fedora

## Required Packages

```bash
sudo dnf install java-21-openjdk-devel java-21-openjdk-jmods
sudo dnf group install c-development
```

- `java-21-openjdk-devel` — provides `javac` and other compiler tools
- `java-21-openjdk-jmods` — provides the `jmods/` directory under the JDK installation; Gradle 9.x checks for this directory to distinguish a JDK from a JRE, and without it the build fails with:
  ```
  Toolchain installation '/usr/lib/jvm/java-21-openjdk' does not provide the required capabilities: [JAVA_COMPILER]
  ```

The base `java-21-openjdk` (JRE) package is pulled in as a dependency and does not need to be installed separately.

If you install these packages while a Gradle daemon is already running, you must restart it (`./gradlew --stop`) so it re-probes the JDK.

## Building

Build a distribution:

```bash
./gradlew buildGhidra
```

Set up for Eclipse development:

```bash
./gradlew prepdev eclipse buildNatives
```

## Running from Eclipse (Flatpak)

Allow local X11 connections and find your display value:

```bash
xhost +local:
echo $DISPLAY
```

Add the `DISPLAY` value as an environment variable in the Eclipse run configuration.

## Ghidra MCP for Claude

Download [GhidraMCP-5.14.2.zip](https://github.com/bethington/ghidra-mcp/releases/download/v5.14.2/GhidraMCP-5.14.2.zip) and install it in Ghidra:

1. File > Install Extensions > Add — select the ZIP
2. Restart Ghidra
3. File > Configure > Configure All Plugins > enable GhidraMCP
4. Tools > GhidraMCP > Start MCP Server

Set up a Python venv and install the MCP bridge:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r https://github.com/bethington/ghidra-mcp/releases/download/v5.14.2/requirements.txt
curl -L -o .venv/bin/bridge_mcp_ghidra.py https://github.com/bethington/ghidra-mcp/releases/download/v5.14.2/bridge_mcp_ghidra.py
```

Create `.mcp.json` in the project root:

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "<project-dir>/.venv/bin/python",
      "args": ["<project-dir>/.venv/bin/bridge_mcp_ghidra.py"],
      "env": {
        "GHIDRA_MCP_URL": "http://127.0.0.1:8089"
      }
    }
  }
}
```

Replace `<project-dir>` with the absolute path to this repository.
