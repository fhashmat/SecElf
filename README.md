# Quickstart

To analyze a binary with all Stage A sub-stages (A1 → A2 → A3), run:


```bash
Stage A1: Extract libraries
PYTHONPATH=src python3 scripts/run_stagea.py <binary>

Stage A2: Extract functions
PYTHONPATH=src python3 scripts/run_stagea2.py <binary>

Stage A3: Categorize functions (obfuscation + type)
PYTHONPATH=src python3 scripts/run_stagea3.py <binary>


Example
PYTHONPATH=src python3 scripts/run_stagea.py tests/fixtures/dummy_binary
PYTHONPATH=src python3 scripts/run_stagea2.py tests/fixtures/dummy_binary
PYTHONPATH=src python3 scripts/run_stagea3.py tests/fixtures/dummy_binary

Outputs

Stage A1 → elfdata_combined.csv

Stage A2 → stageAfuncs/<tool_name>/functions_extracted_<binary>.csv

Stage A3 → stageA3/<tool_name>/functions_obfuscated_<binary>.csv

Stage B: Package Extractor

Purpose:
Maps Stage A’s resolved library paths to their corresponding Linux packages and versions.
Works seamlessly across distributions using rpm (Red Hat) or dpkg (Debian/Ubuntu).

Input (from Stage A):
CSV file under

stageAlibs/<tool_name>/lib_analysis_<binary>.csv


Specifically, Stage B reads the “Resolved Path (ldd)” column.

Process:

Resolves each library path to its owning package.

Extracts both binary package name and version.

Normalizes version strings into a VersionOnly column.

Adds a Status column (Resolved / Unresolved).

Output:
A new CSV under

stageBlibs/<tool_name>/packages_<binary>.csv


with the following columns:

LibraryPath

BinaryPackage

SourcePackage

VersionOnly

Status

Run Command:

# 1. Run Stage A first
PYTHONPATH=src python3 scripts/run_stagea.py /path/to/binary

# 2. Then run Stage B with the same binary path
PYTHONPATH=src python3 src/secelf/stage_b.py /path/to/binary

