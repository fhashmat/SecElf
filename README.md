# Quickstart

To analyze a binary with all Stage A sub-stages (A1 → A2 → A3), run:

Stage A1: Extract libraries
```bash
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


