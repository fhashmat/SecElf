**Quickstart**

**To analyze a binary with all Stage A sub-stages (A1 → A2 → A3), run:**

# Stage A1: Extract libraries
PYTHONPATH=src python3 scripts/run_stagea.py <binary>

# Stage A2: Extract functions
PYTHONPATH=src python3 scripts/run_stagea2.py <binary>

# Stage A3: Categorize functions (obfuscation + type)
PYTHONPATH=src python3 scripts/run_stagea3.py <binary>

**Example**
PYTHONPATH=src python3 scripts/run_stagea.py tests/fixtures/dummy_binary
PYTHONPATH=src python3 scripts/run_stagea2.py tests/fixtures/dummy_binary
PYTHONPATH=src python3 scripts/run_stagea3.py tests/fixtures/dummy_binary

**Outputs**

Stage A1 → elfdata_combined.csv

Stage A2 → stageAfuncs/<tool_name>/functions_extracted_<binary>.csv

Stage A3 → stageA3/<tool_name>/functions_obfuscated_<binary>.csv

**Stage A: Binary Analysis**

Stage A extracts and enriches information from ELF binaries in three sub-stages:

**A1 – Libraries**

**Input: ELF binary**

**Process:**

Extracts DT_NEEDED entries (declared libraries).

Resolves actual library paths on the host using ldd.

Output: CSV with columns:
Library | Resolved Path | Note

**Run:**

PYTHONPATH=src python3 scripts/run_stagea.py <binary>

**A2 – Functions**

**Input: ELF binary**

**Process:**

Parses ELF symbol tables to extract functions.

Records function name, demangled name, address, size, section, and type.

Adds placeholder Obfuscated column.

**Output: CSV in:**
stageAfuncs/<tool_name>/functions_extracted_<binary>.csv

**Run:**

PYTHONPATH=src python3 scripts/run_stagea2.py <binary>

**A3 – Function Categorization**

**Input: Stage A2 function CSV**

**Process:**

Detects obfuscation (mangled names, entropy, suspicious patterns).

Categorizes functions into buckets (e.g., crypto, net, file, proc).

Records reasoning for each categorization.

**Output: CSV in:**
stageA3/<tool_name>/functions_obfuscated_<binary>.csv

**Run:**

PYTHONPATH=src python3 scripts/run_stagea3.py <binary>
