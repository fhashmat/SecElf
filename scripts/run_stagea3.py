#!/usr/bin/env python3

# ---------------------------------------------------------------
# This is the CLI entry point for Stage A3 of SecElf.
#
# It loads the A2 CSV for a given binary:
#   stageAfuncs/<tool>/functions_extracted_<binary>.csv
# applies name-based heuristics to add:
#   - ObfuscationCategory/Score/Reason
#   - FunctionType/TypeReason
# and writes:
#   stageA3/<tool>/functions_obfuscated_<binary>.csv
#
# Usage:
#   PYTHONPATH=src python3 scripts/run_stagea3.py <path_to_binary>
#   e.g., PYTHONPATH=src python3 scripts/run_stagea3.py tests/fixtures/dummy_binary
# ---------------------------------------------------------------

import sys
from secelf.stage_a3_obfuscated_function_categorizer import stage_a3_process

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 scripts/run_stagea3.py <path_to_binary>")
        sys.exit(1)
    stage_a3_process(sys.argv[1])

if __name__ == "__main__":
    main()
