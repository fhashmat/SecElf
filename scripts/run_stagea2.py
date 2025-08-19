#!/usr/bin/env python3

# ---------------------------------------------------------------
# This is the CLI entry point for Stage A2 of SecElf.
#
# Purpose:
#   - Handle reading the command-line arguments
#   - Delegate the function-extraction work to the
#     stage_a2_process function inside the reusable
#     stage_a2_function_extractor module
#
# How to Run?
#   PYTHONPATH=src python3 scripts/run_stagea2.py tests/fixtures/dummy_binary
#
# Notes:
#   - Output will be written under:
#       stageAfuncs/<tool_name>/functions_extracted_<binary>.csv
# ---------------------------------------------------------------

import sys
from secelf.stage_a2_function_extractor import stage_a2_process

def main():
    # -----------------------------------------------------------
    # Check if the user provided the required ELF binary path
    # -----------------------------------------------------------
    if len(sys.argv) < 2:
        print("Usage: python3 scripts/run_stagea2.py <path_to_binary>")
        sys.exit(1)

    # -----------------------------------------------------------
    # Get the binary path from the first argument
    # -----------------------------------------------------------
    binary_path = sys.argv[1]

    # -----------------------------------------------------------
    # Call the Stage A2 orchestration function
    # This will:
    #   - open ELF
    #   - extract function symbols
    #   - demangle names
    #   - write results to CSV under stageAfuncs/<tool_name>/
    # -----------------------------------------------------------
    stage_a2_process(binary_path)

    # -----------------------------------------------------------
    # Print confirmation message
    # -----------------------------------------------------------
    print("Stage A2 complete: functions CSV written to stageAfuncs/<tool_name>/")

# ---------------------------------------------------------------
# Standard Python entrypoint idiom:
#   - If this script is run directly, __name__ == "__main__"
#   - If imported as a module, __name__ != "__main__"
# ---------------------------------------------------------------
if __name__ == "__main__":
    main()
