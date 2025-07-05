#!/usr/bin/env python3

# ---------------------------------------------------------------
# This is the CLI entry point for Stage A2 of SecElf.
# It handles reading the command-line arguments,
# then delegates the function-extraction work to
# the extract_function_symbols function inside the reusable
# stage_a2_function_extractor module.
# How to Run? PYTHONPATH=src python3 scripts/run_stagea2.py tests/fixtures/dummy_binary
# ---------------------------------------------------------------

import sys
from elftools.elf.elffile import ELFFile
from secelf.stage_a2_function_extractor import (
    extract_function_symbols,
    write_functions_to_csv
)


def main():
    # Check if the user gave the required ELF binary filename
    if len(sys.argv) < 2:
        print("Usage: python3 run_stagea2.py <path_to_binary>")
        sys.exit(1)

    # Get the binary path from the first argument
    binary_path = sys.argv[1]

    # Call the function extraction logic
    with open(binary_path, "rb") as f:
        elf_file = ELFFile(f)
        functions = extract_function_symbols(elf_file)

    # Write functions to CSV using the module’s dedicated writer
    write_functions_to_csv(functions)

    print("Functions extracted and written to functions.csv")

# This idiom is a standard Python pattern:
# When this script is executed directly (like: python run_stagea2.py),
# the special variable __name__ is set to "__main__", so main() runs.
# However, if someone IMPORTS this script as a module,
# then __name__ will be "run_stagea2", and main() will NOT run.
# This prevents unintended execution when imported.
if __name__ == "__main__":
    main()
