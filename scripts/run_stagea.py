#!/usr/bin/env python3

# This is the CLI entry point for Stage A of SecElf.
# It handles reading the command-line arguments,
# then delegates the real analysis work to the stage_a_process function
# inside the reusable stage_a module.

import sys
from secelf.stage_a_libraries import stage_a_process

def main():
    # Check if the user gave the required ELF binary filename
    if len(sys.argv) < 2:
        print("Usage: python3 run_stagea.py <path_to_binary>")
        sys.exit(1)
    # Get the binary path from the first argument
    binary_path = sys.argv[1]
    # Call the Stage A processing function with this path
    stage_a_process(binary_path)
# This idiom is a standard Python pattern:
# When this script is executed directly (like: python run_stagea.py),
# the special variable __name__ is set to "__main__", so main() runs.
# However, if someone IMPORTS this script as a module (e.g., import run_stagea),
# then __name__ will be "run_stagea", and main() will NOT run.
# This prevents unintended execution when the file is imported elsewhere.
if __name__ == "__main__":
    main()
