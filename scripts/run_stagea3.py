#!/usr/bin/env python3

# ---------------------------------------------------------------
# This is the CLI entry point for Stage A3 of SecElf.
#
# It loads functions from functions_stage_a2.csv,
# applies the obfuscation categorizer heuristics,
# and saves the results to stagea3_obfuscated_functions.csv.
#
# Usage:
#   PYTHONPATH=src python3 scripts/run_stagea3.py
# ---------------------------------------------------------------

from secelf.stage_a3_obfuscated_function_categorizer import placeholder_ghidra_obfuscated_function_categorizer, write_categorized_obfuscated_functions
import csv

def main():
    input_file = "functions_stage_a2.csv"
    output_file = "stagea3_obfuscated_functions.csv"

    try:
        with open(input_file, "r") as f:
            reader = csv.DictReader(f)
            functions = list(reader)
    except FileNotFoundError:
        print(f"ERROR: {input_file} not found.")
        return

    categorized = placeholder_ghidra_obfuscated_function_categorizer(functions)
    write_categorized_obfuscated_functions(categorized, output_file)
    print(f"Obfuscation categorization complete. Results saved to {output_file}")

if __name__ == "__main__":
    main()
