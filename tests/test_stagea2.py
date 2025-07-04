# ---------------------------------------------------------------
# SecElf Stage A2 Testbench
#
# Description:
#   Validates function extraction logic in stage_a2_function_extractor.py
#
# Usage:
#   PYTHONPATH=src python3 -m pytest
#   PYTHONPATH=src python3 -m pytest tests/test_stagea2.py
#
# Notes:
#   - Pytest automatically collects functions prefixed with 'test_'
#   - Green dots (.) indicate passing tests
#   - Red F's indicate failing tests
# ---------------------------------------------------------------

import pytest
import os
import csv
from elftools.elf.elffile import ELFFile
from secelf.stage_a2_function_extractor import (
    extract_function_symbols,
    write_functions_to_csv
)

# ---------------------------------------------------------------
# Test 1: Check that extract_function_symbols returns functions
# ---------------------------------------------------------------
def test_1_extract_function_symbols_returns_functions():
    """
    Checks that we get at least one function from the dummy binary.
    """
    with open("tests/fixtures/dummy_binary", "rb") as f:
        elf_file = ELFFile(f)
        functions = extract_function_symbols(elf_file)
        assert isinstance(functions, list)
        assert any("main" in func["name"] for func in functions)

# ---------------------------------------------------------------
# Test 2: Check that write_functions_to_csv writes a correct CSV
# ---------------------------------------------------------------
def test_2_functions_csv_written_correctly():
    """
    Verifies that write_functions_to_csv writes a CSV with correct headers
    and at least one function entry.
    """
    with open("tests/fixtures/dummy_binary", "rb") as f:
        elf_file = ELFFile(f)
        functions = extract_function_symbols(elf_file)
        write_functions_to_csv(functions)

    # Check file exists
    assert os.path.exists("functions.csv"), "functions.csv was not created"

    # Validate CSV contents
    with open("functions.csv", "r") as csvfile:
        reader = csv.DictReader(csvfile)
        headers = reader.fieldnames
        assert headers == ["FunctionName", "Address", "Size", "SectionIndex"]
        rows = list(reader)
        assert len(rows) > 0, "functions.csv has no rows"
