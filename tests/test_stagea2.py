# ---------------------------------------------------------------
# SecElf Stage A2 Testbench
#
# Description:
#   Validates function extraction logic in stage_a2_function_extractor.py
#
# Usage:
#   PYTHONPATH=src python3 -m pytest
# ---------------------------------------------------------------

import pytest
from elftools.elf.elffile import ELFFile
from secelf.stage_a2_function_extractor import extract_function_symbols

def test_extract_function_symbols_returns_functions():
    """
    Checks that we get at least one function from the dummy binary.
    """
    with open("tests/fixtures/dummy_binary", "rb") as f:
        elf_file = ELFFile(f)
        functions = extract_function_symbols(elf_file)
        assert isinstance(functions, list)
        assert any("main" in func["name"] for func in functions)
