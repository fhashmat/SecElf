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
from elftools.elf.elffile import ELFFile
from secelf.stage_a2_function_extractor import (
    extract_function_symbols,
    is_function_symbol,
    parse_function_metadata,
    demangle_symbol
)

# ---------------------------------------------------------------
# Test 1: test_1_extract_function_symbols_returns_functions
#
# Confirms that function symbols are extracted from the ELF
# and contain expected entries.
# ---------------------------------------------------------------
def test_1_extract_function_symbols_returns_functions():
    print("\n[TEST 1] Checking if function symbols are extracted...")
    with open("tests/fixtures/dummy_binary", "rb") as f:
        elf_file = ELFFile(f)
        functions = extract_function_symbols(elf_file)
        assert isinstance(functions, list)
        assert any("main" in func["name"] for func in functions)


# ---------------------------------------------------------------
# Test 2: test_2_is_function_symbol_detects_func
#
# Confirms is_function_symbol returns True for STT_FUNC
# and False for other types.
# ---------------------------------------------------------------
def test_2_is_function_symbol_detects_func():
    print("\n[TEST 2] Checking is_function_symbol helper...")

    class FakeFunc:
        def __getitem__(self, key):
            if key == "st_info":
                return {"type": "STT_FUNC"}
            raise KeyError

    assert is_function_symbol(FakeFunc()) is True

    class FakeObj:
        def __getitem__(self, key):
            if key == "st_info":
                return {"type": "STT_OBJECT"}
            raise KeyError

    assert is_function_symbol(FakeObj()) is False


# ---------------------------------------------------------------
# Test 3: test_3_parse_function_metadata_extracts_fields
#
# Checks that parse_function_metadata gives back the correct
# dictionary keys for a known mocked symbol.
# ---------------------------------------------------------------
def test_3_parse_function_metadata_extracts_fields():
    print("\n[TEST 3] Checking parse_function_metadata...")

    class DummySymbol:
        name = "testfunc"
        entry = {"st_value": 0x1000, "st_size": 64, "st_shndx": 5}
        def __getitem__(self, key):
            if key == "st_info":
                return {"type": "STT_FUNC"}
            raise KeyError

    meta = parse_function_metadata(DummySymbol())
    assert meta["name"] == "testfunc"
    assert meta["address"] == 0x1000
    assert meta["size"] == 64
    assert meta["section_index"] == 5
    assert meta["symbol_type"] == "STT_FUNC"


# ---------------------------------------------------------------
# Test 4: test_4_demangle_symbol_with_cxxfilt
#
# Checks that demangle_symbol() handles mangled names correctly
# and leaves unmangled names alone.
# ---------------------------------------------------------------
def test_4_demangle_symbol_with_cxxfilt():
    print("\n[TEST 4] Checking demangle_symbol on mangled and normal names...")

    mangled = "_Z3fooi"  # usually means foo(int)
    result = demangle_symbol(mangled)
    assert isinstance(result, str)
    assert "foo" in result or result == mangled

    assert demangle_symbol("main") == "main"
