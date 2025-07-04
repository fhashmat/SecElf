# ---------------------------------------------------------------
# stage_a2_function_extractor.py
#
# Context:
#   Stage A2 focuses on extracting *functions* specifically
#   from ELF symbol tables. This is separate from general symbol
#   extraction or strings.
#
# Goal:
#   - identify STT_FUNC symbols
#   - record their names, addresses, sizes, and section index
#   - store them in a CSV for later obfuscation or profiling analysis
# How To Run? PYTHONPATH=src python3 scripts/run_stagea2.py tests/fixtures/dummy_binary
#
# ---------------------------------------------------------------

from elftools.elf.elffile import ELFFile
import csv
import subprocess

# ---------------------------------------------------------------
# extract_function_symbols()
#
# Description:
#   This function parses the .symtab and .dynsym sections of
#   an ELF binary, and collects only those symbols whose type
#   is STT_FUNC (function symbols).
#
# Inputs:
#   elf_file (ELFFile) - already opened ELFFile object
#
# Returns:
#   list of dictionaries:
#     [
#       { "name": str, "address": int, "size": int, "section_index": int },
#       ...
#     ]
# ---------------------------------------------------------------
# ---------------------------------------------------------------
# parse_function_metadata()
#
# Description:
#   Given an ELF symbol known to be a function, this helper
#   extracts metadata such as:
#     - name of the function
#     - address where it resides
#     - size in bytes
#     - section index in the ELF file
#     - symbol type (for completeness)
#   It uses safe .get() calls to avoid missing fields.
#
# Inputs:
#   sym (Symbol object) - an ELF function symbol
#
# Returns:
#   dict with keys:
#     name, address, size, section_index, symbol_type
# ---------------------------------------------------------------
def parse_function_metadata(sym):
    """
    Extracts metadata for a given symbol:
    - name
    - address
    - size
    - section index
    """
    return {
        "name": sym.name,
        "address": sym.entry.get('st_value', 0),
        "size": sym.entry.get('st_size', 0),
        "section_index": sym.entry.get('st_shndx', 'UNKNOWN'),
        "symbol_type": sym['st_info']['type'],

    }
# ---------------------------------------------------------------
# is_function_symbol()
#
# Description:
#   Helper function to determine if a given ELF symbol is a
#   function. It checks whether the symbol type matches
#   'STT_FUNC', which represents functions in ELF symbol tables.
#
# Inputs:
#   sym (Symbol object) - the ELF symbol to check
#
# Returns:
#   True if the symbol is of type STT_FUNC, False otherwise
# ---------------------------------------------------------------
def is_function_symbol(sym):
    """
    Checks if a symbol is a function (STT_FUNC)
    """
    try:
        return sym['st_info']['type'] == 'STT_FUNC'
    except KeyError:
        return False
# ---------------------------------------------------------------
# extract_function_symbols()
#
# Description:
#   Walks through the ELF binary's .symtab and .dynsym
#   sections to collect all function symbols (STT_FUNC).
#   Uses is_function_symbol() to filter, and
#   parse_function_metadata() to organize extracted data.
#
# Inputs:
#   elf_file (ELFFile) - parsed ELF file
#
# Returns:
#   list of dictionaries with function metadata
# ---------------------------------------------------------------
def extract_function_symbols(elf_file):
    """
    Extract only function symbols (STT_FUNC) from .symtab and .dynsym.
    """
    functions = []

    for section in elf_file.iter_sections():
        if not hasattr(section, "iter_symbols"):
            continue

        for sym in section.iter_symbols():
            if is_function_symbol(sym):
                func_entry = parse_function_metadata(sym)
                functions.append(func_entry)

    return functions


# ---------------------------------------------------------------
# demangle_symbol()
#
# Description:
#   Uses the external `c++filt` command-line utility to
#   convert mangled C++ symbol names (e.g., "_Z3fooi")
#   into human-readable names (e.g., "foo(int)").
#
# Inputs:
#   mangled_name (str) - the raw symbol name
#
# Returns:
#   demangled_name (str) - or falls back to original if
#   demangling fails or c++filt is missing.
# ---------------------------------------------------------------
def demangle_symbol(mangled_name):
    try:
        result = subprocess.run(
            ["c++filt", mangled_name],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip()
    except Exception:
        # fallback to original if demangling fails
        return mangled_name

# ---------------------------------------------------------------
# write_functions_to_csv()
#
# Description:
#   Writes the collected function metadata to a CSV file,
#   including both the original and demangled function names,
#   address, size, section index, and symbol type.
#
# Inputs:
#   functions (list of dicts) - function metadata extracted
#   output_file (str) - name of the CSV output file
#
# Returns:
#   None (creates CSV on disk)
# ---------------------------------------------------------------
def write_functions_to_csv(functions, output_file="functions.csv"):
    """
    Write extracted function information to a CSV file.
    Includes a separate column for demangled names.
    """
    with open(output_file, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "FunctionName", 
            "DemangledName", 
            "Address", 
            "Size", 
            "SectionIndex",
            "SymbolType"
        ])
        for func in functions:
            demangled = demangle_symbol(func["name"])
            writer.writerow([
                func["name"],
                hex(func["address"]),
                func["size"],
                func["section_index"],
                func["symbol_type"]
])





