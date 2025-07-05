# ---------------------------------------------------------------
# stage_a.py
#
# Context:
#   Originally, Stage A logic was a single large script
#   with mixed procedural code:
#     - get_ldd_library_paths()
#     - parsing ELF sections
#     - CSV writing
#     - sys.argv handling
#
# Problems:
#   - hard to reuse
#   - hard to test
#   - poor separation of concerns
#
# Refactor goals:
#   - clean modular functions in stage_a.py
#   - separate CLI in run_stagea.py
#   - improved maintainability and readability
# ---------------------------------------------------------------

# ---------------------------------------------------------------
# Imports
#
# ELFFile:
#   - from pyelftools, to parse ELF binary structures
#
# re:
#   - for regular expressions to extract printable ASCII strings
#
# csv:
#   - to write extracted data into CSV format
#
# subprocess:
#   - to run the `ldd` system command for resolving shared library paths
#
# elf (alias):
#   - imported for symbol extraction using preferred loading methods
# ---------------------------------------------------------------

from elftools.elf.elffile import ELFFile
import re
import csv
import subprocess
import elftools.elf.elffile as elf

# ---------------------------------------------------------------
# get_ldd_library_paths()
#
# Description:
#   Parses the output of the `ldd` command on a given binary
#   to map shared library names to their resolved full filesystem paths.
#
# Inputs:
#   binary_path (str) - path to the ELF binary
#
# Returns:
#   dict of { library_name: resolved_path }
# ---------------------------------------------------------------
def get_ldd_library_paths(binary_path):
    """
    Parse `ldd` output to map library names to their resolved paths.
    """
    try:
        ldd_output = subprocess.check_output(['ldd', binary_path]).decode()
        lib_map = {}
        for line in ldd_output.splitlines():
            match = re.match(r'\s*(\S+)\s+=>\s+(\S+)', line)
            if match:
                libname = match.group(1)
                libpath = match.group(2)
                lib_map[libname] = libpath
        return lib_map
    except subprocess.CalledProcessError:
        return {}
# ---------------------------------------------------------------
# extract_symbols()
#
# Description:
#   Parses symbol tables (.dynsym and .symtab) to
#   extract symbol names from an ELF binary.
#
# Inputs:
#   binary_path (str) - path to the ELF binary
#
# Returns:
#   list of symbol names
# ---------------------------------------------------------------

def extract_symbols(binary_path):
    """
    Extract symbols from .dynsym and .symtab sections
    """
    symbols = []
    symbol_target = elf.ELFFile.load_from_path(binary_path)
    for section in symbol_target.iter_sections():
        if section.name in [".dynsym", ".symtab"]:
            for sym in section.iter_symbols():
                symbols.append(sym.name)
    return symbols

# ---------------------------------------------------------------
# extract_libraries_from_dynamic()
#
# Description:
#   Parses the .dynamic section to identify DT_NEEDED entries
#   representing linked library dependencies in the ELF binary.
#
# Inputs:
#   elf_file (ELFFile) - an open ELFFile object
#
# Returns:
#   list of needed library names
# ---------------------------------------------------------------


def extract_libraries_from_dynamic(elf_file):
    """
    Extract libraries from .dynamic section
    """
    dynamic = elf_file.get_section_by_name('.dynamic')
    if dynamic is None:
        return []
    return [tag.needed for tag in dynamic.iter_tags() if tag.entry.d_tag == 'DT_NEEDED']

# ---------------------------------------------------------------
# extract_strings()
#
# Description:
#   Extracts printable ASCII strings (2+ characters)
#   from the .rodata section of an ELF file.
#
# Inputs:
#   elf_file (ELFFile) - an open ELFFile object
#
# Returns:
#   list of decoded strings
# ---------------------------------------------------------------
def extract_strings(elf_file):
    """
    Extract printable strings from .rodata
    """
    rodata = elf_file.get_section_by_name('.rodata')
    if rodata is None:
        print("No .rodata section found in this binary.")
        return []

    raw_data = rodata.data()
    strings = re.findall(rb"[ -~]{2,}", raw_data)
    decoded = [s.decode('utf-8', errors='ignore') for s in strings]
    return decoded

# ---------------------------------------------------------------
# combine_stage_a_data()
#
# Description:
#   Combines strings, symbols, libraries, and their resolved
#   paths into a single CSV file for further analysis.
#
# Inputs:
#   decoded (list of strings)
#   symbols (list of symbols)
#   libraries (list of libraries from .dynamic)
#   ldd_map (dict of resolved paths)
#
# Returns:
#   writes 'elfdata_combined.csv' file
# ---------------------------------------------------------------

def combine_stage_a_data(decoded, symbols, libraries, ldd_map):
    """
    Combine all extracted data and write to CSV
    """
    with open("elfdata_combined.csv", "w", newline="") as out:
        writer = csv.writer(out)
        writer.writerow(["String", "Symbol", "Library", "LibraryPath"])
        for s, sym, lib in zip(decoded, symbols, libraries):
            resolved_path = ldd_map.get(lib, "MISSING")
            writer.writerow([s, sym, lib, resolved_path])
        # Second loop: handle ldd-only extras
        extra_ldd_libs = set(ldd_map.keys()) - set(libraries)
        for extra_lib in extra_ldd_libs:
            resolved_path = ldd_map.get(extra_lib, "MISSING")
            writer.writerow(["", "", extra_lib, resolved_path])
    print("Combined strings, symbols, libraries, and resolved paths written to elfdata_combined.csv")

# ---------------------------------------------------------------
# stage_a_process()
#
# Description:
#   The main orchestration function for Stage A. Calls all
#   helper functions in sequence to extract ELF binary
#   analysis data and writes the combined output to CSV.
#
# Inputs:
#   binary_path (str) - path to the ELF binary
#
# Returns:
#   None
# ---------------------------------------------------------------

def stage_a_process(binary_path):
    """
    Orchestrates Stage A processing by calling the modular helpers.
    """
    with open(binary_path, "rb") as fp:
        elf_file = ELFFile(fp)

        decoded = extract_strings(elf_file)
        symbols = extract_symbols(binary_path)
        libraries = extract_libraries_from_dynamic(elf_file)
        ldd_map = get_ldd_library_paths(binary_path)

        combine_stage_a_data(decoded, symbols, libraries, ldd_map)
