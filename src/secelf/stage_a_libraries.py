# ---------------------------------------------------------------
# stage_a.py
#PYTHONPATH=src python3 scripts/run_stagea.py tests/fixtures/dummy_binary

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
import os
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
    Handles lines with and without '=>'.
    """
    try:
        ldd_output = subprocess.check_output(['ldd', binary_path]).decode()
        lib_map = {}
        for line in ldd_output.splitlines():
            line = line.strip()
            if "=>" in line:
                # Matches: libXYZ.so => /path/to/libXYZ.so (0x...)
                parts = line.split("=>")
                if len(parts) >= 2:
                    libname = parts[0].strip()
                    libpath = parts[1].strip().split()[0]  # remove address part
                    lib_map[libname] = libpath
            else:
                # Matches: /lib64/ld-linux-x86-64.so.2 (0x...)
                tokens = line.split()
                if len(tokens) >= 1:
                    libname = tokens[0]
                    lib_map[libname] = libname  # same for both key and path
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
#def extract_strings(elf_file):
 #   """
  #  Extract printable strings from .rodata
   # """
    #rodata = elf_file.get_section_by_name('.rodata')
    #if rodata is None:
     #   print("No .rodata section found in this binary.")
      #  return []

    #raw_data = rodata.data()
    #strings = re.findall(rb"[ -~]{2,}", raw_data)
    #decoded = [s.decode('utf-8', errors='ignore') for s in strings]
    #return decoded

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

def combine_stage_a_data(libraries, ldd_map, binary_path):
    """
    Create a detailed CSV with libraries from pyelftools and ldd.
    """
    seen = set()

    binary_name = os.path.basename(binary_path)
    csv_name = f"lib_analysis_{binary_name}.csv"

    with open(csv_name, "w", newline="") as out:

        writer = csv.writer(out)
        writer.writerow(["Library (pyelftools)", "Resolved Path (ldd)", "Note"])

        # Step 1: libraries from pyelftools (.dynamic)
        for lib in libraries:
            path = ldd_map.get(lib, "MISSING")
            note = "" if lib in ldd_map else "Not in ldd"
            writer.writerow([lib, path, note])
            seen.add(lib)

        # Step 2: remaining libraries from ldd only
        for lib, path in ldd_map.items():
            if lib not in seen:
                writer.writerow(["", path, "Only in ldd"])


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
    Extracts and compares shared libraries from ELF .dynamic section and ldd.
    """
    with open(binary_path, "rb") as fp:
        elf_file = ELFFile(fp)
        libraries = extract_libraries_from_dynamic(elf_file)
        ldd_map = get_ldd_library_paths(binary_path)

        #  Debug prints
        print("==== PYELFTOOLS LIBRARIES ====")
        for lib in libraries:
            print(lib)

        print("\n==== LDD MAP ====")
        for lib, path in ldd_map.items():
            print(f"{lib} => {path}")

        combine_stage_a_data(libraries, ldd_map, binary_path)



