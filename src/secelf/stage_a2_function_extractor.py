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
# ---------------------------------------------------------------

from elftools.elf.elffile import ELFFile
import csv

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

def extract_function_symbols(elf_file):
    """
    Extract only function symbols (STT_FUNC) from .symtab and .dynsym.
    """
    functions = []

    for section in elf_file.iter_sections():
        if not hasattr(section, "iter_symbols"):
            continue

        for sym in section.iter_symbols():
            try:
                if sym['st_info']['type'] == 'STT_FUNC':
                    func_entry = {
                        "name": sym.name,
                        "address": sym.entry['st_value'],
                        "size": sym.entry['st_size'],
                        "section_index": sym.entry['st_shndx'],
                    }
                    functions.append(func_entry)
            except KeyError:
                # If st_info or any entry is missing, just skip this symbol
                continue

    return functions
def write_functions_to_csv(functions, output_file="functions.csv"):
    """
    Write extracted function information to a CSV file.
    """
    import csv
    with open(output_file, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["FunctionName", "Address", "Size", "SectionIndex"])
        for func in functions:
            writer.writerow([
                func["name"],
                hex(func["address"]),
                func["size"],
                func["section_index"]
            ])

