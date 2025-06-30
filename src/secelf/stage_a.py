# stage_a.py
# NOTE:
# Previously, all Stage A logic was in a single file (SecElf_StageA_BinAnalysis.py)
# containing:
#   - functions like get_ldd_library_paths()
#   - procedural code to open files, parse ELF, write CSV
#   - command-line argument handling (sys.argv)
# Problems with that structure:
#   - hard to reuse
#   - hard to test
#   - everything was in one block
#   - no separation between logic and CLI entry
#
# We are now splitting it into:
#   - a reusable module (stage_a.py) with clean functions
#   - a CLI runner script (run_stagea.py)
# for a more maintainable and professional structure.


from elftools.elf.elffile import ELFFile
import re
import csv
import subprocess
import elftools.elf.elffile as elf


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

# you can move the following logic *for now* as a block
# we will break it into proper functions later

def stage_a_process(binary_path):
    """
    Performs Stage A ELF analysis and writes results to CSV.
    """
    fp = open(binary_path, "rb")
    elf_file = ELFFile(fp)

    rodata = elf_file.get_section_by_name('.rodata')
    if rodata is None:
        print("No .rodata section found in this binary.")
        fp.close()
        return

    raw_data = rodata.data()
    strings = re.findall(rb"[ -~]{2,}", raw_data)
    decoded = [s.decode('utf-8', errors='ignore') for s in strings]

    # symbols
    symbol_target = elf.ELFFile.load_from_path(binary_path)
    sections = []
    for section in symbol_target.iter_sections():
        if section.name == ".dynsym" or section.name == ".symtab":
            sections.append(section)

    symbols = []
    for section in sections:
        for sym in section.iter_symbols():
            symbols.append(sym.name)

    # libraries
    dynamic = elf_file.get_section_by_name('.dynamic')
    if dynamic is not None:
        libraries = [tag.needed for tag in dynamic.iter_tags() if tag.entry.d_tag == 'DT_NEEDED']
    else:
        libraries = []

    # resolve paths
    ldd_map = get_ldd_library_paths(binary_path)

    # write CSV
    with open("elfdata_combined.csv", "w", newline="") as out:
        writer = csv.writer(out)
        writer.writerow(["String", "Symbol", "Library", "LibraryPath"])
        for s, sym, lib in zip(decoded, symbols, libraries):
            resolved_path = ldd_map.get(lib, "")
            writer.writerow([s, sym, lib, resolved_path])

    print(f"Combined strings, symbols, libraries and resolved paths written to elfdata_combined.csv")
    fp.close()
