#This is a tool which can be used to analyze elf binaries and sort their data of interest in CSV format.
#A Python file (elffile.py) inside elf, which defines the ELFFile class
from elftools.elf.elffile import ELFFile 
import re #for searching patterns in a file
import csv #for storing the data in the csv format
import sys #for getting the file name from the command line
import subprocess # I have added this for using the ldd
import elftools.elf.elffile as elf  # For preferred symbol section code from professor

# This function parses the output of `ldd` command and creates a mapping of library names to their resolved full paths. 
# This is specially made for using in Stage B becasue according to stage B logic we need the full librarby path for the rpm to resolve
# The otehr reason for that fucntion si that pyelf tools according to my current knowledge dont provide full paths of the libraries which can be directly used in rpm.
def get_ldd_library_paths(binary_path):
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

# if the filename given by the user is not valid then we written certain statement for guidance to enter the correct name.
if len(sys.argv) < 2:
    print("Usage:python3 SecElf.py <filename>")
    sys.exit(1) 

# here we are getting the file name as a parameter from the user of this tool.
with open(sys.argv[1], "rb") as f:
    elf_file = ELFFile(f)

 #BELOW CODE IS FOR GETTING THE STRINGS OUT OF BINARY
    # Get the .rodata section where we have strings.
    rodata = elf_file.get_section_by_name('.rodata')

    if rodata is None:
        print("No .rodata section found in this binary.")
        exit()

    # Get the raw bytes from that section
    raw_data = rodata.data()

    # Find all printable strings (ASCII range 32-126, 4+ chars)
    strings = re.findall(rb"[ -~]{2,}", raw_data)

    # Decode bytes to strings
    decoded = [s.decode('utf-8', errors='ignore') for s in strings]

    print(f"Extracted {len(decoded)} strings to mystrings.csv")

# CODE FOR GETTING THE STRINGS OUT OF BINARY AND PRINTING IT IN CSV ENDS HERE

# BELOW CODE IS FOR GETTING SYMBOLS FROM .dynsym AND .symtab USING PREFERRED METHOD

# Load ELF using preferred method
symbol_target = elf.ELFFile.load_from_path(sys.argv[1])
sections = []
for section in symbol_target.iter_sections():
    if section.name == ".dynsym" or section.name == ".symtab":
        sections.append(section)

symbols = []
for section in sections:
    for sym in section.iter_symbols():
        symbols.append(sym.name)

# CODE FOR GETTING SYMBOLS AND STORING THEM IN CSV ENDS HERE

# CODE FOR GETTING LIBRARIES FROM .dynamic SECTION AND ADDING TO FINAL CSV

# Extract .dynamic section for libraries
with open(sys.argv[1], "rb") as f:
    elf_file = ELFFile(f)
    dynamic = elf_file.get_section_by_name('.dynamic')
    if dynamic is not None:
        libraries = [tag.needed for tag in dynamic.iter_tags() if tag.entry.d_tag == 'DT_NEEDED']
    else:
        libraries = []

# BELOW CODE IS FOR STORING STRINGS, SYMBOLS, AND LIBRARIES WITH RESOLVED PATHS INTO A SINGLE CSV FILE

# Get resolved paths using ldd output
    ldd_map = get_ldd_library_paths(sys.argv[1])

    # Combine into one CSV (align shorter lists with empty strings)
    max_len = max(len(decoded), len(symbols), len(libraries))
    decoded += [""] * (max_len - len(decoded))
    symbols += [""] * (max_len - len(symbols))
    libraries += [""] * (max_len - len(libraries))

    with open("elfdata_combined.csv", "w", newline="") as out:
        writer = csv.writer(out)
        writer.writerow(["String", "Symbol", "Library", "LibraryPath"]) # added a new column for resolved path
        for i in range(max_len):
            lib_name = libraries[i]
            resolved_path = ldd_map.get(lib_name, "")
            writer.writerow([decoded[i], symbols[i], lib_name, resolved_path])

    print(f"Combined strings, symbols, libraries and resolved paths written to elfdata_combined.csv")

