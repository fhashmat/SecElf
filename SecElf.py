#This is a tool which can be used to analyze elf binaries and sort their data of interest in CSV format.
#A Python file (elffile.py) inside elf, which defines the ELFFile class
from elftools.elf.elffile import ELFFile 
import re #for searching patterns in a file
import csv #for storing the data in the csv format
import sys #for getting the file name from the command line

# if the filename given by the user is not valid then we written certain statement for guidance to enter the correct name.
if len(sys.argv) < 2:
    print("Usage:python3 SecElf.py <filename>")
    sys.exit(1) 

# here we are getting the file name as a parameter from the user of this tool.
with open(sys.argv[1], "rb") as f:
    elf = ELFFile(f)

 #BELOW CODE IS FOR GETTING THE STRINGS OUT OF BINARY
    # Get the .rodata section where we have strings.
    rodata = elf.get_section_by_name('.rodata')

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

# BELOW CODE IS FOR GETTING SYMBOLS FROM .symtab SECTION
with open(sys.argv[1], "rb") as f:
    elf = ELFFile(f)

    # Access the symbol table
    symtab = elf.get_section_by_name('.symtab')

    if symtab is None:
        print("No .symtab section found in this binary.")
        symbols = []
    else:
        symbols = [symbol.name for symbol in symtab.iter_symbols() if symbol.name]

# CODE FOR GETTING SYMBOLS AND STORING THEM IN CSV ENDS HERE

# CODE FOR GETTING LIBRARIES FROM .dynamic SECTION AND ADDING TO FINAL CSV

# Extract .dynamic section for libraries
with open(sys.argv[1], "rb") as f:
    elf = ELFFile(f)
    dynamic = elf.get_section_by_name('.dynamic')
    if dynamic is not None:
        libraries = [tag.needed for tag in dynamic.iter_tags() if tag.entry.d_tag == 'DT_NEEDED']
    else:
        libraries = []

# Combine all 3 columns: decoded (strings), symbols, libraries
max_len = max(len(decoded), len(symbols), len(libraries))
decoded += [""] * (max_len - len(decoded))
symbols += [""] * (max_len - len(symbols))
libraries += [""] * (max_len - len(libraries))

# Write final CSV
with open("elfdata_combined.csv", "w", newline="") as out:
    writer = csv.writer(out)
    writer.writerow(["String", "Symbol", "Library"])
    for i in range(max_len):
        writer.writerow([decoded[i], symbols[i], libraries[i]])

print(f"Combined strings, symbols, and libraries written to elfdata_combined.csv")
