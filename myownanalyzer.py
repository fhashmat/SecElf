from elftools.elf.elffile import ELFFile
import re
import csv

# Open your ELF binary
with open("hello", "rb") as f:
    elf = ELFFile(f)

    # Get the .rodata section (where strings live)
    rodata = elf.get_section_by_name('.rodata')

    if rodata is None:
        print("No .rodata section found in this binary.")
        exit()

    # Get the raw bytes from that section
    raw_data = rodata.data()

    # Find all printable strings (ASCII range 32-126, 4+ chars)
    strings = re.findall(rb"[ -~]{4,}", raw_data)

    # Decode bytes to strings
    decoded = [s.decode('utf-8', errors='ignore') for s in strings]

    # Save to CSV
    with open("mystrings.csv", "w", newline="") as out:
        writer = csv.writer(out)
        writer.writerow(["String"])
        for s in decoded:
            writer.writerow([s])

    print(f"Extracted {len(decoded)} strings to mystrings.csv")

