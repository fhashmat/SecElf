def stage_a_strings_process(binary_path):
    """
    Extract strings from .rodata and write to a separate CSV.
    """
    with open(binary_path, "rb") as fp:
        elf_file = ELFFile(fp)
        strings = extract_strings(elf_file)

    with open("stagea_strings.csv", "w", newline="") as out:
        writer = csv.writer(out)
        writer.writerow(["String"])
        for s in strings:
            writer.writerow([s])

    print("Extracted strings written to stagea_strings.csv")
