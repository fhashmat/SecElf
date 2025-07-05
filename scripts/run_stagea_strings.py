#!/usr/bin/env python3
import sys
from secelf.stage_a_strings import stage_a_strings_process

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 run_stagea_strings.py <path_to_binary>")
        sys.exit(1)
    binary_path = sys.argv[1]
    stage_a_strings_process(binary_path)

if __name__ == "__main__":
    main()
