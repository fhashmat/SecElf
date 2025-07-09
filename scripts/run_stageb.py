##!/usr/bin/env python3

#import sys
#from secelf.stage_b import resolve_library_packages, write_resolved_packages

#def main():
    # In the future you might pass a custom CSV, but for now use default
   # input_csv = "lib_analysis_dummy_binary.csv"  # or whatever your Stage A output is called

    # run stage B
 #   results = resolve_library_packages(input_csv)
  #  write_resolved_packages(results)

   # print("Stage B completed: Resolved packages written to library_packages.csv")

#if __name__ == "__main__":
 #   main()
#!/usr/bin/env python3

# Minimal CLI wrapper that calls the script directly
exec(open("src/secelf/stage_b.py").read())
