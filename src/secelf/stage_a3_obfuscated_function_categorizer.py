# ---------------------------------------------------------------
# stage_a3_obfuscated_function_categorizer.py
#
# Context:
#   Stage A3 will analyze extracted functions from Stage A2
#   and attempt to categorize whether they appear obfuscated,
#   crypto-related, or cleartext, using simple heuristics.
#
# Flow:
#   1. Read functions_stageA2.csv
#   2. Apply heuristics to guess obfuscation category
#   3. Save categorized results in functions_stageA3_obfuscated.csv
#
# ---------------------------------------------------------------
import csv
import re
import os
import math
from typing import Tuple, List

# ---------------------------------------------------------------
# _WORDY_PATTERNS
#
# Purpose:
#   Some function names are very "generic" (e.g., "open", "read"),
#   and may appear as substrings inside unrelated words
#   (e.g., "fopen", "breadth", "writer"). To avoid false matches,
#   we use regex patterns with word-boundary-like checks.
#
# Pattern logic:
#   - (?<![A-Za-z0-9])   ensures the keyword is NOT immediately
#                         preceded by a letter or digit.
#                         (prevents matching "fopen" for "open")
#
#   - (?![A-Za-z0-9])    ensures the keyword is NOT immediately
#                         followed by a letter or digit.
#                         (prevents matching "writer" for "write")
#
# Together: match the keyword ONLY when it appears standalone
#           in a function name (or separated by symbols like '_').
# ---------------------------------------------------------------
_WORDY_PATTERNS = {
    # ------------------------------
    # FILE operations
    # ------------------------------
    "open":  re.compile(r'(?<![A-Za-z0-9])open(?![A-Za-z0-9])'),
    # Matches "open" but not "fopen" or "opened"
    
    "read":  re.compile(r'(?<![A-Za-z0-9])read(?![A-Za-z0-9])'),
    # Matches "read" but not "breadth" or "fread"
    
    "write": re.compile(r'(?<![A-Za-z0-9])write(?![A-Za-z0-9])'),
    # Matches "write" but not "overwrite" or "fwrite"
    
    "close": re.compile(r'(?<![A-Za-z0-9])close(?![A-Za-z0-9])'),
    # Matches "close" but not "enclose" or "fclose"
    
    # ------------------------------
    # MATH operations
    # ------------------------------
    "log":   re.compile(r'(?<![A-Za-z0-9])log(?![A-Za-z0-9])'),
    # Matches "log" but not "logout" or "ilogb"
    
    # ------------------------------
    # PROCESS operations
    # ------------------------------
    "clone": re.compile(r'(?<![A-Za-z0-9])clone(?![A-Za-z0-9])'),
    # Matches "clone" but not "cyclone"
    
    # ------------------------------
    # CRYPTO operations
    # ------------------------------
    "des":   re.compile(r'(?<![A-Za-z0-9])des(?![A-Za-z0-9])'),
    # Matches "des" (Data Encryption Standard) but not "design"
    
    "curve": re.compile(r'(?<![A-Za-z0-9])curve(?![A-Za-z0-9])'),
    # Matches "curve" (used in crypto like curve25519) but not "curved"
}


# Where A2 wrote its file:
A2_ROOT = "stageAfuncs"
# Where A3 will write:
A3_ROOT = "stageA3"

# ---------------------------------------------------------------
# Quick detectors for obfuscation
#
# Purpose:
#   These are lightweight heuristics we use to "flag" functions
#   that look suspicious (obfuscated, crypto-related, or mangled).
#   Instead of heavy analysis, we just check names for telltale
#   prefixes or keywords.
# ---------------------------------------------------------------

# ---------------------------------------------------------------
# Mangled Prefixes
#
# "_Z" and "__Z" are special markers used by the
# Itanium C++ ABI (Application Binary Interface).
#
# Example:
#   _Z7encryptPKc → demangles to encrypt(const char*)
#
# Why it matters:
#   - If a function starts with "_Z", it means the compiler
#     encoded its name (C++ mangling).
#   - These are *not necessarily malicious*, but they indicate
#     complexity/obfuscation, since the raw symbol is unreadable.
# ---------------------------------------------------------------
_MANGLED_PREFIXES = ["_Z", "__Z"]

# ---------------------------------------------------------------
# Crypto-related keywords
#
# This list captures common terms used in cryptographic functions.
# If a function name contains one of these substrings (case-insensitive),
# we tentatively classify it as "crypto-related".
#
# Examples:
#   - "sha256_transform" → matches "sha256"
#   - "EVP_aes_128_gcm"  → matches "aes"
#   - "curve25519_scalar"→ matches "curve"
#
# Why it matters:
#   - Cryptographic functions are high-value targets for attackers.
#   - Even obfuscated binaries often leave crypto-related names visible.
# ---------------------------------------------------------------
_CRYPTO_KEYWORDS = [
    # Hash algorithms
    "sha","sha1","sha256","sha3","md5","ripemd","blake","skein",
    # Block ciphers
    "aes","des","chacha","poly1305",
    # MACs
    "hmac","cmac",
    # Generic crypto terms
    "cipher","encrypt","decrypt","kdf","pbkdf",
    # Public-key algorithms
    "rsa","ecdsa","curve","x25519"
]


# ---------------------------------------------------------------
# Function type keyword buckets (name-based)
#
# Purpose:
#   Group function names into broad categories (crypto, net, file, etc.)
#   by scanning for common substrings/keywords.
#
#   This helps us quickly understand the *role* of a function,
#   even if it's not obfuscated.
#
# Logic:
#   - Iterate over each bucket (e.g., "crypto", "net").
#   - If a function name contains any keyword in that bucket,
#     classify it as belonging to that type.
#   - A function can belong to multiple buckets
#     (e.g., "ssl_socket_send" → net + crypto).
# ---------------------------------------------------------------
TYPE_RULES = {
    # -----------------------------
    # Cryptographic algorithms
    # -----------------------------
    # Includes hash functions, block ciphers, stream ciphers,
    # MAC algorithms, and public-key crypto.
    "crypto": [
        "sha","sha1","sha256","sha3","aes","des","chacha","poly1305",
        "md5","ripemd","blake","hmac","cmac","cipher","encrypt","decrypt",
        "kdf","pbkdf","rsa","ecdsa","curve","x25519"
    ],

    # -----------------------------
    # Networking
    # -----------------------------
    # Functions related to sockets, connections, and protocols.
    # Covers both low-level (bind, recv) and higher-level (http, ssl).
    "net": [
        "socket","connect","accept","recv","send","bind","listen",
        "http","tcp","udp","ssl","tls","getaddrinfo","select","epoll","poll"
    ],

    # -----------------------------
    # File operations
    # -----------------------------
    # Standard file I/O functions across C/POSIX.
    "file": [
        "open","read","write","close","stat","fopen","fread","fwrite",
        "fclose","unlink","rename","mkdir","mmap","fsync"
    ],

    # -----------------------------
    # String manipulation
    # -----------------------------
    # Classic C string and memory operations.
    "string": [
        "strcpy","strncpy","strcat","strcmp","strlen","strstr",
        "memcpy","memmove","memset","strtok","sprintf","snprintf"
    ],

    # -----------------------------
    # Math operations
    # -----------------------------
    # Common math library calls, including basic trig/log
    # and FFT (signal processing).
    "math": [
        "sin","cos","tan","sqrt","pow","exp","log","fabs",
        "atan","ceil","floor","fft"
    ],

    # -----------------------------
    # Threading / concurrency
    # -----------------------------
    # pthreads and synchronization primitives.
    "thread": [
        "pthread","thread","mutex","lock","unlock","cond","sem",
        "barrier","atomic"
    ],

    # -----------------------------
    # Process management
    # -----------------------------
    # Process creation, signals, and tracing.
    "proc": [
        "fork","exec","wait","pipe","kill","ptrace","clone"
    ],

    # -----------------------------
    # Time functions
    # -----------------------------
    # System time and sleep functions.
    "time": [
        "clock","time","sleep","nanosleep","gettimeofday"
    ],

    # -----------------------------
    # System-level calls
    # -----------------------------
    # Direct system interaction and identity management.
    "sys": [
        "ioctl","syscall","prctl","uname",
        "getuid","setuid","getpid","gettid"
    ],

    # -----------------------------
    # Memory allocation
    # -----------------------------
    # Covers both C and C++ allocators.
    "alloc": [
        "malloc","free","new","delete","realloc","calloc",
        "operator new","operator delete"
    ],

    # -----------------------------
    # C++ STL (Standard Template Library)
    # -----------------------------
    # Identifiers used in demangled C++ function names.
    "stl": [
        "std::","basic_string","vector","deque","list","map",
        "unordered_","shared_ptr","unique_ptr"
    ],
}


def _shannon_entropy(s: str) -> float:
    """
    Compute the Shannon entropy of a string.
    
    Purpose:
      - Entropy measures how "unpredictable" or "random" a string is.
      - Low entropy → readable/structured (e.g., "main", "open_file").
      - High entropy → random/obfuscated (e.g., "aB9xZQ12...").
    
    Inputs:
      s (str): Function name string.
    
    Returns:
      float: Entropy value (bits per character).
             Higher = more randomness.
    """
    # -----------------------------------------------------------
    # Edge case: if string is empty, entropy is 0
    # -----------------------------------------------------------
    if not s:
        return 0.0

    # -----------------------------------------------------------
    # Step 1: Keep only visible ASCII chars (codes 32–126)
    #         This strips control characters, nulls, etc.
    #         → prevents noise from skewing entropy.
    # -----------------------------------------------------------
    s = "".join(ch for ch in s if 32 <= ord(ch) < 127)

    # If nothing left after filtering → entropy = 0
    if not s:
        return 0.0

    # -----------------------------------------------------------
    # Step 2: Count frequency of each character
    # -----------------------------------------------------------
    from collections import Counter
    n = len(s)                   # total characters
    counts = Counter(s).values() # frequency of each unique char

    # -----------------------------------------------------------
    # Step 3: Shannon entropy formula
    #   H = - Σ (p * log2(p))
    #   where p = probability of each character
    #
    # Example:
    #   "aaa" → entropy = 0 (all same char)
    #   "abc" → entropy = ~1.58 (uniform distribution)
    #   long random string → closer to ~5-6
    # -----------------------------------------------------------
    return -sum((c/n) * math.log2(c/n) for c in counts)

# Back-compat wrapper: old code expects categorize_function(name) -> "category"
def categorize_function(name: str) -> str:
    cat, _score, _reason = categorize_obfuscation(name)
    return cat

def categorize_obfuscation(name: str) -> Tuple[str, float, str]:
    if not name:
        return ("unknown", 0.0, "empty-name")

    n = name.strip()
    low = n.lower()

    # C++ mangled?
    if any(n.startswith(p) for p in _MANGLED_PREFIXES):
        return ("mangled", 0.90, "c++-mangled-prefix")

    # crypto-related (by name)
    if any(k in low for k in _CRYPTO_KEYWORDS):
        return ("crypto-related", 0.85, "keyword-match")

    # very short/opaque
    if len(n) <= 2:
        return ("suspicious", 0.60, "very-short-name")

    # long alnum with few vowels + high entropy
    alnum = re.sub(r"[^A-Za-z0-9]", "", n)
    if len(alnum) >= 24:
        vowel_ratio = sum(ch in "aeiouAEIOU" for ch in alnum) / max(1, len(alnum))
        ent = _shannon_entropy(alnum)
        if vowel_ratio < 0.15 and ent >= 4.0:
            return ("suspicious", 0.80, f"high-entropy:{ent:.2f},low-vowel:{vowel_ratio:.2f}")

    # long name with high entropy
    if len(n) >= 32 and _shannon_entropy(n) >= 4.2:
        return ("suspicious", 0.70, "high-entropy")

    return ("cleartext", 0.10, "default-cleartext")

def classify_function_types(name: str) -> Tuple[str, str]:
    """
    Returns:
      labels:  'crypto;net;file' (may be empty)
      reason:  'crypto:sha256;net:socket' (which keyword hit)
    """
    if not name:
        return ("", "")
    low = name.lower()
    labels, reasons = [], []

    for bucket, keys in TYPE_RULES.items():
        matched = False
        for k in keys:
            # Prefer regex if we have a wordy pattern for this key
            pat = _WORDY_PATTERNS.get(k)
            if pat:
                if pat.search(low):
                    matched = True
                    reasons.append(f"{bucket}:{k}")
                    break
            else:
                if k in low:
                    matched = True
                    reasons.append(f"{bucket}:{k}")
                    break
        if matched:
            labels.append(bucket)

    return (";".join(labels), ";".join(reasons))


def _a2_csv_path(binary_path: str) -> str:
    binary = os.path.basename(binary_path)
    tool   = os.path.splitext(binary)[0]
    return os.path.join(A2_ROOT, tool, f"functions_extracted_{binary}.csv"), tool, binary

def load_a2_rows(binary_path: str) -> List[dict]:
    in_csv, tool, binary = _a2_csv_path(binary_path)
    with open(in_csv, "r", newline="") as f:
        return list(csv.DictReader(f))

def enrich_rows_with_categories(rows: List[dict]) -> List[dict]:
    out = []
    for r in rows:
        dm = (r.get("DemangledName") or "").strip()
        raw = (r.get("FunctionName") or "").strip()
        name = dm or raw  # prefer demangled

        ob_cat, ob_score, ob_reason = categorize_obfuscation(name)
        ftype, treason = classify_function_types(name)

        rr = dict(r)
        rr["ObfuscationCategory"] = ob_cat
        rr["ObfuscationScore"] = f"{ob_score:.2f}"
        rr["ObfuscationReason"] = ob_reason
        rr["FunctionType"] = ftype
        rr["TypeReason"] = treason
        out.append(rr)
    return out

def _a3_csv_path(tool: str, binary: str) -> str:
    return os.path.join(A3_ROOT, tool, f"functions_obfuscated_{binary}.csv")

def write_a3_csv(rows: List[dict], out_csv: str):
    base = ["FunctionName","DemangledName","Address","Size","SectionIndex","SymbolType","Obfuscated"]
    extra = ["ObfuscationCategory","ObfuscationScore","ObfuscationReason","FunctionType","TypeReason"]
    header = base + extra
    os.makedirs(os.path.dirname(out_csv), exist_ok=True)
    with open(out_csv, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=header)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in header})
# ---------------------------------------------------------------
# stage_a3_process()
#
# Reads Stage A2 CSV for a given binary and writes a categorized
# CSV under stageA3/<tool>/functions_obfuscated_<binary>.csv
# ---------------------------------------------------------------
def stage_a3_process(binary_path: str):
    binary_name = os.path.basename(binary_path)            # e.g., "dummy_binary"
    tool_name   = os.path.splitext(binary_name)[0]         # e.g., "dummy_binary"

    in_csv  = os.path.join("stageAfuncs", tool_name, f"functions_extracted_{binary_name}.csv")
    out_dir = os.path.join("stageA3", tool_name)
    os.makedirs(out_dir, exist_ok=True)
    out_csv = os.path.join(out_dir, f"functions_obfuscated_{binary_name}.csv")

    # Load A2 rows (produced by Stage A2)
    try:
        with open(in_csv, "r", newline="") as f:
            rows = list(csv.DictReader(f))
    except FileNotFoundError:
        print(f"ERROR: Stage A2 CSV not found: {in_csv}")
        return

    # Build the minimal obfuscation list using your existing categorizer
    obf_rows = []
    for r in rows:
        # Prefer demangled; fallback to raw
        name = (r.get("DemangledName") or r.get("FunctionName") or "").strip()
        cat  = categorize_function(name)
        obf_rows.append({"FunctionName": name, "ObfuscationCategory": cat})

        # Build enriched rows
    obf_rows = enrich_rows_with_categories(rows)

    # Write with the new writer
    write_a3_csv(obf_rows, out_csv)
    print(f"[A3] Wrote: {out_csv}")

