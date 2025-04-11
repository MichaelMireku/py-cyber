#!/usr/bin/python3
import sys
import hashlib
import datetime
import argparse
from pathlib import Path
from colorama import Fore, init
from time import time
from tqdm import tqdm

# Initialize colorama
init(autoreset=True)
LINE_CLEAR = '\x1b[2K'

# Supported hash algorithms
HASH_FUNCTIONS = {
    'md5': hashlib.md5,
    'sha1': hashlib.sha1,
    'sha224': hashlib.sha224,
    'sha256': hashlib.sha256,
    'sha384': hashlib.sha384,
    'sha512': hashlib.sha512
}

def banner(hash_value, hash_func):
    """Prints startup banner with metadata."""
    print(Fore.CYAN + """
    █▀█ █▄█ ▀█▀ █░█ █▀█ █▄░█   █▀▀ █▀█ █▀█   █░█ █░█ █▀▀ █▄▀ █▀█ █▀
    █▀▀ ░█░ ░█░ █▀█ █▄█ █░▀█   █▀░ █▄█ █▀▄   █▀█ ▀▀█ █▄▄ █░█ █▀▄ ▄█

                                            𝖌𝖎𝖙𝖍𝖚𝖇 𝕸𝖎𝖈𝖍𝖆𝖊𝖑𝕸𝖎𝖗𝖊𝖐𝖚
    """)
    print(Fore.CYAN + "-"*67)
    print(f"""
                    {Fore.YELLOW}Ｈａｓｈ C r a c k eｒ\n
        {Fore.WHITE}START_TIME: {datetime.datetime.ctime(datetime.datetime.now())}
        {Fore.WHITE}Hash:       {hash_value}
        {Fore.WHITE}Hash Type:  {hash_func.__name__}
        """)
    print(Fore.CYAN + "-"*67)


def is_hex(s):
    """Basic hex string validator."""
    return all(c in '0123456789abcdefABCDEF' for c in s)


def count_lines(filepath):
    """Counts lines in a file efficiently without reading all content."""
    with open(filepath, 'rb') as f:
        return sum(1 for _ in f)


def hash_cracker(hash_value, hash_type_str, wordlist_path=None, ignore_case=False, verbose=False, save_result=False):
    if not is_hex(hash_value):
        print(Fore.RED + f"[!] Error: Invalid hex string.", file=sys.stderr)
        sys.exit(1)

    hash_func = HASH_FUNCTIONS.get(hash_type_str.lower())
    if not hash_func:
        print(Fore.RED + f"[!] Unsupported hash type: {hash_type_str}", file=sys.stderr)
        sys.exit(1)

    wordlist_path = Path(wordlist_path or "password.txt")
    if not wordlist_path.is_file():
        print(Fore.RED + f"[!] Wordlist file not found: {wordlist_path}", file=sys.stderr)
        sys.exit(1)

    banner(hash_value, hash_func)

    found = False
    tested = 0
    start = time()
    total_lines = count_lines(wordlist_path)

    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as wordlist:
            with tqdm(total=total_lines, desc="Progress", ncols=75) as pbar:
                for password in wordlist:
                    password = password.strip()
                    tested += 1
                    pbar.update(1)

                    if not password:
                        continue

                    try:
                        line_hash = hash_func(password.encode('utf-8')).hexdigest()
                    except UnicodeEncodeError:
                        if verbose:
                            print(Fore.YELLOW + f"[!] Skipped encoding issue: {password[:30]}")
                        continue

                    compare_target = hash_value.lower() if ignore_case else hash_value
                    if line_hash == compare_target:
                        print(Fore.GREEN + f"\n[+] Match Found on line {tested}: {password}")
                        if save_result:
                            with open("cracked.txt", "w") as f:
                                f.write(f"{password}\n")
                            print(Fore.CYAN + f"[+] Saved to cracked.txt")
                        found = True
                        break

        if not found:
            print(Fore.YELLOW + f"[-] Not found after {tested} entries.")

    except KeyboardInterrupt:
        print(Fore.LIGHTCYAN_EX + "\n[~] Interrupted by user.")
    except Exception as e:
        print(Fore.RED + f"[!] Unexpected error: {e}", file=sys.stderr)

    end = time()
    duration = end - start
    print(Fore.WHITE + f"\nEND_TIME: {datetime.datetime.ctime(datetime.datetime.now())}")
    print(Fore.WHITE + f"Duration: {datetime.timedelta(seconds=round(duration))}")
    print(Fore.WHITE + f"Total Tried: {tested}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Advanced Hash Cracker (Michael Mireku)", add_help=False)
    ap.add_argument('-h', '--hash', dest='hash_value', required=True, help="Target hash (hex).")
    ap.add_argument('-t', '--type', dest='hash_type', required=True, help=f"Hash type. Options: {', '.join(HASH_FUNCTIONS.keys())}")
    ap.add_argument('-w', '--wordlist', type=Path, dest='wordlist_path', help="Wordlist file path (default: password.txt)")
    ap.add_argument('-i', '--info', action='help', default=argparse.SUPPRESS, help="Show this help message.")
    ap.add_argument('--ignore-case', action='store_true', help="Ignore case when comparing hashes.")
    ap.add_argument('--verbose', action='store_true', help="Show skipped/invalid lines.")
    ap.add_argument('--save', action='store_true', help="Save cracked password to 'cracked.txt'.")

    args = ap.parse_args()

    start_time = datetime.datetime.now()
    hash_cracker(args.hash_value, args.hash_type, args.wordlist_path, args.ignore_case, args.verbose, args.save)
