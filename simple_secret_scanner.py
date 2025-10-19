#!/usr/bin/env python3
# simple_secret_scanner.py
# Very simple CLI secret scanner (beginner style)

import os
import re
import argparse
import logging
import sys

# Basic logging setup
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

# A few simple regex patterns (at least 5). Beginner-style: plain dict of compiled regexes.
PATTERNS = {
    "AWS Access Key ID": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "Google API Key": re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    "GitHub PAT": re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),
    "Private Key Header": re.compile(r"-----BEGIN (RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----"),
    "Generic token/secret assignment": re.compile(r"(?i)(api[_-]?key|secret|token)['\"\s:=]+([A-Za-z0-9\-_.]{8,100})"),
    # Simple JWT-like pattern
    "JWT-like token": re.compile(r"\beyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.?[A-Za-z0-9-_.+/=]*\b"),
}

# Scan a single file
def scan_file(path):
    findings = []
    try:
        f = open(path, "r", encoding="utf-8", errors="ignore")
    except Exception as e:
        logging.warning("Can't open file: %s (%s)", path, e)
        return findings

    with f:
        line_no = 0
        for line in f:
            line_no += 1
            for name, regex in PATTERNS.items():
                m = regex.search(line)
                if m:
                    findings.append((path, line_no, name, m.group(0)))
    return findings

# If path is dir, walk it. If file, scan it.
def scan_path(path):
    all_findings = []
    if os.path.isdir(path):
        for root, dirs, files in os.walk(path):
            if ".git" in dirs:
                dirs.remove(".git")
            if "__pycache__" in dirs:
                dirs.remove("__pycache__")
            for fn in files:
                full = os.path.join(root, fn)
                all_findings.extend(scan_file(full))
    elif os.path.isfile(path):
        all_findings.extend(scan_file(path))
    else:
        logging.error("Path is not a file or directory: %s", path)
    return all_findings

# Print report
def print_report(findings):
    if not findings:
        print("No possible secrets found.")
        return
    print("Found possible secrets:")
    for item in findings:
        path, line_no, patt_name, matched = item
        print(f"{path} : line {line_no} : {patt_name} => {matched}")

# Main CLI
def main():
    parser = argparse.ArgumentParser(description="Simple secret scanner (beginner style).")
    parser.add_argument("target", help="File or directory to scan")
    parser.add_argument("-v", "--verbose", action="store_true", help="More logging")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    logging.info("Starting scan: %s", args.target)
    findings = scan_path(args.target)
    logging.info("Scan complete.")
    print_report(findings)

if __name__ == "__main__":
    main()
