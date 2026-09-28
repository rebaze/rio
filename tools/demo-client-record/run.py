#!/usr/bin/env python3
"""One-command client receipt and partial/unknown case; installed Rio, Python 3.9+."""
import argparse
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", help="installed Rio executable")
    args = parser.parse_args()
    binary = str(Path(shutil.which(args.binary) or args.binary).resolve())
    retained = Path(tempfile.mkdtemp(prefix="rio-client-receipts-"))
    generator = Path(__file__).resolve().parent / "example" / "generate.py"
    for name, flags in (("success", []), ("partial", ["--partial"])):
        subprocess.run([sys.executable, str(generator), binary, str(retained / name), *flags], check=True)
    print("PASS: independent full-pipeline receipts for success and partial/unknown delivery.")
    print("Each run verified exact consumed/submitted bytes, metadata, TLS and receiver references;")
    print("inspection and HTML rendering ran after receiver shutdown and source removal.")
    print("Retained synthetic examples:", retained)


if __name__ == "__main__":
    main()
