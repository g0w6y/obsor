#!/usr/bin/env python3
"""
Obsor PRO command-line interface.

    python -m pro.cli -i app.py -o dist/app.py --tier native -k "secret"

Tiers:
  hardened : pure-Python, external key + randomized identifiers + bytecode +
             authenticated AES-GCM + anti-tamper guard. One file, no compiler.
  native   : hardened PLUS the final derive/decrypt/eval in a compiled C
             extension, so hooking Python exec/marshal/AES recovers nothing.
             Produces a launcher .py + a platform .so/.pyd (ship both).
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pro import engine  # noqa: E402


def main(argv=None):
    ap = argparse.ArgumentParser(prog="obsor-pro",
                                 description="Obsor PRO - hardened Python protection")
    ap.add_argument("-i", "--input", required=True, help="input .py")
    ap.add_argument("-o", "--output", required=True, help="output .py (launcher)")
    ap.add_argument("--tier", choices=["hardened", "native"], default="hardened")
    ap.add_argument("--key-mode", choices=["pass", "machine", "license"],
                    default="pass", help="how the runtime key is derived")
    ap.add_argument("-k", "--key", help="passphrase / license token (not stored)")
    ap.add_argument("--guard", action="store_true",
                    help="(hardened) add the anti-tamper tripwire; off by default "
                         "because it is bypassable and breaks debuggers/coverage")
    args = ap.parse_args(argv)

    if args.key_mode in ("pass", "license") and not args.key:
        ap.error(f"--key-mode {args.key_mode} requires -k/--key")

    with open(args.input, encoding="utf-8") as f:
        source = f.read()
    fname = os.path.basename(args.input)

    if args.tier == "hardened":
        engine.protect_file(args.input, args.output, key_mode=args.key_mode,
                            passphrase=args.key, guard=args.guard)
        env = "OBSOR_KEY" if args.key_mode != "license" else "OBSOR_LICENSE"
        print(f"[+] hardened artifact: {args.output}")
        if args.key_mode == "machine":
            print("    runs only on THIS host (machine-bound)")
        else:
            print(f"    run with:  {env}=<secret> python {args.output}")
    else:
        if args.key_mode == "machine":
            ap.error("native tier supports --key-mode pass or license")
        from pro.native.build import build_native_loader
        so = build_native_loader(source, args.output, key_mode=args.key_mode,
                                 passphrase=args.key, filename=fname)
        env = "OBSOR_KEY" if args.key_mode == "pass" else "OBSOR_LICENSE"
        print(f"[+] native module  : {so}")
        print(f"[+] launcher       : {args.output}  (ship BOTH files together)")
        print(f"    run with:  {env}=<secret> python {args.output}")


if __name__ == "__main__":
    main()
