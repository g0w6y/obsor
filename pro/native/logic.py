#!/usr/bin/env python3
"""
Obsor PRO native-logic tier.

Compile a developer-supplied C routine INTO the loader module, so the sensitive
logic ships as machine code and is never reconstructed as a Python code object.
The protected Python payload calls it through an injected module (default name
`obsor_native`); a key-holder can invoke the function as a black box but cannot
read its logic via marshal/settrace/globals -- there is no Python bytecode for
it to recover. This is the only tier that resists a key-holding attacker.

The developer writes standard CPython C functions:

    static PyObject *secret_algo(PyObject *self, PyObject *args) { ... }

and lists their names in `exports`. Everything else (key derivation, decrypt,
the Python payload) works exactly as the native tier.

Design note: to actually protect a gate (e.g. a license check), the native
function must RETURN a value the payload genuinely needs (a decryption key, a
computed result) -- not a bool the Python side can ignore. A black-box boolean
is trivially bypassed by not calling it.
"""
import re

from .build import build_native_loader

_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def build_native_logic(payload_source: str, logic_c: str, exports: list[str],
                       out_py: str, key_mode: str = "pass",
                       passphrase: str | None = None, filename: str = "<obsor>",
                       alias: str = "obsor_native") -> str:
    """Build a native-logic .so + launcher. Returns the .so path."""
    if not exports:
        raise ValueError("native-logic tier needs at least one exported function")
    for name in exports:
        if not _IDENT.match(name):
            raise ValueError(f"invalid C function name: {name!r}")
    if not _IDENT.match(alias):
        raise ValueError(f"invalid alias: {alias!r}")

    extra_methods = "\n".join(
        f'    {{"{n}", {n}, METH_VARARGS, ""}},' for n in exports
    )
    return build_native_loader(
        payload_source, out_py, key_mode=key_mode, passphrase=passphrase,
        filename=filename, extra_funcs=logic_c, extra_methods=extra_methods,
        alias=alias,
    )


if __name__ == "__main__":
    import argparse
    import os
    ap = argparse.ArgumentParser(description="Build an Obsor PRO native-logic loader")
    ap.add_argument("-i", "--input", required=True, help="Python payload")
    ap.add_argument("-c", "--logic", required=True, help="C source with your functions")
    ap.add_argument("-e", "--export", action="append", required=True,
                    help="exported C function name (repeatable)")
    ap.add_argument("-o", "--output", required=True, help="launcher .py")
    ap.add_argument("--key-mode", choices=["pass", "license"], default="pass")
    ap.add_argument("-k", "--key")
    ap.add_argument("--alias", default="obsor_native",
                    help="module name the payload imports to reach the native funcs")
    args = ap.parse_args()
    with open(args.input, encoding="utf-8") as f:
        payload = f.read()
    with open(args.logic, encoding="utf-8") as f:
        logic = f.read()
    so = build_native_logic(payload, logic, args.export, args.output,
                            key_mode=args.key_mode, passphrase=args.key,
                            filename=os.path.basename(args.input), alias=args.alias)
    print("[+] native-logic module:", so)
    print("[+] launcher           :", args.output)
    print(f"    your payload calls: import {args.alias}; {args.alias}.{args.export[0]}(...)")
