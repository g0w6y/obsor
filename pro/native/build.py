#!/usr/bin/env python3
"""
Build an Obsor PRO native loader (.so/.pyd) from source.

Pipeline:
  source.py --(compile+marshal)--> bytecode
            --(scrypt key from external secret + AES-256-GCM)--> blob
            --(embed in C template, compile linking libcrypto)--> loader ext
            --(emit tiny launcher)--> <out>.py  that just imports+runs the ext

The AES key is NOT stored anywhere. It is re-derived in C at runtime from the
OBSOR_KEY / OBSOR_LICENSE environment variable.
"""
import os
import secrets
import subprocess
import sys
import sysconfig
import tempfile

from Crypto.Cipher import AES

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from pro import keyderive  # noqa: E402
from pro.engine import compile_payload  # noqa: E402

_TEMPLATE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "loader_template.c")


def _c_bytes(data: bytes) -> str:
    return ", ".join(str(b) for b in data)


def _find_openssl():
    """Return (include_dir, lib_dir) for libcrypto, or (None, None)."""
    for base in ("/opt/homebrew/opt/openssl@3", "/usr/local/opt/openssl@3",
                 "/usr", "/usr/local"):
        inc = os.path.join(base, "include")
        if os.path.exists(os.path.join(inc, "openssl", "evp.h")):
            for libname in ("lib", "lib64"):
                lib = os.path.join(base, libname)
                if os.path.isdir(lib):
                    return inc, lib
    return None, None


def build_native_loader(source: str, out_py: str, key_mode: str = "pass",
                        passphrase: str | None = None, filename: str = "<obsor>",
                        workdir: str | None = None, extra_funcs: str = "",
                        extra_methods: str = "", alias: str | None = None) -> str:
    """Build a native-loader .so + launcher .py.

    extra_funcs / extra_methods: optional C to splice in (native-logic tier).
    alias: if set, the launcher registers the compiled module under this name in
    sys.modules before running the payload, so the payload can `import <alias>`
    and call the native functions.
    """
    if key_mode not in ("pass", "license"):
        raise ValueError("native loader supports key_mode 'pass' or 'license'")
    key_env = "OBSOR_KEY" if key_mode == "pass" else "OBSOR_LICENSE"

    secret = keyderive.resolve_secret(key_mode, passphrase)
    salt = secrets.token_bytes(16)
    key = keyderive.derive_key(secret, salt)

    payload = compile_payload(source, filename)
    cipher = AES.new(key, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(payload)
    nonce = cipher.nonce

    modname = "obsor_" + secrets.token_hex(6)

    with open(_TEMPLATE) as f:
        csrc = f.read()
    repl = {
        "%%SALT%%": _c_bytes(salt), "%%NONCE%%": _c_bytes(nonce),
        "%%TAG%%": _c_bytes(tag), "%%CT%%": _c_bytes(ct),
        "%%CT_LEN%%": str(len(ct)), "%%KEY_ENV%%": key_env,
        "%%N%%": str(keyderive.SCRYPT_N), "%%R%%": str(keyderive.SCRYPT_R),
        "%%P%%": str(keyderive.SCRYPT_P), "%%MODNAME%%": modname,
        "%%EXTRA_FUNCS%%": extra_funcs, "%%EXTRA_METHODS%%": extra_methods,
    }
    for k, v in repl.items():
        csrc = csrc.replace(k, v)

    out_dir = os.path.dirname(os.path.abspath(out_py))
    os.makedirs(out_dir, exist_ok=True)
    wd = workdir or tempfile.mkdtemp(prefix="obsor_build_")
    c_path = os.path.join(wd, modname + ".c")
    with open(c_path, "w") as f:
        f.write(csrc)

    ext_suffix = sysconfig.get_config_var("EXT_SUFFIX") or ".so"
    so_path = os.path.join(out_dir, modname + ext_suffix)

    py_inc = sysconfig.get_path("include")
    ssl_inc, ssl_lib = _find_openssl()
    cc = os.environ.get("CC", "cc")

    cmd = [cc, "-O2", "-fPIC", "-shared", "-I", py_inc]
    if sys.platform == "darwin":
        cmd += ["-undefined", "dynamic_lookup"]
    if ssl_inc:
        cmd += ["-I", ssl_inc]
    if ssl_lib:
        cmd += ["-L", ssl_lib, "-Wl,-rpath," + ssl_lib]
    cmd += [c_path, "-lcrypto", "-o", so_path]

    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError("native compile failed:\n" + proc.stderr)

    alias_line = f'sys.modules[{alias!r}] = _m\n' if alias else ""
    launcher = f'''#!/usr/bin/env python3
# Obsor PRO native-protected launcher. Logic lives in the compiled module
# {modname}{ext_suffix}; ship BOTH files together (same directory).
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import {modname} as _m
{alias_line}_m.run()
'''
    with open(out_py, "w") as f:
        f.write(launcher)

    return so_path


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Build an Obsor PRO native loader")
    ap.add_argument("-i", "--input", required=True)
    ap.add_argument("-o", "--output", required=True)
    ap.add_argument("--key-mode", choices=["pass", "license"], default="pass")
    ap.add_argument("-k", "--key")
    args = ap.parse_args()
    with open(args.input, encoding="utf-8") as f:
        src = f.read()
    so = build_native_loader(src, args.output, args.key_mode, args.key,
                             filename=os.path.basename(args.input))
    print("[+] native module:", so)
    print("[+] launcher     :", args.output)
