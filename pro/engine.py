#!/usr/bin/env python3
"""
Obsor PRO hardened engine (Tier 1, pure Python).

Fixes the structural weaknesses of the classic obsor pipeline:

  * Key is NEVER embedded -- derived at runtime from an external secret
    (passphrase / machine binding / license token) via scrypt.
  * Payload is compiled BYTECODE (marshal), not recoverable source text:
    even a dumped payload has no comments/formatting and needs decompilation.
  * AES-256-GCM is AUTHENTICATED: a wrong key or a tampered blob fails loudly
    instead of running attacker-controlled plaintext.
  * Every identifier in the bootstrap is RANDOMIZED per build, so no two
    outputs share a static signature (no more grep-for `_xor_key`).
  * Optional anti-tamper guard defeats casual trace/dump deobfuscation.

This still has the fundamental ceiling: the payload must become a runnable
code object, so anyone who can run it (e.g. a licensed customer holding the
key) can recover the logic -- via the marshal.loads audit event, sys.settrace,
or the live __main__ globals after it runs. The native loader (pro/native)
only moves the classic `compile`/`exec` hook off the table; it does NOT close
those paths. The real protection here is the external key against someone who
has the file but NOT the key -- i.e. it reduces to passphrase strength.
"""
import base64
import marshal
import os
import secrets
import string

from Crypto.Cipher import AES

from . import keyderive
from .guard import make_guard

_IDCHARS = string.ascii_lowercase


def _rand_id(n: int = 8) -> str:
    return "_" + "".join(secrets.choice(_IDCHARS) for _ in range(n))


def _b85(data: bytes) -> str:
    return base64.b85encode(data).decode("ascii")


def compile_payload(source: str, filename: str = "<obsor>") -> bytes:
    """Compile to a code object and marshal it to bytes (version-locked)."""
    code_obj = compile(source, filename, "exec")
    return marshal.dumps(code_obj)


def protect(
    source: str,
    key_mode: str = "pass",
    passphrase: str | None = None,
    guard: bool = False,
    filename: str = "<obsor>",
) -> str:
    """Return a self-contained protected .py (Tier 1)."""
    secret = keyderive.resolve_secret(key_mode, passphrase)
    salt = secrets.token_bytes(16)
    key = keyderive.derive_key(secret, salt)

    payload = compile_payload(source, filename)

    cipher = AES.new(key, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(payload)
    nonce = cipher.nonce

    # randomized identifiers
    ids = {k: _rand_id() for k in
           ("secret", "salt", "nonce", "tag", "ct", "key", "cip", "pt", "guard")}

    guard_src = make_guard(ids["guard"]) if guard else ""

    boot = f'''#!/usr/bin/env python3
import base64 as _b64, marshal as _msh
from Crypto.Cipher import AES as _AES
{keyderive.RUNTIME_KEYDERIVE}
{guard_src}
{ids["salt"]}  = _b64.b85decode({_b85(salt)!r})
{ids["nonce"]} = _b64.b85decode({_b85(nonce)!r})
{ids["tag"]}   = _b64.b85decode({_b85(tag)!r})
{ids["ct"]}    = _b64.b85decode({_b85(ct)!r})
import os as _os2
{ids["secret"]} = _obsor_secret({key_mode!r}, _os2.environ.get("OBSOR_KEY"), _os2.environ.get("OBSOR_LICENSE"))
{ids["key"]}  = _obsor_derive({ids["secret"]}, {ids["salt"]})
{ids["cip"]}  = _AES.new({ids["key"]}, _AES.MODE_GCM, nonce={ids["nonce"]})
try:
    {ids["pt"]}   = {ids["cip"]}.decrypt_and_verify({ids["ct"]}, {ids["tag"]})
except Exception:
    raise SystemExit(1)
exec(_msh.loads({ids["pt"]}))
'''
    return boot


def protect_file(
    in_path: str,
    out_path: str,
    key_mode: str = "pass",
    passphrase: str | None = None,
    guard: bool = False,
) -> None:
    with open(in_path, "r", encoding="utf-8") as f:
        source = f.read()
    out = protect(source, key_mode=key_mode, passphrase=passphrase,
                  guard=guard, filename=os.path.basename(in_path))
    out_dir = os.path.dirname(os.path.abspath(out_path))
    os.makedirs(out_dir, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(out)
