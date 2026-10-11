#!/usr/bin/env python3
"""
Key derivation for Obsor PRO.

The whole point: the AES key is NEVER written into the protected file.
It is re-derived at runtime from a secret the attacker does not automatically
get just by having the file:

  - "pass"    : a passphrase supplied at runtime via the OBSOR_KEY env var
  - "machine" : bound to the host (hashed machine id) -> file only runs on that box
  - "license" : a license token supplied via OBSOR_LICENSE env var

Derivation is scrypt (memory-hard) so brute forcing a weak passphrase is costly.
Only the salt is stored in the file; the salt is public, the secret is not.
"""
import hashlib
import os
import sys
import uuid

SCRYPT_N = 1 << 17   # 131072  (CPU/memory cost; ~4x the old 2^15)
SCRYPT_R = 8
SCRYPT_P = 1
DKLEN = 32           # AES-256
MAXMEM = 256 * 1024 * 1024  # scrypt working set ~128MB at N=2^17; leave headroom
MIN_SECRET_LEN = 12  # below this, offline brute force is cheap -> warn at build


def _machine_secret() -> bytes:
    """A stable per-host secret. uuid.getnode() = MAC-derived node id.

    Not a cryptographic hardware id -- it is spoofable -- but it binds the
    artifact to a host well enough to stop "copy the file to another box".
    """
    parts = [
        str(uuid.getnode()),
        os.environ.get("HOSTNAME", ""),
        sys.platform,
    ]
    return hashlib.sha256("|".join(parts).encode()).digest()


def _warn_if_weak(secret: str) -> None:
    if len(secret) < MIN_SECRET_LEN:
        print(f"[obsor] WARNING: secret is {len(secret)} chars; use >= "
              f"{MIN_SECRET_LEN} (a passphrase, not a word). A short secret is "
              f"brute-forceable offline despite scrypt.", file=sys.stderr)


def resolve_secret(mode: str, passphrase: str | None = None) -> bytes:
    """Return the raw secret bytes for the given mode (build time)."""
    if mode == "pass":
        if not passphrase:
            raise ValueError("pass mode needs a passphrase (-k/--key)")
        _warn_if_weak(passphrase)
        return passphrase.encode("utf-8")
    if mode == "machine":
        return _machine_secret()
    if mode == "license":
        if not passphrase:
            raise ValueError("license mode needs a token (-k/--key)")
        _warn_if_weak(passphrase)
        return passphrase.encode("utf-8")
    raise ValueError(f"unknown key mode: {mode}")


def derive_key(secret: bytes, salt: bytes) -> bytes:
    return hashlib.scrypt(
        secret, salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P,
        dklen=DKLEN, maxmem=MAXMEM
    )


# The runtime side of the above, emitted into the protected file as source.
# Kept textually identical to the functions above so build and run agree.
RUNTIME_KEYDERIVE = r'''
import hashlib as _hl, os as _os, sys as _sys, uuid as _uuid
def _obsor_machine_secret():
    _p = [str(_uuid.getnode()), _os.environ.get("HOSTNAME",""), _sys.platform]
    return _hl.sha256("|".join(_p).encode()).digest()
def _obsor_secret(_mode, _envpass, _envlic):
    if _mode == "pass":
        if not _envpass: raise SystemExit("OBSOR_KEY not set")
        return _envpass.encode("utf-8")
    if _mode == "machine":
        return _obsor_machine_secret()
    if _mode == "license":
        if not _envlic: raise SystemExit("OBSOR_LICENSE not set")
        return _envlic.encode("utf-8")
    raise SystemExit("bad key mode")
def _obsor_derive(_secret, _salt):
    return _hl.scrypt(_secret, salt=_salt, n=%(N)d, r=%(R)d, p=%(P)d, dklen=%(DK)d, maxmem=%(MM)d)
''' % {"N": SCRYPT_N, "R": SCRYPT_R, "P": SCRYPT_P, "DK": DKLEN, "MM": MAXMEM}
