<h1 align="center">
  <img src="https://github.com/user-attachments/assets/bad7edad-e5f6-4f28-9fab-5722a173f6ab" alt="Obsor" width="420">
</h1>

<p align="center">
  <b>Multi-layer Python obfuscation / packing toolkit</b><br>
  23 encode &amp; cipher techniques · Preset profiles · Executable builder · PRO external-key mode
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python&logoColor=white">
  <img src="https://img.shields.io/github/license/g0w6y/obsor?style=flat-square&color=green">
  <img src="https://img.shields.io/github/stars/g0w6y/obsor?style=flat-square&color=yellow">
  <img src="https://img.shields.io/github/last-commit/g0w6y/obsor?style=flat-square&color=blue">
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey?style=flat-square">
</p>

---

## What is Obsor?

Obsor is an open-source Python obfuscation / packing toolkit with two engines:

- **Classic (`main.py`)** — layers 23 encoding and cipher techniques to deter *casual* copying. Be clear-eyed about what this is: **obfuscation, not a security boundary.** The layers unwrap themselves at runtime, and for the cipher methods the key is embedded in the output, so a single hook recovers the source. Good for raising the bar against copy-paste and lazy scanners; not protection against anyone who can run the file.
- **PRO (`pro/`)** — a real external-key boundary: the key is never stored (re-derived at runtime via scrypt), the payload is authenticated with AES-256-GCM, identifiers are randomized per build, and a native C loader defeats the classic one-line hook. Read [`pro/README.md`](pro/README.md) for exactly what it does and does not protect — including honest, measured limits against a key-holding attacker.

It also includes preset profiles, standalone executable building, and built-in self-testing.

---

## Features

| Category | Techniques |
|---|---|
| **Encoding** | Base64, Base32, Base85, Hex, Octal, URL, UUEncode, Charcode |
| **Encryption** | AES-256-CBC, XOR, RC4, Vigenère, Caesar, Atbash, Polybius |
| **Compression** | zlib (DEFLATE), bz2 (BZIP2) |
| **Bytecode** | Marshal serialization |
| **Transform** | Minify, Reverse, Split, Whitespace encoding, ROT13 |

- Multi-layer stacking (unlimited depth)
- Automatic random key generation
- Optional custom keys
- 4 built-in preset profiles
- PyInstaller executable builder
- Built-in obfuscated script self-test
- Colored CLI with progress animation

---

## Installation

```bash
git clone https://github.com/g0w6y/obsor
cd obsor
python3 -m venv .venv && source .venv/bin/activate   # recommended
pip install -r requirements.txt
```

On macOS/many Linux distros the interpreter is `python3` (and `pip3`); on a
system-managed Python you need the venv above to avoid `externally-managed-environment`.
The examples below use `python` — read it as whatever runs your interpreter.

**Requirements:** Python 3.10+ (PRO uses `X | None` type hints; the `uu` method needs < 3.13; PRO native needs a C compiler + OpenSSL)

Dependencies (`requirements.txt`):
- `pycryptodome` — required for the classic `aes` method and all of PRO
- `colorama` — colored terminal output (degrades gracefully if absent)
- `pyinstaller` — only for `--build-exe`

---

## Quick Start

```bash
# Basic obfuscation
python main.py -i script.py -o protected.py -m base64,zlib

# Use a preset
python main.py -i script.py --preset military

# Test that obfuscated output still works
python main.py -i script.py --preset max --test

# Build a standalone executable
python main.py -i script.py --preset military --build-exe
```

---

## Preset Profiles

| Preset | Pipeline | Use Case |
|---|---|---|
| `military` | `minify → aes → zlib → base85 → split → reverse → marshal → vigenere` | Heaviest layering (still reversible with one hook — not real protection; use `pro/` for a key boundary) |
| `max` | `minify → aes → marshal → bz2 → base64 → xor → whitespace → rc4` | Heavy layering (reversible) |
| `stealth` | `whitespace → split → charcode → hex → url` | Bulk encodings to slow static scanners |
| `light` | `base64 → reverse` | Quick / lightweight |

```bash
python main.py -i script.py --preset military
python main.py -i script.py --preset stealth
python main.py -i script.py --preset light
```

---

## CLI Reference

```
python main.py [-h]
    -i INPUT                     Input Python script
    [-o OUTPUT]                  Output file (default: obfuscated.py)
    [-m METHODS]                 Comma-separated methods (e.g. aes,base64,zlib)
    [--preset {military,max,light,stealth}]
    [-k KEY]                     Custom key for supported methods
    [--chunk-size CHUNK_SIZE]    Chunk size for split method
    [--list-methods]             List all available obfuscation methods
    [--build-exe]                Build standalone executable via PyInstaller
    [--exe-onefile]              Single-file executable
    [--exe-console]              Console mode executable
    [--exe-icon EXE_ICON]        Icon file for executable
    [--test]                     Run and verify the obfuscated output
    [--save-keys]                Save generated keys to a file
```

---

## Examples

See [`examples/`](examples/) for ready-to-use sample scripts.

```bash
# Try obsor on the included sample script
python main.py -i examples/sample_input.py --preset military --test

# AES with a custom key
python main.py -i examples/sample_input.py -m aes,base85 -k "MySecretKey123"

# Save keys + build exe
python main.py -i examples/sample_input.py --preset max --build-exe --save-keys
```

The file `obsor.py` in the root is a sample of what Obsor produces (an earlier `main.py` run through the `military` preset).

---

## Project Structure

```
obsor/
├── main.py               # Classic obfuscation engine + CLI
├── obsor.py              # sample obfuscated output (military preset demo)
├── pro/                  # PRO engine (external-key, native loader)
│   ├── cli.py            # python -m pro.cli
│   ├── engine.py         # hardened tier
│   ├── keyderive.py      # scrypt key derivation (key never stored)
│   ├── guard.py          # optional anti-tamper tripwire
│   ├── selftest.py       # python -m pro.selftest
│   ├── native/           # native + native-logic tiers (C loader)
│   └── README.md         # PRO docs + honest threat model
├── examples/
│   ├── sample_input.py   # sample script for testing
│   ├── native_logic/     # native-logic tier example (secret.c + app.py)
│   └── README.md         # example usage guide
├── requirements.txt
├── README.md
├── LICENSE               # Apache 2.0
└── NOTICE
```

---

## Cross-Platform Notes

- Classic and PRO **hardened** run anywhere Python does (Windows, macOS, Linux)
- PRO **native** / **native-logic** build on macOS and Linux only (clang + OpenSSL); no Windows/MSVC path yet
- The PRO native `.so` is bound to the build host's CPython minor version and its OpenSSL — build and run on a matching machine
- Generated executables (`--build-exe`) are OS-specific (build on the target OS)
- `marshal` output is Python version-dependent — obfuscate and run on the same Python version
- AES (classic `aes` and all PRO) requires `pycryptodome` on the machine running the output

---

## Contributing

Contributions, issues, and feature requests are welcome.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes (`git commit -m 'Add: my feature'`)
4. Push to the branch (`git push origin feature/my-feature`)
5. Open a Pull Request

---

## Disclaimer

This tool is intended for **educational purposes, security research, and legitimate code protection only.**

Do **not** use Obsor to distribute malware, bypass security systems, or for any illegal activity. The author is not responsible for misuse.

---

## License

Licensed under the [Apache License 2.0](LICENSE).

Built by [g0w6y](https://github.com/g0w6y)
