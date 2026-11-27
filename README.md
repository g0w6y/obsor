<h1 align="center">
  <img src="https://github.com/user-attachments/assets/bad7edad-e5f6-4f28-9fab-5722a173f6ab" alt="Obsor" width="420">
</h1>

<p align="center">
  <b>Multi-layer, multi-language obfuscation / packing toolkit</b><br>
  Python · JavaScript · .NET · Java · PRO external-key mode, honestly measured against this repo's own output
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

Obsor is an open-source obfuscation / packing toolkit spanning four
languages, each with the same two-engine shape:

- **Classic** — layers 20+ encoding and cipher techniques to deter *casual*
  copying. Be clear-eyed about what this is: **obfuscation, not a security
  boundary.** The layers unwrap themselves at runtime, and for the cipher
  methods the key is embedded in the output, so a single hook recovers the
  source. Good for raising the bar against copy-paste and lazy scanners; not
  protection against anyone who can run the file.
- **PRO** — a real external-key boundary: the key is never stored (re-derived
  at runtime via scrypt), the payload is authenticated with AES-256-GCM,
  identifiers are randomized per build, and a native loader defeats the
  classic one-line hook. Each language's `pro/README.md` lays out exactly
  what it does and doesn't protect, with limits measured by actually
  attacking this repo's own output rather than guessed at.

| Language | Classic engine | PRO docs |
|---|---|---|
| Python | [`main.py`](main.py) (23 methods) | [`pro/README.md`](pro/README.md) |
| JavaScript / Node | [`js/main.js`](js/main.js) (22 methods) | [`js/pro/README.md`](js/pro/README.md) |
| .NET / C# | [`dotnet/Obsor.Classic`](dotnet/Obsor.Classic) (IL rewriter, 3 protections) | [`dotnet/Obsor.Pro/README.md`](dotnet/Obsor.Pro/README.md) |
| Java | [`java/obsor-classic`](java/obsor-classic) (ASM bytecode rewriter, 2 protections) | [`java/obsor-pro/README.md`](java/obsor-pro/README.md) |

The Python engine also includes preset profiles, standalone executable
building, and built-in self-testing; see [`js/README.md`](js/README.md) for
the Node port's equivalents and the one real platform difference (no
bytecode-only execution path in stock Node — read "Why JS hardened != Python
hardened" there before assuming parity).

The .NET port is architecturally different, not just thinner: .NET has no
source-level `exec`/`eval` equivalent, so Obsor.Classic rewrites compiled
**IL** via Mono.Cecil (the same library ConfuserEx is built on) instead of
stacking text encodings, and Obsor.Pro has only **two** tiers instead of
three — see [`dotnet/README.md`](dotnet/README.md) for why a middle
"native" tier would be dishonest marketing in .NET's case and doesn't exist
here.

The Java port follows the same reasoning one language further: no
source-level `exec` equivalent, so Obsor.Classic rewrites compiled
**bytecode** via ASM (the library ProGuard/R8 are themselves built on), and
Obsor.Pro also skips the middle native tier for the same honest reason —
see [`java/README.md`](java/README.md), including a measured proof that the
attack recovering hardened output (`-javaagent` + `Instrumentation.
addTransformer`) is a completely ordinary, documented JVM mechanism, not an
exotic hack.

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

### JavaScript / Node

```bash
cd js
node main.js -i script.js -o protected.js -m base64,zlib
node main.js -i script.js --preset military --test

# PRO: real external-key boundary (no npm dependency needed)
node pro/cli.js -i script.js -o dist/protected.js --tier hardened -k "my passphrase"
OBSOR_KEY="my passphrase" node dist/protected.js
```

See [`js/README.md`](js/README.md) for the full method list and the one
real platform difference from Python (no bytecode-only execution path in
stock Node).

### .NET / C#

```bash
cd dotnet
dotnet build -c Release

# Classic: rewrites compiled IL via Mono.Cecil (ConfuserEx's own library)
dotnet Obsor.Classic/bin/Release/net8.0/obsor-classic.dll \
  -i examples/sample_input.cs -o /tmp/protected.dll -m rename,strenc --test

# PRO hardened: Roslyn-compiled payload, AES-256-GCM, external key, no source leak
dotnet Obsor.Pro/bin/Release/net8.0/obsor-pro.dll \
  -i examples/sample_input.cs -o /tmp/hard.dll --tier hardened -k "my passphrase"
OBSOR_KEY="my passphrase" dotnet /tmp/hard.dll
```

See [`dotnet/README.md`](dotnet/README.md) -- this port is not source-level
obfuscation at all, it rewrites compiled IL the way ConfuserEx/Obfuscar do,
and PRO has two tiers instead of three for a documented reason.

### Java

```bash
cd java
mvn -q package -DskipTests

# Classic: rewrites compiled bytecode via ASM (ProGuard/R8's own library)
java -jar obsor-classic/target/obsor-classic-jar-with-dependencies.jar \
  -i examples/sample_input.java -o /tmp/protected --test

# PRO hardened: javac-compiled payload, AES-256-GCM, Argon2id, no source leak
java -jar obsor-pro/target/obsor-pro-jar-with-dependencies.jar \
  -i examples/sample_input.java -o /tmp/hard.jar --tier hardened -k "my passphrase"
OBSOR_KEY="my passphrase" java -jar /tmp/hard.jar
```

See [`java/README.md`](java/README.md) -- same architecture as .NET (rewrite
compiled bytecode, two PRO tiers not three) with its own real wrinkles:
Argon2id from day one (no repeat of .NET's initial PBKDF2 gap), and a
`-javaagent`-based attack that recovers hardened output using a completely
ordinary JVM API, not an exotic hack.

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
├── js/                   # JavaScript/Node port -- same two-engine shape
│   ├── main.js           # Classic engine + CLI (node main.js)
│   ├── pro/               # PRO engine (external-key, N-API native loader)
│   │   ├── native/          # native + native-logic tiers (N-API addon)
│   │   └── README.md        # PRO-JS docs + honest threat model
│   ├── examples/
│   └── README.md          # obsor-js docs + Python-vs-Node differences
├── dotnet/                # .NET port -- IL rewriter, not source-level (different shape)
│   ├── Obsor.Classic/      # Mono.Cecil IL rewriter CLI
│   ├── Obsor.Pro/           # hardened (Roslyn+AES-GCM) + native-logic (P/Invoke)
│   │   └── README.md         # PRO-.NET docs + why only 2 tiers, not 3
│   ├── Obsor.Selftest/      # dotnet obsor-selftest.dll
│   ├── examples/
│   └── README.md          # obsor-.NET docs + the architecture difference
├── java/                  # Java port -- same architecture as .NET, ASM-based
│   ├── obsor-classic/      # ASM bytecode rewriter CLI
│   ├── obsor-pro/           # hardened (javac+AES-GCM+Argon2id) + native-logic (JNI)
│   │   └── README.md         # PRO-Java docs + javaagent measured attack
│   ├── obsor-selftest/      # java -jar obsor-selftest.jar
│   ├── examples/
│   └── README.md          # obsor-Java docs + Java-specific wrinkles
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
