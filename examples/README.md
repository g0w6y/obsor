# Examples

This directory contains sample scripts to test and demonstrate Obsor.

## sample_input.py

A ready-to-use sample Python script with real logic (functions, loops, secrets).
Use it to test any obfuscation preset:

```bash
# Basic
python main.py -i examples/sample_input.py -o output.py -m base64,zlib

# Military preset
python main.py -i examples/sample_input.py --preset military

# Stealth preset with self-test
python main.py -i examples/sample_input.py --preset stealth --test

# AES + custom key
python main.py -i examples/sample_input.py -m aes,base85 -k "MyKey123"

# Build executable
python main.py -i examples/sample_input.py --preset max --build-exe
```

## native_logic/

Example for the PRO native-logic tier: a secret routine written in C
(`secret.c`) compiled into the loader, called from `app.py`. See
[`../pro/README.md`](../pro/README.md).

```bash
python -m pro.native.logic -i examples/native_logic/app.py \
       -c examples/native_logic/secret.c -e secret_transform \
       -o dist/app.py -k "passphrase"
OBSOR_KEY="passphrase" python dist/app.py
```

## obsor.py (in root)

The root `obsor.py` is a sample of what Obsor produces — an earlier `main.py`
run through the `military` preset.
