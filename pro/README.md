# Obsor PRO

Hardened protection for Python source. PRO fixes the structural weaknesses of
the classic obsor packer and adds a native loader so the standard one-line
deobfuscation stops working.

> **Honest framing (read this).** No Python protector is "unbreakable," and
> neither is this. What PRO actually buys you is a real **external-key
> boundary**: someone who has the protected file but NOT the key cannot get
> your code without attacking the passphrase (scrypt + AES-256-GCM). That is
> the whole value. Against someone who **can run the code** — a licensed
> customer, or any host that holds the key — PRO does *not* hide your logic:
> the payload must become a runnable Python object, and that object is
> recoverable in ~50ms with no debugger (see **Measured resistance**). The
> native tier only removes the classic one-line `compile`/`exec` hook; it is
> not meaningfully stronger than the pure-Python tier against a key-holder. We
> do not use the word "military."

## Why classic packing fails

Classic obsor (and most "N-layer" Python obfuscators) wrap your code in layers
that each decode themselves and call `exec`/`marshal.loads`. The whole stack
unwraps in an interpreter the attacker controls, so one hook peels every layer:

```python
import builtins; _c = builtins.compile
builtins.compile = lambda s,*a,**k: (print(s) if isinstance(s,str) else 0) or _c(s,*a,**k)
# run the obfuscated file -> original source prints out
```

Measured in this repo: **one `compile` hook recovers the full original source
from the `military` preset** (the code verbatim; that preset runs `minify`
first, so comments are already gone). Layer count does not help — 2 layers or
20, it is the same single hook.

## What PRO changes

| Weakness in classic | PRO fix |
|---|---|
| AES key embedded next to ciphertext | **Key never stored** — re-derived at runtime (scrypt) from an external secret: passphrase, host binding, or license token |
| Payload is recoverable source text | Payload is compiled **bytecode** (marshal) — no comments/formatting, needs decompilation even if dumped |
| Decoders have fixed names (`_xor_key`…) → trivial signatures | **Every identifier randomized per build** — no two outputs match |
| Unauthenticated: wrong key runs garbage | **AES-256-GCM authenticated** — wrong key/tampered blob refuses to run |
| Final `exec` lives in Python → one-hook peel | **native tier**: derive + decrypt happen in compiled C, so the classic `compile`/`exec` hook fails. (It does *not* make the payload unreachable — see **Honest limits**.) |

## Tiers

- **hardened** (pure Python, no compiler): external key, randomized identifiers,
  bytecode payload, authenticated GCM, optional anti-tamper guard (`--guard`,
  off by default — it is bypassable and breaks debuggers/coverage). One file.
- **native** (needs a C compiler + OpenSSL at build time): everything in
  hardened, plus the final unwrap in a compiled `.so`/`.pyd`. Ship the launcher
  `.py` **and** the compiled module together.

## Usage

```bash
# hardened, passphrase-derived key (key supplied at runtime, never in the file)
python -m pro.cli -i app.py -o dist/app.py --tier hardened -k "my passphrase"
OBSOR_KEY="my passphrase" python dist/app.py

# native loader (defeats the classic compile/exec hook; see Honest limits)
python -m pro.cli -i app.py -o dist/app.py --tier native -k "my passphrase"
OBSOR_KEY="my passphrase" python dist/app.py      # ships app.py + obsor_*.so

# machine-bound: runs only on the build host, no passphrase to distribute
python -m pro.cli -i app.py -o dist/app.py --key-mode machine

# license-token mode (gate per customer)
python -m pro.cli -i app.py -o dist/app.py --tier native --key-mode license -k "TOKEN"
OBSOR_LICENSE="TOKEN" python dist/app.py
```

## Measured resistance (this machine, Python 3.14)

Resistance depends entirely on **which attacker** you mean. The numbers below
were measured by adversarial review, not estimated.

**Attacker has the file but NOT the key** (e.g. a stolen artifact):

| Target | Result | Rough tier |
|---|---|---|
| classic `military` preset | one `compile` hook → full source (keys are embedded) | ~2/10 |
| PRO hardened, strong passphrase | offline brute only; scrypt N=2^17 (~a few guesses/s/core) → infeasible | ~6/10 |
| PRO hardened, weak passphrase | dictionary-cracked in <0.1s → full recovery | ~1/10 |
| PRO native, strong passphrase | same as hardened (blob carved from `.so`, decrypted offline with the key) | ~6/10 |

**Attacker can run the code — a licensed customer / key-holding host** (the
realistic IP-piracy threat):

| Target | Result | Rough tier |
|---|---|---|
| PRO hardened | 1-line `sys.addaudithook("marshal.loads")` or `settrace` dumps the bytecode (~50ms) | ~3/10 |
| PRO native | same — `PyMarshal_ReadObjectFromString` still fires the `marshal.loads` audit event; or just read `__main__` globals after `run()` | ~3/10 |

Note: compiling the launcher with Nuitka does **not** raise the key-holder
numbers — the payload still runs through `PyEval_EvalCode` in the normal
interpreter, where the audit event and `settrace` still fire.

## Honest limits

- **The payload becomes a live Python code object.** Any key-holder recovers
  it with no debugger, three ways: the `marshal.loads` audit event fires even
  from the C loader; `sys.settrace` captures the code objects; and after
  `run()` the decrypted functions/consts sit in `__main__` globals. The native
  tier closes only the classic `compile`/`exec` hook, not these.
- **Literals leak the instant the payload is decrypted.** API keys/tokens in
  `co_consts` are readable by any key-holder. Do not ship plaintext secrets in
  protected code.
- The anti-tamper guard (opt-in, `--guard`) runs in-process, can be patched
  out, does not check for audit hooks, and breaks debuggers/coverage. Treat it
  as cosmetic, not a boundary.
- `machine` binding uses `uuid.getnode()` (MAC-derived, spoofable) and does not
  survive payload extraction — the lifted bytecode runs on any host.
- Marshal bytecode is locked to one CPython minor version: build and run on the
  same `python3.X`.

## Native-logic tier (resists a key-holder)

The hardened and native tiers above do **not** hide logic from someone who can
run the code. The **native-logic tier** does, for the specific routine you move
into C: you write the sensitive function in C, obsor compiles it into the
loader `.so`, and the Python payload calls it through an injected module. That
function ships as machine code — there is no Python code object to dump, so the
`marshal.loads` / `settrace` / `globals()` recoveries do not apply to it. A
key-holder can *invoke* it as a black box but must reverse the compiled `.so`
(IDA/Ghidra) to read the algorithm — the real bar.

```bash
# app.py calls `import obsor_native; obsor_native.secret_transform(...)`
# secret.c defines: static PyObject *secret_transform(PyObject*, PyObject*)
python -m pro.native.logic -i app.py -c secret.c -e secret_transform \
       -o dist/app.py -k "passphrase"
OBSOR_KEY="passphrase" python dist/app.py
```

Measured: a key-holder importing the module gets a `builtin_function_or_method`
with no `__code__` — `dis` fails, the logic is not recoverable as Python.
Rough tier vs a key-holder: **~6–7/10 for the C'd routine** (vs ~3/10 for code
left in Python). See `examples/native_logic/`.

Caveats that keep this honest:
- Only the code you *write in C* is protected; the rest of the payload is still
  recoverable by a key-holder. Put just the crown-jewel routine in C.
- A gate must **return a value the payload needs** (a key, a result), not a
  bool the Python side can skip — a black-box boolean is bypassed by not
  calling it.
- The compiled `.so` is still reversible with native RE tooling; this raises
  cost to IDA/Ghidra effort, it is not unbreakable.
- Same deployment constraints as the native tier (compiler + OpenSSL at build,
  CPython-minor + OpenSSL-path bound `.so`).

Architecturally this brings PRO to roughly PyArmor's pre-BCC model plus a
BCC-style native-function option for the one routine you care most about.
