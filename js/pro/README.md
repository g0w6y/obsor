# Obsor-JS PRO

Hardened protection for JS/Node source. PRO fixes the structural weaknesses
of the classic obsor-js packer and adds a native (N-API) loader so the
standard `Function`/`eval` one-line deobfuscation stops working.

> **Read this before you trust PRO.** Calling anything here "unbreakable" would
> be a lie, so we don't. What PRO delivers is a real **external-key
> boundary** -- holding the protected file without the key leaves an
> attacker stuck brute-forcing a passphrase (scrypt + AES-256-GCM), and
> that's the full extent of the guarantee. It's a different story once
> someone **can run the code** -- a licensed customer, or any host that
> holds the key: the payload has to become runnable JS, and that JS comes
> back with no debugger, or via the inspector, in well under a second (see
> **Measured resistance**, measured directly against this repo's own
> output). The native tier removes exactly one thing, the classic one-line
> `Function`/`eval` hook; against a key-holder who attaches `node
> --inspect`, it isn't meaningfully stronger than the pure-Node tier.

## Why classic packing fails

Classic obsor-js, like javascript-obfuscator's weaker configurations and
most "N-layer" JS obfuscators, stacks layers that each decode themselves and
call `eval`/`Function`. All of that unwrapping happens inside an interpreter
the attacker fully controls, so a single hook at the right spot peels every
layer at once:

```js
const Real = global.Function;
global.Function = function (...a) { console.log(a[a.length-1]); return Real.apply(this,a); };
require('./obfuscated.js'); // -> original source, logged
```

Measured in this repo: **one `Function()` hook recovers the full original
source from the `military` preset** (the code verbatim; that preset runs
`minify` first, so comments are already gone). Adding more layers doesn't
help -- whether it's 2 or 20, the same single hook catches them all.

## What PRO changes

| Weakness in classic | PRO fix |
|---|---|
| AES key embedded next to ciphertext | **Key never stored** -- re-derived at runtime (scrypt) from an external secret: passphrase, host binding, or license token |
| Payload text is plain source | Minified (comments/formatting already gone); see "Why JS != Python" below for why it's not bytecode |
| Decoders have fixed names (`_xor_key`…) → trivial signatures | **Every identifier randomized per build** -- no two outputs share a static signature |
| Unauthenticated: wrong key runs garbage | **AES-256-GCM authenticated** -- wrong key/tampered blob refuses to run |
| Final `eval`/`Function` lives in JS → one-hook peel | **native tier**: derive + decrypt + execute happen via N-API's `napi_run_script`, called from compiled C, so the classic `Function`/`eval` hook fails. (It does *not* make the payload unreachable -- see **Honest limits**.) |

## Tiers

- **hardened** (pure Node, no compiler): external key, randomized
  identifiers, minified payload, authenticated GCM, optional anti-tamper
  guard (`--guard`, off by default -- it is bypassable and breaks
  debuggers/coverage). One file.
- **native** (needs a C compiler + OpenSSL + `node-gyp` at build time):
  everything in hardened, plus the final unwrap in a compiled `.node`
  addon. Ship the launcher `.js` **and** the compiled `.node` together.

## Usage

```bash
# hardened, passphrase-derived key (key supplied at runtime, never in the file)
node pro/cli.js -i app.js -o dist/app.js --tier hardened -k "my passphrase"
OBSOR_KEY="my passphrase" node dist/app.js

# native loader (defeats the classic Function/eval hook; see Honest limits)
node pro/cli.js -i app.js -o dist/app.js --tier native -k "my passphrase"
OBSOR_KEY="my passphrase" node dist/app.js      # ships app.js + obsor_*.node

# license-token mode (gate per customer)
node pro/cli.js -i app.js -o dist/app.js --tier native --key-mode license -k "TOKEN"
OBSOR_LICENSE="TOKEN" node dist/app.js
```

(machine-bound mode exists in `pro/keyderive.js`'s `resolveSecret('machine')`
but is only wired through the hardened-tier engine today, not yet the CLI
`--tier` native path -- same scope as Python's `machine` restriction to
non-native tiers.)

## Measured resistance (this machine, Node 26.13.1, 2026-11-27)

What the numbers mean hinges entirely on **which attacker** you're picturing.
Every figure below came from adversarial review of this repo's own output,
nothing guessed.

**Attacker has the file but NOT the key** (e.g. a stolen artifact):

| Target | Result | Rough tier |
|---|---|---|
| classic `military` preset | one `Function()` hook → full source (keys embedded) | ~2/10 |
| PRO hardened, strong passphrase | offline brute only; scrypt N=2^17 (~a few guesses/s/core) → infeasible | ~6/10 |
| PRO hardened, weak passphrase | dictionary-cracked in <0.1s → full recovery | ~1/10 |
| PRO native, strong passphrase | same as hardened (blob carved from `.node`, decrypted offline with the key) | ~6/10 |

**Attacker can run the code** -- a licensed customer / key-holding host (the
realistic IP-piracy threat):

| Target | Result | Rough tier |
|---|---|---|
| PRO hardened | one `global.Function` override before `require()` → full source recovered, verified | ~2/10 |
| PRO native | `Function` hook does **not** catch it (verified: `napi_run_script` bypasses JS-visible `Function`/`eval` entirely) -- but `node --inspect` + `Debugger.getScriptSource` recovers the full decrypted source anyway, verified in this repo in well under a second, no breakpoint needed | ~3/10 |

Note: the native tier's real win over hardened is narrow and specific --
it defeats the *static* `Function`/`eval`-hook script that works against
every pure-JS packer out of the box. It does **not** defeat the inspector
protocol, and after `run()` the decrypted functions still sit in `global`.

## Honest limits

- **The payload becomes live, running JS.** Any key-holder recovers it two
  verified ways: `node --inspect` + `Debugger.getScriptSource` on the
  `napi_run_script`-compiled script (works even against the native tier);
  or a `global.Function` override before the hardened tier's `require()`
  call (does not work against native -- that is native's one real edge).
  After `run()`, the decrypted functions/consts also sit in `global`,
  readable with no tooling at all.
- **Literals leak the instant the payload is decrypted.** API keys/tokens in
  the source are readable by any key-holder once decrypted. Do not ship
  plaintext secrets in protected code.
- The anti-tamper guard (opt-in, `--guard`) runs in-process, can be patched
  out, only checks `require('inspector').url()` (catches `--inspect`
  attached *before* the guard runs, missing one attached after or any other
  dynamic-analysis tooling), and breaks debuggers/coverage. It's cosmetic,
  nothing more.
- `machine` binding uses the first non-loopback MAC via
  `os.networkInterfaces()` (spoofable) and does not survive payload
  extraction -- lifted source runs on any host.
- The compiled `.node` file is locked to one Node ABI version
  (`NODE_MODULE_VERSION`): build and run on a matching Node.

## Native-logic tier (resists a key-holder)

Hardened and native both leave logic exposed to anyone who can run the
code. The **native-logic tier** closes that gap for one routine: write the
sensitive function as a standard N-API C function, obsor-js compiles it
into the loader `.node`, and the JS payload calls it through an injected
global (default `obsorNative`). That function ships as machine code, so
there's no JS source left to recover. A key-holder can still *invoke* it as
a black box, but reading the algorithm means reversing the compiled
`.node` (IDA/Ghidra/Frida) -- the real bar.

```bash
# app.js calls: obsorNative.secret_transform(7)
# secret.c defines: static napi_value secret_transform(napi_env, napi_callback_info)
node -e "require('./pro/native/logic').buildNativeLogic(
  require('fs').readFileSync('app.js','utf8'),
  require('fs').readFileSync('secret.c','utf8'),
  ['secret_transform'], 'dist/app.js', {keyMode:'pass', passphrase:'passphrase'})"
OBSOR_KEY="passphrase" node dist/app.js
```

Measured: a key-holder calling `obsorNative.secret_transform.toString()` gets
`"function secret_transform() { [native code] }"` -- there is no JS body to
dump, and searching the compiled `.node` for the function's constants with
`strings` finds nothing (they exist only as compiled immediate values).
Rough tier vs a key-holder: **~6-7/10 for the C'd routine** (vs ~2/10 for
logic left in JS, per the table above). See `examples/native_logic/`.

A few things keep this claim honest:
- Only the code you *write in C* is protected; the rest of the payload is
  still recoverable by a key-holder via the inspector protocol above. Put
  just the crown-jewel routine in C.
- Make the gate **return a value the payload actually needs** (a key, a
  result). A bare boolean gets skipped -- the JS side just doesn't call it.
- IDA/Ghidra can still take the compiled `.node` apart. This raises the
  effort bar; it doesn't close the door.
- Same deployment constraints as the native tier (compiler + OpenSSL +
  node-gyp at build, Node-ABI-bound `.node`).

Architecturally this brings Obsor-JS PRO to roughly the same place as the
Python PRO engine relative to PyArmor: matching its external-key model, plus
a crown-jewel native-function option most free JS obfuscators (including
javascript-obfuscator) don't offer at all -- their VM/bytecode protection is
paywalled (Jscrambler, Obfuscator.io Pro), and none of them publish measured
break times the way this file does.
