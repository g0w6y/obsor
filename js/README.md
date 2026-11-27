# Obsor-JS

Node.js port of obsor's two engines: **classic** (22 encode/cipher/compress
layers, the JS equivalent of the Python classic engine) and **PRO** (a real
external-key boundary, with a native N-API tier that resists a key-holder for
the specific routine you move into C). Same honesty policy as the Python
side: measured attacker-resistance claims below, not marketing.

```
js/
├── main.js               # Classic engine + CLI (node main.js)
├── pro/
│   ├── cli.js             # node pro/cli.js
│   ├── engine.js          # hardened tier
│   ├── keyderive.js       # scrypt key derivation (node:crypto, no deps)
│   ├── guard.js            # optional anti-tamper tripwire
│   ├── selftest.js         # node pro/selftest.js
│   ├── native/              # native + native-logic tiers (N-API addon)
│   └── README.md            # PRO docs + honest threat model
├── examples/
│   ├── sample_input.js
│   └── native_logic/        # secret.c + app.js
└── package.json
```

## Classic engine

```bash
node main.js -i script.js -o protected.js -m base64,zlib
node main.js -i script.js --preset military --test
node main.js --list-methods
```

22 methods, pure Node builtins (`crypto`, `zlib`) -- **no npm dependency
needed** (Python classic needs `pycryptodome` for its `aes` method; Node's
builtin `crypto` covers it for free):

| Category | Methods |
|---|---|
| Encoding | base64, base32, base85, hex, octal, url, charcode, unicode |
| Cipher | xor, rc4, caesar, atbash, vigenere, polybius, aes (AES-256-CBC) |
| Compression | zlib (DEFLATE), gzip |
| Transform | rot13, reverse, split, whitespace, minify |

Presets: `military`, `max`, `light`, `stealth` (same four names as Python,
re-tuned to the methods available here).

### What classic does NOT protect against

Verified in this repo: a single `global.Function` override recovers the full
original source from every preset, no matter the layer count:

```js
const Real = global.Function;
global.Function = function (...a) { console.log(a[a.length-1]); return Real.apply(this,a); };
require('./obfuscated.js');  // -> original source printed
```

Each layer's generated code calls `eval(...)` or `new Function(...)` on the
decoded text of the layer below it -- one hook at that boundary peels
everything, exactly like Python classic's `compile`/`exec` hook. Treat this
as a deterrent against casual copy-paste, not a security boundary. For an
external-key boundary, use **PRO**.

## PRO

See [`pro/README.md`](pro/README.md) -- hardened (external key, AES-256-GCM,
randomized identifiers) and native (N-API `.node` loader, decrypts and runs
in compiled C so the classic `Function`/`eval` hook above does not apply),
plus the native-logic tier that resists a key-holder for the one routine you
write in C.

## Why JS hardened != Python hardened

Python's hardened payload is `marshal`-compiled **bytecode**: a dumped
payload has no comments/formatting and needs decompilation even if you have
it in hand. Node/V8 has **no equivalent**. V8's `vm.Script` code cache
(`produceCachedData`) is a hash-checked accelerator, not a substitute for
source -- it only runs paired with the *exact* original source text, so
there is no "ship bytecode, withhold source" path in stock Node. Obsor-JS's
hardened payload is therefore minified **source text**, not bytecode: the
instant it's decrypted (correct key) it is fully readable. This is a real
platform difference, not an oversight -- the native-logic tier is where JS
gets its actual resistance-to-a-key-holder story, via compiled C/N-API
instead of a bytecode format V8 doesn't have.

## Cross-Platform Notes

- Classic and PRO hardened run anywhere Node does (no C compiler needed).
- PRO native / native-logic build a platform-specific `.node` file (needs a
  C compiler + OpenSSL headers + `node-gyp` at build time -- same
  prerequisites as Python PRO's native tier, just via `npx node-gyp` instead
  of `cc` directly). Ship the launcher `.js` **and** the `.node` file
  together; both are tied to the Node ABI (`NODE_MODULE_VERSION`) they were
  built against.
- AES-256-GCM and scrypt use Node's builtin `crypto` module everywhere --
  zero npm runtime dependencies for classic or hardened.

## Requirements

- Node.js 18+ (classic, hardened — builtin `crypto`/`zlib` only)
- A C compiler (clang/gcc) + OpenSSL headers + `node-gyp` (native, native-logic only)

## Disclaimer

Same as the root project: **educational purposes, security research, and
legitimate code protection only.** Do not use Obsor-JS to distribute
malware, bypass security systems, or for any illegal activity.
