# Obsor.Pro (.NET)

Hardened protection for .NET assemblies, plus a native-logic tier for the
one routine you actually want to keep out of reach.

> **Honest framing (read this).** No .NET protector is "unbreakable," and
> neither is this. What PRO buys you is a real **external-key boundary**:
> someone who has the protected file but NOT the key cannot get your code
> without attacking the passphrase (Argon2id + AES-256-GCM). That is the
> whole value. Against someone who **can run the code** -- a licensed
> customer, or any host that holds the key -- PRO does *not* hide your
> logic: the payload must become a loaded managed assembly, and that
> assembly's IL is fully recoverable with no debugger attached (see
> **Measured resistance** -- these numbers came from actually attacking
> this repo's own output, not estimated).

## What PRO changes vs classic

| Weakness in classic | PRO fix |
|---|---|
| XOR key for string literals sits in the IL right next to the call | **Key never stored** -- re-derived at runtime (Argon2id, memory-hard) from an external secret: passphrase, host binding, or license token |
| Static Mono.Cecil pass recovers everything with zero execution | Payload is a whole separate assembly, AES-256-GCM-encrypted; nothing to statically walk until it's decrypted in memory at runtime |
| Member names are the only thing randomized | **Every launcher identifier randomized per build** (class + local names) -- no two outputs share a static signature |
| Classic has no key-mismatch signal | **AES-256-GCM authenticated** -- wrong key or a tampered blob refuses to run |

## Tiers

- **hardened**: Roslyn-compile the payload source to a managed assembly,
  AES-256-GCM-encrypt it with an Argon2id-derived key, emit a launcher that
  decrypts and `Assembly.Load(byte[])`s it, then invokes the entry point
  via reflection. Optional anti-tamper guard (`--guard`, off by default --
  bypassable, breaks debuggers). Ships as a launcher `.dll` + a copy of
  `Obsor.Pro.dll`.
- **native-logic**: everything in hardened, plus one developer-written C
  routine compiled to a native shared library and called via P/Invoke. The
  only tier that resists a key-holder. See below.

There is deliberately no third, middle "native" tier -- see root
`dotnet/README.md` "Why .NET PRO != Python/JS PRO" for why building one
would not add real protection here.

## Usage

```bash
# hardened, passphrase-derived key (key supplied at runtime, never in the file)
dotnet obsor-pro.dll -i app.cs -o dist/app.dll --tier hardened -k "my passphrase"
OBSOR_KEY="my passphrase" dotnet dist/app.dll

# license-token mode (gate per customer)
dotnet obsor-pro.dll -i app.cs -o dist/app.dll --tier hardened --key-mode license -k "TOKEN"
OBSOR_LICENSE="TOKEN" dotnet dist/app.dll
```

(`native-logic` is a library API today, not wired into the CLI --
`Obsor.Pro.Native.LogicBuild.BuildNativeLogic(...)`. See
`examples/NativeLogic/` for the exact call.)

## Measured resistance (this machine, .NET SDK 9.0.321 / net8.0 runtime, 2026-11-27)

Resistance depends entirely on **which attacker** you mean. The numbers
below were measured by adversarial review against this repo's own output --
not estimated.

**Attacker has the file but NOT the key** (e.g. a stolen artifact):

| Target | Result | Rough tier |
|---|---|---|
| classic `rename,strenc` | one static Mono.Cecil pass → every string recovered, zero execution (key is embedded) | ~2/10 |
| PRO hardened, strong passphrase | offline brute only; Argon2id, 128 MiB / 3 iterations / parallelism 1 -- measured ~520ms per derivation on this machine (~1.9 guesses/sec/core), and memory-hard so a GPU/ASIC attacker doesn't get the usual cheap parallelism boost PBKDF2 would have given them -> infeasible | ~6/10 |
| PRO hardened, weak passphrase | dictionary-cracked in well under a second (520ms × a small dictionary) → full recovery | ~1/10 |

**Attacker can run the code** -- a licensed customer / key-holding host (the
realistic IP-piracy threat):

| Target | Result | Rough tier |
|---|---|---|
| PRO hardened | `AppDomain.CurrentDomain.AssemblyLoad` event + `MethodBase.GetMethodBody().GetILAsByteArray()` on every loaded method → full IL recovered for every method, verified in this repo, zero debugger attached | ~2/10 |
| PRO native-logic | the C#-visible part is recovered exactly like hardened above; the one P/Invoke'd routine is not -- `GetMethodBody()` on a P/Invoke stub returns `null`, nothing to dump | ~6-7/10 for the C'd routine, ~2/10 for everything else |

## Honest limits

- **The payload becomes a live, loaded managed assembly.** Any key-holder
  recovers it via the `AssemblyLoad` + `GetILAsByteArray` technique above --
  verified, not theorized. No native loader closes this; see "Why no middle
  native tier" in the root README.
- **Key derivation cost is tunable, and the current numbers are a choice,
  not a law of physics.** Argon2id at 128 MiB / 3 iterations costs ~520ms
  per guess on this machine -- raise `Argon2MemoryKiB`/`Argon2Iterations`
  in `KeyDerive.cs` for more resistance at the cost of slower startup for
  legitimate runs too (same tradeoff scrypt's `N` parameter has in
  Python/JS).
- The anti-tamper guard (opt-in, `--guard`) only checks
  `Debugger.IsAttached` and a timing loop -- it does **not** detect a
  profiler, ETW trace, or `dotnet-dump`/`dotnet-trace` snapshot, and it runs
  in-process so a patched launcher bypasses it entirely. Cosmetic, not a
  boundary.
- `machine` binding uses `Environment.MachineName` + OS platform + core
  count (spoofable, same spirit as Python/JS) and does not survive payload
  extraction.
- The launcher `.dll` is version-locked to the `net8.0` runtime it targets
  (hardcoded in the generated `runtimeconfig.json`); run on a host with a
  compatible `Microsoft.NETCore.App` shared framework installed.

## Native-logic tier (resists a key-holder)

The hardened tier does **not** hide logic from someone who can run the
code -- it is reflectable, full stop, regardless of how the decrypt
happened. The **native-logic tier** does hide the one routine you actually
care about: write it as plain C, Obsor.Pro compiles it with `clang` into a
shared library shipped alongside the launcher, and the payload calls it via
`[DllImport]`. That function ships as machine code -- there is no IL for
it, `MethodBase.GetMethodBody()` on the P/Invoke stub returns `null`. A
key-holder can still *call* it as a black box but must reverse the compiled
library (Ghidra/IDA) to read the algorithm -- the real bar.

```csharp
// app.cs
[DllImport("obsor_native", EntryPoint = "secret_transform")]
static extern long SecretTransform(long x);
```
```c
/* secret.c */
int64_t secret_transform(int64_t x) { /* ... */ }
```
```csharp
Obsor.Pro.Native.LogicBuild.BuildNativeLogic(
    File.ReadAllText("app.cs"), File.ReadAllText("secret.c"), "obsor_native",
    "dist/app.dll", "pass", "passphrase");
```

Measured: calling `MethodBase.GetMethodBody()` on the generated P/Invoke
stub returns `null` -- no IL body exists to dump, by design (P/Invoke stubs
never have one). `strings` against the compiled `.dylib`/`.so` finds the
exported symbol name (same visibility tradeoff as the Python/JS native-logic
examples) but not the algorithm's constants, which exist only as compiled
immediate values.

Caveats that keep this honest:
- Only the code you *write in C* is protected; everything else in the
  payload is recoverable by a key-holder via the `AssemblyLoad` technique
  above. Put just the crown-jewel routine in C.
- A gate must **return a value the payload needs**, not a bool the C# side
  can skip -- a black-box boolean is bypassed by not calling it.
- The compiled library is still reversible with native RE tooling; this
  raises cost to IDA/Ghidra effort, it is not unbreakable.
- Needs a C compiler (clang/gcc) on PATH at build time; produces a
  platform-specific library (`.dylib`/`.so`/`.dll` depending on OS).
