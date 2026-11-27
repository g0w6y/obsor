# Obsor for .NET

A **different architecture** from Python/JS, not a thinner clone of it.
Python and JS obsor stack text-encoding layers around source and
re-interpret it at runtime via `exec`/`eval`. .NET has no portable
equivalent of that outside Roslyn, and every real .NET obfuscator
(ConfuserEx, Obfuscar, dotNET Reactor's weaker modes) works a completely
different way: rewrite the **compiled IL** of an assembly in place. That's
what Obsor.Classic does, via [Mono.Cecil](https://github.com/jbevain/cecil)
-- the same library ConfuserEx itself is built on.

```
dotnet/
├── Obsor.Classic/        # IL rewriter CLI (Mono.Cecil): rename + string encryption
├── Obsor.Runtime/        # tiny helper shipped with classic-protected output
├── Obsor.Pro/             # PRO: hardened (Roslyn + AES-256-GCM "crypter") + native-logic
│   ├── Native/              # P/Invoke native-logic build helper
│   └── README.md            # PRO docs + honest threat model + measured numbers
├── Obsor.Selftest/        # dotnet obsor-selftest.dll -- 11 checks, end to end
├── examples/
│   ├── sample_input.cs
│   └── NativeLogic/         # secret.c + app.cs
└── Obsor.sln
```

## Classic (Obsor.Classic)

```bash
# from .cs source (compiles via Roslyn first, for parity with the other demos)
dotnet obsor-classic.dll -i examples/sample_input.cs -o protected.dll -m rename,strenc -k 0x5A

# from an already-built assembly (the real, intended workflow -- same as ConfuserEx/Obfuscar)
dotnet obsor-classic.dll -i MyApp.dll -o protected.dll -m rename,strenc

dotnet protected.dll   # ships with Obsor.Runtime.dll alongside it
```

Two protections, not 20+ interchangeable encodings -- .NET's unit of
obfuscation is IL **members and literals**, not swappable text transforms:

| Method | What it does |
|---|---|
| `rename` | randomizes private field/method names |
| `strenc` | XORs string literals, replaces `ldstr "x"` with `ldstr <xor'd>` + a call to `ObsorRuntime.StrDec.Decrypt` |

### What classic does NOT protect against

Measured in this repo, with no execution of the protected assembly at all --
a static Mono.Cecil pass that walks the IL looking for the
`ldstr, ldc.i4, call Decrypt` pattern this tool emits, and resolves every
string from the embedded key sitting right next to it:

```
[RECOVERED] hello from a string literal
[RECOVERED] another literal, inline
recovered 2 string literals statically, with NO execution of the assembly
```

This is not a hypothetical -- it is the exact, documented weakness real
deobfuscators (`de4dot`) use against ConfuserEx's equivalent "constants"
protection. The key is embedded in the IL; a tool that reads IL (no
execution, no debugger) recovers everything. Same honesty rule as
Python/JS classic: this is a deterrent against casual decompilation, not a
security boundary.

## PRO (Obsor.Pro)

See [`Obsor.Pro/README.md`](Obsor.Pro/README.md). Two tiers, not three --
and the missing middle tier is a deliberate, documented finding, not a gap:
**hardened** (external key, AES-256-GCM, the "crypter" pattern) and
**native-logic** (the one tier that resists a key-holder, via P/Invoke into
a compiled C library).

## Why .NET PRO != Python/JS PRO

Two real platform differences, both documented in depth in
`Obsor.Pro/README.md`:

1. **No scrypt in the BCL.** Python/JS both get memory-hard key derivation
   for free (`hashlib.scrypt`, `crypto.scryptSync`). .NET's
   `Rfc2898DeriveBytes` is PBKDF2 -- not memory-hard, weaker against a
   GPU/ASIC attacker per CPU-second spent. Pulling in a scrypt/Argon2 NuGet
   package would fix this; this port hasn't made that call yet.
2. **No middle "native" tier.** Python's native loader and JS's N-API
   loader each defeat a *specific* hook (the `compile`/`exec` hook, the
   `Function`/`eval` hook) that works against their own hardened tier.
   .NET's hardened-tier weakness isn't a hookable global function at all --
   it's that `Assembly.Load(byte[])` hands the CLR a normal, fully
   reflectable managed assembly. Moving the AES-GCM decrypt from C# into a
   native loader doesn't change that; the output is still a managed
   assembly. Measured in this repo: `AppDomain.CurrentDomain.AssemblyLoad`
   + `MethodBase.GetMethodBody().GetILAsByteArray()` recovers full IL for
   every method with zero debugger, same result whether the decrypt
   happened in C# or (hypothetically) C. So there's nothing a "native" tier
   would actually buy here -- claiming one would be the kind of marketing
   this project exists to not do.

## Requirements

- .NET SDK 8.0+ (`dotnet --version`)
- Obsor.Classic / Obsor.Pro pull `Mono.Cecil` and `Microsoft.CodeAnalysis.CSharp` from NuGet (both free, both widely used -- Cecil is what ConfuserEx itself is built on)
- `Obsor.Pro.Native.LogicBuild` (native-logic tier) needs `clang` (or another C compiler) on PATH at build time
- No native dependency for classic or hardened -- `Rfc2898DeriveBytes` and `AesGcm` are both BCL builtins

## Disclaimer

Same as the root project: **educational purposes, security research, and
legitimate code protection only.** Do not use Obsor to distribute malware,
bypass security systems, or for any illegal activity.
