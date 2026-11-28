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
dotnet obsor-classic.dll -i examples/sample_input.cs -o protected.dll -m rename,strenc,cflow -k 0x5A

# from an already-built assembly (the real, intended workflow -- same as ConfuserEx/Obfuscar)
dotnet obsor-classic.dll -i MyApp.dll -o protected.dll -m rename,strenc,cflow

dotnet protected.dll   # ships with Obsor.Runtime.dll alongside it
```

Three protections, not 20+ interchangeable encodings -- .NET's unit of
obfuscation is IL **members and literals/control-flow**, not swappable text
transforms:

| Method | What it does |
|---|---|
| `rename` | randomizes private field/method names |
| `strenc` | XORs string literals, replaces `ldstr "x"` with `ldstr <xor'd>` + a call to `ObsorRuntime.StrDec.Decrypt` |
| `cflow` | injects an opaque-predicate branch at the start of every method body, inflating the CFG a decompiler has to untangle |

### `cflow`: opaque predicates

For every method with a body (constructors, static cctors, property/event
accessors, compiler-generated methods included -- the one case skipped is a
method with no body at all, i.e. abstract/extern, which has no
`Instructions` to inject into), `cflow` prepends IL that computes
`t = (Environment.TickCount * Environment.TickCount) % 4` into a local, then
branches on `t != 2`. That's always true -- squares are only ever `0` or `1`
mod 4, never `2`, a property that survives 32-bit truncation (4 divides
2^32) and IL's signed `rem` (the only effect a negative product has is
turning residue `1` into `-3`, never into `2`). `Environment.TickCount` is
read at runtime, not a compile-time constant, so a decompiler can't just
constant-fold the branch away -- it has to recognize the mod-4
quadratic-residue identity to prove the "dead" branch is actually dead.
Verified before shipping with a 54M-case brute force (every int32 edge case
plus 50M random samples): zero counterexamples. The dead branch also ends
with an unconditional jump to the exact same real target as the live branch,
as a second, independent safety net -- even if the number-theory argument
were somehow wrong for some input, both paths converge on the same code, so
behavior can't change.

This injects exactly once per method, always at the very start, never
scattered mid-method: the method entry is the only point in an arbitrary
method body that's provably stack-empty without doing data-flow analysis
(the CLR guarantees an empty evaluation stack at method entry), so it's the
only injection point used here. It only touches the measurable
decompiler-facing shape of the method (basic-block count), not what the
method computes, and it does **not** hide string literals or renamed
members by itself -- combine with `strenc`/`rename` for that, which is
exactly what `-m rename,strenc,cflow` does above.

Measured, not estimated: on this repo's own `examples/sample_input.cs` (2
methods touched), basic blocks go from 6 to 10; on
`examples/sample_with_private.cs` (5 methods touched), 5 to 15. Both are a
flat +2 basic blocks per instrumented method (the opaque-predicate block
itself, plus the dead junk block) -- consistent across both examples, and
printed for any real run (`cflow: injected opaque predicates into N methods
(approx basic blocks X -> Y)`).

Known scope limit shared with `rename`/`strenc`, not new to `cflow`: this
whole tool only walks `module.Types` (top-level types) and never recurses
into `NestedTypes`, so **no nested type is touched by any of the three
protections** -- not just compiler-generated ones (iterator (`yield`) and
async state machines, lambda/local-function display classes), but also
plain, hand-written nested classes a developer declares directly (e.g. a
`class Box<T>` nested inside another class). Verified in this repo: a
nested `class Box<T> { public Box(T v) {...} public override string
ToString() {...} }` gets zero `cflow` instrumentation on its constructor or
`ToString` while every top-level method in the same file is instrumented --
confirmed by inspecting the emitted IL, not just the method count the tool
prints. The outer method that constructs the iterator/state machine (or any
nested type) is still instrumented; the nested type's own methods are not.
Give any class you want protected top-level visibility if this matters to
you.

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

That's not hypothetical -- it's the exact, documented weakness real
deobfuscators (`de4dot`) use against ConfuserEx's equivalent "constants"
protection. The key sits right there in the IL, so any tool that reads IL,
no execution, no debugger, recovers everything. Same honesty rule as the
Python/JS classic engines: this slows down casual decompilation and stops
there.

## PRO (Obsor.Pro)

See [`Obsor.Pro/README.md`](Obsor.Pro/README.md). Only two tiers here --
the missing middle one is a deliberate, documented finding rather than an
oversight: **hardened** (external key, AES-256-GCM, the "crypter" pattern)
and **native-logic** (the one tier that resists a key-holder, via P/Invoke
into a compiled C library).

## Why .NET PRO != Python/JS PRO

One real platform difference, documented in depth in `Obsor.Pro/README.md`
(a second one -- no memory-hard KDF in the BCL -- was closed 2026-11-27 by
pulling in `Konscious.Security.Cryptography.Argon2`, a small pure-.NET NuGet
package with no native dependency; key derivation is now Argon2id,
parameter-matched to the other two languages' scrypt cost):

1. **No middle "native" tier.** Python's native loader and JS's N-API
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
- Obsor.Classic / Obsor.Pro pull `Mono.Cecil`, `Microsoft.CodeAnalysis.CSharp`, and `Konscious.Security.Cryptography.Argon2` from NuGet (all free, all widely used -- Cecil is what ConfuserEx itself is built on, Konscious is a pure-.NET Argon2 implementation with no native dependency)
- `Obsor.Pro.Native.LogicBuild` (native-logic tier) needs `clang` (or another C compiler) on PATH at build time
- No native (C/C++) dependency for classic or hardened -- `AesGcm` is a BCL builtin and Konscious's Argon2id is pure managed code

## Disclaimer

Same as the root project: **educational purposes, security research, and
legitimate code protection only.** Do not use Obsor to distribute malware,
bypass security systems, or for any illegal activity.
