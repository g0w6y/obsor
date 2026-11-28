# Obsor.Pro (Java)

Hardened protection for compiled Java classes, plus a native-logic tier for
the one routine you actually want to keep out of reach.

> **Set expectations correctly.** No Java protector is "unbreakable," and
> neither is this. What PRO buys you is a real **external-key boundary**:
> someone who has the protected jar but NOT the key cannot get your code
> without attacking the passphrase (Argon2id + AES-256-GCM). That is the
> whole value. Against someone who **can run the jar** -- a licensed
> customer, or any host that holds the key -- PRO does *not* hide your
> logic: the payload must become a loaded class, and that class's bytecode
> is fully recoverable with a completely ordinary JVM mechanism (see
> **Measured resistance** below -- captured by actually attacking this
> repo's own output).

## What PRO changes vs classic

| Weakness in classic | PRO fix |
|---|---|
| XOR key for string constants sits in the bytecode right next to the call | **Key never stored** -- re-derived at runtime (Argon2id, memory-hard) from an external secret: passphrase, host binding, or license token |
| Static ASM pass recovers everything with zero execution | Payload is a whole separate class, AES-256-GCM-encrypted inside a jar resource; nothing to statically walk until it's decrypted in memory at runtime |
| No per-build variation beyond renamed members | **Launcher class name randomized per build** -- no two outputs share a static signature |
| Classic has no key-mismatch signal | **AES-256-GCM authenticated** -- wrong key or a tampered blob refuses to run |

## Tiers

- **hardened**: `javac`-compile the payload source in memory, AES-256-GCM
  encrypt the resulting class bytes with an Argon2id-derived key, package a
  launcher jar that decrypts an embedded resource and loads it via
  `ClassLoader.defineClass`, then invokes `main` via reflection. Optional
  anti-tamper guard (`--guard`, off by default -- bypassable, breaks
  debuggers). Ships as a launcher `.jar` + a copy of the runtime
  classpath jar (holds `KeyDerive` + BouncyCastle).
- **native-logic**: everything in hardened, plus one developer-written C
  routine compiled to a native library and called via JNI. The only tier
  that resists a key-holder. See below.

There is no third, middle "native" tier here either -- for the exact same
reason as the .NET port (see root `java/README.md`): the attack that
matters against hardened doesn't care whether the decrypt step ran in Java
or C, so a native loader would buy nothing real.

## Usage

```bash
# hardened, passphrase-derived key (key supplied at runtime, never in the file)
java -jar obsor-pro.jar -i App.java -o dist/app.jar --tier hardened -k "my passphrase"
OBSOR_KEY="my passphrase" java -jar dist/app.jar

# license-token mode (gate per customer)
java -jar obsor-pro.jar -i App.java -o dist/app.jar --tier hardened --key-mode license -k "TOKEN"
OBSOR_LICENSE="TOKEN" java -jar dist/app.jar
```

(`native-logic` is a library API today, not wired into the CLI --
`com.g0w6y.obsor.pro.nativelogic.LogicBuild.buildNativeLogic(...)`. See
`examples/native_logic/` for the exact call, and
`obsor-selftest/src/.../Main.java` for a complete runnable example.)

## Measured resistance (this machine, JDK 21.0.13.1 Temurin, 2026-11-28)

Resistance depends entirely on **which attacker** you mean. The numbers
below were measured by adversarial review against this repo's own output --
not estimated.

**Attacker has the file but NOT the key** (e.g. a stolen artifact):

| Target | Result | Rough tier |
|---|---|---|
| classic `rename,strenc` | one static ASM pass → every string recovered, zero execution (key is embedded) | ~2/10 |
| PRO hardened, strong passphrase | offline brute only; Argon2id, 128 MiB / 3 iterations / parallelism 1 -- measured ~220ms per derivation on this machine (bcprov-jdk18on 1.87), memory-hard so a GPU/ASIC attacker gets no cheap parallelism boost -> infeasible | ~6/10 |
| PRO hardened, weak passphrase | dictionary-cracked in well under a second → full recovery | ~1/10 |

**Attacker can run the jar** -- a licensed customer / key-holding host (the
realistic IP-piracy threat):

| Target | Result | Rough tier |
|---|---|---|
| PRO hardened | a `-javaagent` using the **completely ordinary, documented** `Instrumentation.addTransformer` API sees every class defined by every `ClassLoader`, including ours, and is handed the exact bytes passed to `defineClass` -- reproduced in this repo: the agent's `transform()` fired, dumped 903 bytes, and the dumped `.class` file ran standalone and `javap -c`'d cleanly, string literal and all | ~2/10 |
| PRO native-logic | the Java-visible part is recovered exactly like hardened above; the one JNI-called routine is not -- `native` methods have **no `Code` attribute at all** by the class file spec (confirmed with `javap -c`: no bytecode, nothing to dump, not specific to this tool) | ~6-7/10 for the C'd routine, ~2/10 for everything else |

## Honest limits

- **The payload becomes a live, loaded class.** Any key-holder recovers it
  via the javaagent technique above -- verified, not theorized, and using a
  standard JVM instrumentation API, not an exotic hack. No native loader
  closes this; see "Why no middle native tier" in the root README.
- **Argon2id parameters are a tunable choice, not a law of physics.** 128
  MiB / 3 iterations costs ~220ms per guess on this machine -- raise
  `ARGON2_MEMORY_KIB`/`ARGON2_ITERATIONS` in `KeyDerive.java` for more
  resistance at the cost of slower startup for legitimate runs too, the
  same tradeoff scrypt's `N` and .NET's Argon2id parameters have elsewhere
  in this project.
- The anti-tamper guard (opt-in, `--guard`) only checks for
  `-agentlib:jdwp`/`-agentlib` in the JVM's own startup arguments and a
  timing loop -- it does **not** detect a `-javaagent` attached at launch
  (the exact attack this README measures against!), nor Attach API-based
  dynamic agent loading after startup, and it runs in-process so a patched
  launcher bypasses it entirely. Cosmetic, not a boundary.
- `machine` binding uses OS name + hostname + core count (spoofable, same
  spirit as every other language's `machine` mode) and does not survive
  payload extraction.
- The launcher jar targets whatever JDK built it; class file versions are
  forward-compatible but not backward-compatible -- build with the oldest
  JDK you need to support.

## Native-logic tier (resists a key-holder)

The hardened tier does **not** hide logic from someone who can run the
jar -- it is dumpable via `-javaagent`, full stop, regardless of how the
decrypt happened. The **native-logic tier** does hide the one routine you
actually care about: write it as plain C, Obsor.Pro compiles it with
`clang` into a shared library and auto-generates the JNI glue code (you
write an ordinary C function, not raw JNI boilerplate), and the payload
calls it via a `native` method declaration. That function ships as machine
code -- there is no bytecode for it, confirmed above with `javap`. A
key-holder can still *call* it as a black box but must reverse the compiled
library (Ghidra/IDA) to read the algorithm -- the real bar.

**One Java-specific wiring detail that matters**: JNI resolves a native
library against the `ClassLoader` that loaded it, which must match the
`ClassLoader` of the class declaring the native method. Since the payload
class is loaded by Obsor.Pro's own custom `ClassLoader` (not the launcher's
ordinary one), the *payload* -- not the launcher -- must be the one calling
`System.load`. The launcher hands the native library's absolute path to the
payload via a system property (`obsor.native.lib.path`) before invoking
`main`, and the payload's static initializer reads it:

```java
// app's payload source
public class App {
    static { System.load(System.getProperty("obsor.native.lib.path")); }
    private static native long secretTransform(long x);
    public static void main(String[] args) {
        System.out.println("computed token: " + secretTransform(7));
    }
}
```
```c
/* secret.c */
int64_t secret_transform(int64_t x) { /* ... */ }
```
```java
LogicBuild.buildNativeLogic(
    Files.readString(Path.of("App.java")), Files.readString(Path.of("secret.c")),
    "App", "secretTransform", "secret_transform", "obsor_native",
    "dist/app.jar", "pass", "passphrase");
```

Measured: `javap -c -p` on the plain (un-encrypted) payload class shows
`private static native long secretTransform(long);` with **no `Code:`
block whatsoever** -- confirmed by direct inspection, not assumed from the
spec. `strings` against the compiled library finds the exported C symbol
name (same visibility tradeoff as every other language's native-logic
example) but not the algorithm's constants, which exist only as compiled
immediate values.

Caveats that keep this honest:
- Only the code you *write in C* is protected; everything else in the
  payload is still recoverable by a key-holder via the javaagent technique
  above. Put just the crown-jewel routine in C.
- A gate must **return a value the payload needs**, not a bool the Java
  side can skip -- a black-box boolean is bypassed by not calling it.
- The compiled library is still reversible with native RE tooling; this
  raises cost to IDA/Ghidra effort, it is not unbreakable.
- Needs a C compiler (clang/gcc) on PATH at build time, plus the building
  JDK's own JNI headers; produces a platform-specific library
  (`.dylib`/`.so`/`.dll` depending on OS).
