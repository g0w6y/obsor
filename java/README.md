# Obsor for Java

Same shape as the .NET port, for the same reason: Java has no portable
"exec arbitrary source text" primitive outside `javax.tools.JavaCompiler`,
and real Java obfuscators (ProGuard, R8, Allatori) all work the way
ConfuserEx does for .NET -- rewrite the compiled bytecode in place. This
uses [ASM](https://asm.ow2.io/) (`org.ow2.asm`), the library ProGuard, R8,
and cglib are themselves built on, in the same role Mono.Cecil plays for
the .NET port.

```
java/
├── pom.xml                 # Maven multi-module parent
├── obsor-runtime/            # tiny helper shipped with classic-protected output
├── obsor-classic/             # ASM-based bytecode rewriter CLI
├── obsor-pro/                  # PRO: hardened (javac + AES-GCM) + native-logic (JNI)
│   └── nativelogic/              # JNI glue-code generator + build helper
├── obsor-selftest/             # java -jar obsor-selftest.jar -- 12 checks, end to end
└── examples/
    ├── sample_input.java
    ├── sample_with_private.java
    └── native_logic/              # secret.c + App.java
```

## Classic (obsor-classic)

```bash
mvn -q package -DskipTests
java -jar obsor-classic/target/obsor-classic-jar-with-dependencies.jar \
  -i examples/sample_input.java -o /tmp/protected --test
```

Two protections -- same count and same reasoning as .NET's classic engine:
bytecode members and constants are the unit of obfuscation here, not
swappable text transforms, so there's no "20 more encodings" to add.

| Method | What it does |
|---|---|
| `rename` | randomizes private field/method names, patches every in-class call site (ASM's tree API stores instruction operands as plain strings, not live references the way Mono.Cecil does -- renaming requires a second pass over every method's instructions) |
| `strenc` | XORs `String` constants, replaces each `ldc "x"` with `ldc <xor'd>` + a call to `ObsorRuntime.StrDec.decrypt` |

**One real Java-specific design point**: `-o` here is a **directory**
(a classpath root), not a single output file. A `.class` file's own path
must match its package (`com/example/Foo.class` for package
`com.example`), so there is no single "the" output file in general --
this mirrors how `javac`/`java` actually work, the same honest-architecture
reasoning as every other platform difference in this project.

### What classic does NOT protect against

Measured in this repo, with **zero execution** of the protected class --
a static ASM pass that walks the bytecode looking for the
`ldc, bipush/sipush, invokestatic decrypt` pattern this tool emits, and
resolves every string from the XOR key sitting right next to it:

```
[RECOVERED] classified greeting text
recovered 1 string constants statically, with NO execution of the class
```

This is the exact documented de4dot-vs-ConfuserEx-class attack, reproduced
here against obsor-classic's own output. The key is embedded in the
bytecode; a tool that reads bytecode (no execution, no debugger) recovers
everything. Deterrent against casual decompilation, not a security
boundary -- same honesty rule as every other classic engine in this repo.

## PRO (obsor-pro)

See [`obsor-pro/README.md`](obsor-pro/README.md) -- hardened (external
key, AES-256-GCM, the javac-compile-then-encrypt "crypter" pattern) and
native-logic (the tier that resists a key-holder, via JNI into a compiled C
library).

## Why Java PRO != .NET PRO, even though the shape is almost identical

Same ceiling, different mechanics:

- **Key derivation started right the first time.** .NET's PRO initially
  shipped with PBKDF2 (not memory-hard) because the .NET BCL has no scrypt,
  then had to add a NuGet package later to fix it. Java's BCL has the same
  gap, so this port pulled in BouncyCastle's pure-Java Argon2id
  (`org.bouncycastle:bcprov-jdk18on`) from the start -- measured ~270ms per
  derivation on this machine at the same 128 MiB/3-iteration parameters as
  the (now-fixed) .NET tier and the Python/JS scrypt tiers.
- **The payload-loading mechanism is ClassLoader.defineClass, not
  Assembly.Load.** Conceptually the same idea (hand the runtime a byte
  array, get back a loaded, runnable unit), but Java's version has a real
  wrinkle the other three ports don't: a native library is tied to the
  specific `ClassLoader` that loads it, so the native-logic tier's payload
  class (loaded by our custom `ClassLoader`) must call `System.load` itself
  -- the launcher (loaded by the ordinary application `ClassLoader`) can't
  pre-load it on the payload's behalf. See `obsor-pro/README.md` and
  `examples/native_logic/App.java` for exactly how this is wired.
- **The attack that recovers hardened output is even more standard here
  than .NET's `AssemblyLoad` hook.** A `-javaagent` with
  `Instrumentation.addTransformer` is a completely ordinary, supported JVM
  mechanism (not a dump-the-internals hack) that receives the exact bytes
  handed to `defineClass`, for any `ClassLoader`, including ours. See
  `obsor-pro/README.md` "Measured resistance" for the real command and
  output.

## Requirements

- JDK 17+ (`java -version`, `javac -version`) -- a full JDK, not just a
  JRE: `javax.tools.ToolProvider.getSystemJavaCompiler()` returns `null` on
  a JRE-only install.
- Maven (or compatible build tooling) to resolve `org.ow2.asm:asm`,
  `org.ow2.asm:asm-tree`, and `org.bouncycastle:bcprov-jdk18on` from Maven
  Central -- both free, both widely used, no native dependency for either.
- A C compiler (clang/gcc) on PATH for the native-logic tier only, plus the
  JDK's own bundled JNI headers (`$JAVA_HOME/include`) -- no separate JNI
  SDK to install.

## Disclaimer

Same as the root project: **educational purposes, security research, and
legitimate code protection only.** Do not use Obsor to distribute malware,
bypass security systems, or for any illegal activity.
