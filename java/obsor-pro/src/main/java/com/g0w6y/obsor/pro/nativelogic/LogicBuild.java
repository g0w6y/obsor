package com.g0w6y.obsor.pro.nativelogic;

// Obsor.Pro native-logic tier (Java).
//
// Compile a developer-supplied plain C routine into a native shared
// library, generate the small JNI glue wrapper around it automatically
// (so the developer writes an ordinary C function, not raw JNI
// boilerplate), and protect the Java payload with the hardened engine as
// usual. The payload calls the routine via a `native` method declaration +
// `System.loadLibrary`.
//
// HONEST SCOPE: only the code you write in C is protected. A key-holder
// still recovers the rest of the payload via the javaagent technique
// documented in Obsor.Pro's README "Measured resistance" -- the native
// method call itself has no Java bytecode body to dump (a `native` method
// has no Code attribute at all, by the class file spec), but everything
// else in the payload is ordinary, fully-reflectable/dumpable bytecode.
import com.g0w6y.obsor.pro.Engine;

import java.io.IOException;
import java.nio.file.*;
import java.util.UUID;
import java.util.regex.Pattern;

public final class LogicBuild {
    private LogicBuild() {}

    // javaFqcn/javaNativeMethod/cFunctionName get spliced VERBATIM, unquoted,
    // into generated C source (the JNI wrapper) as identifiers; libName gets
    // spliced VERBATIM into a Java string literal in the generated launcher
    // source (Engine.buildLauncherSource's nativeLibSetup block) AND into a
    // clang -o path. None of that splicing escapes anything, so any of these
    // being attacker-influenced strings containing C/Java-breaking characters
    // (quotes, braces, semicolons, newlines) is a straight code-injection
    // vector into either the compiled native library or the launcher jar
    // that ships to and runs for every end user, key or no key. Demonstrated
    // directly against this class during security review: a crafted libName
    // containing a `"` broke out of the generated launcher's string literal
    // and ran attacker code on every execution of the shipped jar, with NO
    // passphrase/license key required. Reject anything that isn't a plain
    // identifier (dotted, for the FQCN) up front, before any of it reaches a
    // template.
    private static final Pattern IDENT = Pattern.compile("^[A-Za-z_][A-Za-z0-9_]*$");
    private static final Pattern FQCN = Pattern.compile("^[A-Za-z_][A-Za-z0-9_]*(\\.[A-Za-z_][A-Za-z0-9_]*)*$");
    // libName becomes part of a filename (libXXX.so/.dylib/.dll), not a Java/C
    // identifier, but must still be restricted to a safe charset: no quotes,
    // slashes, path-traversal sequences, or other characters that have
    // special meaning once spliced into generated source or a filesystem
    // path.
    private static final Pattern LIBNAME = Pattern.compile("^[A-Za-z0-9_.-]+$");

    private static void checkIdent(String name, String what) {
        if (name == null || !IDENT.matcher(name).matches())
            throw new IllegalArgumentException("invalid " + what + ": " + name);
    }

    public static void buildNativeLogic(String payloadSource, String logicC, String javaFqcn,
                                         String javaNativeMethod, String cFunctionName, String libName,
                                         String outPath, String keyMode, String passphrase) throws Exception {
        if (javaFqcn == null || !FQCN.matcher(javaFqcn).matches())
            throw new IllegalArgumentException("invalid javaFqcn: " + javaFqcn);
        checkIdent(javaNativeMethod, "javaNativeMethod");
        checkIdent(cFunctionName, "cFunctionName");
        if (libName == null || libName.isEmpty() || !LIBNAME.matcher(libName).matches())
            throw new IllegalArgumentException("invalid libName: " + libName);

        Path workDir = Files.createTempDirectory("obsor_native_logic_");
        try {
            String javaHome = System.getProperty("java.home");
            Path includeDir = Path.of(javaHome, "include");
            Path platformIncludeDir = includeDir.resolve(platformIncludeSubdir());

            String mangledClass = mangle(javaFqcn);
            // JNI mangling: '_' in identifiers must be escaped as "_1"; do the
            // underscore-escape BEFORE replacing '.' with '_' for package separators.
            String jniFuncName = "Java_" + mangledClass + "_" + mangle(javaNativeMethod);

            String wrapperC = """
            #include <jni.h>
            #include <stdint.h>
            extern int64_t %s(int64_t x);
            JNIEXPORT jlong JNICALL %s(JNIEnv *env, jclass cls, jlong x) {
                return (jlong) %s((int64_t) x);
            }
            """.formatted(cFunctionName, jniFuncName, cFunctionName);

            Path logicCPath = workDir.resolve("logic.c");
            Path wrapperCPath = workDir.resolve("wrapper.c");
            Files.writeString(logicCPath, logicC);
            Files.writeString(wrapperCPath, wrapperC);

            Path outDir = Path.of(outPath).getParent() == null ? Path.of(".") : Path.of(outPath).getParent();
            Files.createDirectories(outDir);
            String ext = osExt();
            String libFileName = (osIsWindows() ? "" : "lib") + libName + ext;
            Path libOutPath = outDir.resolve(libFileName);

            ProcessBuilder pb = new ProcessBuilder("clang", "-shared", "-O2", "-fPIC",
                    "-I", includeDir.toString(), "-I", platformIncludeDir.toString(),
                    "-o", libOutPath.toString(), logicCPath.toString(), wrapperCPath.toString());
            pb.redirectErrorStream(true);
            Process proc = pb.start();
            String out = new String(proc.getInputStream().readAllBytes());
            int rc = proc.waitFor();
            if (rc != 0) throw new IllegalStateException("native compile failed:\n" + out);

            Engine.protectFile(writeTemp(workDir, payloadSource), outPath, keyMode, passphrase, false, libFileName);
        } finally {
            // logic.c/wrapper.c/payload.java are all fully consumed (compiled
            // by clang into libOutPath, or read by Engine.protectFile) by the
            // time this returns -- without this, every native-logic build
            // leaves its scratch dir behind in the OS temp dir forever.
            deleteRecursive(workDir);
        }
    }

    /** Best-effort recursive delete of a temp directory tree -- never fails the build if cleanup itself hits an error. */
    private static void deleteRecursive(Path root) {
        if (!Files.exists(root)) return;
        try (var stream = Files.walk(root)) {
            stream.sorted(java.util.Comparator.reverseOrder()).forEach(p -> {
                try { Files.deleteIfExists(p); } catch (IOException ignored) {}
            });
        } catch (IOException ignored) {}
    }

    /** JNI name-mangling: escape '_' as "_1", then replace '.' with '_' for package separators. */
    private static String mangle(String s) {
        return s.replace("_", "_1").replace(".", "_");
    }

    private static String writeTemp(Path workDir, String source) throws IOException {
        Path p = workDir.resolve("payload.java");
        Files.writeString(p, source);
        return p.toString();
    }

    private static String platformIncludeSubdir() {
        String os = System.getProperty("os.name").toLowerCase();
        if (os.contains("mac")) return "darwin";
        if (os.contains("win")) return "win32";
        return "linux";
    }

    private static String osExt() {
        String os = System.getProperty("os.name").toLowerCase();
        if (os.contains("mac")) return ".dylib";
        if (os.contains("win")) return ".dll";
        return ".so";
    }

    private static boolean osIsWindows() {
        return System.getProperty("os.name").toLowerCase().contains("win");
    }
}
