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

public final class LogicBuild {
    private LogicBuild() {}

    public static void buildNativeLogic(String payloadSource, String logicC, String javaFqcn,
                                         String javaNativeMethod, String cFunctionName, String libName,
                                         String outPath, String keyMode, String passphrase) throws Exception {
        Path workDir = Files.createTempDirectory("obsor_native_logic_");
        String javaHome = System.getProperty("java.home");
        Path includeDir = Path.of(javaHome, "include");
        Path platformIncludeDir = includeDir.resolve(platformIncludeSubdir());

        String mangledClass = javaFqcn.replace(".", "_").replace("_", "_1").replace(".", "_");
        // JNI mangling: '_' in identifiers must be escaped as "_1"; do the
        // underscore-escape BEFORE replacing '.' with '_' for package separators.
        mangledClass = mangle(javaFqcn);
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
