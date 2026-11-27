package com.g0w6y.obsor.selftest;

// End-to-end self-test for obsor's Java port. Exit 0 = all pass.
//   java -jar obsor-selftest.jar
import com.g0w6y.obsor.pro.Engine;
import com.g0w6y.obsor.pro.nativelogic.LogicBuild;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;

public class Main {
    private static int rc = 0;

    private static void check(String name, boolean cond) {
        System.out.println((cond ? "[PASS] " : "[FAIL] ") + name);
        if (!cond) rc = 1;
    }

    public static void main(String[] args) throws Exception {
        // java/obsor-selftest/target/obsor-selftest.jar -> walk up to java/
        Path javaRoot = Path.of(Main.class.getProtectionDomain().getCodeSource().getLocation().toURI())
                .getParent().getParent().getParent();
        Path classicJar = javaRoot.resolve("obsor-classic/target/obsor-classic-jar-with-dependencies.jar");
        Path sampleInput = javaRoot.resolve("examples/sample_input.java");
        Path sampleWithPrivate = javaRoot.resolve("examples/sample_with_private.java");

        Path wd = Files.createTempDirectory("obsor_selftest_");

        // ---- classic tier ----
        if (Files.exists(classicJar)) {
            Path classicOut = wd.resolve("classic");
            var buildResult = runJar(classicJar, "-i", sampleInput.toString(), "-o", classicOut.toString(),
                    "-m", "rename,strenc", "-k", "0x5A");
            check("classic: builds", buildResult.code() == 0);
            var runResult = runClass(classicOut, "sample_input");
            check("classic: runs and produces correct output", runResult.stdout().trim().equals("FIB [0,1,1,2,3,5,8,13]"));
            byte[] classBytes = Files.readAllBytes(classicOut.resolve("sample_input.class"));
            check("classic: original string literal not present in compiled output",
                    new String(classBytes, StandardCharsets.ISO_8859_1).indexOf("FIB [") < 0);

            Path classicOut2 = wd.resolve("classic2");
            runJar(classicJar, "-i", sampleWithPrivate.toString(), "-o", classicOut2.toString(), "-m", "rename,strenc", "-k", "0x33");
            var runResult2 = runClass(classicOut2, "sample_with_private");
            check("classic: rename+strenc on private field/method call sites", runResult2.stdout().trim().equals("[classified greeting text]"));
        } else {
            check("classic: obsor-classic jar found at " + classicJar, false);
        }

        // ---- PRO hardened tier ----
        String payloadSource = Files.readString(sampleInput);
        Path hardOut = wd.resolve("hard.jar");
        Engine.protectFile(sampleInput.toString(), hardOut.toString(), "pass", "CorrectPass123", false);
        byte[] hardBytes = Files.readAllBytes(hardOut);
        check("hardened: passphrase not embedded", new String(hardBytes, StandardCharsets.ISO_8859_1).indexOf("CorrectPass123") < 0);
        check("hardened: runs with correct key", runJarWithEnv(hardOut, "CorrectPass123").stdout().trim().equals("FIB [0,1,1,2,3,5,8,13]"));
        check("hardened: wrong key refuses", runJarWithEnv(hardOut, "pw-wrong").code() != 0);
        check("hardened: no key refuses", runJarWithEnv(hardOut, null).code() != 0);

        Path hardA = wd.resolve("hardA.jar"), hardB = wd.resolve("hardB.jar");
        Engine.protectFile(sampleInput.toString(), hardA.toString(), "pass", "DummyPass1234", false);
        Engine.protectFile(sampleInput.toString(), hardB.toString(), "pass", "DummyPass1234", false);
        String clsA = extractLauncherClassName(hardA), clsB = extractLauncherClassName(hardB);
        check("hardened: launcher class name randomized per build", clsA != null && !clsA.equals(clsB));

        // ---- native-logic tier ----
        try {
            String logicPayload = """
            public class LogicPayload {
                static { System.load(System.getProperty("obsor.native.lib.path")); }
                private static native long sq(long x);
                public static void main(String[] args) { System.out.println("R " + sq(6)); }
            }
            """;
            String logicC = "#include <stdint.h>\nint64_t sq(int64_t x) { return x * x + 1; }\n";
            Path logicOut = wd.resolve("logic_app.jar");
            LogicBuild.buildNativeLogic(logicPayload, logicC, "LogicPayload", "sq", "sq", "obsor_native_selftest",
                    logicOut.toString(), "pass", "CorrectPass123");
            Path nativeLib = wd.resolve("libobsor_native_selftest.dylib");
            if (!Files.exists(nativeLib)) nativeLib = wd.resolve("libobsor_native_selftest.so");
            check("native-logic: builds", Files.exists(logicOut) && Files.exists(nativeLib));
            check("native-logic: runs + C result", runJarWithEnv(logicOut, "CorrectPass123").stdout().trim().equals("R 37"));
            byte[] libBytes = Files.readAllBytes(nativeLib);
            check("native-logic: no Java source text in native lib", new String(libBytes, StandardCharsets.ISO_8859_1).indexOf("System.out.println") < 0);
        } catch (Exception e) {
            check("native-logic: build/run (" + e.getMessage() + ")", false);
        }

        System.out.println();
        System.out.println(rc == 0 ? "ALL PASS" : "FAILURES ABOVE");
        System.exit(rc);
    }

    private static String extractLauncherClassName(Path jarPath) throws IOException {
        try (var jf = new java.util.jar.JarFile(jarPath.toFile())) {
            return jf.stream().map(e -> e.getName())
                    .filter(n -> n.matches("L[a-f0-9]{8}\\.class"))
                    .findFirst().map(n -> n.replace(".class", "")).orElse(null);
        }
    }

    private record ProcResult(int code, String stdout, String stderr) {}

    private static ProcResult runJar(Path jarFile, String... args) throws IOException, InterruptedException {
        String[] cmd = prepend("java", "-jar", jarFile.toString(), args);
        return run(cmd, null);
    }

    private static ProcResult runJarWithEnv(Path jarFile, String key) throws IOException, InterruptedException {
        return run(new String[]{"java", "-jar", jarFile.toString()}, key);
    }

    private static ProcResult runClass(Path classpathDir, String fqcn) throws IOException, InterruptedException {
        // "dir" alone only picks up loose .class files; a classpath wildcard
        // ("dir/*") is needed to also pick up any .jar sitting in that same
        // directory (e.g. the obsor-runtime companion jar strenc'd output needs).
        String cp = classpathDir + File.pathSeparator + classpathDir + File.separator + "*";
        return run(new String[]{"java", "-cp", cp, fqcn}, null);
    }

    private static String[] prepend(String a, String b, String c, String[] rest) {
        String[] out = new String[3 + rest.length];
        out[0] = a; out[1] = b; out[2] = c;
        System.arraycopy(rest, 0, out, 3, rest.length);
        return out;
    }

    private static ProcResult run(String[] cmd, String obsorKey) throws IOException, InterruptedException {
        ProcessBuilder pb = new ProcessBuilder(cmd);
        if (obsorKey != null) pb.environment().put("OBSOR_KEY", obsorKey);
        else pb.environment().remove("OBSOR_KEY");
        Process p = pb.start();
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        String err = new String(p.getErrorStream().readAllBytes(), StandardCharsets.UTF_8);
        boolean finished = p.waitFor(15, java.util.concurrent.TimeUnit.SECONDS);
        return new ProcResult(finished ? p.exitValue() : -1, out, err);
    }
}
