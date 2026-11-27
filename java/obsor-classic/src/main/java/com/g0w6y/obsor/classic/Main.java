package com.g0w6y.obsor.classic;

// Obsor.Classic (Java) -- bytecode rewriter for compiled .class files.
//
// Same reasoning as the .NET port: Java has no portable "exec arbitrary
// source text" primitive outside javax.tools.JavaCompiler, and real Java
// obfuscators (ProGuard, Allatori, yGuard) all work the same way ConfuserEx
// does for .NET -- rewrite the compiled bytecode in place. This uses ASM
// (org.ow2.asm), the same bytecode-manipulation library ProGuard/R8 and
// cglib are built on, in the same role Mono.Cecil plays for the .NET port.
//
// ONE MORE real platform difference worth stating up front: unlike Python/
// JS/.NET (-o is a single output file), -o here is a DIRECTORY (a classpath
// root). A .class file's own path must match its package
// (com/example/Foo.class for package com.example), so there's no single
// "the" output file in general -- this mirrors how javac/java actually
// work, not an arbitrary choice.

import com.g0w6y.obsor.runtime.StrDec;
import org.objectweb.asm.*;
import org.objectweb.asm.tree.*;

import javax.tools.*;
import java.io.*;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.SecureRandom;
import java.util.*;

public class Main {
    private static final List<String> ALL_METHODS = List.of("rename", "strenc");
    private static final SecureRandom RNG = new SecureRandom();

    public static void main(String[] args) throws Exception {
        String input = null, output = null, methodsArg = null, keyArg = null;
        boolean listMethods = false, test = false;

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "-i": case "--input": input = args[++i]; break;
                case "-o": case "--output": output = args[++i]; break;
                case "-m": case "--methods": methodsArg = args[++i]; break;
                case "-k": case "--key": keyArg = args[++i]; break;
                case "--list-methods": listMethods = true; break;
                case "--test": test = true; break;
                default:
                    System.err.println("[!] Unknown argument: " + args[i]);
                    System.exit(1);
            }
        }

        if (listMethods) {
            System.out.println("Available methods:");
            System.out.println("  rename  - randomizes private field/method names (updates all in-class call sites)");
            System.out.println("  strenc  - XOR-encrypts String constants, replaces each with a call to ObsorRuntime.StrDec.decrypt");
            System.out.println();
            System.out.println("Two protections, not 20+ -- same reasoning as the .NET port: bytecode");
            System.out.println("members/constants are the unit of obfuscation here, not swappable text transforms.");
            return;
        }

        if (input == null || output == null) {
            System.err.println("Usage: obsor-classic -i INPUT(.java|.class) -o OUTPUT_DIR [-m rename,strenc] [-k 0xNN] [--test]");
            System.exit(1);
            return;
        }

        List<String> methods = methodsArg == null
                ? List.of("rename", "strenc")
                : Arrays.stream(methodsArg.split(",")).map(String::trim).toList();
        for (String m : methods) {
            if (!ALL_METHODS.contains(m)) {
                System.err.println("[!] Unknown method: " + m);
                System.exit(1);
            }
        }

        int key;
        if (keyArg == null) {
            key = 1 + RNG.nextInt(255);
            System.out.println("[!] Generated random XOR key: 0x" + Integer.toHexString(key).toUpperCase());
        } else {
            try {
                key = keyArg.startsWith("0x") ? Integer.parseInt(keyArg.substring(2), 16) : Integer.parseInt(keyArg);
            } catch (NumberFormatException e) {
                System.err.println("[!] Invalid -k value: " + keyArg + " (expected a decimal or 0x-hex byte, 0-255)");
                System.exit(1);
                return;
            }
            if (key < 0 || key > 255) {
                System.err.println("[!] -k value out of range: " + keyArg + " (must be 0-255)");
                System.exit(1);
                return;
            }
        }

        byte[] classBytes;
        if (input.endsWith(".java")) {
            if (!Files.exists(Path.of(input))) {
                System.err.println("[!] Input file not found: " + input);
                System.exit(1);
                return;
            }
            System.out.println("[*] Compiling " + input + " via javax.tools.JavaCompiler...");
            classBytes = compileJava(Path.of(input));
        } else {
            if (!Files.exists(Path.of(input))) {
                System.err.println("[!] Input file not found: " + input);
                System.exit(1);
                return;
            }
            classBytes = Files.readAllBytes(Path.of(input));
        }

        ClassReader reader = new ClassReader(classBytes);
        ClassNode cn = new ClassNode();
        reader.accept(cn, 0);

        int renamed = 0, stringsEnc = 0;

        if (methods.contains("rename")) {
            renamed = applyRename(cn);
        }
        if (methods.contains("strenc")) {
            stringsEnc = applyStrEnc(cn, key);
        }

        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        cn.accept(writer);
        byte[] outBytes = writer.toByteArray();

        Path outDir = Path.of(output);
        Path classPath = outDir.resolve(cn.name + ".class"); // cn.name uses '/' for package separators
        Files.createDirectories(classPath.getParent());
        Files.write(classPath, outBytes);

        // Ship the runtime helper jar alongside, same pattern as the .NET port's Obsor.Runtime.dll.
        if (methods.contains("strenc")) {
            Path runtimeJar = findRuntimeJar();
            if (runtimeJar != null) {
                Files.copy(runtimeJar, outDir.resolve(runtimeJar.getFileName()), StandardCopyOption.REPLACE_EXISTING);
            } else {
                System.err.println("[!] Warning: obsor-runtime jar not found next to obsor-classic; " +
                        "the protected class will fail at runtime with NoClassDefFoundError unless you " +
                        "put obsor-runtime on the classpath yourself.");
            }
        }

        System.out.println("[+] Saved to " + classPath);
        System.out.println("    renamed " + renamed + " members, encrypted " + stringsEnc + " string constants");

        if (test) {
            System.out.println("\n[test] Testing obfuscated class: " + classPath);
            runTest(outDir, cn.name.replace('/', '.'));
        }
    }

    private static Path findRuntimeJar() {
        Path jarDir = Path.of(Main.class.getProtectionDomain().getCodeSource().getLocation().getPath()).getParent();
        if (jarDir == null) return null;
        try (var stream = Files.list(jarDir)) {
            return stream.filter(p -> p.getFileName().toString().startsWith("obsor-runtime")
                            && p.getFileName().toString().endsWith(".jar"))
                    .findFirst().orElse(null);
        } catch (IOException e) {
            return null;
        }
    }

    private static byte[] compileJava(Path javaFile) throws IOException {
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        if (compiler == null) throw new IllegalStateException("No system Java compiler available (need a JDK, not just a JRE)");
        Path workDir = Files.createTempDirectory("obsor_classic_");
        int rc = compiler.run(null, null, null, javaFile.toString(), "-d", workDir.toString());
        if (rc != 0) throw new IllegalStateException("javac compilation failed (exit " + rc + ")");
        try (var stream = Files.walk(workDir)) {
            Path classFile = stream.filter(p -> p.toString().endsWith(".class")
                            && !p.getFileName().toString().contains("$"))
                    .findFirst()
                    .orElseThrow(() -> new IllegalStateException("javac produced no top-level .class file"));
            return Files.readAllBytes(classFile);
        }
    }

    /** Renames private fields/methods and fixes up all in-class call sites. Returns count renamed. */
    private static int applyRename(ClassNode cn) {
        Map<String, String> fieldRenames = new HashMap<>(); // old name -> new name
        Map<String, String> methodRenames = new HashMap<>(); // "oldName descriptor" -> new name
        int count = 0;

        for (FieldNode f : cn.fields) {
            boolean isPrivate = (f.access & Opcodes.ACC_PRIVATE) != 0;
            boolean isSynthetic = (f.access & Opcodes.ACC_SYNTHETIC) != 0;
            if (isPrivate && !isSynthetic) {
                String newName = "f_" + randHex(8);
                fieldRenames.put(f.name, newName);
                f.name = newName;
                count++;
            }
        }
        for (MethodNode m : cn.methods) {
            boolean isPrivate = (m.access & Opcodes.ACC_PRIVATE) != 0;
            boolean isCtorOrClinit = m.name.equals("<init>") || m.name.equals("<clinit>");
            boolean isSynthetic = (m.access & Opcodes.ACC_SYNTHETIC) != 0 || (m.access & Opcodes.ACC_BRIDGE) != 0;
            boolean isMain = m.name.equals("main") && m.desc.equals("([Ljava/lang/String;)V");
            if (isPrivate && !isCtorOrClinit && !isSynthetic && !isMain) {
                String newName = "m_" + randHex(8);
                methodRenames.put(m.name + " " + m.desc, newName);
                m.name = newName;
                count++;
            }
        }

        // Fix up call sites: ASM's tree API stores FieldInsnNode/MethodInsnNode
        // name as a plain string, not a live reference -- renaming the
        // FieldNode/MethodNode alone does NOT update instructions that call
        // it, so every reference within this class must be patched by hand.
        for (MethodNode m : cn.methods) {
            for (AbstractInsnNode insn : m.instructions) {
                if (insn instanceof FieldInsnNode fin && fin.owner.equals(cn.name)) {
                    String newName = fieldRenames.get(fin.name);
                    if (newName != null) fin.name = newName;
                } else if (insn instanceof MethodInsnNode min && min.owner.equals(cn.name)) {
                    String newName = methodRenames.get(min.name + " " + min.desc);
                    if (newName != null) min.name = newName;
                }
            }
        }
        return count;
    }

    private static int applyStrEnc(ClassNode cn, int key) {
        String decryptOwner = Type.getInternalName(StrDec.class);
        String decryptDesc = "(Ljava/lang/String;I)Ljava/lang/String;";
        int count = 0;

        for (MethodNode m : cn.methods) {
            InsnList insns = m.instructions;
            for (AbstractInsnNode insn : insns.toArray()) {
                if (insn instanceof LdcInsnNode ldc && ldc.cst instanceof String s) {
                    byte[] utf8 = s.getBytes(StandardCharsets.UTF_8);
                    char[] obfChars = new char[utf8.length];
                    for (int i = 0; i < utf8.length; i++) {
                        obfChars[i] = (char) ((utf8[i] ^ key) & 0xFF);
                    }
                    ldc.cst = new String(obfChars);

                    InsnList extra = new InsnList();
                    extra.add(intPush(key));
                    extra.add(new MethodInsnNode(Opcodes.INVOKESTATIC, decryptOwner, "decrypt", decryptDesc, false));
                    insns.insert(ldc, extra);
                    count++;
                }
            }
        }
        return count;
    }

    private static AbstractInsnNode intPush(int value) {
        if (value >= -1 && value <= 5) return new InsnNode(Opcodes.ICONST_0 + value);
        if (value >= Byte.MIN_VALUE && value <= Byte.MAX_VALUE) return new IntInsnNode(Opcodes.BIPUSH, value);
        if (value >= Short.MIN_VALUE && value <= Short.MAX_VALUE) return new IntInsnNode(Opcodes.SIPUSH, value);
        return new LdcInsnNode(value);
    }

    private static String randHex(int n) {
        byte[] b = new byte[n / 2];
        RNG.nextBytes(b);
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    private static void runTest(Path classpathRoot, String fqcn) throws Exception {
        String javaBin = Path.of(System.getProperty("java.home"), "bin", "java").toString();
        Path runtimeJar = findRuntimeJar();
        String cp = runtimeJar != null ? classpathRoot + File.pathSeparator + classpathRoot.resolve(runtimeJar.getFileName())
                : classpathRoot.toString();
        ProcessBuilder pb = new ProcessBuilder(javaBin, "-cp", cp, fqcn);
        pb.redirectErrorStream(false);
        Process p = pb.start();
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        String err = new String(p.getErrorStream().readAllBytes(), StandardCharsets.UTF_8);
        int rc = p.waitFor();
        if (rc == 0) {
            System.out.println("[ok] Test passed: class executed successfully");
            if (!out.isBlank()) System.out.println("Output:\n" + out);
        } else {
            System.out.println("[!] Test failed with exit code " + rc);
            if (!err.isBlank()) System.out.println("Error:\n" + err);
        }
    }
}
