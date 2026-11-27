package com.g0w6y.obsor.pro;

// Obsor.Pro hardened engine (Java, Tier 1, pure JVM, no native compiler).
//
// Same shape as the Python/JS/.NET hardened engines: compile the payload to
// a normal class file, AES-256-GCM-encrypt the bytes with a key that is
// NEVER stored (re-derived at runtime via Argon2id -- see KeyDerive.java),
// and emit a launcher that decrypts the embedded resource and loads it via
// a custom ClassLoader.defineClass(), then invokes its main() via
// reflection.
//
// Packaging choice specific to this port: the encrypted payload is embedded
// as a JAR RESOURCE ("payload.enc"), not a base64 string literal in the
// generated source the way Python/JS/.NET embed their ciphertext. Reason:
// the JVM class file format caps a single UTF8 constant-pool entry at 65535
// bytes -- a large payload base64-encoded into a source literal could
// exceed that. A jar resource has no such limit and is the idiomatic way to
// ship data alongside Java bytecode.
//
// HONEST CEILING: identical to the other three languages. The payload
// becomes a live, loaded class, so anyone who can run it (a licensed
// customer holding the key) can recover it. Unlike .NET (which needed a
// dedicated AssemblyLoad-hook test to prove this), Java's version of that
// attack is even more standard: any `-javaagent` using
// `Instrumentation.addTransformer` sees every class defined by ANY
// ClassLoader, including ours, and gets handed the exact bytes passed to
// `defineClass` -- see Obsor.Pro's README "Measured resistance" for the
// actual command and output.
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.tools.JavaCompiler;
import javax.tools.ToolProvider;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.SecureRandom;
import java.util.UUID;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;

public final class Engine {
    private static final SecureRandom RNG = new SecureRandom();

    private Engine() {}

    public record CompiledPayload(byte[] classBytes, String fqcn) {}

    public static CompiledPayload compilePayload(String source, String fallbackClassName) throws IOException {
        String fqcn = extractPublicClassName(source).orElse(fallbackClassName);
        Path workDir = Files.createTempDirectory("obsor_pro_payload_");
        Path srcFile = workDir.resolve(fqcn + ".java");
        Files.writeString(srcFile, source);

        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        if (compiler == null) throw new IllegalStateException("No system Java compiler available (need a JDK, not just a JRE)");
        int rc = compiler.run(null, null, null, srcFile.toString(), "-d", workDir.toString());
        if (rc != 0) throw new IllegalStateException("payload compilation failed (exit " + rc + ")");

        Path classFile = workDir.resolve(fqcn + ".class");
        if (!Files.exists(classFile)) throw new IllegalStateException("javac produced no class named " + fqcn + " -- the public class name must match the generated filename");
        return new CompiledPayload(Files.readAllBytes(classFile), fqcn);
    }

    private static java.util.Optional<String> extractPublicClassName(String source) {
        var m = java.util.regex.Pattern.compile("public\\s+(?:final\\s+)?class\\s+(\\w+)").matcher(source);
        return m.find() ? java.util.Optional.of(m.group(1)) : java.util.Optional.empty();
    }

    public static byte[] protect(String source, String keyMode, String passphrase, boolean guard, String fallbackClassName) throws Exception {
        return protect(source, keyMode, passphrase, guard, fallbackClassName, null);
    }

    /**
     * Builds the launcher jar bytes. If {@code nativeLibFileName} is non-null
     * (the native-logic tier), the launcher also exports the absolute path
     * of that file (resolved relative to the launcher jar's own directory)
     * via a system property, since a native library JNI-registers against
     * the ClassLoader that loads it -- the PAYLOAD class (defined by our
     * custom ClassLoader) must be the one calling System.load, not the
     * launcher (loaded by the ordinary application ClassLoader), so the
     * payload needs a way to learn the absolute path itself. See
     * examples/native_logic/App.java for the expected payload-side pattern:
     * {@code System.load(System.getProperty("obsor.native.lib.path"))}.
     */
    public static byte[] protect(String source, String keyMode, String passphrase, boolean guard,
                                  String fallbackClassName, String nativeLibFileName) throws Exception {
        CompiledPayload payload = compilePayload(source, fallbackClassName);

        byte[] secret = KeyDerive.resolveSecret(keyMode, passphrase);
        byte[] salt = new byte[16];
        RNG.nextBytes(salt);
        byte[] key = KeyDerive.deriveKey(secret, salt);

        byte[] nonce = new byte[12];
        RNG.nextBytes(nonce);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        byte[] ctWithTag = cipher.doFinal(payload.classBytes());

        byte[] packed = new byte[salt.length + nonce.length + ctWithTag.length];
        System.arraycopy(salt, 0, packed, 0, salt.length);
        System.arraycopy(nonce, 0, packed, salt.length, nonce.length);
        System.arraycopy(ctWithTag, 0, packed, salt.length + nonce.length, ctWithTag.length);

        String launcherClassName = "L" + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
        String launcherSource = buildLauncherSource(launcherClassName, payload.fqcn(), keyMode, guard, nativeLibFileName);
        // The launcher source declares an anonymous ClassLoader subclass,
        // which javac compiles into ITS OWN class file (e.g. L7418ac9c$1)
        // alongside the named one -- both must ship in the jar, or the
        // launcher throws NoClassDefFoundError the moment it's loaded.
        java.util.Map<String, byte[]> launcherClasses = compileLauncher(launcherClassName, launcherSource);

        return packageJar(launcherClassName, launcherClasses, packed);
    }

    public static void protectFile(String inPath, String outPath, String keyMode, String passphrase, boolean guard) throws Exception {
        protectFile(inPath, outPath, keyMode, passphrase, guard, null);
    }

    public static void protectFile(String inPath, String outPath, String keyMode, String passphrase, boolean guard,
                                    String nativeLibFileName) throws Exception {
        String source = Files.readString(Path.of(inPath));
        String fallback = Path.of(inPath).getFileName().toString().replace(".java", "");
        byte[] launcherJar = protect(source, keyMode, passphrase, guard, fallback, nativeLibFileName);

        Path out = Path.of(outPath);
        Files.createDirectories(out.getParent() == null ? Path.of(".") : out.getParent());
        Files.write(out, launcherJar);

        // Companion classpath jar (holds KeyDerive + BouncyCastle), same
        // "ship both files together" pattern as the other three languages'
        // native/hardened tiers.
        Path runtimeFatJar = findRunningJar();
        if (runtimeFatJar != null) {
            Path dest = out.getParent() == null ? Path.of(runtimeFatJar.getFileName().toString())
                    : out.getParent().resolve(runtimeFatJar.getFileName());
            Files.copy(runtimeFatJar, dest, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private static Path findRunningJar() {
        try {
            String path = Engine.class.getProtectionDomain().getCodeSource().getLocation().toURI().getPath();
            Path p = Path.of(path);
            return p.toString().endsWith(".jar") ? p : null;
        } catch (Exception e) {
            return null;
        }
    }

    private static String buildLauncherSource(String className, String payloadFqcn, String keyMode, boolean guard,
                                               String nativeLibFileName) {
        String envVar = keyMode.equals("license") ? "OBSOR_LICENSE" : "OBSOR_KEY";
        String guardCall = guard ? "com.g0w6y.obsor.pro.Guard.check(0.05);" : "";
        // Native-logic only: export the native lib's absolute path (resolved
        // relative to THIS jar's own directory) via a system property, since
        // the payload class -- not this launcher -- must be the one calling
        // System.load (JNI resolves native symbols against the ClassLoader
        // that loaded the library, which must match the ClassLoader of the
        // class declaring the native method).
        String nativeLibSetup = nativeLibFileName == null ? "" : ("""
                try {
                    java.io.File jarFile = new java.io.File(%s.class.getProtectionDomain().getCodeSource().getLocation().toURI());
                    java.io.File libFile = new java.io.File(jarFile.getParentFile(), "%s");
                    System.setProperty("obsor.native.lib.path", libFile.getAbsolutePath());
                } catch (Exception e) { System.exit(1); return; }
        """.formatted(className, nativeLibFileName));
        return """
        public final class %s {
            public static void main(String[] args) throws Exception {
                %s
                %s
                byte[] secret = com.g0w6y.obsor.pro.KeyDerive.resolveSecret("%s", System.getenv("%s"));
                if (secret == null || secret.length == 0) System.exit(1);
                java.io.InputStream in = %s.class.getResourceAsStream("/payload.enc");
                byte[] packed = in.readAllBytes();
                byte[] salt = java.util.Arrays.copyOfRange(packed, 0, 16);
                byte[] nonce = java.util.Arrays.copyOfRange(packed, 16, 28);
                byte[] ct = java.util.Arrays.copyOfRange(packed, 28, packed.length);
                byte[] key = com.g0w6y.obsor.pro.KeyDerive.deriveKey(secret, salt);
                byte[] pt;
                try {
                    javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
                    cipher.init(javax.crypto.Cipher.DECRYPT_MODE, new javax.crypto.spec.SecretKeySpec(key, "AES"),
                            new javax.crypto.spec.GCMParameterSpec(128, nonce));
                    pt = cipher.doFinal(ct);
                } catch (Exception e) {
                    System.exit(1);
                    return;
                }
                final byte[] fpt = pt;
                ClassLoader loader = new ClassLoader(%s.class.getClassLoader()) {
                    protected Class<?> findClass(String name) throws ClassNotFoundException {
                        if (!name.equals("%s")) throw new ClassNotFoundException(name);
                        return defineClass(name, fpt, 0, fpt.length);
                    }
                };
                Class<?> cls = loader.loadClass("%s");
                java.lang.reflect.Method m = cls.getMethod("main", String[].class);
                m.invoke(null, (Object) new String[0]);
            }
        }
        """.formatted(className, guardCall, nativeLibSetup, keyMode, envVar, className, className, payloadFqcn, payloadFqcn);
    }

    /** Returns every .class file javac produced (named class + any anonymous/inner classes), keyed by class file name. */
    private static java.util.Map<String, byte[]> compileLauncher(String className, String source) throws IOException {
        Path workDir = Files.createTempDirectory("obsor_pro_launcher_");
        Path srcFile = workDir.resolve(className + ".java");
        Files.writeString(srcFile, source);

        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        String classpath = System.getProperty("java.class.path");
        int rc = compiler.run(null, null, null, "-cp", classpath, srcFile.toString(), "-d", workDir.toString());
        if (rc != 0) throw new IllegalStateException("launcher compilation failed (exit " + rc + ")");

        java.util.Map<String, byte[]> classes = new java.util.LinkedHashMap<>();
        try (var stream = Files.walk(workDir)) {
            for (Path p : (Iterable<Path>) stream.filter(p -> p.toString().endsWith(".class"))::iterator) {
                classes.put(p.getFileName().toString(), Files.readAllBytes(p));
            }
        }
        if (!classes.containsKey(className + ".class"))
            throw new IllegalStateException("javac produced no class named " + className);
        return classes;
    }

    private static byte[] packageJar(String launcherClassName, java.util.Map<String, byte[]> launcherClasses, byte[] payloadEnc) throws IOException {
        Manifest manifest = new Manifest();
        manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
        manifest.getMainAttributes().put(Attributes.Name.MAIN_CLASS, launcherClassName);
        Path runtimeFatJar = findRunningJar();
        if (runtimeFatJar != null) {
            manifest.getMainAttributes().put(Attributes.Name.CLASS_PATH, runtimeFatJar.getFileName().toString());
        }

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (JarOutputStream jos = new JarOutputStream(baos, manifest)) {
            for (var entry : launcherClasses.entrySet()) {
                jos.putNextEntry(new JarEntry(entry.getKey()));
                jos.write(entry.getValue());
                jos.closeEntry();
            }

            jos.putNextEntry(new JarEntry("payload.enc"));
            jos.write(payloadEnc);
            jos.closeEntry();
        }
        return baos.toByteArray();
    }
}
