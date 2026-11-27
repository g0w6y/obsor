package com.g0w6y.obsor.pro;

// Obsor.Pro (Java) command-line interface.
//   java -jar obsor-pro.jar -i App.java -o dist/app.jar --tier hardened -k "secret"
//
// Tiers:
//   hardened     : javac-compile the payload in-memory, AES-256-GCM-encrypt
//                  it with an Argon2id-derived key, emit a launcher jar
//                  that decrypts and ClassLoader.defineClass()s it.
//   native-logic : hardened PLUS a developer-supplied crown-jewel routine
//                  compiled to a native library and called via JNI -- the
//                  only tier that resists a key-holder. See
//                  nativelogic/LogicBuild.java.
public final class CliMain {
    public static void main(String[] args) throws Exception {
        String input = null, output = null, keyMode = "pass", key = null, tier = "hardened";
        boolean guard = false;

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "-i": case "--input": input = args[++i]; break;
                case "-o": case "--output": output = args[++i]; break;
                case "--tier": tier = args[++i]; break;
                case "--key-mode": keyMode = args[++i]; break;
                case "-k": case "--key": key = args[++i]; break;
                case "--guard": guard = true; break;
                default:
                    System.err.println("[!] Unknown argument: " + args[i]);
                    System.exit(1);
            }
        }

        if (input == null || output == null) {
            System.err.println("Usage: obsor-pro -i INPUT.java -o OUTPUT.jar [--tier hardened] " +
                    "[--key-mode pass|machine|license] [-k KEY] [--guard]");
            System.exit(1);
            return;
        }
        if (!tier.equals("hardened")) {
            System.err.println("[!] CLI only wires the hardened tier; native-logic is a library API " +
                    "(see nativelogic/LogicBuild.java + examples/native_logic).");
            System.exit(1);
            return;
        }
        if ((keyMode.equals("pass") || keyMode.equals("license")) && (key == null || key.isEmpty())) {
            System.err.println("[!] --key-mode " + keyMode + " requires -k/--key");
            System.exit(1);
            return;
        }
        if (!java.nio.file.Files.exists(java.nio.file.Path.of(input))) {
            System.err.println("[!] Input file not found: " + input);
            System.exit(1);
            return;
        }

        Engine.protectFile(input, output, keyMode, key, guard);
        String envVar = keyMode.equals("license") ? "OBSOR_LICENSE" : "OBSOR_KEY";
        System.out.println("[+] hardened artifact: " + output);
        if (keyMode.equals("machine")) System.out.println("    runs only on THIS host (machine-bound)");
        else System.out.println("    run with: " + envVar + "=<secret> java -jar " + output);
    }
}
