package com.g0w6y.obsor.pro;

// Key derivation for Obsor.Pro (Java).
//
// Unlike the .NET port's FIRST version (which shipped with PBKDF2 because
// the .NET BCL has no memory-hard KDF, then had to be fixed later -- see
// dotnet/Obsor.Pro/KeyDerive.cs's own history), this starts with Argon2id
// from day one via BouncyCastle (org.bouncycastle:bcprov-jdk18on), a
// well-known pure-Java crypto library with no native dependency. Parameters
// below (128 MiB, 3 iterations, parallelism 1) match the same memory/cost
// ballpark as Python/JS's scrypt and .NET's (now-fixed) Argon2id -- measured
// on this machine at ~270ms per derivation.
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.MessageDigest;
import java.util.Arrays;

public final class KeyDerive {
    public static final int ARGON2_MEMORY_KIB = 128 * 1024;
    public static final int ARGON2_ITERATIONS = 3;
    public static final int ARGON2_PARALLELISM = 1;
    public static final int DK_LEN = 32; // AES-256
    public static final int MIN_SECRET_LEN = 12;

    private KeyDerive() {}

    public static byte[] machineSecret() {
        try {
            String parts = System.getProperty("os.name", "") + "|" + java.net.InetAddress.getLocalHost().getHostName()
                    + "|" + Runtime.getRuntime().availableProcessors();
            return MessageDigest.getInstance("SHA-256").digest(parts.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void warnIfWeak(String secret) {
        if (secret.length() < MIN_SECRET_LEN) {
            System.err.println("[obsor] WARNING: secret is " + secret.length() + " chars; use >= " +
                    MIN_SECRET_LEN + " (a passphrase, not a word). A short secret is brute-forceable offline " +
                    "despite Argon2id's memory cost.");
        }
    }

    public static byte[] resolveSecret(String mode, String passphrase) {
        switch (mode) {
            case "pass":
                if (passphrase == null || passphrase.isEmpty())
                    throw new IllegalArgumentException("pass mode needs a passphrase (-k/--key)");
                warnIfWeak(passphrase);
                return passphrase.getBytes(StandardCharsets.UTF_8);
            case "machine":
                return machineSecret();
            case "license":
                if (passphrase == null || passphrase.isEmpty())
                    throw new IllegalArgumentException("license mode needs a token (-k/--key)");
                warnIfWeak(passphrase);
                return passphrase.getBytes(StandardCharsets.UTF_8);
            default:
                throw new IllegalArgumentException("unknown key mode: " + mode);
        }
    }

    public static byte[] deriveKey(byte[] secret, byte[] salt) {
        Argon2Parameters params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withIterations(ARGON2_ITERATIONS)
                .withMemoryAsKB(ARGON2_MEMORY_KIB)
                .withParallelism(ARGON2_PARALLELISM)
                .withSalt(salt)
                .build();
        Argon2BytesGenerator gen = new Argon2BytesGenerator();
        gen.init(params);
        byte[] out = new byte[DK_LEN];
        gen.generateBytes(secret, out);
        return out;
    }
}
