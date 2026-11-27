// Key derivation for Obsor.Pro.
//
// Previously PBKDF2-HMACSHA256 (not memory-hard). As of 2026-11-27 this is
// Argon2id via Konscious.Security.Cryptography.Argon2 -- a small, pure-.NET
// NuGet package with no native dependency, closing the gap flagged in
// dotnet/Obsor.Pro/README.md "Honest limits". Parameters below (128 MiB,
// 3 iterations, parallelism 1) were chosen to land in the same memory/cost
// ballpark as the scrypt parameters Python/JS PRO use (N=2^17, ~128 MiB),
// not copied from an OWASP minimum -- measured on this machine at ~500ms
// per derivation, see Obsor.Pro/README.md "Measured resistance".
using System;
using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;

namespace Obsor.Pro;

public static class KeyDerive
{
    public const int Argon2MemoryKiB = 128 * 1024; // 128 MiB
    public const int Argon2Iterations = 3;
    public const int Argon2Parallelism = 1;
    public const int DkLen = 32; // AES-256
    public const int MinSecretLen = 12;

    public static byte[] MachineSecret()
    {
        // No uuid.getnode()/os.networkInterfaces() MAC-binding dependency
        // here -- Environment.MachineName + a stable OS id is spoofable in
        // exactly the same spirit as Python/JS "machine" mode.
        var parts = $"{Environment.MachineName}|{Environment.OSVersion.Platform}|{Environment.ProcessorCount}";
        return SHA256.HashData(Encoding.UTF8.GetBytes(parts));
    }

    public static void WarnIfWeak(string secret)
    {
        if (secret.Length < MinSecretLen)
            Console.Error.WriteLine($"[obsor] WARNING: secret is {secret.Length} chars; use >= " +
                $"{MinSecretLen} (a passphrase, not a word). A short secret is brute-forceable offline " +
                "despite Argon2id's memory cost.");
    }

    public static byte[] ResolveSecret(string mode, string? passphrase)
    {
        switch (mode)
        {
            case "pass":
                if (string.IsNullOrEmpty(passphrase)) throw new ArgumentException("pass mode needs a passphrase (-k/--key)");
                WarnIfWeak(passphrase);
                return Encoding.UTF8.GetBytes(passphrase);
            case "machine":
                return MachineSecret();
            case "license":
                if (string.IsNullOrEmpty(passphrase)) throw new ArgumentException("license mode needs a token (-k/--key)");
                WarnIfWeak(passphrase);
                return Encoding.UTF8.GetBytes(passphrase);
            default:
                throw new ArgumentException($"unknown key mode: {mode}");
        }
    }

    public static byte[] DeriveKey(byte[] secret, byte[] salt)
    {
        using var argon2 = new Argon2id(secret)
        {
            Salt = salt,
            DegreeOfParallelism = Argon2Parallelism,
            Iterations = Argon2Iterations,
            MemorySize = Argon2MemoryKiB,
        };
        return argon2.GetBytes(DkLen);
    }
}
