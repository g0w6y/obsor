// Key derivation for Obsor.Pro.
//
// HONEST GAP vs Python/JS PRO: both of those use scrypt (memory-hard).
// .NET's BCL has no scrypt implementation, and pulling one in means an
// extra NuGet dependency (e.g. Konscious.Security.Cryptography, Argon2) --
// a call this project hasn't made yet (see dotnet/README.md "Why .NET PRO
// != Python/JS PRO"). This uses PBKDF2-HMACSHA256 (System.Security.
// Cryptography.Rfc2898DeriveBytes, builtin, no NuGet) with a high iteration
// count instead. PBKDF2 is NOT memory-hard the way scrypt is: a GPU/ASIC
// attacker gets much more parallelism against it per watt than against
// scrypt for the same CPU-time cost. Treat the "offline brute force
// infeasible" claims in pro/README.md as weaker for .NET than for the other
// two languages until this gets a real memory-hard KDF.
using System;
using System.Security.Cryptography;
using System.Text;

namespace Obsor.Pro;

public static class KeyDerive
{
    public const int Iterations = 600_000; // OWASP 2023 minimum for PBKDF2-SHA256
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
                $"{MinSecretLen} (a passphrase, not a word). A short secret is brute-forceable " +
                "offline, more so here than the scrypt-based Python/JS tiers (see KeyDerive.cs).");
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

    public static byte[] DeriveKey(byte[] secret, byte[] salt) =>
        Rfc2898DeriveBytes.Pbkdf2(secret, salt, Iterations, HashAlgorithmName.SHA256, DkLen);
}
