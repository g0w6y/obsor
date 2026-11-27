// Obsor.Pro hardened engine (Tier 1, pure .NET, no native compiler).
//
// This is the "crypter" pattern, the real .NET analog of Python's marshal+
// AES-GCM and JS's minify+AES-GCM: compile the payload to a normal managed
// assembly, AES-256-GCM-encrypt the bytes with a key that is NEVER stored
// (re-derived at runtime via PBKDF2 -- see KeyDerive.cs for why not scrypt),
// and emit a tiny launcher assembly that decrypts and
// `Assembly.Load(byte[])`s the payload, then invokes its entry point via
// reflection.
//
// HONEST CEILING: identical shape to Python/JS. The payload becomes a live,
// loaded managed assembly, so anyone who can run it (a licensed customer
// holding the key) can recover it -- verified in this repo via
// AppDomain.CurrentDomain.AssemblyLoad + MethodBase.GetMethodBody().
// GetILAsByteArray() on every loaded method, which fully reconstructs the
// IL with no debugger attached. See dotnet/Obsor.Pro/README.md "Measured
// resistance" for the actual numbers from attacking this repo's own output.
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;

namespace Obsor.Pro;

public static class Engine
{
    public static byte[] CompilePayload(string source, string assemblyName)
    {
        var tree = CSharpSyntaxTree.ParseText(source);
        var tpa = (string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!;
        var refs = tpa.Split(Path.PathSeparator).Select(p => MetadataReference.CreateFromFile(p)).ToArray();
        var compilation = CSharpCompilation.Create(assemblyName, new[] { tree }, refs,
            new CSharpCompilationOptions(OutputKind.ConsoleApplication));
        using var ms = new MemoryStream();
        var result = compilation.Emit(ms);
        if (!result.Success)
        {
            foreach (var d in result.Diagnostics.Where(d => d.Severity == DiagnosticSeverity.Error))
                Console.Error.WriteLine(d);
            throw new InvalidOperationException("payload compilation failed");
        }
        return ms.ToArray();
    }

    /// <summary>Compile a launcher assembly that decrypts and runs the payload. Returns the launcher bytes.</summary>
    public static byte[] Protect(string source, string keyMode = "pass", string? passphrase = null,
        bool guard = false, string payloadName = "payload")
    {
        var secret = KeyDerive.ResolveSecret(keyMode, passphrase);
        var salt = RandomNumberGenerator.GetBytes(16);
        var key = KeyDerive.DeriveKey(secret, salt);

        var payload = CompilePayload(source, payloadName);

        var nonce = RandomNumberGenerator.GetBytes(12);
        var tag = new byte[16];
        var ct = new byte[payload.Length];
        using (var gcm = new AesGcm(key, 16))
            gcm.Encrypt(nonce, payload, ct, tag);

        var launcherSrc = BuildLauncherSource(salt, nonce, tag, ct, keyMode, guard);
        var tree = CSharpSyntaxTree.ParseText(launcherSrc);
        var tpa = (string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!;
        var refs = tpa.Split(Path.PathSeparator).Select(p => MetadataReference.CreateFromFile(p)).ToList();
        refs.Add(MetadataReference.CreateFromFile(typeof(KeyDerive).Assembly.Location));
        var compilation = CSharpCompilation.Create("launcher", new[] { tree }, refs,
            new CSharpCompilationOptions(OutputKind.ConsoleApplication));
        using var ms = new MemoryStream();
        var result = compilation.Emit(ms);
        if (!result.Success)
        {
            foreach (var d in result.Diagnostics.Where(d => d.Severity == DiagnosticSeverity.Error))
                Console.Error.WriteLine(d);
            throw new InvalidOperationException("launcher compilation failed");
        }
        return ms.ToArray();
    }

    public static void ProtectFile(string inPath, string outPath, string keyMode = "pass",
        string? passphrase = null, bool guard = false)
    {
        var source = File.ReadAllText(inPath);
        var launcherBytes = Protect(source, keyMode, passphrase, guard, Path.GetFileNameWithoutExtension(inPath));
        var outDir = Path.GetDirectoryName(Path.GetFullPath(outPath))!;
        Directory.CreateDirectory(outDir);
        File.WriteAllBytes(outPath, launcherBytes);

        // Copy Obsor.Pro.dll AND its transitive dependencies (Konscious's
        // Argon2id implementation) -- the launcher calls into KeyDerive at
        // runtime, so everything KeyDerive itself needs must ship too.
        var proDllPath = typeof(KeyDerive).Assembly.Location; // "obsor-pro.dll" (AssemblyName in the csproj), not "Obsor.Pro.dll"
        var proDir = Path.GetDirectoryName(proDllPath)!;
        foreach (var dep in new[] { Path.GetFileName(proDllPath), "Konscious.Security.Cryptography.Argon2.dll", "Konscious.Security.Cryptography.Blake2.dll" })
        {
            var src = Path.Combine(proDir, dep);
            if (File.Exists(src)) File.Copy(src, Path.Combine(outDir, dep), overwrite: true);
        }

        var outBase = Path.Combine(outDir, Path.GetFileNameWithoutExtension(outPath));
        File.WriteAllText(outBase + ".runtimeconfig.json",
            """{"runtimeOptions":{"tfm":"net8.0","framework":{"name":"Microsoft.NETCore.App","version":"8.0.0"},"rollForward":"LatestMinor"}}""");
    }

    private static string BuildLauncherSource(byte[] salt, byte[] nonce, byte[] tag, byte[] ct, string keyMode, bool guard)
    {
        string b64(byte[] b) => Convert.ToBase64String(b);
        string envVar = keyMode == "license" ? "OBSOR_LICENSE" : "OBSOR_KEY";
        string guardCall = guard ? "Obsor.Pro.Guard.Check();" : "";

        // Randomized per-build identifiers, same spirit as Python/JS hardened
        // -- no two outputs share a static class/variable-name signature.
        string rid() => "_" + Guid.NewGuid().ToString("N")[..8];
        string clsName = "L" + Guid.NewGuid().ToString("N")[..8];
        string vSecret = rid(), vSalt = rid(), vNonce = rid(), vTag = rid(), vCt = rid(), vKey = rid(), vPt = rid(), vAsm = rid(), vEntry = rid(), vParams = rid();

        return $$"""
        using System;
        using Obsor.Pro;
        internal static class {{clsName}}
        {
            private static void Main()
            {
                {{guardCall}}
                var {{vSecret}} = KeyDerive.ResolveSecret({{Lit(keyMode)}}, Environment.GetEnvironmentVariable({{Lit(envVar)}}));
                if ({{vSecret}} is null || {{vSecret}}.Length == 0) Environment.Exit(1);
                var {{vSalt}} = Convert.FromBase64String({{Lit(b64(salt))}});
                var {{vNonce}} = Convert.FromBase64String({{Lit(b64(nonce))}});
                var {{vTag}} = Convert.FromBase64String({{Lit(b64(tag))}});
                var {{vCt}} = Convert.FromBase64String({{Lit(b64(ct))}});
                var {{vKey}} = KeyDerive.DeriveKey({{vSecret}}, {{vSalt}});
                var {{vPt}} = new byte[{{vCt}}.Length];
                try
                {
                    using var gcm = new System.Security.Cryptography.AesGcm({{vKey}}, 16);
                    gcm.Decrypt({{vNonce}}, {{vCt}}, {{vTag}}, {{vPt}});
                }
                catch { Environment.Exit(1); return; }
                var {{vAsm}} = System.Reflection.Assembly.Load({{vPt}});
                var {{vEntry}} = {{vAsm}}.EntryPoint;
                if ({{vEntry}} is null) { Environment.Exit(1); return; }
                var {{vParams}} = {{vEntry}}.GetParameters().Length == 0 ? null : new object[] { Array.Empty<string>() };
                {{vEntry}}.Invoke(null, {{vParams}});
            }
        }
        """;
    }

    private static string Lit(string s) => "\"" + s.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";
}
