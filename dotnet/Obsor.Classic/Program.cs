// Obsor.Classic -- IL-level obfuscator for compiled .NET assemblies.
//
// Unlike the Python/JS classic engines (which stack text-encoding layers
// around source and re-interpret it at runtime via exec/eval), .NET has no
// portable "exec arbitrary source text" primitive outside Roslyn, and real
// .NET obfuscators (ConfuserEx, Obfuscar, dotNET Reactor's weaker modes) all
// work the same way: rewrite the compiled assembly's IL in place via
// Mono.Cecil. That's what this does. See dotnet/README.md for the full
// architectural-difference writeup -- this is not a thinner port, it is a
// different (but equally real) model.
//
//   obsor-classic -i app.dll -o protected.dll --methods rename,strenc
//   obsor-classic -i App.cs  -o protected.dll --methods strenc -k 0x5A
//
using System;
using System.IO;
using System.Linq;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;

namespace Obsor.Classic;

internal static class Program
{
    private static readonly string[] AllMethods = { "rename", "strenc" };

    private static int Main(string[] args)
    {
        string? input = null, output = null, methodsArg = null, keyArg = null;
        bool listMethods = false, test = false;

        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "-i": case "--input": input = args[++i]; break;
                case "-o": case "--output": output = args[++i]; break;
                case "-m": case "--methods": methodsArg = args[++i]; break;
                case "-k": case "--key": keyArg = args[++i]; break;
                case "--list-methods": listMethods = true; break;
                case "--test": test = true; break;
                default:
                    Console.Error.WriteLine($"[!] Unknown argument: {args[i]}");
                    return 1;
            }
        }

        if (listMethods)
        {
            Console.WriteLine("Available methods:");
            Console.WriteLine("  rename  - randomize private member names (fields, methods)");
            Console.WriteLine("  strenc  - XOR-encrypt string literals, call ObsorRuntime.StrDec.Decrypt at each site");
            Console.WriteLine("\nUnlike Python/JS, there is no preset stack of 20+ interchangeable");
            Console.WriteLine("encodings here -- .NET's unit of obfuscation is IL members and");
            Console.WriteLine("literals, not swappable text transforms. See dotnet/README.md.");
            return 0;
        }

        if (input is null || output is null)
        {
            Console.Error.WriteLine("Usage: obsor-classic -i INPUT(.cs|.dll|.exe) -o OUTPUT.dll [-m rename,strenc] [-k 0xNN] [--test]");
            return 1;
        }

        var methods = (methodsArg ?? "rename,strenc").Split(',').Select(s => s.Trim()).ToArray();
        foreach (var m in methods)
        {
            if (!AllMethods.Contains(m))
            {
                Console.Error.WriteLine($"[!] Unknown method: {m}");
                return 1;
            }
        }

        byte key = keyArg is null
            ? (byte)new Random().Next(1, 256)
            : Convert.ToByte(keyArg, keyArg.StartsWith("0x") ? 16 : 10);
        if (keyArg is null) Console.WriteLine($"[!] Generated random XOR key: 0x{key:X2}");

        byte[] assemblyBytes;
        if (input.EndsWith(".cs", StringComparison.OrdinalIgnoreCase))
        {
            Console.WriteLine($"[*] Compiling {input} via Roslyn...");
            assemblyBytes = CompileSource(File.ReadAllText(input), Path.GetFileNameWithoutExtension(input));
        }
        else
        {
            assemblyBytes = File.ReadAllBytes(input);
        }

        using var ms = new MemoryStream(assemblyBytes);
        var module = ModuleDefinition.ReadModule(ms);

        // Always resolve the shipped runtime helper for string decryption,
        // even if "strenc" wasn't requested, so the reference is consistent;
        // only actually used if strenc runs.
        var runtimeDllPath = Path.Combine(AppContext.BaseDirectory, "Obsor.Runtime.dll");
        MethodReference? decryptRef = null;
        if (methods.Contains("strenc"))
        {
            if (!File.Exists(runtimeDllPath))
            {
                Console.Error.WriteLine($"[!] Obsor.Runtime.dll not found next to obsor-classic at {runtimeDllPath}");
                return 1;
            }
            var runtimeModule = ModuleDefinition.ReadModule(runtimeDllPath);
            var decryptDef = runtimeModule.GetType("ObsorRuntime.StrDec").Methods.First(m => m.Name == "Decrypt");
            decryptRef = module.ImportReference(decryptDef);
        }

        int renamed = 0, stringsEnc = 0;
        foreach (var type in module.Types)
        {
            if (type.Name == "<Module>") continue;

            if (methods.Contains("strenc"))
            {
                foreach (var method in type.Methods)
                {
                    if (!method.HasBody) continue;
                    var il = method.Body.GetILProcessor();
                    foreach (var instr in method.Body.Instructions.ToList())
                    {
                        if (instr.OpCode == OpCodes.Ldstr && instr.Operand is string s)
                        {
                            var bytes = System.Text.Encoding.UTF8.GetBytes(s);
                            for (int i = 0; i < bytes.Length; i++) bytes[i] ^= key;
                            instr.Operand = string.Concat(bytes.Select(b => (char)b));
                            var ldKey = il.Create(OpCodes.Ldc_I4, (int)key);
                            var callDecrypt = il.Create(OpCodes.Call, decryptRef);
                            il.InsertAfter(instr, ldKey);
                            il.InsertAfter(ldKey, callDecrypt);
                            stringsEnc++;
                        }
                    }
                }
            }

            if (methods.Contains("rename"))
            {
                foreach (var field in type.Fields.ToList())
                {
                    if (field.IsPrivate && !field.Name.StartsWith("<"))
                    {
                        field.Name = "_f" + Guid.NewGuid().ToString("N")[..8];
                        renamed++;
                    }
                }
                foreach (var method in type.Methods.ToList())
                {
                    if (method.IsPrivate && !method.IsConstructor && !method.IsSpecialName)
                    {
                        method.Name = "_m" + Guid.NewGuid().ToString("N")[..8];
                        renamed++;
                    }
                }
            }
        }

        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(output))!);
        module.Write(output);

        // Copy the runtime dependency + runtimeconfig/deps so `dotnet output.dll` runs directly.
        var outDir = Path.GetDirectoryName(Path.GetFullPath(output))!;
        if (methods.Contains("strenc") && File.Exists(runtimeDllPath))
            File.Copy(runtimeDllPath, Path.Combine(outDir, "Obsor.Runtime.dll"), overwrite: true);

        // Make `dotnet output.dll` runnable: either copy the input's own
        // runtimeconfig/deps (the --input *.dll case, where a real build
        // already produced them) or synthesize a minimal one (the --input
        // *.cs case, where there was no project to begin with).
        var outBase = Path.Combine(outDir, Path.GetFileNameWithoutExtension(output));
        if (!input.EndsWith(".cs", StringComparison.OrdinalIgnoreCase))
        {
            var inBase = Path.Combine(Path.GetDirectoryName(Path.GetFullPath(input))!, Path.GetFileNameWithoutExtension(input));
            foreach (var ext in new[] { ".runtimeconfig.json", ".deps.json" })
                if (File.Exists(inBase + ext)) File.Copy(inBase + ext, outBase + ext, overwrite: true);
        }
        else
        {
            File.WriteAllText(outBase + ".runtimeconfig.json",
                """{"runtimeOptions":{"tfm":"net8.0","framework":{"name":"Microsoft.NETCore.App","version":"8.0.0"},"rollForward":"LatestMinor"}}""");
        }

        Console.WriteLine($"[+] Saved to {output}");
        Console.WriteLine($"    renamed {renamed} members, encrypted {stringsEnc} string literals");

        if (test)
        {
            Console.WriteLine($"\n[test] Testing obfuscated assembly: {output}");
            var psi = new System.Diagnostics.ProcessStartInfo("dotnet", $"\"{output}\"")
            { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
            using var p = System.Diagnostics.Process.Start(psi)!;
            string stdout = p.StandardOutput.ReadToEnd();
            string stderr = p.StandardError.ReadToEnd();
            p.WaitForExit(10000);
            if (p.ExitCode == 0)
            {
                Console.WriteLine("[ok] Test passed: assembly executed successfully");
                if (stdout.Length > 0) Console.WriteLine("Output:\n" + stdout);
            }
            else
            {
                Console.WriteLine($"[!] Test failed with exit code {p.ExitCode}");
                if (stderr.Length > 0) Console.WriteLine("Error:\n" + stderr);
            }
        }
        return 0;
    }

    private static byte[] CompileSource(string source, string assemblyName)
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
            throw new InvalidOperationException("compilation failed");
        }
        return ms.ToArray();
    }
}
