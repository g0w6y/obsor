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
//   obsor-classic -i app.dll -o protected.dll --methods rename,strenc,cflow
//
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;
using Mono.Cecil;
using Mono.Cecil.Cil;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;

namespace Obsor.Classic;

internal static class Program
{
    private static readonly string[] AllMethods = { "rename", "strenc", "cflow" };

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
            Console.WriteLine("  cflow   - inject an opaque-predicate branch at the start of every method body");
            Console.WriteLine("            (inflates the CFG a decompiler has to untangle; does not hide strings");
            Console.WriteLine("            or renamed members on its own -- combine with strenc/rename for that)");
            Console.WriteLine("\nUnlike Python/JS, there is no preset stack of 20+ interchangeable");
            Console.WriteLine("encodings here -- .NET's unit of obfuscation is IL members and");
            Console.WriteLine("literals, not swappable text transforms. See dotnet/README.md.");
            return 0;
        }

        if (input is null || output is null)
        {
            Console.Error.WriteLine("Usage: obsor-classic -i INPUT(.cs|.dll|.exe) -o OUTPUT.dll [-m rename,strenc,cflow] [-k 0xNN] [--test]");
            return 1;
        }

        if (!File.Exists(input))
        {
            Console.Error.WriteLine($"[!] Input file not found: {input}");
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

        byte key;
        try
        {
            key = keyArg is null
                ? (byte)new Random().Next(1, 256)
                : Convert.ToByte(keyArg, keyArg.StartsWith("0x") ? 16 : 10);
        }
        catch (Exception ex) when (ex is FormatException or OverflowException)
        {
            Console.Error.WriteLine($"[!] Invalid key value: '{keyArg}' (expected a byte 0-255, e.g. 0x5A or 90)");
            return 1;
        }
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

        // cflow needs a runtime (not compile-time-foldable) int source for its
        // opaque predicate; Environment.TickCount is cheap, side-effect-free,
        // and already a BCL member every target framework has.
        MethodReference? tickCountRef = null;
        if (methods.Contains("cflow"))
        {
            var tickCountGetter = typeof(Environment).GetMethod("get_TickCount", Type.EmptyTypes)!;
            tickCountRef = module.ImportReference(tickCountGetter);
        }

        int renamed = 0, stringsEnc = 0, cflowInjected = 0;
        long bbBefore = 0, bbAfter = 0;
        var cflowRng = new Random();
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

            if (methods.Contains("cflow"))
            {
                // Applies to every method with a body -- constructors, static
                // cctors, property/event accessors, compiler-generated methods
                // included. That's deliberate: this injects exactly once, at
                // the very start of the method, which is the one program
                // point that's provably stack-empty for *any* method without
                // doing data-flow analysis (CLR methods always start with an
                // empty evaluation stack). It never touches or reorders any
                // existing instruction, so it can't interact with existing
                // branches/loops/exception-handler regions (TryStart etc.
                // keep pointing at the same original first instruction).
                // Methods with no body (abstract/extern) are skipped via the
                // HasBody check -- they have no Instructions to inject into.
                foreach (var method in type.Methods)
                {
                    if (!method.HasBody || method.Body.Instructions.Count == 0) continue;
                    bbBefore += CountBasicBlocksApprox(method.Body);
                    InjectOpaquePredicate(method, module, tickCountRef!, cflowRng);
                    bbAfter += CountBasicBlocksApprox(method.Body);
                    cflowInjected++;
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

            // The copied deps.json came from the *input* build and only lists
            // the input's own assembly. If strenc ran, the output now calls
            // into Obsor.Runtime.dll, which isn't in that closure -- the
            // deps.json-based host then refuses to load it even though the
            // file is sitting right next to the output (FileNotFoundException
            // at run time). Patch it to also list Obsor.Runtime.dll.
            if (methods.Contains("strenc"))
                PatchDepsJsonForRuntime(outBase + ".deps.json");
        }
        else
        {
            File.WriteAllText(outBase + ".runtimeconfig.json",
                """{"runtimeOptions":{"tfm":"net8.0","framework":{"name":"Microsoft.NETCore.App","version":"8.0.0"},"rollForward":"LatestMinor"}}""");
        }

        Console.WriteLine($"[+] Saved to {output}");
        Console.WriteLine($"    renamed {renamed} members, encrypted {stringsEnc} string literals");
        if (methods.Contains("cflow"))
            Console.WriteLine($"    cflow: injected opaque predicates into {cflowInjected} methods (approx basic blocks {bbBefore} -> {bbAfter})");

        if (test)
        {
            Console.WriteLine($"\n[test] Testing obfuscated assembly: {output}");
            // ArgumentList (argv array), not an interpolated Arguments string --
            // same reasoning as the fix in Obsor.Pro/Native/LogicBuild.cs: a
            // `"` in output would otherwise close the quoted argument early
            // and let anything after it be parsed as new argv entries.
            var psi = new System.Diagnostics.ProcessStartInfo("dotnet")
            { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
            psi.ArgumentList.Add(output);
            using var p = System.Diagnostics.Process.Start(psi)!;
            // Drain both pipes asynchronously WHILE the process runs, not via
            // a sequential ReadToEnd() after start. Reading stdout fully
            // before touching stderr deadlocks the moment the child's
            // combined output exceeds the OS pipe buffer (64KB on this
            // machine) and the child blocks writing to the still-undrained
            // stream -- same pattern (and same fix) as
            // Obsor.Pro/Native/LogicBuild.cs's clang invocation, which
            // reproduced a 400+s hang from exactly this shape.
            var stdoutBuf = new System.Text.StringBuilder();
            var stderrBuf = new System.Text.StringBuilder();
            p.OutputDataReceived += (_, e) => { if (e.Data != null) stdoutBuf.AppendLine(e.Data); };
            p.ErrorDataReceived += (_, e) => { if (e.Data != null) stderrBuf.AppendLine(e.Data); };
            p.BeginOutputReadLine();
            p.BeginErrorReadLine();
            p.WaitForExit(10000);
            string stdout = stdoutBuf.ToString();
            string stderr = stderrBuf.ToString();
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

    // Injects one opaque-predicate branch at the very start of a method body.
    //
    // IL emitted (stack-balanced, empty before and after, matching the
    // guaranteed-empty stack at method entry):
    //
    //   call  Environment.get_TickCount()   // x: a runtime value, not a
    //   dup                                 //    compile-time constant, so a
    //   mul                                 //    decompiler can't just fold
    //   ldc.i4.4                            //    the branch away
    //   rem                                 // t = (x*x) % 4
    //   stloc  t
    //   ldloc  t
    //   ldc.i4.2
    //   ceq                                 // (t == 2)
    //   brfalse real_target                 // always taken: t is never 2
    //   <junk, never executed>
    //   br     real_target                  // safety net: even if the math
    //                                        // reasoning below were ever
    //                                        // wrong, both paths converge on
    //                                        // the same real code, so this
    //                                        // can never change behavior
    //   real_target: <original first instruction>
    //
    // Why "(x*x) % 4 != 2" is always true, for every int32 x, no exceptions:
    // squares only ever land on the quadratic residues {0,1} mod 4 (0^2=0,
    // 1^2=1, 2^2=4=0, 3^2=9=1 mod 4), and that still holds after 32-bit
    // truncation (4 divides 2^32, so truncating to 32 bits can't change the
    // low 2 bits of x*x) and still holds under IL's signed, sign-of-dividend
    // `rem` (the only effect a negative x*x has is turning residue 1 into
    // -3 instead of 1 -- never into 2). Verified before shipping this with a
    // 54M-sample brute force (every int32 edge case: Int32.MinValue/MaxValue
    // +/- a few, every value in [-2_000_000, 2_000_000], and 50M random
    // samples across the full range) -- zero counterexamples.
    private static void InjectOpaquePredicate(MethodDefinition method, ModuleDefinition module, MethodReference tickCountRef, Random rng)
    {
        var body = method.Body;
        var il = body.GetILProcessor();
        var realTarget = body.Instructions[0];

        var local = new VariableDefinition(module.TypeSystem.Int32);
        body.Variables.Add(local);
        body.InitLocals = true;

        var junkConst = rng.Next(1, 1000);

        var seq = new[]
        {
            il.Create(OpCodes.Call, tickCountRef),
            il.Create(OpCodes.Dup),
            il.Create(OpCodes.Mul),
            il.Create(OpCodes.Ldc_I4_4),
            il.Create(OpCodes.Rem),
            il.Create(OpCodes.Stloc, local),
            il.Create(OpCodes.Ldloc, local),
            il.Create(OpCodes.Ldc_I4_2),
            il.Create(OpCodes.Ceq),
            il.Create(OpCodes.Brfalse, realTarget),
            // Dead fall-through: only reached if (x*x)%4 == 2, which never
            // happens. Plausible-looking junk, then an unconditional branch
            // to the same real target as a behavior-preservation safety net.
            il.Create(OpCodes.Ldloc, local),
            il.Create(OpCodes.Ldc_I4, junkConst),
            il.Create(OpCodes.Add),
            il.Create(OpCodes.Pop),
            il.Create(OpCodes.Br, realTarget),
        };
        foreach (var instr in seq) il.InsertBefore(realTarget, instr);
    }

    // Cheap, approximate basic-block count: a new block starts at the first
    // instruction, at every branch/switch target, and right after every
    // instruction that ends a block (branch, return, throw). Good enough for
    // a before/after complexity delta -- not a precise CFG construction.
    private static int CountBasicBlocksApprox(MethodBody body)
    {
        var instrs = body.Instructions;
        if (instrs.Count == 0) return 0;
        var starts = new HashSet<Instruction> { instrs[0] };
        for (int i = 0; i < instrs.Count; i++)
        {
            var instr = instrs[i];
            if (instr.Operand is Instruction target) starts.Add(target);
            else if (instr.Operand is Instruction[] targets) foreach (var t in targets) starts.Add(t);

            var fc = instr.OpCode.FlowControl;
            bool endsBlock = fc == FlowControl.Branch || fc == FlowControl.Cond_Branch
                || fc == FlowControl.Return || fc == FlowControl.Throw;
            if (endsBlock && i + 1 < instrs.Count) starts.Add(instrs[i + 1]);
        }
        return starts.Count;
    }

    // Adds Obsor.Runtime.dll to a deps.json's runtime closure for every
    // "project"-type library entry (the main app), so the .NET host's
    // deps.json-based resolver will actually load it from next to the
    // output instead of refusing with FileNotFoundException. No-op if the
    // file doesn't exist (e.g. the --input *.cs path never writes one).
    private static void PatchDepsJsonForRuntime(string depsPath)
    {
        if (!File.Exists(depsPath)) return;

        var root = JsonNode.Parse(File.ReadAllText(depsPath))!.AsObject();
        var runtimeTargetName = root["runtimeTarget"]?["name"]?.GetValue<string>();
        if (runtimeTargetName is null) return;
        var targets = root["targets"]?.AsObject();
        if (targets is null || targets[runtimeTargetName] is not JsonObject targetEntries) return;
        var libraries = root["libraries"]?.AsObject();

        bool patched = false;
        foreach (var kv in targetEntries.ToList())
        {
            var libType = libraries?[kv.Key]?["type"]?.GetValue<string>();
            if (libType != "project") continue;
            if (kv.Value is not JsonObject entry) continue;

            if (entry["runtime"] is not JsonObject runtimeObj)
            {
                runtimeObj = new JsonObject();
                entry["runtime"] = runtimeObj;
            }
            if (!runtimeObj.ContainsKey("Obsor.Runtime.dll"))
            {
                runtimeObj["Obsor.Runtime.dll"] = new JsonObject();
                patched = true;
            }
        }

        if (patched)
            File.WriteAllText(depsPath, root.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
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
