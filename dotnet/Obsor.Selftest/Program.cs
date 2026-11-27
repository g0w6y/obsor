// End-to-end self-test for obsor's .NET port. Exit 0 = all pass.
//   dotnet obsor-selftest.dll
using System;
using System.Diagnostics;
using System.IO;
using Obsor.Pro;
using Obsor.Pro.Native;

int rc = 0;
void Check(string name, bool cond)
{
    Console.WriteLine((cond ? "[PASS]" : "[FAIL]") + " " + name);
    if (!cond) rc = 1;
}

// dotnet/Obsor.Selftest/bin/<Config>/net8.0/ -> walk up to dotnet/
var dotnetRoot = Directory.GetParent(AppContext.BaseDirectory)!.Parent!.Parent!.Parent!.Parent!.FullName;
var classicDll = Path.Combine(dotnetRoot, "Obsor.Classic", "bin", "Release", "net8.0", "obsor-classic.dll");
var sampleCs = Path.Combine(dotnetRoot, "examples", "sample_input.cs");

(int code, string stdout) Run(string dllPath, string args, string? envKey = null, string? envVarName = "OBSOR_KEY")
{
    var psi = new ProcessStartInfo("dotnet", $"\"{dllPath}\" {args}")
    {
        RedirectStandardOutput = true,
        RedirectStandardError = true,
        UseShellExecute = false,
    };
    if (envKey is not null) psi.Environment[envVarName!] = envKey;
    else psi.Environment.Remove(envVarName!);
    using var p = Process.Start(psi)!;
    string stdout = p.StandardOutput.ReadToEnd();
    p.WaitForExit(15000);
    return (p.ExitCode, stdout);
}

var wd = Directory.CreateTempSubdirectory("obsor_selftest_").FullName;

// ---- classic tier ----
if (File.Exists(classicDll))
{
    var classicOut = Path.Combine(wd, "classic.dll");
    var (code, stdout) = Run(classicDll, $"-i \"{sampleCs}\" -o \"{classicOut}\" -m rename,strenc -k 0x5A");
    Check("classic: builds", code == 0 && File.Exists(classicOut));
    var runResult = Run(classicOut, "");
    Check("classic: runs and produces correct output", runResult.stdout.Trim() == "FIB [0,1,1,2,3,5,8,13]");
    var bytes = File.ReadAllBytes(classicOut);
    var text = System.Text.Encoding.ASCII.GetString(bytes);
    Check("classic: original string literal not present in compiled output", !text.Contains("FIB ["));
}
else
{
    Check($"classic: obsor-classic.dll found at {classicDll}", false);
}

// ---- PRO hardened tier ----
var hardOut = Path.Combine(wd, "hard.dll");
Engine.ProtectFile(sampleCs, hardOut, "pass", "CorrectPass123");
var hardBytes = File.ReadAllBytes(hardOut);
Check("hardened: passphrase not embedded", !System.Text.Encoding.UTF8.GetString(hardBytes).Contains("CorrectPass123"));
var okRun = Run(hardOut, "", "CorrectPass123");
Check("hardened: runs with correct key", okRun.stdout.Trim() == "FIB [0,1,1,2,3,5,8,13]");
Check("hardened: wrong key refuses", Run(hardOut, "", "pw-wrong").code != 0);
Check("hardened: no key refuses", Run(hardOut, "", null).code != 0);

var hardA = Path.Combine(wd, "hardA.dll");
var hardB = Path.Combine(wd, "hardB.dll");
Engine.ProtectFile(sampleCs, hardA, "pass", "DummyPass1234");
Engine.ProtectFile(sampleCs, hardB, "pass", "DummyPass1234");
var textA = System.Text.Encoding.ASCII.GetString(File.ReadAllBytes(hardA));
var textB = System.Text.Encoding.ASCII.GetString(File.ReadAllBytes(hardB));
var clsA = System.Text.RegularExpressions.Regex.Match(textA, @"L[a-f0-9]{8}").Value;
var clsB = System.Text.RegularExpressions.Regex.Match(textB, @"L[a-f0-9]{8}").Value;
Check("hardened: launcher class name randomized per build", clsA != clsB && clsA.Length > 0);

// ---- native-logic tier ----
try
{
    var logicPayload = "using System;\nusing System.Runtime.InteropServices;\n" +
        "public static class Program {\n" +
        "  [DllImport(\"obsor_native_selftest\", EntryPoint=\"sq\")]\n" +
        "  static extern long Sq(long x);\n" +
        "  public static void Main() { Console.WriteLine(\"R \" + Sq(6)); }\n" +
        "}\n";
    var logicC = "#include <stdint.h>\nint64_t sq(int64_t x) { return x * x + 1; }\n";
    var logicOut = Path.Combine(wd, "logic_app.dll");
    LogicBuild.BuildNativeLogic(logicPayload, logicC, "obsor_native_selftest", logicOut, "pass", "CorrectPass123");
    Check("native-logic: builds", File.Exists(logicOut) && File.Exists(Path.Combine(wd, "libobsor_native_selftest.dylib")));
    var logicRun = Run(logicOut, "", "CorrectPass123");
    Check("native-logic: runs + C result", logicRun.stdout.Trim() == "R 37");
    var dylibBytes = File.ReadAllBytes(Path.Combine(wd, "libobsor_native_selftest.dylib"));
    Check("native-logic: no C# source in native lib", !System.Text.Encoding.ASCII.GetString(dylibBytes).Contains("Console.WriteLine"));
}
catch (Exception e)
{
    Check($"native-logic: build/run ({e.Message})", false);
}

Console.WriteLine();
Console.WriteLine(rc == 0 ? "ALL PASS" : "FAILURES ABOVE");
return rc;
