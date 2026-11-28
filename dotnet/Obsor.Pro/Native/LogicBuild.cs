// Obsor.Pro native-logic tier.
//
// IMPORTANT ARCHITECTURAL NOTE (read dotnet/Obsor.Pro/README.md "Why no
// middle native tier"): Python and JS PRO each have three tiers --
// hardened, a native loader that defeats the hardened tier's specific
// eval/Function hook, and native-logic. .NET PRO only has TWO: hardened and
// native-logic. There is no .NET equivalent of the middle tier, because the
// attack that matters against hardened (AppDomain.AssemblyLoad +
// MethodBase.GetMethodBody().GetILAsByteArray(), verified in this repo) is
// inherent to loading ANY managed assembly via Assembly.Load -- moving the
// AES-GCM decrypt step from C# into a native loader would not change that;
// the result is still a managed assembly handed to Assembly.Load. Claiming
// a "native" tier here would be dishonest marketing, so it does not exist.
//
// What DOES work, same as Python/JS: move the one crown-jewel routine out
// of managed code entirely. Compile it as plain C, call it via P/Invoke.
// There is no IL for that routine -- MethodBase.GetMethodBody() on a
// P/Invoke stub returns null, nothing to dump. A key-holder can still call
// it as a black box but must reverse the compiled native library
// (Ghidra/IDA) to read the algorithm.
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace Obsor.Pro.Native;

public static class LogicBuild
{
    // libName becomes a filename fragment (lib<libName>.so/.dylib/.dll) via
    // plain string concatenation, with no escaping anywhere downstream. An
    // unrestricted libName containing "../" would let the compiled library
    // land outside outDir (path traversal / arbitrary file write) even with
    // the clang invocation now using a safe ArgumentList; restrict it to a
    // plain filename-safe charset so it can never contain a path separator
    // or traversal sequence.
    private static readonly Regex LibNamePattern = new("^[A-Za-z0-9_.-]+$", RegexOptions.Compiled);

    /// <summary>
    /// Compiles nativeCSource to a shared library with clang, protects
    /// payloadSource with the hardened engine (the payload is expected to
    /// P/Invoke into the native library by name), and places both files
    /// together at outPath's directory.
    /// </summary>
    public static void BuildNativeLogic(string payloadSource, string nativeCSource, string libName,
        string outPath, string keyMode = "pass", string? passphrase = null, bool guard = false)
    {
        if (string.IsNullOrEmpty(libName) || !LibNamePattern.IsMatch(libName))
            throw new ArgumentException($"invalid libName: {libName!}");

        var outDir = Path.GetDirectoryName(Path.GetFullPath(outPath))!;
        Directory.CreateDirectory(outDir);

        var workdir = Path.Combine(Path.GetTempPath(), "obsor_native_" + Guid.NewGuid().ToString("N")[..8]);
        // Directory.CreateDirectory(string) alone leaves this at the
        // platform default (0755 on this machine, confirmed) -- world-
        // readable. The whole point of this tool is confidentiality of the
        // source dropped here (the developer's payload + the native
        // crown-jewel C routine), so on a shared/multi-tenant build host any
        // other local user could read both in plaintext while/after this
        // runs. Restrict to owner-only, matching what Python's
        // tempfile.mkdtemp/Node's fs.mkdtempSync/Java's
        // Files.createTempDirectory already do by default (all confirmed
        // 0700 during this review).
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            Directory.CreateDirectory(workdir, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        else
            Directory.CreateDirectory(workdir);
        var cPath = Path.Combine(workdir, "logic.c");
        File.WriteAllText(cPath, nativeCSource);

        string ext = RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? ".dylib"
            : RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? ".dll" : ".so";
        string libFileName = (RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "" : "lib") + libName + ext;
        var libOutPath = Path.Combine(outDir, libFileName);

        // Use ArgumentList (a real argv array), not a single interpolated
        // Arguments string. .NET's Process class parses a string Arguments
        // property with its own quote-splitting rules even with
        // UseShellExecute=false and no shell involved -- confirmed directly:
        // a libOutPath/cPath containing a `"` closes the quoted argument
        // early and lets everything after it be parsed as NEW argv entries
        // (e.g. a second "-o <attacker path>", which clang honors last-wins,
        // writing the compiled library wherever the attacker chose instead
        // of outDir). libName has no character restrictions, so a crafted
        // libName was enough to trigger this. ArgumentList passes each
        // element as one argv entry with no quote-splitting, closing the
        // vector regardless of what libName/outPath contain.
        var psi = new ProcessStartInfo("clang")
        {
            RedirectStandardError = true,
            RedirectStandardOutput = true,
            UseShellExecute = false,
        };
        psi.ArgumentList.Add("-shared");
        psi.ArgumentList.Add("-O2");
        psi.ArgumentList.Add("-fPIC");
        psi.ArgumentList.Add("-o");
        psi.ArgumentList.Add(libOutPath);
        psi.ArgumentList.Add(cPath);
        using var proc = Process.Start(psi)!;
        // Drain both pipes asynchronously WHILE the process runs, not after
        // WaitForExit(). Both streams are redirected but nothing read them
        // until exit, which deadlocks the moment clang's combined
        // stdout+stderr exceeds the OS pipe buffer (64KB on this machine):
        // clang blocks on the write, so it never exits, so WaitForExit()
        // never returns. Reproduced directly: a C source that makes clang
        // emit >64KB of diagnostics hung this exact pattern for 400+s until
        // force-killed. A developer-supplied native-logic C source hitting
        // enough legitimate warnings is a realistic way to trip this.
        var stderrBuf = new System.Text.StringBuilder();
        proc.ErrorDataReceived += (_, e) => { if (e.Data != null) stderrBuf.AppendLine(e.Data); };
        proc.OutputDataReceived += (_, e) => { };
        proc.BeginErrorReadLine();
        proc.BeginOutputReadLine();
        proc.WaitForExit();
        if (proc.ExitCode != 0)
            throw new InvalidOperationException("native compile failed:\n" + stderrBuf.ToString());

        Engine.ProtectFile(WriteTemp(workdir, payloadSource), outPath, keyMode, passphrase, guard);
    }

    private static string WriteTemp(string workdir, string source)
    {
        var path = Path.Combine(workdir, "payload.cs");
        File.WriteAllText(path, source);
        return path;
    }
}
