// Anti-tamper tripwire for the hardened launcher.
//
// HONEST SCOPE: runs in the same process as the attacker, so a determined
// reverser (dnSpy "edit & continue", a patched launcher) defeats it. .NET
// also has no JS/Python-style monkey-patchable global eval/Function to
// check the integrity of -- the realistic attached-tooling threat here is a
// managed debugger (dnSpy, Visual Studio, WinDbg+SOS) or a profiler, so
// that's what this checks. Deterrent against casual dynamic analysis only.
using System;
using System.Diagnostics;

namespace Obsor.Pro;

public static class Guard
{
    public static void Check(double timeBudgetSeconds = 0.05)
    {
        // 1. A managed debugger attached?
        if (Debugger.IsAttached) Environment.Exit(1);

        // 2. Gross single-step slowdown between two cheap ops (tracer/stepper).
        var sw = Stopwatch.StartNew();
        long x = 0;
        for (int i = 0; i < 1_000_000; i++) x += i;
        sw.Stop();
        if (sw.Elapsed.TotalSeconds > timeBudgetSeconds) Environment.Exit(1);
    }
}
