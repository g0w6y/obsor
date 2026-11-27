package com.g0w6y.obsor.pro;

// Anti-tamper tripwire for the hardened launcher.
//
// HONEST SCOPE: runs in the same process as the attacker, so a determined
// reverser (a patched launcher, a java agent loaded before this runs)
// defeats it. This is a deterrent against casual dynamic analysis only --
// not a security boundary. See Obsor.Pro/README.md "Honest limits".
import java.lang.management.ManagementFactory;

public final class Guard {
    private Guard() {}

    public static void check(double timeBudgetSeconds) {
        // 1. A debugger attached via -agentlib:jdwp (the standard JVM remote-debug flag)?
        String jvmArgs = String.join(" ", ManagementFactory.getRuntimeMXBean().getInputArguments());
        if (jvmArgs.contains("jdwp") || jvmArgs.contains("agentlib")) {
            System.exit(1);
        }
        // 2. Gross single-step slowdown between two cheap ops (tracer/stepper).
        long start = System.nanoTime();
        long x = 0;
        for (int i = 0; i < 1_000_000; i++) x += i;
        double elapsed = (System.nanoTime() - start) / 1e9;
        if (elapsed > timeBudgetSeconds) System.exit(1);
    }
}
