// Obsor.Pro command-line interface.
//   obsor-pro -i app.cs -o dist/protected.dll --tier hardened -k "secret"
//
// Tiers:
//   hardened     : pure .NET, external key + authenticated AES-256-GCM +
//                  PBKDF2 (see KeyDerive.cs for why not scrypt). One
//                  launcher .dll + a copy of Obsor.Pro.dll, no compiler.
//   native-logic : hardened PLUS a developer-supplied crown-jewel routine
//                  compiled to a native library and called via P/Invoke --
//                  the only tier that resists a key-holder. See
//                  Native/LogicBuild.cs.
using System;
using System.IO;

namespace Obsor.Pro;

internal static class CliMain
{
    private static int Main(string[] args)
    {
        string? input = null, output = null, keyMode = "pass", key = null, tier = "hardened";
        bool guard = false;

        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "-i": case "--input": input = args[++i]; break;
                case "-o": case "--output": output = args[++i]; break;
                case "--tier": tier = args[++i]; break;
                case "--key-mode": keyMode = args[++i]; break;
                case "-k": case "--key": key = args[++i]; break;
                case "--guard": guard = true; break;
                default: Console.Error.WriteLine($"[!] Unknown argument: {args[i]}"); return 1;
            }
        }

        if (input is null || output is null)
        {
            Console.Error.WriteLine("Usage: obsor-pro -i INPUT.cs -o OUTPUT.dll [--tier hardened] " +
                "[--key-mode pass|machine|license] [-k KEY] [--guard]");
            return 1;
        }
        if (tier != "hardened")
        {
            Console.Error.WriteLine($"[!] CLI only wires the hardened tier; native-logic is a library API (see Native/LogicBuild.cs + examples/NativeLogic).");
            return 1;
        }
        if ((keyMode == "pass" || keyMode == "license") && string.IsNullOrEmpty(key))
        {
            Console.Error.WriteLine($"[!] --key-mode {keyMode} requires -k/--key");
            return 1;
        }

        Engine.ProtectFile(input, output, keyMode!, key, guard);
        var envVar = keyMode == "license" ? "OBSOR_LICENSE" : "OBSOR_KEY";
        Console.WriteLine($"[+] hardened artifact: {output}");
        if (keyMode == "machine") Console.WriteLine("    runs only on THIS host (machine-bound)");
        else Console.WriteLine($"    run with: {envVar}=<secret> dotnet {output}");
        return 0;
    }
}
