# Examples

- `sample_input.cs` -- a small console app used to exercise Obsor.Classic
  and Obsor.Pro hardened.
- `sample_with_private.cs` -- has private fields/methods, to exercise the
  `rename` method (`sample_input.cs` has none, so `rename` has nothing to do
  on it).
- `NativeLogic/` -- `secret.c` (a plain C routine) + `app.cs` (a payload
  that P/Invokes it), used by `Obsor.Pro.Native.LogicBuild`. See
  `../Obsor.Pro/README.md` -> "Native-logic tier".

```bash
# classic, from source
dotnet ../Obsor.Classic/bin/Release/net8.0/obsor-classic.dll \
  -i sample_input.cs -o /tmp/protected.dll -m rename,strenc --test
dotnet /tmp/protected.dll

# PRO hardened
dotnet ../Obsor.Pro/bin/Release/net8.0/obsor-pro.dll \
  -i sample_input.cs -o /tmp/hard.dll --tier hardened -k "MySecretKey123"
OBSOR_KEY="MySecretKey123" dotnet /tmp/hard.dll

# PRO native-logic (library API -- see Obsor.Selftest/Program.cs for a
# complete, runnable example of this exact call)
```
