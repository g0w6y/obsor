# Examples

- `sample_input.java` -- a small program used to exercise the classic
  engine and PRO hardened tier.
- `sample_with_private.java` -- has a private field and a private method
  that calls it, to exercise the `rename` method's call-site patching
  (`sample_input.java` has no private members, so `rename` has nothing to
  do on it).
- `native_logic/` -- `secret.c` (a plain C routine) + `App.java` (a payload
  that calls it via a `native` method), used by the PRO native-logic tier.
  See `../obsor-pro/README.md` -> "Native-logic tier".

```bash
# classic
java -jar ../obsor-classic/target/obsor-classic-jar-with-dependencies.jar \
  -i sample_input.java -o /tmp/protected --test

# PRO hardened
java -jar ../obsor-pro/target/obsor-pro-jar-with-dependencies.jar \
  -i sample_input.java -o /tmp/hard.jar --tier hardened -k "MySecretKey123"
OBSOR_KEY="MySecretKey123" java -jar /tmp/hard.jar

# PRO native-logic (library API -- see obsor-selftest/src/.../Main.java for
# a complete, runnable example of this exact call)
```
