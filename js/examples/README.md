# Examples

- `sample_input.js` -- a small script used to exercise the classic engine
  and PRO hardened/native tiers.
- `native_logic/` -- `secret.c` (an N-API routine) + `app.js` (a payload
  that calls it via the injected `obsorNative` global), used by the PRO
  native-logic tier. See `../pro/README.md` -> "Native-logic tier".

```bash
# classic
node ../main.js -i sample_input.js --preset military --test

# PRO hardened
node ../pro/cli.js -i sample_input.js -o /tmp/hard.js --tier hardened -k "MySecretKey123"
OBSOR_KEY="MySecretKey123" node /tmp/hard.js

# PRO native-logic
node -e "require('../pro/native/logic').buildNativeLogic(
  require('fs').readFileSync('native_logic/app.js','utf8'),
  require('fs').readFileSync('native_logic/secret.c','utf8'),
  ['secret_transform'], '/tmp/logic_app.js', {keyMode:'pass', passphrase:'MySecretKey123'})"
OBSOR_KEY="MySecretKey123" node /tmp/logic_app.js
```
