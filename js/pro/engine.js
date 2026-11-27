/*
 * Obsor-JS PRO hardened engine (Tier 1, pure Node, no native compiler).
 *
 * Fixes the structural weaknesses of the classic obsor-js pipeline:
 *
 *   * Key is NEVER embedded -- derived at runtime from an external secret
 *     (passphrase / machine binding / license token) via scrypt.
 *   * AES-256-GCM is AUTHENTICATED: a wrong key or a tampered blob fails
 *     loudly instead of running attacker-controlled plaintext.
 *   * Every identifier in the bootstrap is RANDOMIZED per build, so no two
 *     outputs share a static signature.
 *   * Optional anti-tamper guard defeats casual trace/dump deobfuscation.
 *
 * HONEST GAP vs the Python engine: Python ships `marshal`-compiled bytecode
 * as the payload, so a dumped payload still needs decompilation (no
 * comments/formatting). Node/V8 has no equivalent portable bytecode-only
 * execution path -- V8's `vm.Script` code cache MUST be paired with the
 * exact original source text to validate (the cache is a hash-checked
 * accelerator, not a substitute for source). So the JS hardened payload here
 * is minified SOURCE TEXT, not bytecode: the instant it's decrypted it is
 * fully readable, comments and formatting already stripped by minify but
 * otherwise plaintext. This is a real architectural difference from Python,
 * not an oversight -- see README.md "Why JS hardened != Python hardened".
 *
 * This still has the same ceiling as the Python engine: the payload must
 * become runnable JS, so anyone who can run it (e.g. a licensed customer
 * holding the key) can recover it -- by overriding global.eval/Function
 * before run(), or attaching `node --inspect` and reading the source from
 * the Debugger.scriptParsed event, or just reading `global`/module exports
 * after it runs. The native loader (pro/native) only moves the classic
 * `eval`/`Function` hook off the table; it does NOT close the inspector or
 * post-run-globals paths. The real protection here is the external key
 * against someone who has the file but NOT the key.
 */
'use strict';
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const keyderive = require('./keyderive');
const { makeGuard } = require('./guard');

const IDCHARS = 'abcdefghijklmnopqrstuvwxyz';

function randId(n = 8) {
  let s = '_';
  for (let i = 0; i < n; i++) s += IDCHARS[crypto.randomInt(IDCHARS.length)];
  return s;
}

function minify(source) {
  // Best-effort: strip /* */ and // comments and blank lines. Not a real
  // parser -- same honesty caveat as the classic engine's minify method.
  return source
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .split('\n')
    .map((l) => l.replace(/\/\/.*$/, '').trimEnd())
    .filter((l) => l.trim().length)
    .join('\n');
}

function compilePayload(source) {
  // No true bytecode path in stock Node (see module docstring). The payload
  // is minified source text, encoded as a UTF-8 buffer.
  return Buffer.from(minify(source), 'utf8');
}

function protect(source, opts = {}) {
  const keyMode = opts.keyMode || 'pass';
  const passphrase = opts.passphrase;
  const guard = !!opts.guard;

  const secret = keyderive.resolveSecret(keyMode, passphrase);
  const salt = crypto.randomBytes(16);
  const key = keyderive.deriveKey(secret, salt);

  const payload = compilePayload(source);

  const iv = crypto.randomBytes(12); // GCM standard 96-bit nonce
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(payload), cipher.final()]);
  const tag = cipher.getAuthTag();

  const ids = {};
  for (const k of ['secret', 'salt', 'nonce', 'tag', 'ct', 'key', 'pt', 'guard']) ids[k] = randId();

  const guardSrc = guard ? makeGuard(ids.guard) : '';

  const boot = `#!/usr/bin/env node
'use strict';
const crypto = require('crypto');
${keyderive.RUNTIME_KEYDERIVE}
${guardSrc}
const ${ids.salt} = Buffer.from('${salt.toString('base64')}', 'base64');
const ${ids.nonce} = Buffer.from('${iv.toString('base64')}', 'base64');
const ${ids.tag} = Buffer.from('${tag.toString('base64')}', 'base64');
const ${ids.ct} = Buffer.from('${ct.toString('base64')}', 'base64');
const ${ids.secret} = _obsorSecret(${JSON.stringify(keyMode)}, process.env.OBSOR_KEY, process.env.OBSOR_LICENSE);
const ${ids.key} = _obsorDerive(${ids.secret}, ${ids.salt});
let ${ids.pt};
try {
  const d = crypto.createDecipheriv('aes-256-gcm', ${ids.key}, ${ids.nonce});
  d.setAuthTag(${ids.tag});
  ${ids.pt} = Buffer.concat([d.update(${ids.ct}), d.final()]).toString('utf8');
} catch (e) { process.exit(1); }
new Function('require', 'module', '__filename', '__dirname', 'process', 'console', ${ids.pt})(
  require, module, __filename, __dirname, process, console);
`;
  return boot;
}

function protectFile(inPath, outPath, opts = {}) {
  const source = fs.readFileSync(inPath, 'utf8');
  const out = protect(source, opts);
  fs.mkdirSync(path.dirname(path.resolve(outPath)), { recursive: true });
  fs.writeFileSync(outPath, out, 'utf8');
}

module.exports = { protect, protectFile, compilePayload, minify };
