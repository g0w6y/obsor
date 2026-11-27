/*
 * Build an Obsor-JS PRO native loader (.node) from source.
 *
 * Pipeline:
 *   source.js --(minify)--> payload text
 *             --(scrypt key from external secret + AES-256-GCM)--> blob
 *             --(embed in C template, compile linking libcrypto + N-API)-->
 *                loader addon (.node)
 *             --(emit tiny launcher)--> <out>.js  that just requires+runs it
 *
 * The AES key is NOT stored anywhere. It is re-derived in C at runtime from
 * the OBSOR_KEY / OBSOR_LICENSE environment variable.
 */
'use strict';
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const keyderive = require('../keyderive');
const { minify } = require('../engine');

const TEMPLATE_PATH = path.join(__dirname, 'loader_template.c');

function cBytes(buf) { return Array.from(buf).join(', '); }

function findOpenssl() {
  const candidates = ['/opt/homebrew/opt/openssl@3', '/usr/local/opt/openssl@3', '/usr', '/usr/local'];
  for (const base of candidates) {
    const inc = path.join(base, 'include');
    if (fs.existsSync(path.join(inc, 'openssl', 'evp.h'))) {
      for (const libname of ['lib', 'lib64']) {
        const lib = path.join(base, libname);
        if (fs.existsSync(lib)) return { inc, lib };
      }
    }
  }
  return { inc: null, lib: null };
}

function buildNativeLoader(source, outJs, opts = {}) {
  const keyMode = opts.keyMode || 'pass';
  if (!['pass', 'license'].includes(keyMode)) throw new Error("native loader supports keyMode 'pass' or 'license'");
  const keyEnv = keyMode === 'license' ? 'OBSOR_LICENSE' : 'OBSOR_KEY';

  const secret = keyderive.resolveSecret(keyMode, opts.passphrase);
  const salt = crypto.randomBytes(16);
  const key = keyderive.deriveKey(secret, salt);

  const payload = Buffer.from(minify(source), 'utf8');
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
  const ct = Buffer.concat([cipher.update(payload), cipher.final()]);
  const tag = cipher.getAuthTag();

  const modName = 'obsor_' + crypto.randomBytes(6).toString('hex');
  let csrc = fs.readFileSync(TEMPLATE_PATH, 'utf8');
  const repl = {
    '%%SALT%%': cBytes(salt), '%%NONCE%%': cBytes(nonce), '%%TAG%%': cBytes(tag),
    '%%CT%%': cBytes(ct), '%%CT_LEN%%': String(ct.length), '%%KEY_ENV%%': keyEnv,
    '%%N%%': String(keyderive.SCRYPT_N), '%%R%%': String(keyderive.SCRYPT_R), '%%P%%': String(keyderive.SCRYPT_P),
    '%%ALIAS%%': opts.alias || '', '%%EXTRA_FUNCS%%': opts.extraFuncs || '', '%%EXTRA_ATTACH%%': opts.extraAttach || '',
  };
  for (const [k, v] of Object.entries(repl)) csrc = csrc.split(k).join(v);

  const outDir = path.dirname(path.resolve(outJs));
  fs.mkdirSync(outDir, { recursive: true });
  const workdir = opts.workdir || fs.mkdtempSync(path.join(os.tmpdir(), 'obsor_build_'));
  fs.writeFileSync(path.join(workdir, 'addon.c'), csrc, 'utf8');

  const { inc: sslInc, lib: sslLib } = findOpenssl();
  const bindingGyp = {
    targets: [{
      target_name: modName,
      sources: ['addon.c'],
      include_dirs: sslInc ? [sslInc] : [],
      libraries: sslLib ? [`-L${sslLib}`, '-lcrypto', `-Wl,-rpath,${sslLib}`] : ['-lcrypto'],
    }],
  };
  fs.writeFileSync(path.join(workdir, 'binding.gyp'), JSON.stringify(bindingGyp, null, 2), 'utf8');

  try {
    execFileSync('npx', ['--yes', 'node-gyp', 'rebuild'], { cwd: workdir, stdio: 'pipe' });
  } catch (e) {
    throw new Error('native compile failed:\n' + (e.stderr ? e.stderr.toString() : e.message));
  }

  const builtNode = path.join(workdir, 'build', 'Release', `${modName}.node`);
  const destNode = path.join(outDir, `${modName}.node`);
  fs.copyFileSync(builtNode, destNode);

  const launcher = `#!/usr/bin/env node
// Obsor-JS PRO native-protected launcher. Logic lives in the compiled
// module ${modName}.node; ship BOTH files together (same directory).
'use strict';
const path = require('path');
const m = require(path.join(__dirname, '${modName}.node'));
m.run();
`;
  fs.writeFileSync(outJs, launcher, 'utf8');
  return destNode;
}

module.exports = { buildNativeLoader, findOpenssl };
