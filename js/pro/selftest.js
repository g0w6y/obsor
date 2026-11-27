#!/usr/bin/env node
/*
 * End-to-end self-test for Obsor-JS PRO. Exit 0 = all pass.
 *   node pro/selftest.js
 */
'use strict';
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const engine = require('./engine');

const SAMPLE = `
function fibonacci(n) {
  const seq = [0, 1];
  for (let i = 0; i < n - 2; i++) seq.push(seq[seq.length - 1] + seq[seq.length - 2]);
  return seq.slice(0, n);
}
console.log('FIB', JSON.stringify(fibonacci(8)));
`;

let rc = 0;
function check(name, cond) {
  console.log((cond ? '[PASS]' : '[FAIL]'), name);
  if (!cond) rc = 1;
}

function run(file, envKey) {
  try {
    const env = { ...process.env };
    if (envKey !== undefined) env.OBSOR_KEY = envKey;
    else delete env.OBSOR_KEY;
    const out = execFileSync(process.execPath, [file], { encoding: 'utf8', env, timeout: 10000 });
    return { status: 0, stdout: out };
  } catch (e) {
    return { status: e.status ?? 1, stdout: e.stdout || '' };
  }
}

function main() {
  const wd = fs.mkdtempSync(path.join(os.tmpdir(), 'obsor_selftest_'));
  const src = path.join(wd, 'in.js');
  fs.writeFileSync(src, SAMPLE, 'utf8');

  // ---- hardened tier ----
  const hard = path.join(wd, 'hard.js');
  engine.protectFile(src, hard, { keyMode: 'pass', passphrase: 'CorrectPass123' });
  const text = fs.readFileSync(hard, 'utf8');
  check('hardened: passphrase not embedded', !text.includes('CorrectPass123'));
  check('hardened: runs with correct key', run(hard, 'CorrectPass123').stdout.trim() === 'FIB [0,1,1,2,3,5,8,13]');
  check('hardened: wrong key refuses', run(hard, 'pw-wrong').status !== 0);
  check('hardened: no key refuses', run(hard, undefined).status !== 0);

  const a = engine.protect('console.log(1);', { passphrase: 'DummyPass1234' });
  const b = engine.protect('console.log(1);', { passphrase: 'DummyPass1234' });
  const idsA = new Set(a.match(/_[a-z]{8}/g));
  const idsB = new Set(b.match(/_[a-z]{8}/g));
  check('hardened: identifiers randomized per build', JSON.stringify([...idsA].sort()) !== JSON.stringify([...idsB].sort()));

  // ---- native tier ----
  try {
    const { buildNativeLoader } = require('./native/build');
    const napp = path.join(wd, 'native_app.js');
    const nodeFile = buildNativeLoader(SAMPLE, napp, { keyMode: 'pass', passphrase: 'CorrectPass123' });
    check('native: builds', fs.existsSync(nodeFile));
    check('native: runs with correct key', run(napp, 'CorrectPass123').stdout.trim() === 'FIB [0,1,1,2,3,5,8,13]');
    check('native: wrong key refuses', run(napp, 'pw-wrong').status !== 0);
    const blob = fs.readFileSync(nodeFile);
    check('native: no original source in .node', !blob.includes('function fibonacci'));
  } catch (e) {
    check(`native: build/run (${e.message})`, false);
  }

  // ---- native-logic tier ----
  try {
    const { buildNativeLogic } = require('./native/logic');
    const logicC = `static napi_value sq(napi_env env, napi_callback_info info) {
      size_t argc = 1; napi_value args[1];
      napi_get_cb_info(env, info, &argc, args, NULL, NULL);
      int64_t x; napi_get_value_int64(env, args[0], &x);
      napi_value out; napi_create_int64(env, x * x + 1, &out); return out;
    }`;
    const payload = "console.log('R', obsorNative.sq(6));\n";
    const lapp = path.join(wd, 'logic_app.js');
    const lnode = buildNativeLogic(payload, logicC, ['sq'], lapp, { keyMode: 'pass', passphrase: 'CorrectPass123' });
    check('native-logic: builds', fs.existsSync(lnode));
    check('native-logic: runs + C result', run(lapp, 'CorrectPass123').stdout.trim() === 'R 37');
    const m = require(lnode);
    process.env.OBSOR_KEY = 'CorrectPass123';
    check('native-logic: C func is [native code]', /\[native code\]/.test(global.obsorNative.sq.toString()));
  } catch (e) {
    check(`native-logic: build/run (${e.message})`, false);
  }

  console.log('\n' + (rc === 0 ? 'ALL PASS' : 'FAILURES ABOVE'));
  return rc;
}

if (require.main === module) process.exit(main());
module.exports = { main };
