#!/usr/bin/env node
/*
 * Obsor-JS PRO command-line interface.
 *
 *   node pro/cli.js -i app.js -o dist/app.js --tier native -k "secret"
 *
 * Tiers:
 *   hardened : pure Node, external key + randomized identifiers + minified
 *              payload + authenticated AES-GCM + optional anti-tamper guard.
 *              One file, no compiler needed.
 *   native   : hardened PLUS the final derive/decrypt/run in a compiled
 *              N-API addon, so hooking global.eval/Function recovers
 *              nothing. Produces a launcher .js + a platform .node file
 *              (ship both). Needs a C compiler + OpenSSL at build time.
 */
'use strict';
const fs = require('fs');
const path = require('path');
const engine = require('./engine');

function parseArgs(argv) {
  const args = { tier: 'hardened', keyMode: 'pass' };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => argv[++i];
    switch (a) {
      case '-i': case '--input': args.input = next(); break;
      case '-o': case '--output': args.output = next(); break;
      case '--tier': args.tier = next(); break;
      case '--key-mode': args.keyMode = next(); break;
      case '-k': case '--key': args.key = next(); break;
      case '--guard': args.guard = true; break;
      default: console.error(`[!] Unknown argument: ${a}`); process.exit(1);
    }
  }
  return args;
}

function main(argv = process.argv.slice(2)) {
  const args = parseArgs(argv);
  if (!args.input || !args.output) {
    console.error('Usage: pro/cli.js -i INPUT -o OUTPUT [--tier hardened|native] ' +
      '[--key-mode pass|machine|license] [-k KEY] [--guard]');
    process.exit(1);
  }
  if (!['hardened', 'native'].includes(args.tier)) {
    console.error(`[!] Unknown tier: ${args.tier}`);
    process.exit(1);
  }
  if (['pass', 'license'].includes(args.keyMode) && !args.key) {
    console.error(`[!] --key-mode ${args.keyMode} requires -k/--key`);
    process.exit(1);
  }

  if (args.tier === 'hardened') {
    engine.protectFile(args.input, args.output, { keyMode: args.keyMode, passphrase: args.key, guard: args.guard });
    const env = args.keyMode === 'license' ? 'OBSOR_LICENSE' : 'OBSOR_KEY';
    console.log(`[+] hardened artifact: ${args.output}`);
    if (args.keyMode === 'machine') console.log('    runs only on THIS host (machine-bound)');
    else console.log(`    run with: ${env}=<secret> node ${args.output}`);
  } else {
    if (args.keyMode === 'machine') {
      console.error('[!] native tier supports --key-mode pass or license');
      process.exit(1);
    }
    const { buildNativeLoader } = require('./native/build');
    const source = fs.readFileSync(args.input, 'utf8');
    const nodeFile = buildNativeLoader(source, args.output, { keyMode: args.keyMode, passphrase: args.key });
    const env = args.keyMode === 'license' ? 'OBSOR_LICENSE' : 'OBSOR_KEY';
    console.log(`[+] native module : ${nodeFile}`);
    console.log(`[+] launcher      : ${args.output}  (ship BOTH files together)`);
    console.log(`    run with: ${env}=<secret> node ${args.output}`);
  }
}

if (require.main === module) main();
module.exports = { main };
