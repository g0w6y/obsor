/*
 * Key derivation for Obsor-JS PRO.
 *
 * The whole point: the AES key is NEVER written into the protected file.
 * It is re-derived at runtime from a secret the attacker does not
 * automatically get just by having the file:
 *
 *   "pass"    : a passphrase supplied at runtime via the OBSOR_KEY env var
 *   "machine" : bound to the host (hashed machine id) -> file only runs there
 *   "license" : a license token supplied via OBSOR_LICENSE env var
 *
 * Derivation is scrypt (memory-hard), same parameters as Python PRO, via
 * node:crypto's builtin scrypt -- no npm dependency needed.
 */
'use strict';
const crypto = require('crypto');
const os = require('os');

const SCRYPT_N = 1 << 17; // 131072
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const DKLEN = 32; // AES-256
const MAXMEM = 256 * 1024 * 1024;
const MIN_SECRET_LEN = 12;

function machineSecret() {
  // Node has no uuid.getnode() equivalent builtin; use the first non-loopback
  // MAC via os.networkInterfaces(), same spoofable-but-good-enough binding
  // as Python PRO's uuid.getnode().
  let mac = '00:00:00:00:00:00';
  const ifaces = os.networkInterfaces();
  for (const name of Object.keys(ifaces)) {
    for (const iface of ifaces[name]) {
      if (!iface.internal && iface.mac && iface.mac !== '00:00:00:00:00:00') { mac = iface.mac; break; }
    }
  }
  const parts = [mac, os.hostname() || '', process.platform];
  return crypto.createHash('sha256').update(parts.join('|')).digest();
}

function warnIfWeak(secret) {
  if (secret.length < MIN_SECRET_LEN) {
    process.stderr.write(`[obsor] WARNING: secret is ${secret.length} chars; use >= ` +
      `${MIN_SECRET_LEN} (a passphrase, not a word). A short secret is ` +
      `brute-forceable offline despite scrypt.\n`);
  }
}

function resolveSecret(mode, passphrase) {
  if (mode === 'pass') {
    if (!passphrase) throw new Error('pass mode needs a passphrase (-k/--key)');
    warnIfWeak(passphrase);
    return Buffer.from(passphrase, 'utf8');
  }
  if (mode === 'machine') return machineSecret();
  if (mode === 'license') {
    if (!passphrase) throw new Error('license mode needs a token (-k/--key)');
    warnIfWeak(passphrase);
    return Buffer.from(passphrase, 'utf8');
  }
  throw new Error(`unknown key mode: ${mode}`);
}

function deriveKey(secret, salt) {
  return crypto.scryptSync(secret, salt, DKLEN, { N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P, maxmem: MAXMEM });
}

// The runtime side of the above, emitted into the protected bootstrap as
// source text. Kept logically identical to the functions above so build and
// run agree.
const RUNTIME_KEYDERIVE = `
const _os = require('os');
function _obsorMachineSecret() {
  let mac = '00:00:00:00:00:00';
  const ifs = _os.networkInterfaces();
  for (const n of Object.keys(ifs)) for (const i of ifs[n]) {
    if (!i.internal && i.mac && i.mac !== '00:00:00:00:00:00') { mac = i.mac; break; }
  }
  return require('crypto').createHash('sha256').update([mac, _os.hostname() || '', process.platform].join('|')).digest();
}
function _obsorSecret(mode, envPass, envLic) {
  if (mode === 'pass') { if (!envPass) { console.error('OBSOR_KEY not set'); process.exit(1); } return Buffer.from(envPass, 'utf8'); }
  if (mode === 'machine') return _obsorMachineSecret();
  if (mode === 'license') { if (!envLic) { console.error('OBSOR_LICENSE not set'); process.exit(1); } return Buffer.from(envLic, 'utf8'); }
  console.error('bad key mode'); process.exit(1);
}
function _obsorDerive(secret, salt) {
  return require('crypto').scryptSync(secret, salt, ${DKLEN}, { N: ${SCRYPT_N}, r: ${SCRYPT_R}, p: ${SCRYPT_P}, maxmem: ${MAXMEM} });
}
`;

module.exports = { SCRYPT_N, SCRYPT_R, SCRYPT_P, DKLEN, MAXMEM, MIN_SECRET_LEN, resolveSecret, deriveKey, RUNTIME_KEYDERIVE };
