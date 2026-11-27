/*
 * Obsor-JS PRO native-logic tier.
 *
 * Compile a developer-supplied N-API C routine INTO the loader addon, so the
 * sensitive logic ships as machine code and is never reconstructed as JS
 * source. The protected payload calls it through an injected global (default
 * name `obsorNative`); a key-holder can invoke the function as a black box
 * but cannot read its logic via eval/Function hooks, the inspector, or
 * globals -- there is no JS source for it to recover. This is the only tier
 * that resists a key-holding attacker.
 *
 * The developer writes a standard N-API C function:
 *
 *   static napi_value secret_algo(napi_env env, napi_callback_info info) { ... }
 *
 * and lists its exported name. Everything else (key derivation, decrypt,
 * the JS payload) works exactly as the native tier.
 *
 * Design note: to actually protect a gate (e.g. a license check), the
 * native function must RETURN a value the payload genuinely needs (a key, a
 * computed result) -- not a bool the JS side can ignore. A black-box boolean
 * is trivially bypassed by not calling it.
 */
'use strict';
const { buildNativeLoader } = require('./build');

const IDENT = /^[A-Za-z_][A-Za-z0-9_]*$/;

function buildNativeLogic(payloadSource, logicC, exports, outJs, opts = {}) {
  if (!exports || !exports.length) throw new Error('native-logic tier needs at least one exported function');
  for (const name of exports) if (!IDENT.test(name)) throw new Error(`invalid C function name: ${name}`);
  const alias = opts.alias || 'obsorNative';
  if (!IDENT.test(alias)) throw new Error(`invalid alias: ${alias}`);

  const extraAttach = exports.map((n) =>
    `        { napi_value fn; napi_create_function(env, "${n}", NAPI_AUTO_LENGTH, ${n}, NULL, &fn); ` +
    `napi_set_named_property(env, native_obj, "${n}", fn); }`
  ).join('\n');

  return buildNativeLoader(payloadSource, outJs, {
    ...opts, extraFuncs: logicC, extraAttach, alias,
  });
}

module.exports = { buildNativeLogic };
