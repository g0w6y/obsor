/*
 * Anti-tamper tripwires emitted into the protected bootstrap.
 *
 * HONEST SCOPE: these run in the same process as the attacker, so a
 * determined reverser can patch them out before they fire. These are
 * deterrents against casual dynamic analysis (attach the inspector, hook
 * eval) -- not a security boundary. The real boundary is the native loader
 * (pro/native).
 */
'use strict';

const GUARD_TEMPLATE = (fn, budget) => `
function ${fn}() {
  // 1. Node inspector/debugger attached?
  try { if (require('inspector').url()) process.exit(1); } catch (e) {}
  // 2. gross single-step slowdown between two cheap ops (tracer/stepper)
  const _a = process.hrtime.bigint();
  let _x = 0; for (let _i = 0; _i < 100000; _i++) _x += _i;
  if (Number(process.hrtime.bigint() - _a) / 1e9 > ${budget}) process.exit(1);
  // 3. global.eval / Buffer still native (not monkey-patched by a dump hook)?
  if (!/\\[native code\\]/.test(global.eval.toString())) process.exit(1);
}
${fn}();
`;

function makeGuard(fnName, timeBudget = 0.25) {
  return GUARD_TEMPLATE(fnName, timeBudget);
}

module.exports = { makeGuard };
