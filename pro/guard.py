#!/usr/bin/env python3
"""
Anti-tamper tripwires emitted into the protected bootstrap.

HONEST SCOPE: these run in the same interpreter as the attacker, so a
determined reverser can patch them out. Python's own docs say audit hooks
"can be trivially disabled or bypassed" from within the process. These are
*deterrents* that defeat casual dynamic analysis (attach a tracer, dump via
a hooked exec) -- they are not a security boundary. The real boundary is the
native loader (pro/native).

Returned snippet, when tripped, raises SystemExit before the payload decrypts.
Identifier names are substituted by the engine so no two builds match.
"""

GUARD_TEMPLATE = r'''
def {fn}():
    import sys as _s, time as _t
    # 1. a Python tracer attached (pdb, coverage, a dump hook)?
    if _s.gettrace() is not None:
        raise SystemExit()
    # 2. gross single-step slowdown between two cheap ops
    _a = _t.perf_counter()
    _x = 0
    for _i in range(1000):
        _x += _i
    if (_t.perf_counter() - _a) > {budget}:
        raise SystemExit()
    # 3. builtins.exec / marshal.loads replaced with a non-builtin (dump hook)?
    import builtins as _b, marshal as _m
    if getattr(_b.exec, "__class__", None).__name__ != "builtin_function_or_method":
        raise SystemExit()
    if getattr(_m.loads, "__class__", None).__name__ != "builtin_function_or_method":
        raise SystemExit()
{fn}()
'''


def make_guard(fn_name: str, time_budget: float = 0.05) -> str:
    return GUARD_TEMPLATE.format(fn=fn_name, budget=time_budget)
