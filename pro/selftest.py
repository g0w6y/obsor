#!/usr/bin/env python3
"""
End-to-end self-test for Obsor PRO. Exit 0 = all pass.

    python -m pro.selftest
"""
import builtins
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pro import engine  # noqa: E402

SAMPLE = '''
def fibonacci(n):
    seq = [0, 1]
    for _ in range(n - 2):
        seq.append(seq[-1] + seq[-2])
    return seq[:n]
print("FIB", fibonacci(8))
'''

PASS, FAIL = "[PASS]", "[FAIL]"
rc = 0


def check(name, cond):
    global rc
    print((PASS if cond else FAIL), name)
    if not cond:
        rc = 1


def run(path, env_key=None):
    env = dict(os.environ)
    if env_key is not None:
        env["OBSOR_KEY"] = env_key
    p = subprocess.run([sys.executable, path], capture_output=True, text=True, env=env)
    return p.returncode, p.stdout, p.stderr


def main():
    wd = tempfile.mkdtemp(prefix="obsor_selftest_")
    src = os.path.join(wd, "in.py")
    open(src, "w").write(SAMPLE)

    # ---- hardened tier ----
    out = os.path.join(wd, "hard.py")
    engine.protect_file(src, out, key_mode="pass", passphrase="CorrectPass123")
    text = open(out).read()
    check("hardened: passphrase not embedded", "CorrectPass123" not in text)
    check("hardened: runs with correct key", run(out, "CorrectPass123")[1].strip() == "FIB [0, 1, 1, 2, 3, 5, 8, 13]")
    check("hardened: wrong key refuses", run(out, "pw-wrong")[0] != 0)
    check("hardened: no key refuses", run(out, None)[0] != 0)

    a = engine.protect("print(1)", passphrase="DummyPass1234")
    b = engine.protect("print(1)", passphrase="DummyPass1234")
    import re
    ida = set(re.findall(r"_[a-z]{8}", a))
    idb = set(re.findall(r"_[a-z]{8}", b))
    check("hardened: identifiers randomized per build", ida != idb)

    # ---- native tier ----
    try:
        from pro.native.build import build_native_loader
        napp = os.path.join(wd, "native_app.py")
        so = build_native_loader(SAMPLE, napp, key_mode="pass", passphrase="CorrectPass123")
        check("native: builds", os.path.exists(so))
        check("native: runs with correct key", run(napp, "CorrectPass123")[1].strip() == "FIB [0, 1, 1, 2, 3, 5, 8, 13]")
        check("native: wrong key refuses", run(napp, "pw-wrong")[0] != 0)
        with open(so, "rb") as f:
            blob = f.read()
        check("native: no original source in .so", b"def fibonacci" not in blob)
    except Exception as e:
        check(f"native: build/run ({e})", False)

    # ---- native-logic tier ----
    try:
        from pro.native.logic import build_native_logic
        logic_c = ('static PyObject *sq(PyObject *self, PyObject *args){'
                   'long x; if(!PyArg_ParseTuple(args,"l",&x)) return NULL;'
                   'return PyLong_FromLong(x*x+1);}')
        payload = 'import obsor_native\nprint("R", obsor_native.sq(6))\n'
        lapp = os.path.join(wd, "logic_app.py")
        lso = build_native_logic(payload, logic_c, ["sq"], lapp,
                                 key_mode="pass", passphrase="CorrectPass123")
        check("native-logic: builds", os.path.exists(lso))
        check("native-logic: runs + C result", run(lapp, "CorrectPass123")[1].strip() == "R 37")
        # the C function must not expose Python bytecode
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            os.path.basename(lso).split(".")[0], lso)
        m = importlib.util.module_from_spec(spec)
        os.environ["OBSOR_KEY"] = "CorrectPass123"
        spec.loader.exec_module(m)
        check("native-logic: C func has no __code__", not hasattr(m.sq, "__code__"))
    except Exception as e:
        check(f"native-logic: build/run ({e})", False)

    print("\n" + ("ALL PASS" if rc == 0 else "FAILURES ABOVE"))
    return rc


if __name__ == "__main__":
    sys.exit(main())
