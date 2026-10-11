/* Secret algorithm compiled into the .so. Returns a value the payload needs,
   so it cannot be bypassed by ignoring a boolean. Logic never ships as Python. */
static PyObject *secret_transform(PyObject *self, PyObject *args) {
    long x;
    if (!PyArg_ParseTuple(args, "l", &x)) return NULL;
    long r = (x * 2654435761L) ^ 0x5A17;
    r = (r % 1000000) + 42;
    return PyLong_FromLong(r);
}
