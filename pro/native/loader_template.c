/* Obsor PRO native loader (generated).
 *
 * Key derivation (scrypt), AES-256-GCM decrypt+verify and the marshal read
 * happen here in compiled C, so the classic one-line `compile`/`exec` hook
 * that peels pure-Python packers does NOT recover the payload.
 *
 * It does NOT make the payload unreachable from Python. Verified attacks that
 * still work for anyone who can run this module (e.g. a licensed customer):
 *   - PyMarshal_ReadObjectFromString still raises CPython's "marshal.loads"
 *     audit event, so a one-line sys.addaudithook captures the plaintext
 *     bytecode (~50ms, no debugger).
 *   - PyEval_EvalCode runs into __main__, so after run() the decrypted
 *     functions/consts are readable from the live globals with no tooling.
 *   - The salt/nonce/tag/ciphertext are embedded here and can be carved from
 *     the binary and decrypted offline by anyone holding the key.
 * Net: against a key-holder this is roughly as strong as the pure-Python
 * tier; the C step only hides key derivation/decryption, not the logic.
 * The real protection is the external key (strong passphrase) against someone
 * who has the file but NOT the key.
 */
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <marshal.h>
#include <openssl/evp.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

/* ---- embedded, filled by build.py ---- */
static const unsigned char SALT[]  = { %%SALT%% };
static const unsigned char NONCE[] = { %%NONCE%% };
static const unsigned char TAG[]   = { %%TAG%% };
static const unsigned char CT[]    = { %%CT%% };
static const size_t CT_LEN = %%CT_LEN%%;
static const char *KEY_ENV = "%%KEY_ENV%%";   /* OBSOR_KEY | OBSOR_LICENSE */

#define SC_N %%N%%
#define SC_R %%R%%
#define SC_P %%P%%
#define SC_MAXMEM ((uint64_t)256 * 1024 * 1024)
#define KEYLEN 32

static int derive_key(const unsigned char *secret, size_t slen, unsigned char *out) {
    return EVP_PBE_scrypt((const char *)secret, slen, SALT, sizeof(SALT),
                          SC_N, SC_R, SC_P, SC_MAXMEM, out, KEYLEN) == 1;
}

static int decrypt_payload(const unsigned char *key,
                           unsigned char **pt_out, int *pt_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;
    int ok = 0, len = 0, total = 0;
    unsigned char *pt = (unsigned char *)malloc(CT_LEN ? CT_LEN : 1);
    if (!pt) { EVP_CIPHER_CTX_free(ctx); return 0; }
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)sizeof(NONCE), NULL) != 1) goto done;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, NONCE) != 1) goto done;
    if (EVP_DecryptUpdate(ctx, pt, &len, CT, (int)CT_LEN) != 1) goto done;
    total = len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, (int)sizeof(TAG), (void *)TAG) != 1) goto done;
    if (EVP_DecryptFinal_ex(ctx, pt + total, &len) != 1) goto done;  /* verifies tag */
    total += len;
    *pt_out = pt; *pt_len = total; ok = 1;
done:
    if (!ok) { OPENSSL_cleanse(pt, CT_LEN); free(pt); }
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

/* Developer-supplied native functions (empty in the plain native tier). Each
 * must have the signature: static PyObject *NAME(PyObject *self, PyObject *args)
 * Their logic lives only in this compiled module -- never as Python bytecode. */
%%EXTRA_FUNCS%%

static PyObject *obsor_run(PyObject *self, PyObject *args) {
    const char *secret = getenv(KEY_ENV);
    if (!secret || !*secret) { PyErr_SetString(PyExc_SystemError, "init failed"); return NULL; }

    unsigned char key[KEYLEN];
    if (!derive_key((const unsigned char *)secret, strlen(secret), key)) {
        PyErr_SetString(PyExc_SystemError, "init failed");
        return NULL;
    }

    unsigned char *pt = NULL; int ptlen = 0;
    int okd = decrypt_payload(key, &pt, &ptlen);
    OPENSSL_cleanse(key, KEYLEN);
    if (!okd) { PyErr_SetString(PyExc_SystemError, "init failed"); return NULL; }

    PyObject *code = PyMarshal_ReadObjectFromString((const char *)pt, (Py_ssize_t)ptlen);
    OPENSSL_cleanse(pt, ptlen);
    free(pt);
    if (!code) return NULL;

    PyObject *main_mod = PyImport_AddModule("__main__");   /* borrowed */
    if (!main_mod) { Py_DECREF(code); return NULL; }
    PyObject *globals = PyModule_GetDict(main_mod);          /* borrowed */

    PyObject *res = PyEval_EvalCode(code, globals, globals);
    Py_DECREF(code);
    if (!res) return NULL;
    Py_DECREF(res);
    Py_RETURN_NONE;
}

static PyMethodDef Methods[] = {
    {"run", obsor_run, METH_NOARGS, "decrypt and execute embedded payload"},
%%EXTRA_METHODS%%
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef moduledef = {
    PyModuleDef_HEAD_INIT, "%%MODNAME%%", NULL, -1, Methods,
    NULL, NULL, NULL, NULL
};

PyMODINIT_FUNC PyInit_%%MODNAME%%(void) {
    return PyModule_Create(&moduledef);
}
