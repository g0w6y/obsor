/* Obsor-JS PRO native loader (generated).
 *
 * Key derivation (scrypt), AES-256-GCM decrypt+verify, and the script
 * execution happen here in compiled C via N-API's `napi_run_script`, so the
 * classic one-line `global.eval`/`Function` hook that peels pure-JS packers
 * does NOT see this call -- napi_run_script goes straight into V8, bypassing
 * the JS-visible eval/Function references entirely.
 *
 * It does NOT make the payload unreachable from Node. Verified attacks that
 * still work for anyone who can run this module (e.g. a licensed customer):
 *   - `node --inspect` + the V8 Inspector protocol sees EVERY compiled
 *     script regardless of how it was compiled, including ones run via
 *     napi_run_script -- Debugger.scriptParsed fires for it like any other.
 *   - After run() the decrypted functions/consts sit in the global object,
 *     readable with no tooling.
 *   - The salt/nonce/tag/ciphertext are embedded here and can be carved from
 *     the compiled .node file and decrypted offline by anyone holding the key.
 * Net: against a key-holder this is roughly as strong as the pure-JS tier;
 * the C step only hides key derivation/decryption and avoids the eval/
 * Function hook, not the inspector or post-run-globals paths. The real
 * protection is the external key (strong passphrase) against someone who
 * has the file but NOT the key.
 */
#include <node_api.h>
#include <openssl/evp.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

/* ---- embedded, filled by build.js ---- */
static const unsigned char SALT[]  = { %%SALT%% };
static const unsigned char NONCE[] = { %%NONCE%% };
static const unsigned char TAG[]   = { %%TAG%% };
static const unsigned char CT[]    = { %%CT%% };
static const size_t CT_LEN = %%CT_LEN%%;
static const char *KEY_ENV = "%%KEY_ENV%%";   /* OBSOR_KEY | OBSOR_LICENSE */
static const char *ALIAS   = "%%ALIAS%%";     /* global name for native-logic exports, "" if none */

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

static napi_value env_var(napi_env env, const char *name) {
    const char *v = getenv(name);
    napi_value out;
    if (!v) { napi_get_undefined(env, &out); return out; }
    napi_create_string_utf8(env, v, NAPI_AUTO_LENGTH, &out);
    return out;
}

/* Developer-supplied native functions (empty in the plain native tier). Each
 * must have the N-API signature: static napi_value NAME(napi_env, napi_callback_info)
 * Their logic lives only in this compiled module -- never as JS source. */
%%EXTRA_FUNCS%%

static napi_value Run(napi_env env, napi_callback_info info) {
    const char *secret = getenv(KEY_ENV);
    if (!secret || !*secret) { napi_throw_error(env, NULL, "init failed"); return NULL; }

    unsigned char key[KEYLEN];
    if (!derive_key((const unsigned char *)secret, strlen(secret), key)) {
        napi_throw_error(env, NULL, "init failed");
        return NULL;
    }

    unsigned char *pt = NULL; int ptlen = 0;
    int okd = decrypt_payload(key, &pt, &ptlen);
    OPENSSL_cleanse(key, KEYLEN);
    if (!okd) { napi_throw_error(env, NULL, "init failed"); return NULL; }

    napi_value script, result;
    napi_status st = napi_create_string_utf8(env, (const char *)pt, (size_t)ptlen, &script);
    OPENSSL_cleanse(pt, ptlen);
    free(pt);
    if (st != napi_ok) { napi_throw_error(env, NULL, "init failed"); return NULL; }

    if (napi_run_script(env, script, &result) != napi_ok) return NULL; /* exception already pending */
    return result;
}

static napi_value Init(napi_env env, napi_value exports) {
    napi_value run_fn;
    napi_create_function(env, "run", NAPI_AUTO_LENGTH, Run, NULL, &run_fn);
    napi_set_named_property(env, exports, "run", run_fn);

    if (ALIAS[0] != '\0') {
        napi_value global, native_obj;
        napi_get_global(env, &global);
        napi_create_object(env, &native_obj);
%%EXTRA_ATTACH%%
        napi_set_named_property(env, global, ALIAS, native_obj);
    }

    return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
