/* Secret algorithm compiled into the .node addon. Returns a value the
   payload needs, so it cannot be bypassed by ignoring a boolean. Logic
   never ships as JS source. */
static napi_value secret_transform(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value args[1];
    napi_get_cb_info(env, info, &argc, args, NULL, NULL);
    int64_t x;
    napi_get_value_int64(env, args[0], &x);
    int64_t r = (x * 2654435761LL) ^ 0x5A17;
    r = (r % 1000000 + 1000000) % 1000000 + 42;
    napi_value out;
    napi_create_int64(env, r, &out);
    return out;
}
