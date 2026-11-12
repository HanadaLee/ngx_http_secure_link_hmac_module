# Changelog

## 0.4.0

### Breaking changes

- Rename `ngx_http_auth_hmac_module` to `ngx_http_secure_link_hmac_module`, including the dynamic module filename, directives and variables. Replace `auth_hmac` with `secure_link_hmac` in existing configurations.
- Reject malformed or empty configured time bounds and unsupported variable-length digests.
- Reject empty HMAC keys.

### Fixes

- Restore configuration inheritance when built without `ngx_expr_module`.
- Validate Base64 and Base64URL lengths and padding before decoding into the digest buffer.
- Compare binary tokens using the supplied token bytes and check the computed digest length.
- Reject invalid millisecond suffixes and date suffixes, terminate date input, and avoid overflow in time range checks.
- Reject unknown or duplicate time parameters and invalid timezone offsets.
- Reevaluate verification when its input changes during a request.
- Check HMAC calculation failures.

### Examples

- Add a tested Akamai G2O v5 configuration using `if`, `set` and `$secure_link_hmac`.
