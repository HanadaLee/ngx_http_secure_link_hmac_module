# ngx_http_secure_link_hmac_module

Verifies HMAC-signed URLs with optional time limits. Supported algorithms depend on the OpenSSL build and include `blake2b512`, `blake2s256`, `gost`, `md4`, `md5`, `mdc2`, `rmd160`, `sha1`, `sha224`, `sha256`, `sha3-224`, `sha3-256`, `sha3-384`, `sha3-512`, `sha384`, `sha512`, `sha512-224`, `sha512-256`, and `sm3`.

Tokens use the HMAC construction defined by RFC 2104: `H(secret_key XOR opad, H(secret_key XOR ipad, message))`.

## Table of Contents

- [Synopsis](#synopsis)
- [Installation](#installation)
- [Conditional configuration](#conditional-configuration)
- [Directives](#directives)
  - [secure_link_hmac](#secure_link_hmac)
  - [secure_link_hmac_check_time](#secure_link_hmac_check_time)
  - [secure_link_hmac_check_token](#secure_link_hmac_check_token)
  - [secure_link_hmac_message](#secure_link_hmac_message)
  - [secure_link_hmac_secret](#secure_link_hmac_secret)
  - [secure_link_hmac_algorithm](#secure_link_hmac_algorithm)
- [Embedded Variables](#embedded-variables)
  - [$secure_link_hmac](#secure_link_hmac-1)
- [Token generation](#token-generation)
  - [Perl](#perl)
  - [PHP](#php)
  - [Node.js](#nodejs)
  - [Python](#python)
  - [Bash](#bash)
- [Akamai G2O](#akamai-g2o)
- [Akamai Auth Token 2.0](#akamai-auth-token-20)
- [Contributing](#contributing)
- [License](#license)

## Synopsis

Set the signed message with `secure_link_hmac_message`, the key with `secure_link_hmac_secret`, and the digest algorithm with `secure_link_hmac_algorithm`.

Include the timestamp and lifetime in the signed message when using time-limited links.

The optional `range_start` and `range_end` parameters limit the token's validity period. Without configured time bounds, verification does not check expiration.

```nginx
location ^~ /files/ {
    # Enables the feature, if disabled, $secure_link_hmac will always be empty
    secure_link_hmac on;

    # Set the time value used for checking.
    # You can set the expiration time range, the format of the time value, and the time zone of the time value
    secure_link_hmac_check_time $arg_ts range_end=$arg_e format=%s;

    # Set the token value used for checking
    # Available digests are hex (default), base64, base64url and bin
    secure_link_hmac_check_token $arg_st digest=hex;

    # Secret key
    secure_link_hmac_secret "my_secret_key";

    # Message to be verified
    secure_link_hmac_message "$uri|$arg_ts|$arg_e";

    # Cryptographic hash function to be used
    secure_link_hmac_algorithm sha256;

    # In production environment, we should not reveal to potential attacker
    # why hmac authentication has failed
    # - If the hash is incorrect then $secure_link_hmac is a NULL string.
    # - If the hash is correct and the link has not expired then $secure_link_hmac is "1".
    if ($secure_link_hmac != "1") {
        return 403;
    }

    rewrite ^/files/(.*)$ /files/$1 break;
}
```

## Installation

To build a static module:

```sh
./configure --add-module=/absolute/path/to/ngx_http_secure_link_hmac_module
```

To build the dynamic module `ngx_http_secure_link_hmac_module.so`:

```sh
./configure --with-compat --add-dynamic-module=/absolute/path/to/ngx_http_secure_link_hmac_module
```

To enable `expr` and `when`, build `ngx_expr_module` statically in the same Nginx configuration:

```bash
./configure \
    --add-module=/path/to/ngx_expr_module \
    --add-module=/path/to/ngx_http_secure_link_hmac_module
```

Build and install nginx:

```sh
make
make install
```

## Conditional configuration

All module directives support `http`, `server` and `location`. When [`ngx_expr_module`](https://git.hanada.info/hanada/ngx_expr_module) is built into Nginx, they also support `when` in each of those contexts. Every directive selects its value independently:

```nginx
expr use_sha512 str_eq $host secure.example.com;

when use_sha512 {
    secure_link_hmac_algorithm sha512;
    secure_link_hmac_secret secure_key;
}

secure_link_hmac_algorithm sha256;
secure_link_hmac_secret default_key;
```

The first matching value is used. An unconditional value participates in the same ordering, so put it after conditional values when it is intended as a fallback. The parameters of one `secure_link_hmac_check_time` or `secure_link_hmac_check_token` directive are selected as one configuration value.

## Directives

### secure_link_hmac

| Syntax: | **secure_link_hmac** `on` \| `off`; |
| :--- | :--- |
| Default: | `secure_link_hmac off;` |
| Context: | `http`, `server`, `location`, `when` |

Enables or disables HMAC verification. When disabled, `$secure_link_hmac` is empty.

### secure_link_hmac_check_time

| Syntax: | **secure_link_hmac_check_time** `complex_value [range_start=complex_value] [range_end=complex_value] [format=format] [timezone=gmt\|gmt+HHMM\|gmt-HHMM];` |
| :--- | :--- |
| Default: | — |
| Context: | `http`, `server`, `location`, `when` |

Specifies the request time and its valid range. `format=%s` selects a Unix timestamp, `format=%ms` a millisecond timestamp, and `format=%x` a hexadecimal timestamp. Other format strings are parsed as dates. `range_start` and `range_end` may contain variables.

### secure_link_hmac_check_token

| Syntax: | **secure_link_hmac_check_token** `complex_value [digest=hex\|base64\|base64url\|bin];` |
| :--- | :--- |
| Default: | — |
| Context: | `http`, `server`, `location`, `when` |

Specifies the supplied HMAC and its encoding. The default digest encoding is `hex`.

### secure_link_hmac_message

| Syntax: | **secure_link_hmac_message** `complex_value;` |
| :--- | :--- |
| Default: | — |
| Context: | `http`, `server`, `location`, `when` |

Specifies the message whose HMAC is verified. The value may contain variables.

### secure_link_hmac_secret

| Syntax: | **secure_link_hmac_secret** `complex_value;` |
| :--- | :--- |
| Default: | — |
| Context: | `http`, `server`, `location`, `when` |

Specifies the HMAC key. The value may contain variables. An empty key is rejected.

### secure_link_hmac_algorithm

| Syntax: | **secure_link_hmac_algorithm** `name;` |
| :--- | :--- |
| Default: | `secure_link_hmac_algorithm sha256;` |
| Context: | `http`, `server`, `location`, `when` |

Specifies an OpenSSL digest algorithm name with a fixed output size. Extendable-output functions such as SHAKE are not supported.

## Embedded Variables

### $secure_link_hmac

`1` when the HMAC matches and the configured time bounds are satisfied; an empty string otherwise.

## Token generation

Use the same key, message format, and digest algorithm as the nginx configuration. The examples below produce a hexadecimal HMAC-SHA256 token; Base64URL alternatives are shown where applicable.

### Perl

The example returns query parameters containing the token, Unix timestamp, and lifetime in seconds.

```nginx
perl_set $secure_token '
    sub {
        use Digest::SHA qw(hmac_sha256 hmac_sha256_base64);

        my $now = time();
        my $secret = "my_very_secret_key";
        my $expire = 60;
        my $timestamp = $now;
        my $r = shift;
        my $data = $r->uri;

        # hex
        my $string_to_hash = $data . "|" . $timestamp . "|" . $expire;
        my $digest_binary = hmac_sha256($string_to_hash, $secret);
        my $digest = unpack("H*", $digest_binary);

        # base64url
        # my $digest = hmac_sha256_base64($data . "|" . $timestamp . "|" . $expire,  $secret);
        # $digest =~ tr(+/)(-_);

        $data = "st=" . $digest . "&ts=" . $timestamp . "&e=" . $expire;
        return $data;
    }
';
```

### PHP

```php
$secret = 'my_very_secret_key';
$expire = 60;
$algo = 'sha256';
$unixtimestamp = time();
$stringtosign = "/files/top_secret.pdf|{$unixtimestamp}|{$expire}";
// hex
$hashmac = bin2hex(hash_hmac($algo, $stringtosign, $secret, true));
// base64url
// $hashmac = base64_encode(hash_hmac($algo, $stringtosign, $secret, true));
// $hashmac = strtr($hashmac, '+/', '-_');
// $hashmac = str_replace('=', '', $hashmac);
$host = $_SERVER['HTTP_HOST'];
$loc = "https://{$host}/files/top_secret.pdf?st={$hashmac}&ts={$unixtimestamp}&e={$expire}";
```

### Node.js

```javascript
const crypto = require("crypto");
const secret = 'my_very_secret_key';
const expire = 60;
const unixTimestamp = Math.round(Date.now() / 1000.);
const stringToSign = `/files/top_secret.pdf|${unixTimestamp}|${expire}`;
// hex
const hashmac = crypto.createHmac('sha256', secret).update(stringToSign).digest('hex')
// base64url
// const hashmac = crypto.createHmac('sha256', secret).update(stringToSign).digest('base64')
//       .replace(/=/g, '')
//       .replace(/\+/g, '-')
//       .replace(/\//g, '_');
const loc = `https://host/files/top_secret.pdf?st=${hashmac}&ts=${unixTimestamp}&e=${expire}`;
```

### Python

This example uses only the Python standard library and matches the nginx configuration above.

```python
import hashlib
import hmac
import time
from urllib.parse import urlencode

secret = b"my_secret_key"
path = "/files/top_secret.pdf"
timestamp = int(time.time())
lifetime = 60
message = f"{path}|{timestamp}|{lifetime}".encode("utf-8")
signature = hmac.new(secret, message, hashlib.sha256).hexdigest()

query = urlencode({"st": signature, "ts": timestamp, "e": lifetime})
url = f"https://host{path}?{query}"
print(url)
```

### Bash

```bash
#!/bin/bash

SECRET="my_super_secret"
TIME_STAMP="$(date -d "today + 0 minutes" +%s)";
EXPIRES="3600"; # seconds
URL="/file/my_secret_file.txt"
ST="$URL|$TIME_STAMP|$EXPIRES"
# hex
TOKEN="$(printf '%s' "$ST" | openssl dgst -sha256 -hmac "$SECRET" | awk '{print $NF}')"
# Base64url
# TOKEN="$(printf '%s' "$ST" | openssl dgst -sha256 -hmac "$SECRET" -binary | openssl base64 | tr +/ -_ | tr -d =)"

echo "http://127.0.0.1$URL?st=$TOKEN&ts=$TIME_STAMP&e=$EXPIRES"
```

## Akamai G2O

[`examples/akamai-g2o.conf`](examples/akamai-g2o.conf) verifies G2O v5 with HMAC-SHA256 and a 30-second window in both directions. Include it in `server {}`, replace `edge01` and the shared secret, and set the document root or your content handler. Timestamp extraction uses the standard rewrite module's `if` and `set` directives.

The signed message is the original `X-Akamai-G2O-Auth-Data` header immediately followed by `$request_uri`, with no added separator. Do not rebuild the header or substitute `$uri`: query parameters and the original URI escaping are covered by the signature. The shared secret is used as raw bytes.

The regular expression extracts the timestamp while restricting the six-field header to the configured version and key ID. `\s+` accepts spaces and tabs between fields. The module validates the timestamp, time window and signature; the configuration rejects requests unless `$secure_link_hmac` is `1`. Duplicate authentication headers are rejected. The key ID identifies the configured secret; it is not a per-request replay nonce. Like the former G2O module, this configuration does not maintain a replay cache or bind the IP fields to the connection addresses.

| G2O version | Digest algorithm |
| --- | --- |
| 3 | `md5` |
| 4 | `sha1` |
| 5 | `sha256` |

To support another version, change the accepted version and digest together.

The example rejects requests with `if` and `return` in the rewrite phase. To retain ACCESS-phase ordering or `satisfy` behavior, have your access handler consume `$secure_link_hmac`. For observation without rejection, remove the `if` block and record `$secure_link_hmac` in an access log. Verification runs when its result variable is read.

## Akamai Auth Token 2.0

**This example requires [ngx_var_module](https://git.hanada.info/hanada/ngx_var_module)** for `hex_decode`, `extract_param`, and `sub`. Build it together with this module. `ngx_expr_module` is not required by this example.

[`examples/akamai-auth-token.conf`](examples/akamai-auth-token.conf) verifies an [Akamai Auth Token 2.0](https://techdocs.akamai.com/property-mgr/docs/auth-token-2-0-ver) supplied in the `X-Auth-Token` request header. Include it in `server {}`, replace `REPLACE_WITH_YOUR_HEX_KEY` with the configured hexadecimal key, and set the document root or content handler.

The example accepts this field sequence, with HMAC-SHA256 and the fixed ACL `/protected/*`:

```text
st=<start-time>~exp=<end-time>~acl=/protected/*~hmac=<hex-digest>
```

Both timestamps are Unix seconds. The key is decoded from hexadecimal before verification; the signed message is the original token text before `~hmac=`. The ACL is restricted to the protected location. Tokens with missing, repeated, reordered, or additional fields are rejected. URL tokens, other ACLs, and salt are outside this example's scope.

Generate a matching token with the [Akamai Python SDK](https://github.com/akamai/EdgeAuth-Token-Python):

```python
from akamai.edgeauth import EdgeAuth

auth = EdgeAuth(
    key="REPLACE_WITH_YOUR_HEX_KEY",
    start_time="now",
    window_seconds=300,
    escape_early=False,
)
print(auth.generate_acl_token("/protected/*"))
```

Send the result in `X-Auth-Token` when requesting a file under `/protected/`. Invalid signatures and requests outside the token's time range return 403.

## Contributing

Submit issues and pull requests to the [GitHub repository](https://github.com/HanadaLee/ngx_http_secure_link_hmac_module).

## License

See [LICENSE](LICENSE).
