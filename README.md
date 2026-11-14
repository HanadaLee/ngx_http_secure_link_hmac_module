# ngx_http_secure_link_hmac_module

Verifies HMAC-signed URLs with optional time limits. Supports fixed-length OpenSSL digests, hexadecimal and Base64 tokens, variable inputs, and conditional configuration through `ngx_expr_module`.

## Table of Contents

- [Synopsis](#synopsis)
- [Installation](#installation)
  - [Static module](#static-module)
  - [Dynamic module](#dynamic-module)
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
- [Google Cloud CDN](#google-cloud-cdn)
  - [Signed URL](#signed-url)
  - [Signed Cookie](#signed-cookie)
  - [Generate signatures](#generate-signatures)
- [Tests](#tests)
- [Changelog](#changelog)
- [Contributing](#contributing)
- [License](#license)

## Synopsis

```nginx
location /files/ {
    secure_link_hmac on;
    secure_link_hmac_algorithm sha256;
    secure_link_hmac_secret my_secret_key;
    secure_link_hmac_message "$uri|$arg_ts|$arg_e";
    secure_link_hmac_check_token $arg_st digest=hex;
    secure_link_hmac_check_time $arg_ts range_end=$arg_e format=%s;

    if ($secure_link_hmac != 1) {
        return 403;
    }

    root /srv/www;
}
```

The token authenticates the resource path, Unix timestamp, and lifetime in seconds using the configured key. Verification runs when `$secure_link_hmac` is read; the `if` block rejects invalid or expired tokens.

## Installation

Requires nginx sources and the OpenSSL development headers and `libcrypto`. Run the following commands from the nginx source directory.

### Static module

```sh
./configure --add-module=/path/to/ngx_http_secure_link_hmac_module
make
make install
```

### Dynamic module

Build against the same nginx version and compatible configuration options as the target binary:

```sh
./configure --with-compat --add-dynamic-module=/path/to/ngx_http_secure_link_hmac_module
make modules
```

Copy `objs/ngx_http_secure_link_hmac_module.so` to the nginx modules directory, then load it in the main configuration context:

```nginx
load_module modules/ngx_http_secure_link_hmac_module.so;
```

## Conditional configuration

Build [ngx_expr_module](https://git.hanada.info/hanada/ngx_expr_module) statically in the same nginx configuration to enable `expr` and `when`:

```sh
./configure \
    --add-module=/path/to/ngx_expr_module \
    --add-module=/path/to/ngx_http_secure_link_hmac_module
make
make install
```

All module directives support `when`. Each directive selects its value independently; place an unconditional fallback after conditional entries.

```nginx
expr use_sha512 str_eq $host secure.example.com;

when use_sha512 {
    secure_link_hmac_algorithm sha512;
    secure_link_hmac_secret secure_key;
}

secure_link_hmac_algorithm sha256;
secure_link_hmac_secret default_key;
```

The parameters of one `secure_link_hmac_check_time` or `secure_link_hmac_check_token` directive are selected together.

## Directives

### secure_link_hmac

| Syntax: | **secure_link_hmac** `on` \| `off`; |
| :--- | :--- |
| Default: | `secure_link_hmac off;` |
| Context: | `http`, `server`, `location`, `when` |

Enables or disables HMAC verification. When disabled, `$secure_link_hmac` is empty.

### secure_link_hmac_check_time

| Syntax: | **secure_link_hmac_check_time** `value [range_start=value] [range_end=value] [format=format] [timezone=gmt\|gmt+HHMM\|gmt-HHMM];` |
| :--- | :--- |
| Default: | — |
| Context: | `http`, `server`, `location`, `when` |

Specifies the token timestamp and its valid range. The timestamp, `range_start`, and `range_end` may contain variables.

The bounds apply to the token's age, `current time - timestamp`, in seconds. Both bounds are inclusive. An omitted bound is unrestricted; if neither is configured, expiration is not checked.

| Format | Timestamp representation |
| :--- | :--- |
| `%s` | Decimal Unix seconds; the default |
| `%ms` | Decimal Unix milliseconds |
| `%x` | Hexadecimal Unix seconds |
| Other | A date parsed using the [POSIX `strptime()` format specifiers](https://pubs.opengroup.org/onlinepubs/9799919799/functions/strptime.html) |

The exact values `%s`, `%ms`, and `%x` select the module's timestamp modes listed above. `timezone` applies to date formats and defaults to `gmt`. Unix timestamps are independent of this setting.

### secure_link_hmac_check_token

| Syntax: | **secure_link_hmac_check_token** `value [digest=hex\|base64\|base64url\|bin];` |
| :--- | :--- |
| Default: | — |
| Context: | `http`, `server`, `location`, `when` |

Specifies the supplied HMAC. The value may contain variables. The default encoding is `hex`.

| Encoding | Token representation |
| :--- | :--- |
| `hex` | Hexadecimal, accepting uppercase or lowercase letters |
| `base64` | Standard Base64 |
| `base64url` | URL-safe Base64 |
| `bin` | Raw digest bytes |

### secure_link_hmac_message

| Syntax: | **secure_link_hmac_message** `value;` |
| :--- | :--- |
| Default: | — |
| Context: | `http`, `server`, `location`, `when` |

Specifies the message whose HMAC is verified. The value may contain variables. Include the timestamp and any client-supplied lifetime in the message when using time-limited links.

### secure_link_hmac_secret

| Syntax: | **secure_link_hmac_secret** `value;` |
| :--- | :--- |
| Default: | — |
| Context: | `http`, `server`, `location`, `when` |

Specifies the HMAC key. The value may contain variables. An empty key is rejected.

### secure_link_hmac_algorithm

| Syntax: | **secure_link_hmac_algorithm** `name;` |
| :--- | :--- |
| Default: | `secure_link_hmac_algorithm sha256;` |
| Context: | `http`, `server`, `location`, `when` |

Specifies an OpenSSL digest algorithm, such as `md5`, `sha256`, `sha512`, or `sha3-256`. Available algorithms depend on the OpenSSL build. Only fixed-length digests are supported; extendable-output functions such as SHAKE are not supported.

## Embedded Variables

### $secure_link_hmac

`1` when the HMAC matches and the configured time bounds are satisfied; an empty string otherwise.

## Token generation

The following examples match the HMAC-SHA256 configuration in [Synopsis](#synopsis). They use `my_secret_key` and a 60-second lifetime. The message is `path|timestamp|lifetime`; `path` must match nginx's normalized `$uri`.

For a Base64URL token, also change the nginx configuration to `digest=base64url`.

### Perl

With `ngx_http_perl_module`, this variable returns the query parameters for the current request path:

```nginx
perl_set $secure_token '
    sub {
        use Digest::SHA qw(hmac_sha256_hex hmac_sha256_base64);

        my $r = shift;
        my $secret = "my_secret_key";
        my $timestamp = time();
        my $lifetime = 60;
        my $message = join("|", $r->uri, $timestamp, $lifetime);
        my $signature = hmac_sha256_hex($message, $secret);

        # Base64URL alternative:
        # my $signature = hmac_sha256_base64($message, $secret);
        # $signature =~ tr(+/)(-_);

        return "st=$signature&ts=$timestamp&e=$lifetime";
    }
';
```

### PHP

```php
<?php
$secret = 'my_secret_key';
$path = '/files/top_secret.pdf';
$timestamp = time();
$lifetime = 60;
$message = "{$path}|{$timestamp}|{$lifetime}";
$signature = hash_hmac('sha256', $message, $secret);

// Base64URL alternative:
// $signature = rtrim(strtr(base64_encode(hash_hmac('sha256', $message, $secret, true)), '+/', '-_'), '=');

$query = http_build_query(['st' => $signature, 'ts' => $timestamp, 'e' => $lifetime], '', '&', PHP_QUERY_RFC3986);
echo "https://example.com{$path}?{$query}\n";
```

### Node.js

```javascript
const crypto = require('crypto');

const secret = 'my_secret_key';
const path = '/files/top_secret.pdf';
const timestamp = Math.floor(Date.now() / 1000);
const lifetime = 60;
const message = `${path}|${timestamp}|${lifetime}`;
const signature = crypto.createHmac('sha256', secret).update(message).digest('hex');

// Base64URL alternative:
// const signature = crypto.createHmac('sha256', secret).update(message).digest('base64')
//     .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');

const query = new URLSearchParams({st: signature, ts: timestamp, e: lifetime});
console.log(`https://example.com${path}?${query}`);
```

### Python

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

# Base64URL alternative:
# import base64
# signature = base64.urlsafe_b64encode(hmac.new(secret, message, hashlib.sha256).digest()).rstrip(b"=").decode("ascii")

query = urlencode({"st": signature, "ts": timestamp, "e": lifetime})
print(f"https://example.com{path}?{query}")
```

### Bash

```bash
#!/usr/bin/env bash

secret='my_secret_key'
path='/files/top_secret.pdf'
timestamp=$(date +%s)
lifetime=60
message="$path|$timestamp|$lifetime"
signature=$(printf '%s' "$message" | openssl dgst -sha256 -hmac "$secret" | awk '{print $NF}')

# Base64URL alternative:
# signature=$(printf '%s' "$message" | openssl dgst -sha256 -hmac "$secret" -binary | openssl base64 -A | tr '/+' '_-' | tr -d '=')

printf '%s\n' "https://example.com$path?st=$signature&ts=$timestamp&e=$lifetime"
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

## Google Cloud CDN

These examples require [ngx_var_module](https://git.hanada.info/hanada/ngx_var_module). Include one configuration in a dedicated `server {}`, replace `example-key` and `REPLACE_WITH_YOUR_BASE64URL_KEY`, and set the document root or content handler. The signing key is a Base64URL-encoded 128-bit value. `ngx_expr_module` is not required.

Both examples accept `GET` and `HEAD` and reject unsigned requests. They reconstruct the public URL from `$scheme://$host$request_uri`; this must match the URL used by the signer, including its original escaping. Behind a reverse proxy, the public scheme and host must be supplied from trusted configuration.

### Signed URL

[`examples/google-cloud-cdn-signed-url.conf`](examples/google-cloud-cdn-signed-url.conf) verifies a [Google Cloud CDN Signed URL](https://docs.cloud.google.com/cdn/docs/using-signed-urls) using HMAC-SHA1 and Base64URL:

```text
https://cdn.example.com/video.mp4?Expires=<unix-seconds>&KeyName=example-key&Signature=<signature>
```

The signature covers the complete URL through `KeyName`, including any preceding query parameters. The signing fields must appear last in the order shown. Duplicate signing parameters are rejected. The `URLPrefix` form of Signed URL is not included in this example.

### Signed Cookie

[`examples/google-cloud-cdn-signed-cookie.conf`](examples/google-cloud-cdn-signed-cookie.conf) verifies the [Cloud-CDN-Cookie](https://docs.cloud.google.com/cdn/docs/using-signed-cookies) policy:

```text
URLPrefix=<base64url-prefix>:Expires=<unix-seconds>:KeyName=example-key:Signature=<signature>
```

The signature covers the policy through `KeyName`. The configuration checks expiration and matches the decoded prefix against both the original URL and the normalized resource path. The prefix must include a path beginning with `/`; end it with `/` for directory-wide access. Duplicate authentication cookies and Signed URL query parameters are rejected.

### Generate signatures

[`examples/google-cloud-cdn.py`](examples/google-cloud-cdn.py) uses the Python standard library. Pass a percent-encoded URL without an explicit port or fragment. `--expires` is an absolute Unix timestamp, independent of the local time zone.

```sh
expires=$(($(date +%s) + 1800))

python3 examples/google-cloud-cdn.py url 'https://cdn.example.com/video.mp4?download=1' \
    --key-name example-key --key REPLACE_WITH_YOUR_BASE64URL_KEY --expires "$expires"

python3 examples/google-cloud-cdn.py cookie 'https://cdn.example.com/videos/' \
    --key-name example-key --key REPLACE_WITH_YOUR_BASE64URL_KEY --expires "$expires"
```

The first command prints the signed URL. Send the second command's output in the request's `Cookie` header.

## Tests

The integration tests require Perl, the `nginx-tests` harness, and an nginx binary built with this module. Run from the module directory:

```sh
TEST_NGINX_BINARY=/path/to/nginx \
PERL5LIB=/path/to/nginx-tests/lib \
prove -v t/*.t
```

Tests for conditional configuration are skipped when `ngx_expr_module` is unavailable. For a dynamic build, also set `TEST_NGINX_GLOBALS='load_module /path/to/ngx_http_secure_link_hmac_module.so;'`.

The [CI workflow](.github/workflows/test.yml) covers static and dynamic builds, builds with and without `ngx_expr_module`, and AddressSanitizer/UndefinedBehaviorSanitizer checks.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and breaking changes.

## Contributing

Submit issues and pull requests to the [GitHub repository](https://github.com/HanadaLee/ngx_http_secure_link_hmac_module).

## License

Licensed under the [BSD 2-Clause License](LICENSE).
