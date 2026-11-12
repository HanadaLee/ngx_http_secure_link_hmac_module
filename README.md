Nginx Secure Link HMAC Module
=============================

Description:
============

The Nginx secure link HMAC module enhances the security and functionality of the standard secure link module.
Secure token is created using secure HMAC construction with an arbitrary hash algorithm supported by OpenSSL, e.g.:
`blake2b512`, `blake2s256`, `gost`, `md4`, `md5`, `mdc2`, `rmd160`, `sha1`, `sha224`, `sha256`,
`sha3-224`, `sha3-256`, `sha3-384`, `sha3-512`, `sha384`, `sha512`, `sha512-224`, `sha512-256`, `sm3`.

Furthermore, secure token is created as described in RFC2104, that is,
`H(secret_key XOR opad,H(secret_key XOR ipad, message))` instead of a simple `MD5(secret_key,message, expire)`.

Installation:
=============

You'll need to re-compile Nginx from source to include this module.
Modify your compile of Nginx by adding the following directive (modified to suit your path of course):

Static module (built-in nginx binary)

    ./configure --add-module=/absolute/path/to/ngx_http_secure_link_hmac_module

Dynamic nginx module `ngx_http_secure_link_hmac_module.so` module

    ./configure --with-compat --add-dynamic-module=/absolute/path/to/ngx_http_secure_link_hmac_module

To enable `expr` and `when`, build `ngx_expr_module` statically in
the same Nginx configuration:

```bash
./configure \
    --add-module=/path/to/ngx_expr_module \
    --add-module=/path/to/ngx_http_secure_link_hmac_module
```

Build Nginx

    make
    make install

Usage:
======

Message to be hashed is defined by `secure_link_hmac_message`, `secret_key` is given by `secure_link_hmac_secret`, and hashing algorithm H is defined by `secure_link_hmac_algorithm`.

For improved security, the time or a timestamp (depending on the date format specified by format parameter) should be appended to the message to be hashed.

It is possible to create links with limited lifetime. This is defined by optional parameters range_start or range_end. If the expiration period is not specified, a link has the unlimited lifetime.

Configuration example for server side.

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

Conditional configuration
=========================

All module directives support `http`, `server` and `location`. When
[`ngx_expr_module`](https://git.hanada.info/hanada/ngx_expr_module)
is built into Nginx, they also support `when` in each of those contexts.
Every directive selects its value independently:

```nginx
expr use_sha512 str_eq $host secure.example.com;

when use_sha512 {
    secure_link_hmac_algorithm sha512;
    secure_link_hmac_secret secure_key;
}

secure_link_hmac_algorithm sha256;
secure_link_hmac_secret default_key;
```

The first matching value is used. An unconditional value participates in the
same ordering, so put it after conditional values when it is intended as a
fallback. The parameters of one `secure_link_hmac_check_time` or
`secure_link_hmac_check_token` directive are selected as one configuration value.

Directives
==========

secure_link_hmac
---------

**syntax:** `secure_link_hmac on | off`

**default:** `secure_link_hmac off`

**context:** `http`, `server`, `location`, `when`

Enables or disables HMAC verification. When disabled, `$secure_link_hmac` is empty.

secure_link_hmac_check_time
--------------------

**syntax:** `secure_link_hmac_check_time complex_value [range_start=complex_value] [range_end=complex_value] [format=format] [timezone=gmt|gmt+HHMM|gmt-HHMM]`

**default:** none

**context:** `http`, `server`, `location`, `when`

Specifies the request time and its valid range. `format=%s` selects a Unix
timestamp, `format=%ms` a millisecond timestamp, and `format=%x` a hexadecimal
timestamp. Other format strings are parsed as dates. `range_start` and
`range_end` may contain variables.

secure_link_hmac_check_token
---------------------

**syntax:** `secure_link_hmac_check_token complex_value [digest=hex|base64|base64url|bin]`

**default:** none

**context:** `http`, `server`, `location`, `when`

Specifies the supplied HMAC and its encoding. The default digest encoding is
`hex`.

secure_link_hmac_message
-----------------

**syntax:** `secure_link_hmac_message complex_value`

**default:** none

**context:** `http`, `server`, `location`, `when`

Specifies the message whose HMAC is verified. The value may contain variables.

secure_link_hmac_secret
----------------

**syntax:** `secure_link_hmac_secret complex_value`

**default:** none

**context:** `http`, `server`, `location`, `when`

Specifies the HMAC key. The value may contain variables. An empty key is rejected.

secure_link_hmac_algorithm
-------------------

**syntax:** `secure_link_hmac_algorithm name`

**default:** `secure_link_hmac_algorithm sha256`

**context:** `http`, `server`, `location`, `when`

Specifies an OpenSSL digest algorithm name with a fixed output size. Extendable-output functions such as SHAKE are not supported.

Application side should use a standard hash_hmac function to generate hash, which then needs to be hex or base64url encoded. Example in Perl below.

#### Variable $data contains secure token, Unix timestamp, and expiration period in seconds

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

A similar function in PHP

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

Using Unix timestamp in Node.js

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

Bash version

```shell
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

Embedded Variables
==================
* `$secure_link_hmac` - If the hash is correct and the link has not expired then $secure_link_hmac is "1". Otherwise, it is null.


Akamai G2O
==========

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

Contributing:
=============

Git source repositories: http://github.com/hanadalee/ngx_http_secure_link_hmac_module/tree/master

Please feel free to fork the project at GitHub and submit pull requests or patches.
