#!/usr/bin/env python3

import argparse
import base64
import binascii
import hashlib
import hmac
import re
from urllib.parse import parse_qsl, urlsplit


def validate_url(url, prefix=False):
    if not url.isascii() or any(ord(char) <= 32 or ord(char) == 127 for char in url):
        raise ValueError("use a percent-encoded URL without whitespace")
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname or "#" in url:
        raise ValueError("use an absolute HTTP or HTTPS URL without a fragment")
    if parts.username is not None or parts.password is not None or parts.port is not None:
        raise ValueError("omit credentials and explicit ports from the URL")
    if not parts.path.startswith("/"):
        raise ValueError("include a path beginning with /, including for a URL prefix")
    if prefix and "?" in url:
        raise ValueError("a URL prefix must not contain query parameters")
    reserved = {"expires", "keyname", "signature", "urlprefix"}
    if any(name.lower() in reserved for name, _ in parse_qsl(parts.query, keep_blank_values=True)):
        raise ValueError("the URL already contains signing parameters")


def signature(message, key_name, base64_key, expires):
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,63}", key_name):
        raise ValueError("use 1 to 63 letters, digits, underscores or hyphens for the key name")
    if not isinstance(expires, int) or expires <= 0:
        raise ValueError("expiration must be a positive Unix timestamp")
    if not re.fullmatch(r"[A-Za-z0-9_-]{22}(?:==)?", base64_key):
        raise ValueError("use a Base64URL-encoded 128-bit key")
    try:
        key = base64.b64decode(base64_key.rstrip("=") + "==", altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as error:
        raise ValueError("invalid Base64URL key") from error
    if len(key) != 16 or base64.urlsafe_b64encode(key).decode().rstrip("=") != base64_key.rstrip("="):
        raise ValueError("use a canonical Base64URL-encoded 128-bit key")
    digest = hmac.new(key, message.encode("ascii"), hashlib.sha1).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii")


def sign_url(url, key_name, base64_key, expires):
    validate_url(url)
    separator = "&" if "?" in url else "?"
    if "?" in url and url.endswith(("?", "&")):
        separator = ""
    message = f"{url}{separator}Expires={expires}&KeyName={key_name}"
    return f"{message}&Signature={signature(message, key_name, base64_key, expires)}"


def sign_cookie(url_prefix, key_name, base64_key, expires):
    validate_url(url_prefix, prefix=True)
    prefix = base64.urlsafe_b64encode(url_prefix.encode("ascii")).decode("ascii")
    policy = f"URLPrefix={prefix}:Expires={expires}:KeyName={key_name}"
    return f"Cloud-CDN-Cookie={policy}:Signature={signature(policy, key_name, base64_key, expires)}"


def main():
    parser = argparse.ArgumentParser(description="Generate Google Cloud CDN signed URLs or cookies.")
    parser.add_argument("type", choices=("url", "cookie"))
    parser.add_argument("url", help="the complete URL, or URL prefix for a cookie")
    parser.add_argument("--key-name", default="example-key")
    parser.add_argument("--key", required=True, help="Base64URL-encoded 128-bit key")
    parser.add_argument("--expires", required=True, type=int, help="expiration time in Unix seconds")
    args = parser.parse_args()
    try:
        sign = sign_url if args.type == "url" else sign_cookie
        result = sign(args.url, args.key_name, args.key, args.expires)
    except ValueError as error:
        parser.error(str(error))
    print(result)


if __name__ == "__main__":
    main()
