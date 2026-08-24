#!/usr/bin/perl

# Tests for ngx_http_auth_hmac_module.

###############################################################################

use warnings;
use strict;

use Digest::SHA qw/hmac_sha256 hmac_sha256_hex hmac_sha512_hex/;
use MIME::Base64 qw/encode_base64/;
use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http rewrite ngx_condition_module
	ngx_http_auth_hmac_module/)->plan(12);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    auth_hmac on;
    auth_hmac_check_token $http_x_token digest=hex;
    auth_hmac_message payload;
    auth_hmac_secret default-secret;
    auth_hmac_algorithm sha256;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        condition alternate str_eq $arg_mode alternate;

        location = /verify {
            when alternate {
                auth_hmac on;
                auth_hmac_message alternate;
                auth_hmac_secret alternate-secret;
                auth_hmac_algorithm sha512;
            }

            return 200 "$auth_hmac";
        }

        location = /base64 {
            auth_hmac_check_token $http_x_token digest=base64;
            return 200 "$auth_hmac";
        }

        location = /base64url {
            auth_hmac_check_token $http_x_token digest=base64url;
            return 200 "$auth_hmac";
        }

        location = /disabled {
            auth_hmac off;
            return 200 "$auth_hmac";
        }

        location = /time {
            auth_hmac_check_time $arg_ts range_start=-5 range_end=5
                format=%s;
            return 200 "$auth_hmac";
        }

        location = /milliseconds {
            auth_hmac_check_time $arg_ts range_start=-5 range_end=5
                format=%ms;
            return 200 "$auth_hmac";
        }

        location = /hex-time {
            auth_hmac_check_time $arg_ts range_start=-5 range_end=5
                format=%x;
            return 200 "$auth_hmac";
        }
    }
}

EOF

$t->run();

###############################################################################

sub request {
	my ($uri, $token) = @_;
	my $header = defined $token ? "X-Token: $token\r\n" : '';

	return http("GET $uri HTTP/1.0\r\nHost: localhost\r\n$header\r\n");
}

sub body_is {
	my ($response, $body, $name) = @_;
	like($response, qr/\x0d\x0a\x0d\x0a\Q$body\E$/, $name);
}

my $hex = hmac_sha256_hex('payload', 'default-secret');
my $binary = hmac_sha256('payload', 'default-secret');
my $base64 = encode_base64($binary, '');
my $base64url = $base64;
$base64url =~ tr!+/!-_!;
$base64url =~ s/=+$//;

body_is(request('/verify', $hex), '1',
	'valid inherited hexadecimal token');
body_is(request('/verify', '00' x 32), '', 'invalid token is rejected');
body_is(request('/verify', undef), '', 'missing token is rejected');
body_is(request('/base64', $base64), '1', 'valid base64 token');
body_is(request('/base64url', $base64url), '1', 'valid base64url token');

body_is(request('/verify?mode=alternate',
	hmac_sha512_hex('alternate', 'alternate-secret')), '1',
	'matching condition selects alternate values');
body_is(request('/verify?mode=other', $hex), '1',
	'condition miss falls back to inherited values');
body_is(request('/disabled', $hex), '',
	'disabled verification returns an empty result');

my $now = time();
body_is(request("/time?ts=$now", $hex), '1',
	'current timestamp is accepted');
body_is(request('/time?ts=' . ($now - 30), $hex), '',
	'expired timestamp is rejected');
body_is(request('/milliseconds?ts=' . ($now * 1000), $hex), '1',
	'millisecond timestamp is accepted');
body_is(request('/hex-time?ts=' . sprintf('%x', $now), $hex), '1',
	'hexadecimal timestamp is accepted');

###############################################################################
