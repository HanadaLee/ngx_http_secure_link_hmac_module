#!/usr/bin/perl

# Tests for secure link decoding, binary comparisons and time validation.

###############################################################################

use warnings;
use strict;

use Digest::SHA qw/hmac_sha256 hmac_sha512 hmac_sha256_hex/;
use MIME::Base64 qw/encode_base64/;
use POSIX qw/strftime/;
use Test::More;
use Config;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use Test::Nginx qw/ :DEFAULT http_content /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http rewrite ngx_http_secure_link_hmac_module/);

my $conf = <<'EOF';
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    secure_link_hmac on;
    secure_link_hmac_secret default-secret;
    secure_link_hmac_message payload;
    secure_link_hmac_algorithm sha256;
    secure_link_hmac_check_token $http_x_token digest=hex;

    server {
        listen 127.0.0.1:8080;
        location /hex { return 200 "$secure_link_hmac"; }
        location /base64 {
            secure_link_hmac_check_token $http_x_token digest=base64;
            return 200 "$secure_link_hmac";
        }
        location /base64url {
            secure_link_hmac_check_token $http_x_token digest=base64url;
            return 200 "$secure_link_hmac";
        }
        location /sha512 {
            secure_link_hmac_algorithm sha512;
            secure_link_hmac_check_token $http_x_token digest=base64;
            return 200 "$secure_link_hmac";
        }
        location /binary {
            secure_link_hmac_check_token $http_x_token digest=bin;
            return 200 "$secure_link_hmac";
        }
        location /time {
            secure_link_hmac_check_time $arg_ts
                range_start=$arg_start range_end=$arg_end;
            return 200 "$secure_link_hmac";
        }
        location /ms {
            secure_link_hmac_check_time $arg_ts range_start=-30 range_end=30
                format=%ms;
            return 200 "$secure_link_hmac";
        }
        location /date {
            secure_link_hmac_check_time $http_x_date range_start=-30 range_end=30
                format=%Y-%m-%dT%H:%M:%S timezone=gmt;
            return 200 "$secure_link_hmac";
        }
        location /empty-key {
            secure_link_hmac_secret "";
            return 200 "$secure_link_hmac";
        }
        location /xof {
            secure_link_hmac_algorithm shake128;
            return 200 "$secure_link_hmac";
        }
        location /reevaluate {
            secure_link_hmac_message $payload;
            set $payload payload;
            set $first $secure_link_hmac;
            set $payload changed;
            set $second $secure_link_hmac;
            return 200 "$first|$second";
        }
    }
}
EOF

my $binary = hmac_sha256('payload', 'default-secret');
my $hex = unpack('H*', $binary);
my $base64 = encode_base64($binary, '');
my $unpadded = $base64;
$unpadded =~ s/=+$//;
my $url = $unpadded;
$url =~ tr!+/!-_!;
my $wide = encode_base64(hmac_sha512('payload', 'default-secret'), '');
my $now = time();
my $max = $Config{ivsize} == 8 ? '9223372036854775807' : '2147483647';
my $date = strftime('%Y-%m-%dT%H:%M:%S', gmtime($now));

my @cases = (
    ['/hex', $hex, '1', 'hex token'],
    ['/hex', uc($hex), '1', 'uppercase hex token'],
    ['/hex', substr($hex, 0, -2), '', 'truncated hex token'],
    ['/hex', '00' x 2048, '', 'oversized hex token'],
    ['/base64', $base64, '1', 'padded base64'],
    ['/base64', $unpadded, '1', 'unpadded base64'],
    ['/base64url', $url, '1', 'unpadded base64url'],
    ['/base64url', $url . '=', '1', 'padded base64url'],
    ['/sha512', $wide, '1', 'maximum digest fits decoded buffer'],
    ['/base64', 'A' x 4096, '', 'oversized base64 is rejected before decoding'],
    ['/base64url', 'A' x 4096, '', 'oversized base64url is rejected before decoding'],
    ['/base64', substr($base64, 0, 8), '', 'valid signature prefix is rejected'],
    ['/base64', $base64 . 'AAAA', '', 'suffix after padding is rejected'],
    ['/base64', $unpadded . 'A', '', 'non-padding final character is rejected'],
    ['/base64', '=' . substr($base64, 1), '', 'early padding is rejected'],
    ['/base64', $base64 . '=', '', 'excess padding is rejected'],
    ['/binary', $binary, '1', 'binary token compares supplied bytes'],
    ['/binary', '0' x 32, '', 'wrong binary token'],
    ['/binary', '0' x 31, '', 'short binary token'],
    ["/time?ts=$now&start=-30&end=30", $hex, '1', 'signed decimal range'],
    ["/time?ts=$now&start=-0x1e&end=0x1e", $hex, '1', 'signed hexadecimal range'],
    ["/time?ts=$now&start=invalid&end=30", $hex, '', 'invalid start fails closed'],
    ["/time?ts=$now&start=-30&end=invalid", $hex, '', 'invalid end fails closed'],
    ["/time?ts=$now&start=&end=30", $hex, '', 'empty start fails closed'],
    ["/time?ts=$now&start=-30&end=", $hex, '', 'empty end fails closed'],
    ["/time?ts=$now&start=30&end=-30", $hex, '', 'reversed range'],
    ["/time?ts=$now&start=-$max&end=$max", $hex, '1', 'large offsets do not overflow'],
    ["/time?ts=$max&start=0&end=$max", $hex, '', 'future time with large end is rejected'],
    ["/time?ts=$now&start=-30&end=${max}0", $hex, '', 'overflowing range is rejected'],
    ['/ms?ts=' . $now . '123', $hex, '1', 'milliseconds'],
    ['/ms?ts=' . $now . 'bad', $hex, '', 'non-numeric milliseconds'],
    ['/date', $hex, '1', 'date input', "X-Date: $date\r\n"],
    ['/date', $hex, '', 'date suffix is rejected', "X-Date: ${date}junk\r\n"],
    ['/xof', '00' x 16, '', 'variable length digest is rejected'],
    ['/reevaluate', $hex, '1|', 'verification follows a changed message'],
    ['/hex', $hex, '1', 'worker remains usable after malformed inputs'],
);
push @cases, ['/empty-key', hmac_sha256_hex('payload', ''), '', 'empty key fails closed'];

$t->plan(scalar @cases);
$t->write_file_expand('nginx.conf', $conf)->run();

for my $case (@cases) {
    my ($uri, $token, $expected, $name, $extra) = @$case;
    $extra //= '';
    my $response = http("GET $uri HTTP/1.0\r\nHost: localhost\r\n"
        . "X-Token: $token\r\n$extra\r\n");
    is(http_content($response), $expected, $name);
}

###############################################################################
