#!/usr/bin/perl

# Tests for the documented Akamai G2O configuration.

###############################################################################

use warnings;
use strict;

use Digest::SHA qw/hmac_sha256/;
use MIME::Base64 qw/encode_base64/;
use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http rewrite pcre
    ngx_http_secure_link_hmac_module/)->plan(20);

open my $file, '<', '../examples/akamai-g2o.conf' or die $!;
my $example = do { local $/; <$file> };
close $file;

$example =~ s/REPLACE_WITH_YOUR_SHARED_SECRET/test-secret/;
$example =~ s!root /srv/g2o;!root %%TESTDIR%%;!;

my $conf = <<'EOF';
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    server {
        listen 127.0.0.1:8080;
        %%EXAMPLE%%
    }
}
EOF

$conf =~ s/%%EXAMPLE%%/$example/;
$t->write_file_expand('nginx.conf', $conf);
mkdir $t->testdir() . '/download' or die $!;
$t->write_file('download/file', 'ok');
$t->run();

my $now = time();
my $data = "5, 192.0.2.1, 198.51.100.1, $now, request1, edge01";
my $uri = '/download/%66ile?x=1&y=%2F';
my $sign = signature($data, $uri);

like(request($uri, $data, $sign), qr/^HTTP\/1\.1 200/, 'valid G2O v5 request');

for my $separator ('  ', "\t") {
    my $value = $data;
    $value =~ s/, /,$separator/g;
    like(request($uri, $value, signature($value, $uri)), qr/^HTTP\/1\.1 200/,
        'field separators allow repeated spaces and tabs');
}

my $changed_spacing = $data;
$changed_spacing =~ s/, /,  /g;
like(request($uri, $changed_spacing, $sign), qr/^HTTP\/1\.1 403/,
    'header whitespace remains part of the signed message');

my $unpadded = $sign;
$unpadded =~ s/=+$//;
like(request($uri, $data, $unpadded), qr/^HTTP\/1\.1 200/,
    'module handles a valid unpadded signature without a separate precheck');

like(request('/download/file?x=1&y=%2F', $data, $sign), qr/^HTTP\/1\.1 403/,
    'normalized URI does not replace the signed URI');
like(request('/download/%66ile?x=2&y=%2F', $data, $sign), qr/^HTTP\/1\.1 403/,
    'query string is covered by the signature');
like(request($uri, $data, substr($sign, 0, 8)), qr/^HTTP\/1\.1 403/,
    'signature prefix is rejected');
like(request($uri, $data, 'A' x 4096), qr/^HTTP\/1\.1 403/,
    'oversized signature is rejected');
like(request($uri, undef, $sign), qr/^HTTP\/1\.1 403/, 'missing data header');
like(request($uri, $data, undef), qr/^HTTP\/1\.1 403/, 'missing signature header');

for my $case (
    ['4, 192.0.2.1, 198.51.100.1, ' . $now . ', request1, edge01', 'wrong version'],
    ['5, 192.0.2.1, 198.51.100.1, ' . $now . ', request1, unknown', 'unknown key'],
    ['5, 192.0.2.1, 198.51.100.1, ' . ($now - 120) . ', request1, edge01', 'expired'],
    ['5, 192.0.2.1, 198.51.100.1, ' . ($now + 120) . ', request1, edge01', 'future'],
    ['5, 192.0.2.1, 198.51.100.1, invalid, request1, edge01', 'invalid timestamp'],
    [$data . ', extra', 'extra field'],
) {
    my ($value, $name) = @$case;
    like(request($uri, $value, signature($value, $uri)), qr/^HTTP\/1\.1 403/,
        "$name is rejected even with a matching HMAC");
}

like(request($uri, $data, $sign, "X-Akamai-G2O-Auth-Data: $data\r\n"),
    qr/^HTTP\/1\.1 403/, 'duplicate data headers are rejected');
like(request($uri, $data, $sign, "X-Akamai-G2O-Auth-Sign: $sign\r\n"),
    qr/^HTTP\/1\.1 403/, 'duplicate signature headers are rejected');
like(request($uri, $data, $sign), qr/^HTTP\/1\.1 200/,
    'valid request remains accepted after invalid inputs');

###############################################################################

sub signature {
    my ($data, $uri) = @_;
    return encode_base64(hmac_sha256($data . $uri, 'test-secret'), '');
}

sub request {
    my ($uri, $data, $sign, $extra) = @_;
    my $headers = defined $data ? "X-Akamai-G2O-Auth-Data: $data\r\n" : '';
    $headers .= "X-Akamai-G2O-Auth-Sign: $sign\r\n" if defined $sign;
    $headers .= $extra // '';
    return http("GET $uri HTTP/1.0\r\nHost: localhost\r\n$headers\r\n");
}

###############################################################################
