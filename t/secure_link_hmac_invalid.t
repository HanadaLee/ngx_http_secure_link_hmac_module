#!/usr/bin/perl

# Tests for secure link configuration validation.

###############################################################################

use warnings;
use strict;
use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my @cases = (
    ['range_start=', qr/invalid numeric value/, 'empty start'],
    ['range_end=', qr/invalid numeric value/, 'empty end'],
    ['range_end=bad', qr/invalid numeric value/, 'non-numeric end'],
    ['range_end=999999999999999999999999', qr/invalid numeric value/, 'overflow'],
    ['range_start=0 range_start=1', qr/duplicate range_start/, 'duplicate start'],
    ['range_end=0 range_end=1', qr/duplicate range_end/, 'duplicate end'],
    ['format=%s format=%ms', qr/duplicate format/, 'duplicate format'],
    ['timezone=gmt timezone=gmt+0100', qr/duplicate timezone/, 'duplicate timezone'],
    ['timezone=g', qr/invalid timezone/, 'short timezone'],
    ['timezone=gmt+2400', qr/invalid timezone offset/, 'invalid hours'],
    ['timezone=gmt+0060', qr/invalid timezone offset/, 'invalid minutes'],
    ['range_end=1 typo=1', qr/invalid parameter/, 'unknown parameter'],
);

my $t = Test::Nginx->new()->has(qw/http ngx_http_secure_link_hmac_module/)
    ->plan(2 * scalar(@cases) + 2);

for my $case (@cases) {
    my ($parameters, $expected, $name) = @$case;
    check_invalid("secure_link_hmac_check_time 1 $parameters;", $expected, $name);
}

check_invalid('secure_link_hmac_check_token value digest=base64suffix;',
    qr/invalid token format/, 'digest suffix');

undef $t;

###############################################################################

sub check_invalid {
    my ($directive, $expected, $name) = @_;
    $t->write_file_expand('nginx.conf', <<EOF);
%%TEST_GLOBALS%%
daemon off;
events {}
http { $directive }
EOF
    my $output = $t->dump_config();
    my $status = $?;
    isnt($status, 0, "$name is rejected");
    like($output, $expected, "$name diagnostic");
}

###############################################################################
