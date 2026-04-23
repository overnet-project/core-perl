use strict;
use warnings;

use File::Spec;
use FindBin;
use JSON::PP qw(decode_json);
use Test::More;

my $readme = File::Spec->catfile($FindBin::Bin, '..', 'README.md');

ok -f $readme, 'README exists'
  or BAIL_OUT('README.md is required');

open my $fh, '<', $readme
  or die "open $readme failed: $!";
my $content = do { local $/; <$fh> };
close $fh
  or die "close $readme failed: $!";

like $content, qr/overnet-auth-agent\.pl --config-file/,
  'README documents starting the auth-agent daemon';
like $content, qr/overnet-auth\.pl identities/,
  'README documents the auth client CLI';

my ($config_json) = $content =~ /```json\n(.*?)\n```/s;
ok defined $config_json, 'README includes a JSON auth-agent config example'
  or BAIL_OUT('README auth-agent config example is required');

my $config = decode_json($config_json);
is ref($config), 'HASH', 'config example decodes to an object';
ok ref($config->{daemon}) eq 'HASH', 'config example includes a daemon section';
ok ref($config->{identities}) eq 'ARRAY' && @{$config->{identities}},
  'config example includes at least one identity';
ok ref($config->{policies}) eq 'ARRAY' && @{$config->{policies}},
  'config example includes at least one policy';

done_testing;
