use strict;
use warnings;
use Test::More;

use lib 'lib';
use lib 'local/lib/perl5';

use_ok('Overnet::Core::Validator');
use_ok('Overnet::Program::Runtime');
use_ok('Overnet::Authority::HostedChannel');

ok !-e 'lib/Overnet/Relay.pm',
  'core-perl no longer ships the relay entrypoint module';
ok !-d 'lib/Overnet/Relay',
  'core-perl no longer ships the relay module tree';
ok !-e 'bin/overnet-relay.pl',
  'core-perl no longer ships the relay daemon';
ok !-e 'bin/overnet-relay-sync.pl',
  'core-perl no longer ships the relay sync CLI';
ok !-e 'bin/overnet-release-gate.pl',
  'core-perl no longer ships the relay-heavy release gate';

done_testing;
