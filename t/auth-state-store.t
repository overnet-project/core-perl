use strict;
use warnings;

use FindBin;
use File::Glob qw(bsd_glob);
use File::Spec;
use File::Temp qw(tempdir);
use JSON::PP qw(encode_json);
use Test::More;

use Overnet::Auth::StateStore;

subtest 'load_state returns undef when the state file does not exist yet' => sub {
  my $dir = tempdir(CLEANUP => 1, DIR => File::Spec->catdir($FindBin::Bin, '..'));
  my $path = File::Spec->catfile($dir, 'auth-state.json');

  my $store = Overnet::Auth::StateStore->new(path => $path);
  my $state = $store->load_state;

  ok !defined($state), 'missing state file returns undef';
};

subtest 'save_state writes atomically and load_state reads the same state back' => sub {
  my $dir = tempdir(CLEANUP => 1, DIR => File::Spec->catdir($FindBin::Bin, '..'));
  my $path = File::Spec->catfile($dir, 'auth-state.json');

  my $store = Overnet::Auth::StateStore->new(path => $path);
  my $state = {
    policies => [
      {
        policy_id   => 'policy-1',
        identity_id => 'default',
        program_id  => 'irc.bridge',
        locators    => [ 'irc://irc.example.test/overnet' ],
        scope       => 'irc://irc.example.test/overnet',
        action      => 'session.authenticate',
      },
    ],
    service_pins => {
      'wss://relay.example.test/auth' => {
        scheme => 'nostr.pubkey',
        value  => ('1' x 64),
      },
    },
    sessions => [
      {
        session_handle => { id => 'sess-1' },
        identity_id    => 'default',
        program_id     => 'irc.bridge',
        service        => {
          locators => [ 'wss://relay.example.test/auth' ],
        },
        scope       => 'irc://irc.example.test/overnet',
        action      => 'session.authenticate',
        renewable   => 1,
        artifacts   => [],
      },
    ],
  };

  $store->save_state(state => $state);
  my $loaded = $store->load_state;

  is_deeply $loaded, $state, 'saved state loads back unchanged';
  is_deeply [ bsd_glob($path . '.*') ], [], 'atomic save leaves no temp files behind';
};

subtest 'load_state rejects invalid JSON state objects' => sub {
  my $dir = tempdir(CLEANUP => 1, DIR => File::Spec->catdir($FindBin::Bin, '..'));
  my $path = File::Spec->catfile($dir, 'auth-state.json');

  open my $fh, '>', $path or die "open $path failed: $!";
  print {$fh} encode_json([ 'not', 'an', 'object' ]) or die "write $path failed: $!";
  close $fh or die "close $path failed: $!";

  my $store = Overnet::Auth::StateStore->new(path => $path);
  my $error = eval {
    $store->load_state;
    1;
  } ? undef : $@;

  like $error, qr/auth state must decode to an object/,
    'non-object state files are rejected';
};

done_testing;
