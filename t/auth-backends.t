use strict;
use warnings;

use Test::More;

use Net::Nostr::Key;
use Overnet::Auth::Backend;
use Overnet::Auth::Backend::DirectSecret;
use Overnet::Auth::Backend::Pass;

my $fixture_secret = '1111111111111111111111111111111111111111111111111111111111111111';
my $fixture_pubkey = '4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa';

subtest 'base backend requires implementation methods' => sub {
  my $backend = Overnet::Auth::Backend->new;

  my $error = eval { $backend->backend_type; 1 } ? undef : $@;
  like $error, qr/backend_type must be implemented/, 'backend_type is abstract';

  $error = eval { $backend->load_signing_key; 1 } ? undef : $@;
  like $error, qr/load_signing_key must be implemented/, 'load_signing_key is abstract';
};

subtest 'direct secret backend loads one signing key from backend config' => sub {
  my $backend = Overnet::Auth::Backend::DirectSecret->new;
  my ($key, $error) = $backend->load_signing_key(
    backend_config => {
      secret => $fixture_secret,
    },
  );

  ok !$error, 'no backend error';
  is $key->pubkey_hex, $fixture_pubkey, 'expected pubkey loaded from direct secret backend';
};

subtest 'direct secret backend preserves compatibility with identity secret fields' => sub {
  my $backend = Overnet::Auth::Backend::DirectSecret->new;
  my ($key, $error) = $backend->load_signing_key(
    identity => {
      privkey_secret => $fixture_secret,
    },
  );

  ok !$error, 'no backend error';
  is $key->pubkey_hex, $fixture_pubkey, 'compatibility secret field still works';
};

subtest 'direct secret backend reports backend_unavailable when no secret is configured' => sub {
  my $backend = Overnet::Auth::Backend::DirectSecret->new;
  my ($key, $error) = $backend->load_signing_key(
    identity       => {},
    backend_config => {},
  );

  ok !defined $key, 'no signing key is returned';
  is_deeply $error, {
    code    => 'backend_unavailable',
    message => 'no direct secret is configured for the selected identity',
  }, 'direct_secret backend returns a structured backend_unavailable error';
};

subtest 'pass backend uses the first line returned by the command runner' => sub {
  my @seen;
  my $backend = Overnet::Auth::Backend::Pass->new(
    command_runner => sub {
      @seen = @_;
      return ($fixture_secret . "\nignored metadata\n", undef);
    },
  );

  my ($key, $error) = $backend->load_signing_key(
    backend_config => {
      entry => 'overnet-priv-key',
    },
  );

  ok !$error, 'no backend error';
  is_deeply \@seen, [ 'pass', 'show', 'overnet-priv-key' ], 'pass backend invokes the pass command with the configured entry';
  is $key->pubkey_hex, $fixture_pubkey, 'expected pubkey loaded from pass backend output';
};

subtest 'pass backend accepts nsec secrets' => sub {
  my $key = Net::Nostr::Key->new;
  my $backend = Overnet::Auth::Backend::Pass->new(
    command_runner => sub {
      return ($key->privkey_nsec . "\n", undef);
    },
  );

  my ($loaded, $error) = $backend->load_signing_key(
    backend_config => {
      entry => 'overnet-priv-key',
    },
  );

  ok !$error, 'no backend error';
  is $loaded->pubkey_hex, $key->pubkey_hex, 'nsec secret loads through the pass backend';
};

subtest 'pass backend accepts PEM secrets' => sub {
  my $key = Net::Nostr::Key->new;
  my $backend = Overnet::Auth::Backend::Pass->new(
    command_runner => sub {
      return ($key->privkey_pem, undef);
    },
  );

  my ($loaded, $error) = $backend->load_signing_key(
    backend_config => {
      entry => 'overnet-priv-key',
    },
  );

  ok !$error, 'no backend error';
  is $loaded->pubkey_hex, $key->pubkey_hex, 'PEM secret loads through the pass backend';
};

subtest 'pass backend reports backend_unavailable when no entry is configured' => sub {
  my $backend = Overnet::Auth::Backend::Pass->new;
  my ($key, $error) = $backend->load_signing_key(
    backend_config => {},
  );

  ok !defined $key, 'no signing key is returned';
  is_deeply $error, {
    code    => 'backend_unavailable',
    message => 'no pass entry is configured for the selected identity',
  }, 'missing pass entry returns backend_unavailable';
};

subtest 'pass backend reports backend_unavailable when output is empty' => sub {
  my $backend = Overnet::Auth::Backend::Pass->new(
    command_runner => sub {
      return ("\n", undef);
    },
  );

  my ($key, $error) = $backend->load_signing_key(
    backend_config => {
      entry => 'overnet-priv-key',
    },
  );

  ok !defined $key, 'no signing key is returned';
  is_deeply $error, {
    code    => 'backend_unavailable',
    message => 'pass entry overnet-priv-key did not return a usable secret',
  }, 'empty pass output returns backend_unavailable';
};

subtest 'pass backend reports backend_unavailable when output is malformed' => sub {
  my $backend = Overnet::Auth::Backend::Pass->new(
    command_runner => sub {
      return ("not-a-private-key\n", undef);
    },
  );

  my ($key, $error) = $backend->load_signing_key(
    backend_config => {
      entry => 'overnet-priv-key',
    },
  );

  ok !defined $key, 'no signing key is returned';
  is $error->{code}, 'backend_unavailable', 'malformed pass output returns backend_unavailable';
  like $error->{message}, qr/(unable to read key|privkey|No such file|non-existing file|BEGIN)/, 'malformed pass output reports a key-loading failure';
};

subtest 'pass backend reports backend_unavailable when the command runner fails' => sub {
  my $backend = Overnet::Auth::Backend::Pass->new(
    command_runner => sub {
      return (undef, 'pass show failed');
    },
  );

  my ($key, $error) = $backend->load_signing_key(
    backend_config => {
      entry => 'overnet-priv-key',
    },
  );

  ok !defined $key, 'no signing key is returned';
  is_deeply $error, {
    code    => 'backend_unavailable',
    message => 'pass show failed',
  }, 'pass backend returns a structured backend_unavailable error';
};

done_testing;
