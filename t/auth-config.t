use strict;
use warnings;

use FindBin;
use File::Spec;
use File::Temp qw(tempdir);
use JSON::PP qw(encode_json);
use Test::More;

use Overnet::Auth::Config;

my $fixture_secret = '1111111111111111111111111111111111111111111111111111111111111111';
my $fixture_pubkey = '4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa';

subtest 'load_file returns endpoint and agent config from JSON' => sub {
  my $dir = tempdir(CLEANUP => 1, DIR => File::Spec->catdir($FindBin::Bin, '..'));
  my $config_file = File::Spec->catfile($dir, 'auth-agent.json');
  my $socket_path = File::Spec->catfile($dir, 'auth.sock');

  _write_json(
    $config_file,
    {
      daemon => {
        endpoint => $socket_path,
      },
      identities => [
        {
          identity_id  => 'default',
          backend_type => 'direct_secret',
          backend_config => {
            secret => $fixture_secret,
          },
          public_identity => {
            scheme => 'nostr.pubkey',
            value  => $fixture_pubkey,
          },
        },
      ],
      policies => [
        {
          identity_id => 'default',
          program_id  => 'irc.bridge',
          locator     => 'irc://irc.example.test/overnet',
          scope       => 'irc://irc.example.test/overnet',
          action      => 'session.authenticate',
        },
      ],
    },
  );

  my $config = Overnet::Auth::Config->load_file(path => $config_file);

  is $config->endpoint, $socket_path, 'config exposes the daemon endpoint';
  is_deeply $config->agent_args, {
    identities => [
      {
        identity_id  => 'default',
        backend_type => 'direct_secret',
        backend_config => {
          secret => $fixture_secret,
        },
        public_identity => {
          scheme => 'nostr.pubkey',
          value  => $fixture_pubkey,
        },
      },
    ],
    policies => [
      {
        identity_id => 'default',
        program_id  => 'irc.bridge',
        locator     => 'irc://irc.example.test/overnet',
        scope       => 'irc://irc.example.test/overnet',
        action      => 'session.authenticate',
      },
    ],
    service_pins => {},
    sessions     => [],
  }, 'config exposes the agent constructor args';
};

subtest 'load_file rejects non-object JSON configs' => sub {
  my $dir = tempdir(CLEANUP => 1, DIR => File::Spec->catdir($FindBin::Bin, '..'));
  my $config_file = File::Spec->catfile($dir, 'auth-agent.json');
  _write_raw($config_file, qq{["not","an","object"]\n});

  my $error = eval {
    Overnet::Auth::Config->load_file(path => $config_file);
    1;
  } ? undef : $@;

  like $error, qr/auth config must decode to an object/,
    'non-object auth config files are rejected';
};

done_testing;

sub _write_json {
  my ($path, $value) = @_;
  _write_raw($path, encode_json($value));
}

sub _write_raw {
  my ($path, $content) = @_;
  open my $fh, '>', $path
    or die "open $path failed: $!";
  print {$fh} $content
    or die "write $path failed: $!";
  close $fh
    or die "close $path failed: $!";
}
