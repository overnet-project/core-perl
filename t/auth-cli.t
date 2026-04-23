use strict;
use warnings;

use File::Spec;
use FindBin;
use JSON::PP qw(decode_json);
use Test::More;

use Overnet::Auth::CLI;

{
  package t::auth_cli::FakeClient;

  sub new {
    my ($class, %args) = @_;
    return bless {
      responses => $args{responses} || {},
      calls     => [],
    }, $class;
  }

  sub identities_list {
    my ($self) = @_;
    push @{$self->{calls}}, {
      method => 'identities.list',
      params => {},
    };
    return $self->{responses}{'identities.list'};
  }

  sub sessions_authorize {
    my ($self, %params) = @_;
    push @{$self->{calls}}, {
      method => 'sessions.authorize',
      params => \%params,
    };
    return $self->{responses}{'sessions.authorize'};
  }

  sub sessions_renew {
    my ($self, %params) = @_;
    push @{$self->{calls}}, {
      method => 'sessions.renew',
      params => \%params,
    };
    return $self->{responses}{'sessions.renew'};
  }

  sub sessions_revoke {
    my ($self, %params) = @_;
    push @{$self->{calls}}, {
      method => 'sessions.revoke',
      params => \%params,
    };
    return $self->{responses}{'sessions.revoke'};
  }

  sub calls {
    my ($self) = @_;
    return $self->{calls};
  }
}

my $script = File::Spec->catfile($FindBin::Bin, '..', 'bin', 'overnet-auth.pl');
my $libdir = File::Spec->catdir($FindBin::Bin, '..', 'lib');

subtest 'identities command prints the identity list result as JSON' => sub {
  my $client = t::auth_cli::FakeClient->new(
    responses => {
      'identities.list' => {
        type   => 'response',
        id     => 'auth-1',
        ok     => JSON::PP::true,
        result => {
          identities => [
            {
              identity_id => 'default',
              public_identity => {
                scheme => 'nostr.pubkey',
                value  => ('a' x 64),
              },
            },
          ],
        },
      },
    },
  );

  my $result = Overnet::Auth::CLI->run(
    argv   => [ 'identities' ],
    client => $client,
  );

  is $result->{exit_code}, 0, 'identities exits successfully';
  is_deeply decode_json($result->{output}), {
    ok     => JSON::PP::true,
    result => {
      identities => [
        {
          identity_id => 'default',
          public_identity => {
            scheme => 'nostr.pubkey',
            value  => ('a' x 64),
          },
        },
      ],
    },
  }, 'identities prints the auth-agent result payload';
  is_deeply $client->calls, [
    {
      method => 'identities.list',
      params => {},
    },
  ], 'identities calls identities.list';
};

subtest 'authorize command builds the expected sessions.authorize request' => sub {
  my $artifact_file = File::Spec->catfile($FindBin::Bin, 'auth-cli-artifact.json');
  _write_file($artifact_file, <<'JSON');
{"type":"nostr.event","params":{"kind":22242,"tags":[["relay","irc://irc.example.test/overnet"],["challenge","abcd"]]} }
JSON

  my $client = t::auth_cli::FakeClient->new(
    responses => {
      'sessions.authorize' => {
        type   => 'response',
        id     => 'auth-1',
        ok     => JSON::PP::true,
        result => {
          session_handle => { id => 'sess-1' },
        },
      },
    },
  );

  my $result = Overnet::Auth::CLI->run(
    argv => [
      'authorize',
      '--identity-id', 'default',
      '--program-id', 'irc.bridge',
      '--service-locator', 'irc://irc.example.test/overnet',
      '--scope', 'irc://irc.example.test/overnet',
      '--action', 'session.authenticate',
      '--challenge-type', 'opaque',
      '--challenge-value', 'abcd',
      '--artifact-file', $artifact_file,
      '--service-identity-scheme', 'nostr.pubkey',
      '--service-identity-value', ('b' x 64),
      '--service-identity-display', 'irc.example.test authority',
      '--no-interactive',
    ],
    client => $client,
  );

  is $result->{exit_code}, 0, 'authorize exits successfully';
  is_deeply decode_json($result->{output}), {
    ok     => JSON::PP::true,
    result => {
      session_handle => { id => 'sess-1' },
    },
  }, 'authorize prints the auth-agent result payload';
  is_deeply $client->calls, [
    {
      method => 'sessions.authorize',
      params => {
        identity_id => 'default',
        program_id  => 'irc.bridge',
        service     => {
          locators => [ 'irc://irc.example.test/overnet' ],
          service_identity => {
            scheme  => 'nostr.pubkey',
            value   => ('b' x 64),
            display => 'irc.example.test authority',
          },
        },
        scope       => 'irc://irc.example.test/overnet',
        action      => 'session.authenticate',
        interactive => JSON::PP::false,
        challenge   => {
          type  => 'opaque',
          value => 'abcd',
        },
        artifacts => [
          {
            type => 'nostr.event',
            params => {
              kind => 22242,
              tags => [
                [ 'relay', 'irc://irc.example.test/overnet' ],
                [ 'challenge', 'abcd' ],
              ],
            },
          },
        ],
      },
    },
  ], 'authorize maps CLI flags onto sessions.authorize';

  unlink $artifact_file or die "unlink $artifact_file failed: $!";
};

subtest 'renew and revoke commands wrap session ids as session handles' => sub {
  my $client = t::auth_cli::FakeClient->new(
    responses => {
      'sessions.renew' => {
        type   => 'response',
        id     => 'auth-1',
        ok     => JSON::PP::true,
        result => {
          session_handle => { id => 'sess-2' },
        },
      },
      'sessions.revoke' => {
        type   => 'response',
        id     => 'auth-2',
        ok     => JSON::PP::true,
        result => {
          revoked => JSON::PP::true,
        },
      },
    },
  );

  my $renew = Overnet::Auth::CLI->run(
    argv   => [ 'renew', '--session-id', 'sess-2', '--no-interactive' ],
    client => $client,
  );
  my $revoke = Overnet::Auth::CLI->run(
    argv   => [ 'revoke', '--session-id', 'sess-2' ],
    client => $client,
  );

  is $renew->{exit_code}, 0, 'renew exits successfully';
  is $revoke->{exit_code}, 0, 'revoke exits successfully';
  is_deeply $client->calls, [
    {
      method => 'sessions.renew',
      params => {
        session_handle => { id => 'sess-2' },
        interactive    => JSON::PP::false,
      },
    },
    {
      method => 'sessions.revoke',
      params => {
        session_handle => { id => 'sess-2' },
      },
    },
  ], 'renew and revoke wrap the session id as a session_handle object';
};

subtest 'client CLI script exists and prints help' => sub {
  ok -f $script, 'auth client script exists'
    or BAIL_OUT('auth client script is required');

  my $syntax = system($^X, "-I$libdir", '-c', $script);
  is $syntax >> 8, 0, 'auth client script has valid syntax';

  my $help = qx{$^X -I$libdir $script --help 2>&1};
  is $? >> 8, 0, '--help exits cleanly';
  like $help, qr/Usage:\s+overnet-auth\.pl identities/,
    '--help prints the command synopsis';
};

done_testing;

sub _write_file {
  my ($path, $content) = @_;
  open my $fh, '>', $path
    or die "open $path failed: $!";
  print {$fh} $content
    or die "write $path failed: $!";
  close $fh
    or die "close $path failed: $!";
}
